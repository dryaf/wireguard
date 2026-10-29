#!/usr/bin/env python3
"""Server-side WireGuard operations. No private keys are returned or logged."""

import argparse
from contextlib import contextmanager
import fcntl
import io
import ipaddress
import json
import os
from pathlib import Path
from string import Template
import tempfile
import time
import zipfile

from wireguard import (
    wireguard_normalize_line, wireguard_peer_config,
    wireguard_next_client_address, wireguard_peer_networks,
    wireguard_safe_client_name, wireguard_valid_client_name,
)
from wireguard_firewall import OperationError, WireGuardFirewall, managed_policy, run_command


def read_config(path):
    if path.is_symlink():
        raise OperationError("Refusing to access a symlink in the WireGuard directory")
    return path.read_text() if path.exists() else None


def atomic_write(path, content):
    """Persist a private file before exposing its new name to other operations."""
    if path.is_symlink():
        raise OperationError("Refusing to overwrite a symlink")
    data = content.encode() if isinstance(content, str) else content
    current = path.read_bytes() if path.exists() else None
    if current == data:
        path.chmod(0o600)
        return False
    fd, temporary = tempfile.mkstemp(prefix=".wireguard-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return True


def sections(config):
    result = []
    current = None
    for raw_line in config.splitlines():
        line = wireguard_normalize_line(raw_line)
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            current = {"section": line[1:-1].lower(), "values": {}}
            result.append(current)
        else:
            key, separator, value = line.partition("=")
            if current is None or not separator:
                raise OperationError("Invalid WireGuard configuration")
            current["values"].setdefault(key.lower(), []).append(value)
    return result


def one_value(section, key):
    values = section["values"].get(key, [])
    if len(values) != 1 or not values[0]:
        raise OperationError(f"Expected exactly one {key} in the client configuration")
    return values[0]


def managed_block(config, name):
    lines = config.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines) if line.strip() == f"# BEGIN ANSIBLE MANAGED BLOCK FOR {name}"]
    ends = [i for i, line in enumerate(lines) if line.strip() == f"# END ANSIBLE MANAGED BLOCK FOR {name}"]
    if not starts and not ends:
        return lines, None
    if len(starts) != 1 or len(ends) != 1 or starts[0] >= ends[0]:
        raise OperationError("Incomplete or duplicate client management markers")
    return lines, (starts[0], ends[0] + 1)


class WireGuardManager:
    def __init__(self, directory="/etc/wireguard", runner=run_command, lock_timeout=60):
        self.directory = Path(directory)
        self.config_path = self.directory / "wg0.conf"
        self.run = runner
        self.lock_timeout = lock_timeout
        self.firewall = WireGuardFirewall(directory, runner)

    @contextmanager
    def locked(self):
        # Keep the lock file: unlinking it would allow locks on different inodes.
        fd = os.open(self.directory / ".management.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            deadline = time.monotonic() + self.lock_timeout
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise OperationError("Another WireGuard operation is still running; retry later")
                    time.sleep(0.05)
            yield
        finally:
            os.close(fd)

    def server_config(self):
        config = read_config(self.config_path)
        if config is None:
            raise OperationError("wg0.conf is missing; restore the server configuration first")
        return config

    def initialize_key(self):
        with self.locked():
            key_path = self.directory / "privatekey"
            private_key = read_config(key_path)
            if private_key is None:
                existing = read_config(self.config_path)
                if existing is not None:
                    interfaces = [part for part in sections(existing) if part["section"] == "interface"]
                    if len(interfaces) != 1:
                        raise OperationError("Cannot recover the existing server private key")
                    private_key = one_value(interfaces[0], "privatekey")
                else:
                    private_key = self.run(["wg", "genkey"]).strip()
            self.run(["wg", "pubkey"], stdin=private_key)
            return {"changed": atomic_write(key_path, private_key)}

    def sync(self, require_running=False):
        if "wg0" not in self.run(["wg", "show", "interfaces"]).split():
            if require_running:
                raise OperationError("The wg0 interface is missing after service startup")
            return
        stripped = self.run(["wg-quick", "strip", str(self.config_path)])
        self.run(["wg", "syncconf", "wg0", "/dev/stdin"], stdin=stripped)

    def profile_keys(self, profile):
        parsed = sections(profile)
        interfaces = [part for part in parsed if part["section"] == "interface"]
        peers = [part for part in parsed if part["section"] == "peer"]
        if len(interfaces) != 1 or len(peers) != 1:
            raise OperationError("The file is not a single-server client profile")
        private_key = one_value(interfaces[0], "privatekey")
        server_key = read_config(self.directory / "privatekey")
        if server_key is None:
            raise OperationError("The server private key is missing")
        server_public = self.run(["wg", "pubkey"], stdin=server_key).strip()
        if one_value(peers[0], "publickey") != server_public:
            raise OperationError("The client profile belongs to a different server")
        public_key = self.run(["wg", "pubkey"], stdin=private_key).strip()
        return private_key, public_key, one_value(interfaces[0], "address")

    def archive(self, name):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.write(self.directory / f"{name}.conf", arcname=f"{name}.conf")
        return atomic_write(self.directory / f"{name}.zip", buffer.getvalue())

    def pending_addresses(self, exclude_name):
        """Reserve profiles persisted before an interrupted peer-config update."""
        occupied = []
        for path in self.directory.glob("*.conf"):
            if path.name in ("wg0.conf", f"{exclude_name}.conf"):
                continue
            for part in sections(read_config(path)):
                if part["section"] == "interface":
                    for value in part["values"].get("address", []):
                        for address in value.split(","):
                            occupied.append(str(ipaddress.ip_interface(address).ip))
        return occupied

    def add(self, name, profile_template):
        if not wireguard_safe_client_name(name):
            raise OperationError("Invalid or reserved client name")
        with self.locked():
            if read_config(self.directory / f".remove-{name}.json") is not None:
                raise OperationError("Client removal is unfinished; repeat the removal before adding this name")
            config = self.server_config()
            if "wg0" not in self.run(["wg", "show", "interfaces"]).split():
                raise OperationError("wg0 is not running; run the server setup first")
            interfaces = json.loads(self.run(["ip", "-j", "-4", "address", "show", "dev", "wg0"]))
            addresses = [address for interface in interfaces for address in interface["addr_info"] if address["family"] == "inet"]
            if len(addresses) != 1:
                raise OperationError("wg0 must have exactly one IPv4 address")
            gateway = ipaddress.ip_interface(f"{addresses[0]['local']}/{addresses[0]['prefixlen']}")
            profile_path = self.directory / f"{name}.conf"
            profile = read_config(profile_path)
            lines, span = managed_block(config, name)
            others = "".join(lines[:span[0]] + lines[span[1]:]) if span else config
            occupied = wireguard_peer_networks(others) + self.pending_addresses(name)
            if profile is None:
                if span:
                    raise OperationError("Client peer exists but its private profile is missing; restore the profile or remove the client first")
                if not wireguard_valid_client_name(name):
                    raise OperationError("New client names must be valid interface names of at most 15 characters")
                address = wireguard_next_client_address(str(gateway), occupied)
                private_key = self.run(["wg", "genkey"]).strip()
                public_key = self.run(["wg", "pubkey"], stdin=private_key).strip()
                server_private = read_config(self.directory / "privatekey")
                if server_private is None:
                    raise OperationError("The server private key is missing")
                server_public = self.run(["wg", "pubkey"], stdin=server_private).strip()
                port = int(self.run(["wg", "show", "wg0", "listen-port"]).strip())
                if not 1 <= port <= 65535:
                    raise OperationError("Invalid WireGuard listening port")
                profile = Template(read_config(Path(profile_template))).substitute(
                    WG_CLIENT_ADDRESS=address, WG_CLIENT_PRIVATE_KEY=private_key,
                    WG_SERVER_PUBLIC_KEY=server_public, WG_GATEWAY_IP=str(gateway.ip),
                    WG_SERVER_PORT=str(port),
                )
            else:
                private_key, public_key, address = self.profile_keys(profile)
            if any(public_key in part["values"].get("publickey", []) for part in sections(others) if part["section"] == "peer"):
                raise OperationError("The client key already has another peer entry; resolve the duplicate first")
            client_ip = ipaddress.ip_interface(address)
            if client_ip.version != 4 or client_ip.network.prefixlen != 32 or client_ip.ip not in gateway.network or client_ip.ip in (
                gateway.ip, gateway.network.network_address, gateway.network.broadcast_address,
            ):
                raise OperationError("The existing client address is not usable in the current VPN subnet")
            if any(client_ip.ip in ipaddress.ip_network(network, strict=False) for network in occupied if ipaddress.ip_network(network, strict=False).version == 4):
                raise OperationError("The client address is already reserved by another peer or profile")
            if span:
                block_peers = [part for part in sections("".join(lines[span[0]:span[1]])) if part["section"] == "peer"]
                if len(block_peers) != 1 or one_value(block_peers[0], "publickey") != public_key:
                    raise OperationError("Existing peer and client private key do not match")
                if address not in wireguard_peer_networks("".join(lines[span[0]:span[1]])):
                    raise OperationError("Existing peer and client address do not match")
                updated = config
            else:
                updated = config.rstrip() + (
                    f"\n\n# BEGIN ANSIBLE MANAGED BLOCK FOR {name}\n"
                    f"[Peer]\n# {name}\nPublicKey = {public_key}\nAllowedIPs = {address}\n"
                    f"# END ANSIBLE MANAGED BLOCK FOR {name}\n"
                )
            # Persist the only copy of the private key before publishing its peer.
            # A retry reuses this profile, and other allocations reserve its address.
            changed = atomic_write(profile_path, profile)
            changed = atomic_write(self.config_path, updated) or changed
            self.sync()
            changed = self.archive(name) or changed
            return {"changed": changed, "address": address, "archive": str(self.directory / f"{name}.zip")}

    def remove(self, name):
        if not wireguard_safe_client_name(name):
            raise OperationError("Invalid or reserved client name")
        with self.locked():
            config = self.server_config()
            profile_path = self.directory / f"{name}.conf"
            profile = read_config(profile_path)
            public_key = self.profile_keys(profile)[1] if profile is not None else None
            lines, span = managed_block(config, name)
            if span:
                peers = [part for part in sections("".join(lines[span[0]:span[1]])) if part["section"] == "peer"]
                if len(peers) != 1:
                    raise OperationError("Expected exactly one peer in the managed client block")
                block_key = one_value(peers[0], "publickey")
                if public_key is not None and public_key != block_key:
                    raise OperationError("Client profile and managed peer disagree; refusing ambiguous revocation")
                public_key = block_key
            pending_path = self.directory / f".remove-{name}.json"
            pending = read_config(pending_path)
            if pending is not None:
                pending_key = json.loads(pending)["public_key"]
                if not isinstance(pending_key, str) or not pending_key or (public_key is not None and public_key != pending_key):
                    raise OperationError("Pending removal and current client identity disagree")
                public_key = pending_key
            updated = "".join(lines[:span[0]] + lines[span[1]:]) if span else config
            if public_key and any(
                public_key in part["values"].get("publickey", [])
                for part in sections(updated) if part["section"] == "peer"
            ):
                raise OperationError("The client still has an unmanaged peer entry; remove that entry first")
            # Keep the identity across interruption even when the private profile
            # was already lost. Otherwise a retry cannot detect an unmanaged copy.
            if public_key is not None:
                atomic_write(pending_path, json.dumps({"public_key": public_key}))
            changed = atomic_write(self.config_path, updated)
            # Reconcile on every retry; keep recovery files until revocation succeeds.
            self.sync()
            for path in (profile_path, self.directory / f"{name}.zip"):
                if path.is_symlink():
                    raise OperationError("Refusing to remove a symlink")
                if path.exists():
                    path.unlink()
                    changed = True
            pending_path.unlink(missing_ok=True)
            return {"changed": changed}

    def apply(self, candidate_path):
        """Run entirely on the server, including rollback after a failed start."""
        with self.locked():
            candidate = read_config(Path(candidate_path))
            if candidate is None:
                raise OperationError("Staged configuration is missing")
            parsed = sections(candidate)
            if len(parsed) != 1 or parsed[0]["section"] != "interface":
                raise OperationError("Stage only the interface; current peers are merged under the lock")
            policy = managed_policy(candidate)
            self.run(["wg", "pubkey"], stdin=one_value(parsed[0], "privatekey"))
            original = read_config(self.config_path)
            if original is not None:
                previous = sections(original)
                if not previous or previous[0]["section"] != "interface" or any(
                    part["section"] != "peer" for part in previous[1:]
                ):
                    raise OperationError("Expected one interface followed by peer sections; original configuration was retained")
            peers = wireguard_peer_config(original or "")
            updated = candidate.rstrip() + ("\n\n" + peers if peers else "") + "\n"
            changed = original != updated
            if original is not None and changed:
                atomic_write(Path(candidate_path).parent / "previous.conf", original)
            try:
                if original is not None and changed:
                    self.run(["systemctl", "stop", "wg-quick@wg0"])
                atomic_write(self.config_path, updated)
                self.run(["systemctl", "enable", "--now", "wg-quick@wg0"])
                if "wg0" not in self.run(["wg", "show", "interfaces"]).split():
                    # A oneshot unit can remain active after the kernel interface
                    # was removed. Starting an already active unit does nothing.
                    self.run(["systemctl", "restart", "wg-quick@wg0"])
                # enable --now does not reload a running unit. Always reconcile
                # the kernel, including when a previous client sync was interrupted.
                self.sync(require_running=True)
                if policy is not None:
                    self.firewall.up(*policy)
            except (OperationError, OSError) as failure:
                if original is not None:
                    try:
                        stop_failed = False
                        try:
                            self.run(["systemctl", "stop", "wg-quick@wg0"])
                        except OperationError:
                            stop_failed = True
                        # A failed wg-quick PostUp does not execute PostDown, and
                        # systemd does not run ExecStop for a failed ExecStart.
                        if policy is not None:
                            self.firewall.down()
                        atomic_write(self.config_path, original)
                        self.run(["systemctl", "start", "wg-quick@wg0"])
                        if stop_failed:
                            raise OperationError("Could not confirm that the failed service was fully stopped")
                    except (OperationError, OSError) as error:
                        raise OperationError(f"Configuration update and rollback failed; the previous file was saved in the staging directory. {failure}") from error
                    raise OperationError(f"Configuration update failed; the previous configuration was restored. {failure}") from failure
                if policy is not None:
                    self.firewall.down()
                raise
            return {"changed": changed}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", default="/etc/wireguard")
    commands = parser.add_subparsers(dest="operation", required=True)
    commands.add_parser("initialize-key")
    remove = commands.add_parser("remove")
    remove.add_argument("name")
    add = commands.add_parser("add")
    add.add_argument("name")
    add.add_argument("--profile-template", required=True)
    apply = commands.add_parser("apply")
    apply.add_argument("candidate")
    apply.add_argument("--result", required=True)
    args = parser.parse_args()
    try:
        manager = WireGuardManager(args.directory)
        if args.operation == "initialize-key":
            result = manager.initialize_key()
        elif args.operation == "apply":
            result = manager.apply(args.candidate)
        elif args.operation == "add":
            result = manager.add(args.name, args.profile_template)
        else:
            result = manager.remove(args.name)
        result = dict(result, ok=True)
    except OperationError as error:
        result = {"ok": False, "error": str(error)}
    except (OSError, ValueError, KeyError, TypeError):
        result = {"ok": False, "error": "WireGuard operation failed; check file permissions and configuration"}
    if args.operation == "apply":
        atomic_write(Path(args.result), json.dumps(result))
    print(json.dumps(result))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
