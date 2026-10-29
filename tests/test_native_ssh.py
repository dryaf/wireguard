"""Render the locked role's real template and exercise the patched client."""

from pathlib import Path
import socket
import subprocess
import tempfile
import time

import yaml


def run_tests(root):
    def run(*args, **kwargs):
        return subprocess.run(args, check=True, capture_output=True, text=True, **kwargs).stdout

    role = Path("/opt/collections/ansible_collections/devsec/hardening/roles/ssh_hardening")
    hardening = yaml.safe_load((root / "server_hardening.yml").read_text())[0]
    ssh_role = next(item for item in hardening["tasks"]
                    if item.get("ansible.builtin.import_role", {}).get("name") == "devsec.hardening.ssh_hardening")
    settings = ssh_role["vars"]
    Path("/run/sshd").mkdir(exist_ok=True)
    # The real role creates its empty revocation list before reloading sshd.
    Path("/etc/ssh/revoked_keys").touch(mode=0o644)
    # basic.target deliberately omits the normal boot service that clears
    # /run/nologin. Start it before testing an actual non-root login through PAM.
    run("systemctl", "start", "systemd-user-sessions.service")
    version = subprocess.run(["ssh", "-V"], check=True, capture_output=True, text=True).stderr
    assert version.startswith("OpenSSH_10.6p1,"), version
    # StrictModes checks every ancestor of AuthorizedKeysFile; /tmp is writable
    # by other accounts, so use the disposable fixture's root-owned /etc.
    with tempfile.TemporaryDirectory(prefix="ssh-fixture-", dir="/etc") as temporary:
        directory = Path(temporary)
        directory.chmod(0o755)
        variables = dict(settings, ansible_port=22222, ansible_facts={"os_family": "Debian"},
                         ansible_managed="Integration test", ansible_role_name="devsec.hardening.ssh_hardening",
                         sshd_version="10.0", ssh_pam_support=True, ssh_kerberos_support=False,
                         ssh_listen_to=["127.0.0.1"])
        defaults = yaml.safe_load((role / "defaults/main.yml").read_text())
        play = [{"hosts": "localhost", "gather_facts": False, "vars": dict(defaults, **variables), "tasks": [
            {"ansible.builtin.template": {"src": str(role / "templates/opensshd.conf.j2"),
                                          "dest": str(directory / "sshd-{{ item }}")},
             "loop": ["root", "wg-ssh-test"], "vars": {"ansible_user": "{{ item }}"}},
        ]}]
        playbook = directory / "fixture.yml"
        playbook.write_text(yaml.safe_dump(play))
        run("ansible-playbook", "-i", "localhost,", "-c", "local", str(playbook), cwd=str(root))
        for user, root_login in (("root", "without-password"), ("wg-ssh-test", "no")):
            effective = run("/usr/sbin/sshd", "-T", "-f", str(directory / f"sshd-{user}"),
                            "-C", f"user={user},host=localhost,addr=127.0.0.1")
            options = dict(line.split(" ", 1) for line in effective.splitlines())
            expected = {"passwordauthentication": "no", "authenticationmethods": "publickey",
                        "permitrootlogin": root_login, "allowusers": user, "maxauthtries": "3",
                        "clientalivecountmax": "5", "compression": "no", "allowagentforwarding": "no"}
            for key, value in expected.items():
                assert options[key] == value, (user, key, options[key], value)
        print("PASS: real sshd configuration enforces key-only login and the configured hardening values")

        # The account has no usable password. It and every key exist only in the
        # isolated fixture, which has no external network or host mounts.
        run("useradd", "--no-create-home", "--shell", "/bin/sh", "--password", "invalid-fixture-hash", "wg-ssh-test")
        for name in ("host", "client"):
            run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(directory / name))
        (directory / "authorized_keys").write_text((directory / "client.pub").read_text())
        (directory / "authorized_keys").chmod(0o644)
        (directory / "client.pub").chmod(0o644)
        (directory / "known_hosts").write_text("[127.0.0.1]:22222 " + (directory / "host.pub").read_text())
        server = subprocess.Popen(["/usr/sbin/sshd", "-D", "-e", "-f", str(directory / "sshd-wg-ssh-test"),
                                   "-h", str(directory / "host"),
                                   "-o", f"AuthorizedKeysFile={directory / 'authorized_keys'}"],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        try:
            for attempt in range(50):
                try:
                    with socket.create_connection(("127.0.0.1", 22222), timeout=0.1):
                        break
                except OSError:
                    if server.poll() is not None:
                        raise AssertionError(server.stderr.read())
                    time.sleep(0.1)
            args = ("-F", "/dev/null", "-o", "BatchMode=yes", "-o", "Compression=no", "-o", "ForwardAgent=no",
                    "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={directory / 'known_hosts'}",
                    "-o", "Port=22222", "-o", "User=wg-ssh-test", "-i", str(directory / "client"))
            assert run("ssh", *args, "127.0.0.1", "printf ssh-ok").strip() == "ssh-ok"
            batch = directory / "batch"
            batch.write_text(f"get {directory}/client.pub {directory}/downloaded.pub\n")
            run("sftp", *args, "-b", str(batch), "127.0.0.1")
            assert (directory / "downloaded.pub").read_bytes() == (directory / "client.pub").read_bytes()
            (directory / "known_hosts").write_text("[127.0.0.1]:22222 " + (directory / "client.pub").read_text())
            rejected = subprocess.run(["ssh", *args, "127.0.0.1", "true"], capture_output=True, text=True)
            assert rejected.returncode != 0 and "HOST IDENTIFICATION HAS CHANGED" in rejected.stderr
        except Exception:
            server.terminate()
            server.wait(timeout=10)
            print(server.stderr.read())
            raise
        finally:
            if server.poll() is None:
                server.terminate()
                server.wait(timeout=10)
            server.stderr.close()
        print("PASS: OpenSSH client executes commands, transfers with SFTP and rejects an incorrect host key")
        (directory / "known_hosts").write_text("[127.0.0.1]:22222 " + (directory / "host.pub").read_text())
        from test_native_ssh_socket import run_tests as socket_checks
        socket_checks(root, directory, args, ssh_role)
