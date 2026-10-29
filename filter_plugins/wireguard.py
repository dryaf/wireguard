"""WireGuard configuration helpers used by the playbooks."""

import ipaddress
import re


def wireguard_ipv4(value):
    """Only a literal address may enter the server's DNS firewall policy."""
    if not isinstance(value, str):
        raise ValueError("The DNS resolver must be an IPv4 address")
    address = ipaddress.IPv4Address(value)
    if address.is_unspecified or address.is_multicast:
        raise ValueError("The DNS resolver must be a unicast IPv4 address")
    return str(address)


def wireguard_interface(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.][A-Za-z0-9_.-]{0,14}", value) or value in ("wg0", ".", ".."):
        raise ValueError("A valid WAN interface other than wg0 is required")
    return value


def wireguard_number(value, minimum, maximum):
    if isinstance(value, bool) or not re.fullmatch(r"[0-9]+", str(value)):
        raise ValueError("WireGuard ports and MTU must be integers")
    number = int(value)
    if not minimum <= number <= maximum:
        raise ValueError(f"WireGuard value must be between {minimum} and {maximum}")
    return number


def wireguard_address(value):
    interface = ipaddress.IPv4Interface(value)
    if interface.network.prefixlen > 30 or interface.ip in (interface.network.network_address, interface.network.broadcast_address):
        raise ValueError("WireGuard needs a usable IPv4 gateway in a /30 or larger subnet")
    return str(interface)


def wireguard_gateway(value):
    return str(ipaddress.IPv4Interface(wireguard_address(value)).ip)


def wireguard_network(value):
    return str(ipaddress.IPv4Interface(wireguard_address(value)).network)


def wireguard_endpoint_host(value):
    if not isinstance(value, str) or not value:
        raise ValueError("A public WireGuard endpoint is required")
    host = value[1:-1] if value.startswith("[") and value.endswith("]") else value
    if ":" in host:
        if not re.fullmatch(r"[A-Za-z0-9_.:%-]+", host):
            raise ValueError("Invalid IPv6 endpoint")
        return f"[{ipaddress.IPv6Address(host)}]"
    if len(value) > 253 or not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) for label in value.rstrip(".").split(".")):
        raise ValueError("Invalid WireGuard endpoint hostname")
    return value


def wireguard_export_host(value):
    """An inventory alias becomes one local directory, never a path."""
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.:-]{0,252}", value):
        raise ValueError("Inventory host aliases must be safe directory names")
    return value


def wireguard_normalize_line(line):
    """WireGuard ignores comments and ASCII whitespace before parsing keys."""
    return re.sub(r"[ \t\r\n\v\f]", "", line.split("#", 1)[0])


def wireguard_valid_client_name(name):
    """Names are also filenames and, when imported, WireGuard interface names."""
    return (
        isinstance(name, str)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+=-]{0,14}", name) is not None
        and name.lower() != "wg0"
    )


def wireguard_safe_client_name(name):
    """Permit safe legacy basenames without permitting paths or shell syntax."""
    return (
        isinstance(name, str)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+=-]{0,249}", name) is not None
        and name.lower() != "wg0"
    )


def wireguard_peer_config(config):
    """Keep peer sections and their comments, including blockinfile markers."""
    lines = config.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if wireguard_normalize_line(line).lower() == "[peer]":
            start = index
            while start > 0:
                previous = lines[start - 1].strip()
                if previous and not previous.startswith("#"):
                    break
                start -= 1
            return "".join(lines[start:]).strip("\n")
    return ""


def wireguard_peer_networks(config):
    """Extract only public routing data from peer sections."""
    networks = []
    section = None
    for raw_line in config.splitlines():
        line = wireguard_normalize_line(raw_line)
        if line.startswith("["):
            section = line.lower()
        elif section == "[peer]":
            key, separator, value = line.partition("=")
            if separator and key.lower() == "allowedips" and value:
                for entry in value.split(","):
                    networks.append(str(ipaddress.ip_network(entry.strip(), strict=False)))
    return networks


def wireguard_next_client_address(interface_address, used_networks):
    """Find the first free IPv4 host without iterating over large address pools."""
    interface = ipaddress.ip_interface(interface_address)
    if interface.version != 4:
        raise ValueError("Client allocation requires an IPv4 WireGuard interface")

    pool = interface.network
    first = int(pool.network_address) + 1
    last = int(pool.broadcast_address) - 1
    gateway = int(interface.ip)
    if not first <= gateway <= last:
        raise ValueError("WireGuard must use a usable host address in an IPv4 subnet of /30 or larger")

    reserved = [(gateway, gateway)]
    for value in used_networks:
        network = ipaddress.ip_network(value, strict=False)
        if network.version == 4 and network.overlaps(pool):
            reserved.append((
                max(first, int(network.network_address)),
                min(last, int(network.broadcast_address)),
            ))

    candidate = first
    for start, end in sorted(reserved):
        if end < candidate:
            continue
        if start > candidate:
            break
        candidate = end + 1

    if candidate > last:
        raise ValueError(f"No free client address in {pool}; remove an unused client or enlarge the VPN subnet")
    return f"{ipaddress.IPv4Address(candidate)}/32"


class FilterModule:
    def filters(self):
        return {
            "wireguard_ipv4": wireguard_ipv4,
            "wireguard_interface": wireguard_interface,
            "wireguard_number": wireguard_number,
            "wireguard_address": wireguard_address,
            "wireguard_gateway": wireguard_gateway,
            "wireguard_network": wireguard_network,
            "wireguard_endpoint_host": wireguard_endpoint_host,
            "wireguard_export_host": wireguard_export_host,
            "wireguard_peer_config": wireguard_peer_config,
            "wireguard_valid_client_name": wireguard_valid_client_name,
            "wireguard_safe_client_name": wireguard_safe_client_name,
            "wireguard_peer_networks": wireguard_peer_networks,
            "wireguard_next_client_address": wireguard_next_client_address,
        }
