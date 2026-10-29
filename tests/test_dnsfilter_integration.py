"""Run the pinned Go service against local DNS fixtures; no external network."""

import contextlib
import ipaddress
from pathlib import Path
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time
import urllib.request

import yaml
from test_dnsfilter import templates

BINARY = "/opt/dnsfilter/dns-filter"


def question(name, kind=1):
    encoded = b"".join(bytes([len(label)]) + label.encode() for label in name.rstrip(".").split(".")) + b"\0"
    return struct.pack("!6H", 3123, 0x0100, 1, 0, 0, 0) + encoded + struct.pack("!HH", kind, 1)


def skip_name(data, position):
    while data[position]:
        if data[position] & 0xC0 == 0xC0:
            return position + 2
        position += data[position] + 1
    return position + 1


def receive_exact(stream, length):
    result = b""
    while len(result) < length:
        part = stream.recv(length - len(result))
        if not part:
            raise RuntimeError("Truncated DNS response")
        result += part
    return result


def query(name, transport):
    data = question(name)
    if transport == "udp":
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
            stream.settimeout(7)
            stream.sendto(data, ("127.0.0.1", 1053))
            response = stream.recv(65535)
    else:
        with socket.create_connection(("127.0.0.1", 1053), timeout=7) as stream:
            stream.sendall(struct.pack("!H", len(data)) + data)
            response = receive_exact(stream, struct.unpack("!H", receive_exact(stream, 2))[0])
    _, flags, questions, answers, _, _ = struct.unpack("!6H", response[:12])
    position = 12
    for _ in range(questions):
        position = skip_name(response, position) + 4
    addresses = []
    for _ in range(answers):
        position = skip_name(response, position)
        kind, _, _, length = struct.unpack("!HHIH", response[position:position + 10])
        position += 10
        if kind == 1 and length == 4:
            addresses.append(str(ipaddress.IPv4Address(response[position:position + length])))
        position += length
    return flags & 15, addresses


class Upstream:
    def __init__(self, role):
        self.role = role
        self.requests = []
        fixture = self

        class UDP(socketserver.BaseRequestHandler):
            def handle(self):
                data, stream = self.request
                stream.sendto(fixture.reply(data), self.client_address)

        class TCP(socketserver.BaseRequestHandler):
            def handle(self):
                length = struct.unpack("!H", receive_exact(self.request, 2))[0]
                response = fixture.reply(receive_exact(self.request, length))
                self.request.sendall(struct.pack("!H", len(response)) + response)

        self.udp = socketserver.ThreadingUDPServer(("127.0.0.1", 0), UDP)
        self.port = self.udp.server_address[1]
        self.tcp = socketserver.ThreadingTCPServer(("127.0.0.1", self.port), TCP)
        self.servers = [self.udp, self.tcp]
        for server in self.servers:
            server.daemon_threads = True
            threading.Thread(target=server.serve_forever, daemon=True).start()

    def reply(self, data):
        end = skip_name(data, 12)
        labels, position = [], 12
        while data[position]:
            length = data[position]
            labels.append(data[position + 1:position + 1 + length].decode())
            position += length + 1
        name = ".".join(labels)
        self.requests.append(name)
        kind = struct.unpack("!H", data[end:end + 2])[0]
        if kind == 2:
            answer = b"\x02ns\x07example\x04test\0"
        else:
            blocked = (self.role == "malware" and name.startswith("malware.")) or (self.role == "family" and name.startswith("adult."))
            answer = ipaddress.IPv4Address("0.0.0.0" if blocked else "192.0.2.10").packed
        return (data[:2] + struct.pack("!5H", 0x8180, 1, 1, 0, 0) + data[12:end + 4]
                + b"\xc0\x0c" + struct.pack("!HHIH", kind, 1, 60, len(answer)) + answer)

    def close(self):
        for server in self.servers:
            server.shutdown()
            server.server_close()
        self.servers = []


def main():
    with contextlib.ExitStack() as stack, tempfile.TemporaryDirectory() as temporary:
        upstreams = {}
        for role in ("unfiltered", "malware", "family"):
            upstreams[role] = Upstream(role)
            stack.callback(upstreams[role].close)
        config = yaml.safe_load(templates().get_template("dnsfilter.yml.j2").render(wireguard_address="10.99.0.1/24"))
        for name, role in (("resolver_unfiltered", "unfiltered"), ("resolver_anti_malware", "malware"), ("resolver_anti_porn", "family")):
            config[name] = {"name": role, "protocol": "udp", "addr": f"127.0.0.1:{upstreams[role].port}"}
        config_file = Path(temporary) / "config.yml"
        config_file.write_text(yaml.safe_dump(config))
        subprocess.run([BINARY, "-checkConfig", "-configFile", str(config_file)], check=True, capture_output=True)
        with (Path(temporary) / "service.log").open("w+") as log:
            process = subprocess.Popen([BINARY, "-configFile", str(config_file)], stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        log.seek(0)
                        raise AssertionError(log.read())
                    try:
                        with urllib.request.urlopen("http://127.0.0.1:18080/health", timeout=0.2) as response:
                            if response.status == 200:
                                break
                    except OSError:
                        time.sleep(0.05)
                else:
                    raise AssertionError("DNS filter did not become healthy")
                subprocess.run([BINARY, "-checkDNS", "127.0.0.1:1053"], check=True, capture_output=True)
                for transport in ("udp", "tcp"):
                    self_test = query("adult.example.test", transport)
                    assert self_test == (0, ["192.0.2.10"]), self_test
                    self_test = query("malware.example.test", transport)
                    assert self_test == (0, ["0.0.0.0"]), self_test
                assert upstreams["family"].requests == [], upstreams["family"].requests
                assert upstreams["unfiltered"].requests == [], upstreams["unfiltered"].requests
                print("PASS: pinned dnsfilter blocks malware and permits adult sites over UDP and TCP")
                upstreams["malware"].close()
                for transport in ("udp", "tcp"):
                    self_test = query("after-outage.example.test", transport)
                    assert self_test[0] == 2, self_test
                assert upstreams["unfiltered"].requests == []
                print("PASS: upstream failure returns SERVFAIL without an unfiltered fallback")
            finally:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


if __name__ == "__main__":
    main()
    from test_dnsfilter_deployment import run_tests
    run_tests(BINARY)
