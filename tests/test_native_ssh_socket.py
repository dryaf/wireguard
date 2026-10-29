"""Exercise the pinned socket-migration tasks against real systemd and sshd."""

from copy import deepcopy
from pathlib import Path
import subprocess
import sys
import time

import yaml


def run_tests(root, directory, ssh_args, ssh_role):
    def run(*args):
        return subprocess.run(args, check=True, text=True, capture_output=True, timeout=30).stdout

    role = "devsec.hardening.ssh_hardening"
    unit = Path("/etc/systemd/system/ssh.service")
    socket_unit = Path("/usr/lib/systemd/system/ssh.socket")
    dependency = Path("/etc/systemd/system/ssh.service.requires/ssh.socket")
    dropin = Path("/etc/systemd/system/ssh.service.d/00-socket.conf")
    sink = Path("/etc/systemd/system/wg-test-socket-sink.service")
    original_socket = socket_unit.read_bytes() if socket_unit.exists() else None
    assert not unit.exists(), "The disposable fixture must not have a custom SSH service"

    def login():
        # A Type=simple service can become active just before sshd binds its port.
        for attempt in range(30):
            result = subprocess.run(["ssh", *ssh_args, "127.0.0.1", "printf ssh-reconnected"],
                                    text=True, capture_output=True, timeout=10)
            if result.returncode == 0:
                assert result.stdout == "ssh-reconnected"
                return
            time.sleep(0.1)
        raise AssertionError(result.stderr)

    def play(fixed):
        # Import the role exactly as the playbook does, but select only its real
        # socket transition tasks. No mock systemctl or copied vendor tasks.
        task = deepcopy(ssh_role)
        task["ansible.builtin.import_role"] = {"name": role, "tasks_from": "disable-systemd-socket.yml"}
        task["vars"]["sshd_service_name"] = "ssh"
        if not fixed:
            task.pop("module_defaults")
        playbook = directory / "socket-migration.yml"
        playbook.write_text(yaml.safe_dump([{
            "hosts": "localhost", "gather_facts": False,
            "vars": {"ansible_connection": "local", "ansible_python_interpreter": sys.executable,
                     "ansible_user": "wg-ssh-test", "ansible_port": 22222},
            "tasks": [task],
        }]))
        return subprocess.run(["ansible-playbook", "-i", "localhost,", str(playbook)],
                              cwd=root, text=True, capture_output=True, timeout=90)

    def prepare_socket_dependency():
        run("systemctl", "unmask", "ssh.socket")
        dependency.parent.mkdir(exist_ok=True)
        dependency.symlink_to(socket_unit)
        dropin.parent.mkdir(exist_ok=True)
        dropin.write_text("[Unit]\nAfter=ssh.socket\n")
        run("systemctl", "daemon-reload")
        run("systemctl", "enable", "--now", "ssh.socket", "ssh.service")
        assert "ssh.socket" in run("systemctl", "show", "ssh.service", "--property=Requires", "--value").split()
        login()

    def verify_service():
        assert run("systemctl", "is-active", "ssh.service").strip() == "active"
        assert run("systemctl", "is-enabled", "ssh.service").strip() == "enabled"
        # is-enabled returns nonzero for a masked socket.
        masked = subprocess.run(["systemctl", "is-enabled", "ssh.socket"], text=True, capture_output=True)
        assert masked.stdout.strip() == "masked", masked.stdout + masked.stderr
        assert "ssh.socket" not in run("systemctl", "show", "ssh.service", "--property=Requires", "--value").split()
        login()

    try:
        # The socket belongs to an unused sink service; SSH listens on TCP with
        # the actual hardened configuration from test_native_ssh. This reproduces
        # the cached Requires dependency independently of distro socket patches.
        socket_unit.write_text("[Socket]\nListenStream=/run/wg-test-ssh.socket\n"
                               "Service=wg-test-socket-sink.service\n[Install]\nWantedBy=sockets.target\n")
        sink.write_text("[Service]\nType=oneshot\nExecStart=/bin/true\n")
        unit.write_text("[Unit]\nDescription=SSH hardening regression fixture\n"
                        "[Service]\nType=simple\nKillMode=process\n"
                        f"ExecStart=/usr/sbin/sshd -D -e -f {directory}/sshd-wg-ssh-test "
                        f"-h {directory}/host -o AuthorizedKeysFile={directory}/authorized_keys\n"
                        "[Install]\nWantedBy=multi-user.target\n")
        prepare_socket_dependency()
        broken = play(fixed=False)
        assert broken.returncode != 0 and "ssh.socket is masked" in broken.stdout, broken.stdout + broken.stderr
        assert not dependency.exists()
        assert "ssh.socket" in run("systemctl", "show", "ssh.service", "--property=Requires", "--value").split()
        print("PASS: reproduced the pinned role's masked-socket startup failure with real systemd")

        repaired = play(fixed=True)
        assert repaired.returncode == 0, repaired.stdout + repaired.stderr
        verify_service()
        print("PASS: corrected role recovers from the failed migration and accepts a new key-only SSH login")

        prepare_socket_dependency()
        fresh = play(fixed=True)
        assert fresh.returncode == 0, fresh.stdout + fresh.stderr
        verify_service()
        repeated = play(fixed=True)
        assert repeated.returncode == 0 and "changed=0" in repeated.stdout, repeated.stdout + repeated.stderr
        run("systemctl", "daemon-reload")
        run("systemctl", "restart", "ssh.service")
        verify_service()
        print("PASS: first migration, repeat hardening and subsequent SSH service restart retain key-only access")
    except Exception:
        print(run("journalctl", "-u", "ssh.service", "-u", "ssh.socket", "-n", "50", "--no-pager", "-o", "cat"))
        raise
    finally:
        subprocess.run(["systemctl", "stop", "ssh.service", "ssh.socket"], capture_output=True)
        subprocess.run(["systemctl", "disable", "ssh.service"], capture_output=True)
        subprocess.run(["systemctl", "unmask", "ssh.socket"], capture_output=True)
        for path in (unit, sink, dependency, dropin):
            path.unlink(missing_ok=True)
        if original_socket is None:
            socket_unit.unlink(missing_ok=True)
        else:
            socket_unit.write_bytes(original_socket)
        run("systemctl", "daemon-reload")
