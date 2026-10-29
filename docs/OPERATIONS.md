# Technical operations and recovery

For the step-by-step installation on a fresh Debian 13 VPS, use the
[quick start](../README.md). This document retains the operational details.

## Prerequisites

The local machine needs Bash, Make and Docker or Podman. Rootless Podman is preferred
when both engines are installed. Use a regular, non-root account; `CONTAINER_ENGINE`
can select another engine executable. No local Python, pip, Ansible or Galaxy
installation is needed. All Make commands that use project dependencies run inside
containers, including tests, dependency resolution and vulnerability checks.
For rootless execution with matching host-file ownership, use Podman. Docker
deployment commands assume its default UID mapping, without `userns-remap`.

The controller currently uses Python 3.14.10 and ansible-core 2.21.5. The recommended
managed host is Debian 13 with its packaged Python 3.13; for other versions consult
the [Ansible support matrix](https://docs.ansible.com/projects/ansible/latest/reference_appendices/release_and_maintenance.html).
The server playbooks use Debian/Ubuntu packages and systemd. WireGuard and the
server-side helper still run natively on the managed server.

`make build` builds the controller. Subsequent commands reuse cached build layers
and incorporate source changes. Dependencies are installed only from committed
locks, never upgraded as a side effect of a normal command.

## Setup

### Initialize
Initialize the server IP, username, and SSH port.

```shell
make init
```
The `make init` command will prompt you for the server host, server username, and SSH port (default: 22).

### SSH access

Load the deployment key into your local SSH agent, preferably a dedicated agent
containing only that key. Private key files and your home directory are not mounted
into the container. Remove `ansible_ssh_private_key_file` / `ansible_private_key_file`
entries from older inventories; authentication now uses the agent.

Verify the server's ED25519 host-key fingerprint through its console or your hosting
provider, then run:

```shell
make trust-host
```

Paste that independently obtained `SHA256:...` fingerprint or the complete ED25519
`ssh-keygen -lf` output line when prompted. The fingerprint field is compared exactly;
malformed or ambiguous input and mismatches leave existing trust unchanged.
Verified keys are saved in `.container/known_hosts`,
which is excluded from Git and container builds. Ordinary deployment commands mount
this file read-only and require strict host-key checking. `make clean_known_hosts`
explicitly removes the inventory servers from this project-specific file.

Run `make check-ssh` before and after hardening. It uses the patched container client
to verify key-only access and, for a non-root inventory user, passwordless sudo.

You can reuse an existing verified file with `WG_KNOWN_HOSTS=/absolute/path/known_hosts`.
`WG_INVENTORY` selects another inventory file and `WG_CLIENTS_DIR` selects the export
directory. Relative paths are resolved against this project. Only the selected files
and, for exports, the output directory are mounted. Inventory sidecar directories
such as `group_vars` and `host_vars` are not mounted; keep required values in the
inventory file or pass explicit Ansible arguments.

On Linux the agent socket comes from `SSH_AUTH_SOCK`; `WG_SSH_AUTH_SOCK` overrides it.
Docker Desktop on macOS uses its `/run/host-services/ssh-auth.sock` proxy. An agent
mount permits the running deployment to authenticate with the keys loaded in that
agent, so it is provided only to commands that connect to the servers.

### VPN Server Setup
To set up the WireGuard server, run the following command:

```shell
make vpn-server-setup
```
This command first asks whether to use [dnsfilter](https://github.com/dryaf/dnsfilter)
for all VPN clients (`yes/no`, default `no`). Choosing `yes` installs or updates the
filter and enables malware blocking while allowing adult sites. Ads filtering is
off and there are no whitelist exceptions by default.

```shell
# Enable filtering without an interactive prompt.
DNSFILTER=yes make vpn-server-setup

# Use an external resolver without installing/enabling filtering.
DNSFILTER=no DNS_SERVER=9.9.9.9 make vpn-server-setup
```

Choosing `no` asks for an IPv4 DNS server (default: 1.1.1.1). The address and filter
choice are validated and passed as JSON data to Ansible.
VPN clients send DNS requests through the tunnel; the server redirects them to this resolver.
Use `10.99.0.1` only if you have separately installed a DNS service listening on that address.
The playbook preserves the host's resolver configuration and existing VPN peers when rerun.
Interface changes run in a detached systemd job, so stopping the VPN does not interrupt
the remaining setup steps on the server. If the new service fails to start, the job
restores the previous configuration and attempts to start it again. Failed runs retain
their private `/etc/wireguard/.apply-*` directory with `result.json` and, when replacing
an existing configuration, `previous.conf` for recovery. Successful runs remove it.
The setup validates DNS, subnet, port, MTU and the WAN interface before making changes.
After package installation it also checks kernel access before creating keys or
replacing the VPN configuration. Repeating setup reconciles live peers even when the
configuration file has not changed, and repairs a missing `wg0` interface.

Firewall hooks use rules tagged `wireguard-manager:wg0`. Cleanup removes only those
rules, including rules left by a failed or killed startup hook. Other firewall rules
are preserved. When AppArmor is enabled and the distribution supplies `wg-quick` or
`usr.bin.wg-quick`, setup adds a confined child profile for the firewall hook through
the distribution's local customization file. It preserves existing local rules,
compiles the policy before loading it, and checks the actual helper transition and
firewall permissions without changing rules. A failed check restores the previous
local policy. This happens before deploying DNS or changing VPN configuration. Disabled profiles
are respected. Custom profiles without the expected local include require explicit
integration. This follows the [AppArmor local override workflow](https://apparmor.dev/monitoring/denial_quick_guide/).

If setup reports a WireGuard service failure, use the VPS provider console to run:

```shell
sudo journalctl -u wg-quick@wg0 -n 60 --no-pager
sudo journalctl -k --grep='apparmor=.*DENIED' -n 30 --no-pager
```

An AppArmor denial for `wireguard_firewall.py` explains an exit status of 126 even
when Unix file permissions are correct. Rerun the updated `DNSFILTER=yes make
vpn-server-setup` to install the policy and retry setup. A receipt that has not yet
been written while the detached setup job is running is normal.

Debian security updates are matched by release codename and origin rather than a
moving suite name. Ubuntu-only packages are installed only on Ubuntu. Fail2Ban uses
the systemd journal, including on servers without `/var/log/auth.log`.

### Optional DNS filtering

The optional installer supports amd64 and arm64 Debian/Ubuntu servers. It installs
Podman and builds dnsfilter at commit `0af7f225b892b32444d9497f581ddcf237c67306`.
The source archive is checked against its SHA-256 before extraction. The Go builder
and Distroless runtime are pinned by digest in `Dockerfile`; the build verifies the
upstream `go.mod`/`go.sum` and runs its tests. No Go toolchain runs directly on the host.
The server build context contains only this pinned recipe.
The build is capped at 1 GiB of memory; allow additional RAM for the OS and disk
space for the Go builder image and build cache.

The `wireguard-dnsfilter.service` system unit supervises Podman. The DNS process runs
inside a container as UID/GID 65532, with a read-only filesystem, all capabilities
dropped, no privilege escalation, and memory/PID limits. Its only host file mount is
the read-only DNS configuration. Host networking preserves client addresses. No SSH
agent, private keys or container engine socket are mounted into the DNS container.

DNS listens on port **1053**, protected on both IPv4 and IPv6 to allow only `wg0`
and loopback. The application additionally restricts clients to the configured VPN
subnet. Metrics listen on `127.0.0.1:18080`. These ports must be available before the
first installation; the host's system resolver and privileged-port settings stay intact.

All IPv4 UDP/TCP port 53 traffic arriving through `wg0` is redirected to the filter at the
actual VPN gateway, including requests addressed to another DNS server. Existing
profiles generated by this project already use that gateway and need no re-export.
If the filter or its upstream fails, DNS fails rather than silently using an unfiltered
fallback. DNS-over-HTTPS, DNS-over-TLS, other VPNs and direct IP connections are outside
this DNS routing rule; enforce client/browser policy separately if those must be blocked.

The default malware resolver is [Cloudflare's malware-only service](https://developers.cloudflare.com/1.1.1.1/setup/)
at `1.1.1.2` over HTTPS. For explicit policy
changes, use `make dnsfilter-enable-malware`, `make dnsfilter-disable-malware`,
`make dnsfilter-enable-porn`, `make dnsfilter-disable-porn`, `make dnsfilter-enable-ads`
and `make dnsfilter-disable-ads`. The playbook also accepts boolean
`dnsfilter_block_malware`, `dnsfilter_block_porn` and `dnsfilter_block_ads` variables
as explicit setup overrides. Without overrides, later setup runs preserve the flags
from the installed configuration. First installation defaults to malware on, porn and ads off.
For example, direct noninteractive execution also supports:

```shell
./scripts/container playbook wireguard_server_setup.yml \
  --extra-vars '{"dnsfilter_enabled":true,"dnsfilter_block_malware":true,"dnsfilter_block_porn":false}'
```

Configuration is validated before activation, then DNS is probed over UDP and TCP.
VPN routing changes only after those checks pass. A failed DNS deployment restores
the previous files and service state; a subsequent VPN setup failure restores the
previous DNS policy too. Incomplete recovery retains the private `.deploy-*` directory
under `/etc/wireguard-dnsfilter` and reports its path. Choosing `no` on a later setup
uses the selected external resolver; it does not uninstall an existing filter service.
Use `make vpn-monitor` to follow the service logs alongside WireGuard.

`make dnsfilter-status` reads the saved policy, service state, local `/health` and
`/metrics` endpoints, and managed port-53 redirect rules. It reports `ok` and makes
no configuration changes. A running filter without VPN redirect rules does not mean
VPN clients use that filter; this can happen after setup with `DNSFILTER=no`.
An unhealthy service is reported as `healthy: false`; this diagnostic command's exit
status is not a substitute for reading the health field.

Category commands use the same deployment lock, candidate validation, UDP/TCP probe
and rollback path as installation. They reuse the immutable image in the installed
managed systemd unit, preserve the other configuration fields and service definition,
and do not install packages or rebuild the server image. Enabling ads on an older
configuration adds the AdGuard HTTPS resolver if absent. A semantic no-op retains
the original configuration bytes and does not restart a healthy running service.
After success, the command displays the current status. `--check` on the management
playbook shows the existing configuration without applying a change.

Cloudflare Family blocks adult content and malware together; AdGuard's default
resolver also blocks trackers and phishing. Filter flags select these resolver
policies and are not three independent domain lists. All three flags off selects
only the unfiltered resolver. Changes restart DNS briefly and clear its cache and counters.

`make dnsfilter-logs` reads the latest 100 journal entries; `make dnsfilter-monitor`
follows them until Ctrl-C. These commands select the first inventory server and use
`sudo -n` when the SSH administrator is not root. Journal selection includes both
the systemd service and `CONTAINER_NAME=wireguard-dnsfilter`, because Podman's conmon
may log from a separate scope. Historical container entries remain available after
a managed restart, subject to the system journal's retention policy.
No new logging endpoint or public metrics port is exposed.

Upstream block entries contain the domain, VPN client IP, query type, transport,
resolver and reason. Cache hits do not emit block entries or increment
`blocked_total` again. NXDOMAIN is also counted/logged as blocked by this pinned
upstream, including genuinely nonexistent domains. Use the harmless Cloudflare test
domains and compare answers for policy verification. Logs contain browsing metadata;
apply the VPS's journal access controls and retention policy accordingly.

An atomic `/run/wireguard-dnsfilter-setup.lock` directory prevents overlapping DNS
deployments until VPN setup also finishes. Successful completion or recovery removes
it. An abruptly interrupted run or failed recovery leaves the lock in place. Before
removing that empty directory manually, ensure no setup is still active and inspect
the retained `.deploy-*` files and current DNS/VPN state. Setup never breaks another
run's lock automatically.

### Firewall Setup
Secure the server by blocking external access to sensitive ports (like DNS:53 and Web:8080) while allowing VPN clients and SSH.

```shell
make vpn-firewall-setup
```

Firewall setup and server hardening share the same policy. A guard in UFW's IPv4 and
IPv6 before-rules blocks public UDP/TCP 53 and TCP 8080 even when older UFW rules allow
them. Loopback, `wg0`, the configured SSH TCP port, and the WireGuard UDP port are
exempt. These files run before UFW user rules; `ufw status` does not display their
contents. Use `ufw show raw` to inspect the loaded rules, as described in the
[UFW framework documentation](https://manpages.ubuntu.com/manpages/noble/man8/ufw-framework.8.html).

### Server Hardening
The recommended installation includes the pinned `devsec.hardening` roles,
key-only SSH, Fail2Ban and the shared UFW policy via `server_hardening.yml`.

```shell
make server-hardening
```

The SSH role refreshes systemd's unit definitions when it switches from socket
activation to a continuously running SSH service. This prevents a removed socket
dependency from remaining in systemd's cache. After applying the SSH configuration,
hardening closes its old control connection and verifies a fresh connection before
continuing with Fail2Ban and firewall setup.

#### SSH recovery after a failed socket migration

If an earlier run failed with `Unit ssh.socket is masked` and new SSH connections
are refused, open your VPS provider's web or serial console. Run these commands
**as root on the VPS**:

```bash
install -d -o root -g root -m 0755 /run/sshd &&
/usr/sbin/sshd -t &&
systemctl daemon-reload &&
systemctl enable --now ssh.service
```

The configuration check must succeed before the service starts. `daemon-reload`
refreshes the dependency graph after the old socket links have been removed;
see the [systemd documentation](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html#daemon-reload).
The intended state is `ssh.service` active and enabled, with `ssh.socket` masked.

Then run **on your computer**, using this updated checkout:

```bash
make check-ssh &&
make server-hardening &&
make check-auto-upgrades
```

Keep the provider console open until the SSH check succeeds. If the recovery
command fails, inspect `systemctl status ssh.service --no-pager` and
`journalctl -u ssh.service -n 60 --no-pager` in that console.

For additional Ansible options, use the same container launcher:

```shell
./scripts/container playbook server_hardening.yml --check --diff
```

## Managing VPN Clients

To add, remove, list, or generate QR codes for VPN clients, use the following commands:

### Add a Client
```shell
make vpn-client-add
```
The command will prompt you to enter the client name. New names must contain 1-15
letters, digits or `_.+=-` and start with a letter or digit. `wg0` is reserved for
the server. Existing safe names, including longer names and names such as `sal.mac`,
remain usable for removal, QR codes and repeat exports. Paths and shell syntax are rejected.
The ZIP is saved to `clients/<inventory-host>/<client-name>.zip` with mode `0600`.
Its local directories use mode `0700`; this directory is excluded from Git.
Inventory aliases must be single safe directory names. IPv6 server endpoints are
written with the brackets required by WireGuard. Each inventory server produces its
own archive and QR code.
`CLIENT_NAME=phone make vpn-client-add` supplies a name without a prompt.
Addresses are allocated from the IPv4 subnet configured on `wg0`. Removed clients'
addresses can be reused; a full subnet causes an error before any keys or peers are created.

If activation or export fails, repeat the add command with the same name. It reuses
the saved key and address, reconciles the running server, and recreates the archive.
The peer is activated before the archive is downloaded. If a managed peer exists
but its private profile is missing, restore the profile or remove the client first;
the command will not silently replace its key.

Server setup, client creation and removal use a shared server-side file lock.
Address allocation, peer edits and activation run inside that lock. Pending client
profiles reserve their addresses until they are completed or removed. A busy operation
waits up to 60 seconds for the lock; process termination releases it automatically.

Client profiles route both IPv4 and IPv6 into the tunnel. The server provides IPv4
connectivity; IPv6 is captured but not forwarded, preventing it from bypassing the VPN.
For profiles already installed on devices, change their peer's `AllowedIPs` to
`0.0.0.0/0, ::/0` as well. Updating the template does not change existing device profiles.

### Remove a Client
```shell
make vpn-client-remove
```
You will need to enter the client name that you want to remove.
Removal reconciles the running peer configuration even when a previous attempt already
removed the on-disk entry. Recovery files are deleted only after this succeeds, or
after the helper confirms that `wg0` is stopped. Repeat the same command after an interruption.
If the private profile is missing, the managed peer still supplies its public key.
A pending `.remove-<name>.json` preserves that identity until revocation completes;
an unmanaged duplicate peer makes removal fail explicitly instead of leaving access
active after reporting success.

### List All Clients
```shell
make vpn-client-list
```

### Display Client's QR Code
```shell
make vpn-client-qrcode
```
You will be asked to enter the client name whose QR code you want to display.

For further help and a list of all available commands, run `make help`.

## Local tests

The regression tests cover peer preservation, client input handling, IPv4/IPv6
routing, address exhaustion, interrupted operations, setup rollback, concurrent
processes and firewall precedence over legacy allow rules. They use temporary files
and simulated system commands. They also exercise the container launcher, lock
consistency, rejected archive tampering and credential isolation. They do not
replace a deployment test on the intended server OS.

```shell
make test
make syntax-check
make deps-check
make dnsfilter-test
```

These commands run as a non-root user with a read-only root filesystem, temporary
home and scratch directories, dropped capabilities, resource limits and no runtime
network access. They receive no inventory, SSH agent, host home directory or client
exports. The initial image build still needs network access to fetch pinned artifacts.
`dnsfilter-test` runs the pinned Go binary with local upstream fixtures, verifies
malware/adult policy and both DNS transports, and tests the real Ansible file recovery
workflow with simulated container/service management. It contacts no public DNS servers.

On Linux with rootless Podman, additional tests use a disposable systemd container:

```shell
make firewall-test
make integration-test
```

`firewall-test` exercises real Netfilter rollback after a partial rule update and
SIGKILL of a hook process, with a simulated WireGuard service lifecycle. It also runs
Fail2Ban, the installed unattended-upgrades matcher, and the actual Ansible/UFW tasks
for IPv4 and IPv6. `integration-test` additionally requires the host WireGuard kernel
driver and checks the native systemd service, client revocation and live peer repair.

This separate fixture runs as root inside a rootless user namespace, adds NET_ADMIN
only within its network namespace, and has a writable disposable filesystem for
systemd. It has no host mounts, credentials or external network and is removed on
exit. Regular project commands retain their stricter non-root execution settings.
Host AppArmor executable profiles can block native WireGuard tests under rootless
Podman; the test fails explicitly in that case. Run it on a compatible disposable
Linux test host. A production release still requires staging checks for SSH access,
a client handshake, DNS/NAT traffic, reboot persistence and recovery after failure.

## Dependency locks and updates

Python supports complete version locks with artifact hashes. This project keeps
the small editable inputs separate from the generated installation locks:

| File | Purpose |
| --- | --- |
| `requirements.in` | Editable exact direct controller dependencies |
| `requirements-dev.in` | Editable exact additional audit dependency |
| `requirements.txt` | Installer/scanner entry point referencing the complete runtime lock |
| `requirements-dev.txt` | Installer/scanner entry point referencing the complete development lock |
| `locks/requirements.lock` | Complete controller dependency graph with SHA-256 hashes |
| `locks/requirements-dev.lock` | Complete development graph, constrained to controller versions |
| `requirements.yml` | Exact direct Ansible collection versions |
| `locks/collections.lock.json` | Every transitive collection, artifact URL and SHA-256 |
| `locks/manifest.sha256` | Checksums tying inputs and all generated locks together |
| `Dockerfile` | Python/uv/Go/Distroless/OSV image digests, dnsfilter and OpenSSH source hashes, and a dated Debian package snapshot |

The container installs Python with `pip --require-hashes --only-binary=:all:`. Missing
hashes, changed artifacts and unavailable wheels fail the build; source-package
build scripts are not run. Collections are checked against their hashes and dependency
constraints before installation. Archives with traversal paths, unsafe links, special files,
duplicate paths or excessive unpacked sizes are rejected before Galaxy receives them.
Only direct symlinks to regular files within the archive are allowed; directory links,
link chains and members beneath a link are rejected. Collections are then installed with `--offline --no-deps` so Galaxy
cannot resolve additional dependencies during a normal build. The Debian snapshot
retains APT signature and package checksum validation; only historical metadata expiry
is disabled for the dated snapshot.

To update dependencies, edit the exact versions in the input files, then run:

```shell
make deps-lock
git diff -- requirements.in requirements-dev.in requirements.txt requirements-dev.txt requirements.yml locks/
make test syntax-check deps-check audit
make osv-scan
```

`make deps-lock` resolves transitive updates using the digest-pinned uv image and
Ansible Galaxy inside a separate container. Its only host mount is `locks/`; it gets
no inventory, agent, private keys or exports. Failed resolution preserves the existing
locks. A partially written lock set is rejected by the next build. Commit the input
changes together with every generated lock file.

Update both image digests and `DEBIAN_SNAPSHOT` in `Dockerfile` explicitly when updating
the OS/Python/toolchain baseline, then rebuild and repeat the checks. Regenerate the
locks when changing the Python major/minor version. The build context uses an allowlist;
add new source paths to `.dockerignore` when needed, and keep credentials out of source.

`make audit` checks the locked Python dependency set for known vulnerabilities. Its
container has network access for the advisory database, but no host files or SSH agent.
It does not audit Debian packages or Ansible collection source. Hashes prevent unnoticed
artifact substitution after locking; they do not establish that an upstream release
is benign. Review version and hash changes before deploying them.

`make osv-scan` runs OSV 2.7.0 from a digest-pinned image. It scans both complete
Python locks without dependency resolution and separately exercises default recursive
discovery of the dependency files, then scans the actual `runtime`, `dev` and
`dnsfilter-runtime` images exported as Docker archives. The scanner gets read-only
archives, not a container-engine socket, project checkout, inventory or SSH agent.
Each run retains raw JSON, stderr logs, image IDs and scanner exit statuses under
`.container/osv/run.*/`. Source and image scans continue after vulnerability findings;
operational scan errors remain failures. The launcher returns 0 for no active findings,
1 for findings and 2 for incomplete scans (GNU Make itself returns 2 for a failed target).
Build/export failures also fail the command; absent reports must never be read as clean.
No project suppression list is applied. OSV's own filtered/unimportant records remain
in the JSON and are counted separately in the summary.

The standard `.txt` files include the complete `.lock` files, enforce hashes and
allow wheels only. The editable direct pins live in `.in` files. This distinction
matters: recursive OSV scans do not automatically discover our custom `.lock` names.
Scanning only incomplete direct requirements can resolve a different transitive
graph from the one actually installed. The extra recursive check prevents that
discrepancy from returning. No advisory is suppressed to reconcile the reports.

The controller builds OpenSSH 10.6p1 client tools from the upstream SHA-256-pinned
archive, without zlib/compression, and runs upstream unit tests during the build.
The compiler and old Debian SSH client do not enter deployment images. OSV does not
automatically identify this custom C build; its upstream release notes and source pin
must be reviewed independently. The native SSH fixture tests the actual role template,
command execution, SFTP and host-key rejection against a disposable Debian server.
The production VPS uses Debian's SSH server and security repositories, not this custom client.

OSV does not audit Ansible role logic or the live VPS/kernel. See the
[current findings and remaining limitations](SECURITY-REVIEW.md).
