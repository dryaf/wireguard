# Set up a hardened WireGuard VPS

Follow these steps to install **WireGuard, a DNS malware filter, a firewall,
SSH hardening, Fail2Ban and automatic security updates** on a fresh VPS.
Adult sites and ads remain allowed by default. No setup can promise perfect security; see the
[security review](docs/SECURITY-REVIEW.md) for remaining findings and test limits.

You need:

- **Your computer:** Linux, such as Debian or Ubuntu, with a regular user account
  and `sudo`. Keep this project here. Run every `make` command here.
- **Your VPS:** a fresh **Debian 13** VM with a public IPv4 address, at least 2 GB RAM
  and about 20 GB free disk space. Use a VM with WireGuard kernel support, such as
  KVM. You must have access to your provider's web console.

These instructions use the VPS account `root` and SSH port `22`. Choose an image
that installs your SSH key for `root`. For a different account, configure that account
in the inventory and ensure it has passwordless `sudo` before applying hardening.

Python, Ansible and scanners run inside containers on your computer. On the VPS,
WireGuard and system management run natively; dnsfilter runs in a restricted container.

## 1. Prepare your computer

**On your computer**, as your regular user:

```bash
sudo apt-get update
sudo apt-get install -y git make openssh-client podman uidmap fuse-overlayfs slirp4netns
git clone https://github.com/dryaf/wireguard.git
cd wireguard
podman info
```

`podman info` must work without `sudo`. If it fails, fix your distribution's rootless
Podman setup first. Never run the project with `sudo make ...`.
If you already have the project, just open a terminal in its directory.

Create a dedicated SSH key. Set a passphrase and do not overwrite an existing key:

```bash
install -d -m 700 "$HOME/.ssh"
ssh-keygen -t ed25519 -a 100 -f "$HOME/.ssh/wireguard_vps"
cat "$HOME/.ssh/wireguard_vps.pub"
```

Copy the printed **public** key into your provider's SSH-key field when creating the
VPS. The file without `.pub` is private and stays on your computer.

Start a dedicated SSH agent containing only this key:

```bash
eval "$(ssh-agent -s)"
ssh-add "$HOME/.ssh/wireguard_vps"
```

Use this terminal for the remaining local steps. In a new terminal or after restarting
your computer, run these two agent commands again.

## 2. Prepare the fresh VPS

Create the VPS with Debian 13 and your public key from step 1.
If your provider has a separate firewall, allow these incoming connections:

| Port | Protocol | Allowed source |
| --- | --- | --- |
| 22 | TCP | Your current public administrator IP |
| 51820 | UDP | Your VPN devices; usually any source for roaming/mobile devices |

Keep other incoming ports closed. **Do not expose ports 53, 1053, 18080 or 8080.**
Allow outgoing connections for package downloads and DNS. If your administrator IP
changes, update the provider's SSH firewall rule before reconnecting.

Open the **provider's web console**, log in as `root`, and run these commands
**on the VPS**:

```bash
apt-get update
apt-get upgrade -y
apt-get install -y python3 sudo ca-certificates
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

Save the displayed `SHA256:...` value. This is the **server's** fingerprint,
not your personal SSH key's fingerprint. Keep the provider console open throughout setup.

## 3. Connect to the right server

Back **on your computer**, in the project directory and the terminal with your agent:

```bash
make init
```

Answer the three questions:

```text
Server host:          YOUR_VPS_IP
SSH username:         root
SSH port:             22
```

Replace `YOUR_VPS_IP` with the real public IPv4 address. Pressing Enter accepts the
default username and port. The first container build takes several minutes.
Settings are saved in `inventory.ini`; an existing inventory will not be overwritten.

Your local inventory, `clients/` exports and `.container/` state are excluded from
Git and container builds. Keep extracted VPN profiles, QR images and saved logs in
`clients/` or `private/`. If you choose another location inside this project, exclude
it in both `.gitignore` and `.dockerignore` before saving private data there. Ignore
rules do not remove data already committed or detect secrets pasted into source files.

```bash
make trust-host
```

Paste the `SHA256:...` fingerprint you obtained **from the provider console**.
You can also paste the complete `256 SHA256:... root@server (ED25519)` line;
both formats are accepted and the fingerprint must match exactly.
If it differs, stop and investigate. Do not simply accept the fingerprint shown by
the network connection you are trying to verify.

Test key-only SSH access using the project's patched SSH client inside its container:

```bash
make check-ssh
```

This must print `Verified key-only SSH and required administrator access`.
For a non-root inventory user it also checks passwordless `sudo`. If it fails,
check the SSH agent, public key and provider firewall. Continue only after success.

## 4. Install the firewall, VPN, DNS filter and hardening

**On your computer**, in the project directory, copy this block. The `&&` operators
stop the sequence if a step fails:

```bash
make vpn-firewall-setup &&
DNSFILTER=yes make vpn-server-setup &&
make server-hardening &&
make check-auto-upgrades
```

**Stop if a command fails.** Read the error and retry that step after resolving it.
Do not continue through a failed installation.
For `Unit ssh.socket is masked` from an earlier version, follow the
[SSH recovery steps](docs/OPERATIONS.md#ssh-recovery-after-a-failed-socket-migration)
in your VPS provider's console before retrying hardening.

This configures:

- **UFW firewall:** SSH and WireGuard are allowed; private service ports are protected.
- **WireGuard:** VPN gateway `10.99.0.1/24`, UDP port `51820`.
- **AppArmor compatibility:** where a distribution WireGuard profile is enabled,
  setup installs and checks a confined firewall hook before starting the VPN.
- **dnsfilter:** malware blocking through Cloudflare's malware resolver. Adult and
  advertisement filtering are off on first installation. Ordinary DNS queries from VPN clients go through
  the filter, including requests addressed to another resolver such as `8.8.8.8`.
- **SSH hardening:** key-only access, restricted to your inventory user. In this guide,
  `root` remains accessible by key. Password login, compression and agent forwarding are off.
- **Fail2Ban:** SSH attempts are monitored through the system journal; repeated failures
  trigger a temporary ban.
- **Automatic security updates:** enabled. Required reboots remain your responsibility.

Running `make vpn-server-setup` without `DNSFILTER=yes` asks a yes/no question; answer
`yes` to enable filtering. **Use `DNSFILTER=yes` on later setup runs too.** Answering
`no` switches VPN DNS forwarding to an external resolver.

## 5. Check the installation and reboot

Run `make check-ssh` again to test a **new** SSH connection. Keep the provider console open.
Then run these checks **in the VPS console**:

```bash
systemctl is-active wg-quick@wg0 wireguard-dnsfilter fail2ban
fail2ban-client status sshd
ufw status verbose
wg show
sshd -T | grep -E '^(passwordauthentication|authenticationmethods|permitrootlogin|compression|allowusers) '
```

All three services must report `active`; Fail2Ban must show the `sshd` jail and UFW must
be active. SSH must show `passwordauthentication no`, `authenticationmethods publickey`,
`compression no` and `allowusers root`. `permitrootlogin without-password` means the
intended key-only root access. If you chose another inventory user, only that user
is allowed and root login is disabled. No WireGuard handshake is expected until you add a device.

Run `reboot` once **from the provider console**. After the VPS comes back, repeat
the SSH and service checks above to verify that everything starts automatically.

## 6. Connect your phone or laptop

**On your computer**, in the project directory:

```bash
CLIENT_NAME=phone make vpn-client-add
```

Install the [official WireGuard app](https://www.wireguard.com/install/) on your device
and scan the displayed QR code. Alternatively, extract `clients/vpn/phone.zip` and
import its `.conf` file. **The QR code and ZIP contain a private VPN key. Keep them private.**
Create a separate client name for every device, such as `laptop`.

Enable the VPN on the device and open a normal website. Then **on your computer**:

```bash
make vpn-server-status
```

The device should have a recent `latest handshake` and transferred data. Open
[the public IPv4 check](https://api.ipify.org) in the connected device's browser:
the displayed address must match your VPS's public IPv4 address.

To test DNS from a connected Debian/Ubuntu laptop:

```bash
sudo apt-get install -y dnsutils
dig @10.99.0.1 malware.testcategory.com A +short
dig +tcp @10.99.0.1 malware.testcategory.com A +short
dig @8.8.8.8 malware.testcategory.com A +short
dig @10.99.0.1 nudity.testcategory.com A +short
```

The first three queries must return `0.0.0.0`; the last must return a different address.
These are [harmless Cloudflare test domains](https://developers.cloudflare.com/1.1.1.1/setup/#test-1111-for-families).
An empty response or timeout does not count as a successful test.
Disable browser “Secure DNS”/DNS-over-HTTPS and device “Private DNS”/DNS-over-TLS if
all DNS queries should use this filter. Port-53 redirection cannot reliably intercept
these encrypted alternatives.

Generated profiles route IPv4 and IPv6 into the tunnel. This server provides IPv4
Internet access; IPv6 Internet traffic is blocked inside the tunnel. Protection when
the VPN is switched off or removed by the operating system requires your device's
Always-on VPN / kill-switch setting.

## Everyday commands and updates

Run these **on your computer, in the project directory**:

| Task | Command |
| --- | --- |
| Check SSH and administrator access | `make check-ssh` |
| List devices | `make vpn-client-list` |
| Show a QR code again | `CLIENT_NAME=phone make vpn-client-qrcode` |
| Revoke a device | `CLIENT_NAME=phone make vpn-client-remove` |
| VPN status | `make vpn-server-status` |
| Follow logs; exit with Ctrl+C | `make vpn-monitor` |
| DNS filter health, settings and counters | `make dnsfilter-status` |
| Latest 100 DNS filter log entries | `make dnsfilter-logs` |
| Follow DNS filter logs; exit with Ctrl+C | `make dnsfilter-monitor` |
| Troubleshoot | `make vpn-debug` |
| Check automatic updates | `make check-auto-upgrades` |
| Audit Python dependencies | `make audit` |
| Scan Python locks and built containers with OSV | `make osv-scan` |

### Change DNS filtering

Run these **on your computer, in the project directory**, after installing with
`DNSFILTER=yes`. Each change applies to **all VPN clients**; existing profiles keep working.

| Filter | Enable blocking | Disable blocking |
| --- | --- | --- |
| Ads and trackers | `make dnsfilter-enable-ads` | `make dnsfilter-disable-ads` |
| Adult content | `make dnsfilter-enable-porn` | `make dnsfilter-disable-porn` |
| Malware | `make dnsfilter-enable-malware` | `make dnsfilter-disable-malware` |

Use `make dnsfilter-status` to see the selected flags, service health, counters and
VPN DNS redirect rules. Changes are validated and DNS is checked over UDP and TCP;
a failed change restores the previous configuration. A changed policy briefly
restarts DNS. Repeating an already-applied setting does not restart it. Your filter
choices survive reboot and later `DNSFILTER=yes make vpn-server-setup` runs.

The upstream policies overlap: [Cloudflare's adult-content resolver](https://developers.cloudflare.com/1.1.1.1/setup/)
also blocks malware, and [AdGuard's default resolver](https://adguard-dns.io/kb/general/dns-providers/#default)
blocks ads, trackers and phishing. Disabling the malware flag does not override
protection provided by another enabled resolver. All three flags must be off to
select only the unfiltered resolver.

### See whether a client was filtered

On your computer, leave this running:

```bash
make dnsfilter-monitor
```

With the VPN connected on your phone, open Cloudflare's harmless test address
`https://malware.testcategory.com/`. With malware filtering enabled, the page should
not load and a fresh DNS lookup should produce a log entry containing `INFO blocked`,
`domain=malware.testcategory.com.`, `client_ip=10.99.0.x` and `reason=0.0.0.0`.
Use `make vpn-client-list` to match that VPN address to a device. For exact UDP/TCP
checks, use the `dig` commands in step 6.

`make dnsfilter-logs` shows recent history without following it. These log commands
read the first server in your inventory; status and category changes cover all servers.
Logs contain queried domains and client IPs, so keep them private.

Cached answers can be blocked without a new block log or a new `blocked_total` count.
`requests_total` and `cache_hits` help confirm activity; all counters reset when DNS
restarts. The upstream service also labels NXDOMAIN responses as `blocked`, so a
nonexistent domain alone does not prove a policy block. Browser/device encrypted DNS
can bypass this filter; use the client settings described in step 6.

### Dependency maintenance

`make osv-scan` saves JSON reports and logs under `.container/osv/run.*/`. A failing
exit status is expected while vulnerabilities remain. These reports contain no
inventory or VPN keys. See the [security review](docs/SECURITY-REVIEW.md) for the current results.

The standard `requirements.txt` and `requirements-dev.txt` files reference the full
hashed locks, so recursive OSV scans see the same Python versions as container builds.
Edit direct dependency versions in `requirements.in` / `requirements-dev.in`, then
run `make deps-lock`. `make osv-scan` checks both recursive discovery and explicit locks.

Automatic VPS updates do **not** refresh pinned controller images, Python locks or
the dnsfilter image. Update the reviewed project pins and rerun setup with
`DNSFILTER=yes` to deploy a new DNS image. Maintenance, dependency updates,
recovery and tests are explained in [Technical operations](docs/OPERATIONS.md).

After an interrupted DNS setup, errors may refer to recovery files or
`/run/wireguard-dnsfilter-setup.lock`. Do not delete them blindly; first check for
an active setup and inspect the current services and retained recovery state.
