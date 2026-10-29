# Dependency security review — 2026-10-29

**This is not a zero-findings release.** Actionable controller SSH issues have been
addressed, but 44 active Debian advisory IDs remain in the controller and audit
images. A clean Python or DNS scan is not a security guarantee for the whole VPS.

## OSV results

OSV Scanner **2.7.0**, pinned by OCI digest in `Dockerfile`, scanned the complete
Python locks and exported images built from this project. No project ignore list
was used. The following counts are distinct advisory IDs, not duplicate binary
packages or a count of proven exploitable paths.

| Scanned artifact | Before | After |
| --- | ---: | ---: |
| Python runtime and development locks | 0 | 0 |
| Default recursive Python requirements discovery | 4 IDs (2 vulnerabilities) | 0 |
| Deployment controller image | 68 | 44 |
| Development / pip-audit image | Not measured | 44 |
| dnsfilter executable and runtime image | 0 | 0 |

The runtime lock contains 10 Python packages. The development lock includes those
packages and contains 36 total. OSV also retains 25 additional advisory IDs in each
controller image that its own analysis marks as filtered/unimportant. They are
present in the raw JSON; they have not been deleted to make the result look better.

Run **`make osv-scan`** to reproduce the check. Each run creates a private directory
under `.container/osv/run.*/` containing:

- `locks.json`, `requirements.json`, `runtime.json`, `dev.json`, `dnsfilter-runtime.json`: complete results.
- Matching `.log` files: scanner diagnostics.
- `images.tsv`: immutable IDs of the images actually built and scanned.
- `status.tsv`: each scanner exit code. `0` means no active findings, `1` findings,
  and other codes indicate an unsuccessful scan.

The launcher continues scanning the other artifacts when findings exist, but
returns failure overall. GNU Make reports a failed target as exit 2, including
when the scanner correctly returned 1 for vulnerabilities. Missing reports or
operational errors must never be interpreted as clean results.

## Changes made

**Fixed recursive source-scan coverage.** The original checks scanned explicit
locks and built images, but omitted the default `osv-scanner -r .` discovery path.
That path found only the short direct-requirements files and inferred an older
transitive graph: certifi 2026.7.22 and idna 3.9.0. The actual development lock and
image already contained certifi 2026.10.23 and idna 3.20, beyond the reported fixed
versions in [PYSEC-2026-4320](https://osv.dev/vulnerability/PYSEC-2026-4320) and
[PYSEC-2026-215](https://osv.dev/vulnerability/PYSEC-2026-215).

Editable pins now live in `.in` files. The standard `.txt` entry points reference
the complete hashed locks, and `make osv-scan` additionally tests recursive discovery
with default resolution enabled. Both OSV 2.6.0 (the locally installed version) and
2.7.0 discovered 10 runtime / 36 development packages and returned no Python
vulnerability findings with this layout. No package or advisory was ignored.

**Updated the controller's OpenSSH client to 10.6p1.** Debian 13's packaged client
`1:10.0p1-7+deb13u4` did not include the upstream fixes. For example, the client-side
host-key re-exchange use-after-free was fixed in OpenSSH 10.4.
[Debian's CVE-2026-60002 tracker](https://security-tracker.debian.org/tracker/CVE-2026-60002)
confirms the affected stable package.

The client is built from the official release archive with a checked SHA-256;
upstream unit tests run during the build. Only the client tools and helpers enter
the deployment image. The compiler, SSH daemon and old Debian SSH client do not.
Removing the old client also removes its Kerberos-library dependency. Together,
these changes remove the package matches behind 24 of the original advisory IDs.
This does not mean that all 24 were exploitable through this project.

**Disabled SSH compression and agent forwarding explicitly.** The custom client
is built without zlib. Ansible and the log-monitor command also request
`Compression=no` and `ForwardAgent=no`. OpenSSH 10.6 includes additional SFTP,
username-validation and compression fixes described in the
[official release notes](https://www.openssh.org/txt/release-10.6).

**Corrected SSH hardening variables.** The pinned role now receives the actual
settings `ssh_server_password_login`, `ssh_client_alive_count` and
`ssh_max_auth_retries`. Authentication explicitly requires a public key; only the
inventory user is allowed. Root key access is retained only when root is that user.
The quick start uses `make check-ssh` to verify access with the patched client
before and after hardening, without a password fallback.

**Added collection archive containment checks.** Before Galaxy installs any checked
archive, the installer rejects traversal paths, hard links, special files, duplicate
paths, directory/link chains and members beneath a symbolic link. Direct aliases
to regular files within the archive remain supported. This adds a local guard
against the extraction class described in
[CVE-2026-89091](https://security-tracker.debian.org/tracker/CVE-2026-89091).
The zero-finding PyPI scan alone did not establish protection against this issue.

**Fail builds on APT index failures.** Snapshot updates use `--error-on=any` so an
unavailable repository cannot silently produce an apparently updated build.

## Remaining Debian findings

The configured signed snapshot is `20261029T000000Z`. The build upgrades packages
against it. None of the remaining advisory records in this scan provides a fixed
Debian 13 version; no additional upgrade was available in that snapshot. Replacing
the stable distribution's core libraries with arbitrary unstable packages is not
an appropriate automatic fix.

| Source package | Active advisory IDs |
| --- | ---: |
| glibc | 14 |
| util-linux | 5 |
| perl | 3 |
| sqlite3 | 3 |
| systemd | 3 |
| tar | 3 |
| acl | 2 |
| gcc-14 runtime libraries | 2 |
| ncurses | 2 |
| pam | 2 |
| zlib | 2 |
| attr | 1 |
| bzip2 | 1 |
| shadow | 1 |

These are source-package matches: a match for systemd or GCC can refer to an
installed library rather than a running daemon or compiler. Some records have high
severity scores. The leading util-linux/ACL/attribute findings describe local
privilege escalation or privileged processing of attacker-controlled paths.
The ordinary controller runs without root, capabilities or writable system files,
which limits those paths; this is mitigation, not proof that every finding is harmless.

Some records also require upstream/distribution clarification. For example,
[CVE-2026-85091](https://security-tracker.debian.org/tracker/CVE-2026-85091) describes
zlib 1.3.1.2–1.3.2 while also marking Debian's 1.3.1 package as affected. This remains
visible pending a verified resolution; the project does not silently suppress it.

Monitor Debian security updates, advance the reviewed image digests and snapshot,
then rerun the scans and tests. The live VPS uses its normal Debian security
repositories; its SSH server is not replaced by the controller's custom client.

## Coverage and deployment checks

The scanner recognizes Python packages, Debian package metadata and dnsfilter's Go
build information. **It does not automatically identify the custom OpenSSH C build.**
Review that source pin and upstream security releases separately; the reduced
OSV count must not be treated as independent validation of the custom binary.

OSV does not audit the Ansible roles' behavior, the live VPS, the host kernel,
provider firewall rules or device kill switches. Scanner and build containers
receive no deployment credentials. Deployment containers receive the dedicated
SSH-agent socket, which is a sensitive capability even though private key files
are not mounted.

Validation completed for these changes: 86 regression tests, all 12 playbook syntax
checks, lock consistency and pip-audit; upstream OpenSSH unit tests; native SSH/SFTP
and host-key rejection; Netfilter/UFW on IPv4 and IPv6, Fail2Ban and update-origin
checks; real DNS UDP/TCP policy/outage checks and 13 Ansible deployment/recovery
scenarios with simulated runtime management. The full native WireGuard
integration test is blocked by this workstation's AppArmor restrictions; no host
security policy was relaxed. A fresh VPS still needs the README's SSH reconnect,
client handshake, DNS, public-IP and reboot checks before production use.
