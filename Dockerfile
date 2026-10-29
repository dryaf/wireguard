# Base images pin multi-platform manifests, not mutable tags.
FROM ghcr.io/astral-sh/uv:0.13.6@sha256:af22a52f5eafef3d78e551599d405c02df61919d18028f0cea8eda93bc9986d0 AS uv

FROM ghcr.io/google/osv-scanner:v2.7.0@sha256:4f3b7e2c64b9d38a5febc5a7e4a3dfef1d1362f726dea7a2ef4762b46469fcd0 AS osv

# Optional dnsfilter: fixed upstream source, toolchain, module sums and runtime.
# This target also builds remotely using only this Dockerfile as its context.
FROM docker.io/library/golang:1.27.3-trixie@sha256:c65ecfe613b539ac74c62a4c3b2c27e8f8a6076384c8f27e8a3c0f3be17cc385 AS dnsfilter-build
ENV GOTOOLCHAIN=local GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org CGO_ENABLED=0 GOFLAGS=-mod=readonly GOMAXPROCS=2
WORKDIR /src
RUN wget --https-only --timeout=60 --tries=3 -q -O /tmp/source.tar.gz https://codeload.github.com/dryaf/dnsfilter/tar.gz/0af7f225b892b32444d9497f581ddcf237c67306 \
    && printf '%s  /tmp/source.tar.gz\n' d3964bac5adaf5536f3edbb972abdeccc80cdceb0f40db8b228744147efc8fd0 | sha256sum --check \
    && tar -xzf /tmp/source.tar.gz --strip-components=1 -C /src \
    && rm /tmp/source.tar.gz
RUN sha256sum go.mod go.sum > /tmp/modules.sha256 \
    && go mod download \
    && go mod verify \
    && sha256sum --check /tmp/modules.sha256
RUN --network=none go test -p 2 ./... \
    && go build -p 2 -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o /out/dns-filter ./service \
    && sha256sum --check /tmp/modules.sha256

FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99 AS dnsfilter-runtime
LABEL org.opencontainers.image.source="https://github.com/dryaf/dnsfilter" \
    org.opencontainers.image.revision="0af7f225b892b32444d9497f581ddcf237c67306"
COPY --from=dnsfilter-build --chmod=0555 /out/dns-filter /dns-filter
USER 65532:65532
STOPSIGNAL SIGTERM
ENTRYPOINT ["/dns-filter"]
CMD ["-configFile", "/etc/dnsfilter.yml"]

FROM docker.io/library/python:3.14.10-slim-trixie@sha256:cd89c30eda26ee911a4611b18680086e0ea42e6f5f8cbe653d07fa7958c9cec8 AS os-base

# Immutable, signed Debian repositories also fix the OS dependency resolution.
ARG DEBIAN_SNAPSHOT=20261029T000000Z
RUN printf 'Types: deb\nURIs: https://snapshot.debian.org/archive/debian/%s/\nSuites: trixie trixie-updates\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\nCheck-Valid-Until: no\n\nTypes: deb\nURIs: https://snapshot.debian.org/archive/debian-security/%s/\nSuites: trixie-security\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\nCheck-Valid-Until: no\n' "$DEBIAN_SNAPSHOT" "$DEBIAN_SNAPSHOT" > /etc/apt/sources.list.d/debian.sources \
    && apt-get update --error-on=any \
    && apt-get upgrade --yes --no-install-recommends \
    && apt-get install --yes --no-install-recommends ca-certificates make \
    && rm -rf /var/lib/apt/lists/*

# Debian 13's SSH client does not contain the 10.4-10.6 upstream security fixes.
# Build only our client tools from the release archive; no compiler enters base.
FROM os-base AS openssh-build
RUN apt-get update --error-on=any \
    && apt-get install --yes --no-install-recommends build-essential curl libssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN curl --fail --show-error --location --proto '=https' --proto-redir '=https' --max-time 120 \
      https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-10.6p1.tar.gz -o source.tar.gz \
    && printf '%s  source.tar.gz\n' a9dc9565dffe8640f64d863cd29a32bc4a3dbdec0566a7fc44c5d6ee767d5f39 | sha256sum --check \
    && tar -xzf source.tar.gz --strip-components=1 \
    && rm source.tar.gz
RUN --network=none ./configure --prefix=/opt/openssh --sysconfdir=/etc/ssh --without-zlib \
    && make -j2 ssh scp sftp ssh-keygen ssh-keyscan ssh-agent ssh-add ssh-pkcs11-helper ssh-sk-helper \
    && make -j2 unit \
    && mkdir -p /out/bin /out/libexec /out/share/licenses/openssh \
    && cp ssh scp sftp ssh-keygen ssh-keyscan ssh-agent ssh-add /out/bin/ \
    && cp ssh-pkcs11-helper ssh-sk-helper /out/libexec/ \
    && cp LICENCE /out/share/licenses/openssh/ \
    && /out/bin/ssh -V

FROM os-base AS base
COPY --from=openssh-build /out/ /opt/openssh/
ENV PATH=/opt/openssh/bin:$PATH

ARG WG_UID=65532
ARG WG_GID=65532
RUN if ! getent group "$WG_GID" >/dev/null; then groupadd --gid "$WG_GID" wireguard; fi \
    && useradd --uid "$WG_UID" --gid "$WG_GID" --no-log-init --no-create-home --home-dir /tmp/wireguard wireguard \
    && mkdir -p /workspace/clients /workspace/locks /run/wireguard /opt/collections \
    && touch /run/wireguard/inventory.ini /run/wireguard/known_hosts /run/wireguard/ssh-agent

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_ONLY_BINARY=:all: \
    PIP_INDEX_URL=https://pypi.org/simple \
    UV_DEFAULT_INDEX=https://pypi.org/simple \
    UV_PYTHON_DOWNLOADS=never \
    UV_CACHE_DIR=/tmp/uv-cache \
    UV_SYSTEM_CERTS=true \
    ANSIBLE_HOME=/tmp/ansible \
    ANSIBLE_LOCAL_TEMP=/tmp/ansible/local \
    ANSIBLE_COLLECTIONS_PATH=/opt/collections \
    XDG_CACHE_HOME=/tmp/cache
WORKDIR /workspace

FROM base AS lock-tools
COPY --from=uv /uv /usr/local/bin/uv
COPY requirements.in requirements-dev.in requirements.txt requirements-dev.txt requirements.yml ./
COPY scripts/dependency_lock.py scripts/dependency_lock.py
USER ${WG_UID}:${WG_GID}
ENTRYPOINT ["python", "scripts/dependency_lock.py"]

# Scan inputs and exported images without access to the container engine socket.
FROM os-base AS osv-tools
WORKDIR /workspace
COPY --from=osv /osv-scanner /usr/local/bin/osv-scanner
COPY requirements.in requirements-dev.in requirements.txt requirements-dev.txt ./
COPY locks/requirements.lock locks/requirements-dev.lock locks/
COPY scripts/osv_report.py scripts/osv_report.py
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 XDG_CACHE_HOME=/tmp/osv-cache GOMAXPROCS=2
ENTRYPOINT ["osv-scanner"]

FROM base AS python-deps
COPY requirements.in requirements-dev.in requirements.txt requirements-dev.txt requirements.yml ./
COPY locks/ ./locks/
COPY scripts/dependency_lock.py scripts/dependency_lock.py
RUN python scripts/dependency_lock.py check \
    && python -m venv /opt/venv \
    && /opt/venv/bin/python -m pip install --force-reinstall --require-hashes --only-binary=:all: -r locks/requirements.lock \
    && /opt/venv/bin/python -m pip check \
    && chmod -R u=rwX,go=rX /workspace \
    && rm -rf /tmp/ansible /tmp/wireguard /tmp/cache
ENV PATH=/opt/venv/bin:$PATH

FROM python-deps AS controller
RUN python scripts/dependency_lock.py install-collections \
    && rm -rf /tmp/ansible /tmp/wireguard /tmp/cache
COPY . .
RUN chmod -R u=rwX,go=rX /workspace /opt/collections
USER ${WG_UID}:${WG_GID}
ENTRYPOINT ["python", "scripts/container_cli.py"]

# The audit image does not contain project playbooks, tests or application sources.
FROM python-deps AS dev
COPY scripts/container_cli.py scripts/container_cli.py
RUN python -m pip install --force-reinstall --require-hashes --only-binary=:all: -r locks/requirements-dev.lock \
    && python -m pip check
USER ${WG_UID}:${WG_GID}
ENTRYPOINT ["python", "scripts/container_cli.py"]

FROM python-deps AS network-tools
RUN apt-get update --error-on=any \
    && apt-get install --yes --no-install-recommends wireguard-tools iproute2 iptables procps systemd dbus ufw fail2ban python3-systemd unattended-upgrades openssh-server \
    && rm -rf /var/lib/apt/lists/* /tmp/ansible /tmp/wireguard /tmp/cache

FROM network-tools AS network-tests
COPY --from=controller /workspace /workspace
COPY --from=controller /opt/collections /opt/collections
RUN mkdir -p /usr/local/lib/wireguard-manager \
    && cp files/wireguard_manager.py files/wireguard_firewall.py filter_plugins/wireguard.py /usr/local/lib/wireguard-manager/ \
    && chmod 700 /usr/local/lib/wireguard-manager /usr/local/lib/wireguard-manager/*.py \
    && rm -rf /tmp/ansible /tmp/wireguard /tmp/cache

FROM controller AS dnsfilter-tests
COPY --from=dnsfilter-build --chmod=0555 /out/dns-filter /opt/dnsfilter/dns-filter

FROM controller AS runtime
