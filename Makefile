.DEFAULT_GOAL := help
.PHONY: check-ssh
.PHONY: build init trust-host clean_known_hosts vpn-server-setup vpn-server-status vpn-firewall-setup server-hardening vpn-client-add vpn-client-qrcode vpn-client-remove vpn-client-list vpn-debug vpn-monitor check-auto-upgrades enable-auto-upgrades disable-auto-upgrades test dnsfilter-test integration-test firewall-test syntax-check deps-lock deps-check audit osv-scan help

build: ## Build the pinned controller image
init: ## Initialize inventory.ini
trust-host: ## Verify server fingerprints and save SSH host keys
check-ssh: ## Verify key-only SSH and administrator access using the patched container client
clean_known_hosts: ## Remove inventory servers from the project's known_hosts
vpn-server-setup: ## Set up the WireGuard server
vpn-server-status: ## Get the VPN server status
vpn-firewall-setup: ## Configure the WireGuard firewall
server-hardening: ## Apply the pinned devsec.hardening roles
vpn-client-add: ## Add or re-export a client
vpn-client-qrcode: ## Display a client's QR code
vpn-client-remove: ## Remove a client
vpn-client-list: ## List clients
vpn-debug: ## Diagnose IP forwarding, firewall and DNS
vpn-monitor: ## Monitor the first server's WireGuard and DNS logs
check-auto-upgrades: ## Check unattended-upgrades on the servers
enable-auto-upgrades: ## Enable daily server auto-updates
disable-auto-upgrades: ## Disable server auto-updates
test: ## Run regression tests in a container without network or credentials
dnsfilter-test: ## Test the pinned DNS filter with isolated UDP/TCP upstream fixtures
firewall-test: ## Test real Netfilter failure recovery in a disposable rootless container
integration-test: ## Test native WireGuard, systemd and Netfilter in a disposable rootless container
syntax-check: ## Check all playbooks in a container without contacting servers
deps-lock: ## Resolve pinned inputs and regenerate all dependency hashes
deps-check: ## Check dependency lock consistency and installed Python packages
audit: ## Check all locked Python dependencies for known vulnerabilities
osv-scan: ## Scan Python locks and controller/dev/DNS images with pinned OSV; keep JSON reports

build init trust-host check-ssh clean_known_hosts vpn-server-setup vpn-server-status vpn-firewall-setup server-hardening vpn-client-add vpn-client-qrcode vpn-client-remove vpn-client-list vpn-debug vpn-monitor check-auto-upgrades enable-auto-upgrades disable-auto-upgrades test dnsfilter-test integration-test firewall-test syntax-check deps-lock deps-check audit osv-scan:
	@./scripts/container $@

help: ## Show available commands (no container required)
	@awk 'BEGIN {FS = ":.*## "; print "Usage: make COMMAND\n"} /^[a-zA-Z_-]+:.*## / {printf "  %-24s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
