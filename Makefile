.PHONY: clean_known_hosts vpn-server-setup vpn-server-status vpn-client-add vpn-client-qrcode vpn-client-remove vpn-client-list help init vpn-debug vpn-monitor check-auto-upgrades enable-auto-upgrades disable-auto-upgrades vpn-firewall-setup

.DEFAULT_GOAL := help

check_ansible:
	@which ansible >/dev/null || (echo "Ansible is not installed. Please install it before running these commands." && exit 1)

clean_known_hosts: check_ansible ## to play around with server_debug.yml
	 ansible-playbook -i inventory.ini server_clean_known_hosts.yml

vpn-server-setup: check_ansible ## Setup the WireGuard server
	@read -p "Enter DNS server (default: 10.99.0.1): " dns_server; \
	 ansible-playbook -i inventory.ini wireguard_server_setup.yml -e "dns_server=$${dns_server:-10.99.0.1}"

vpn-firewall-setup: check_ansible ## Configure firewall (Block Ext 53/8080, Allow VPN/SSH)
	@ansible-playbook -i inventory.ini server_firewall_setup.yml

vpn-server-status: check_ansible ## Get the vpn server status
	@ansible-playbook -i inventory.ini wireguard_server_status.yml

vpn-client-add: check_ansible ## Add a client
	@read -p "Enter client name: " client_name; \
	 ansible-playbook -i inventory.ini wireguard_client_add.yml -e "client_name=$$client_name"

vpn-client-qrcode: check_ansible ## Display the QR code for a client
	@read -p "Enter client name: " client_name; \
	 ansible-playbook -i inventory.ini wireguard_client_qrcode.yml -e "client_name=$$client_name"

vpn-client-remove: check_ansible ## Remove a client
	@read -p "Enter client name: " client_name; \
	 ansible-playbook -i inventory.ini wireguard_client_remove.yml -e "client_name=$$client_name"

vpn-client-list: check_ansible ## List all clients
	@ansible-playbook -i inventory.ini wireguard_client_list.yml

vpn-debug: check_ansible ## Debug VPN connection issues (IP forwarding, firewall, DNS)
	@ansible-playbook -i inventory.ini server_debug_vpn.yml

vpn-monitor: check_ansible ## Live monitor WireGuard & DNS logs (Ctrl+C to stop)
	@echo "Starting live monitor..."
	@SERVER_LINE=$$(grep 'ansible_host=' inventory.ini | head -n 1); \
	HOST=$$(echo $$SERVER_LINE | tr ' ' '\n' | grep 'ansible_host=' | cut -d= -f2); \
	USER=$$(echo $$SERVER_LINE | tr ' ' '\n' | grep 'ansible_user=' | cut -d= -f2); \
	PORT=$$(echo $$SERVER_LINE | tr ' ' '\n' | grep 'ansible_port=' | cut -d= -f2); \
	KEY=$$(echo $$SERVER_LINE | tr ' ' '\n' | grep 'ansible_ssh_private_key_file=' | cut -d= -f2); \
	echo "Connecting to $$USER@$$HOST:$$PORT with key $$KEY..."; \
	ssh -t -p $$PORT -i $$KEY $$USER@$$HOST "journalctl -u dns-filter -u wg-quick@wg0 -f -n 20"

check-auto-upgrades: check_ansible ## Check status of unattended upgrades
	@echo "Checking APT configuration..."
	@ansible -i inventory.ini servers -b -m shell -a "apt-config dump | grep 'APT::Periodic'"
	@echo "\nChecking service status..."
	@ansible -i inventory.ini servers -b -m shell -a "systemctl status unattended-upgrades --no-pager" | grep "Active:"

enable-auto-upgrades: check_ansible ## Enable daily auto-updates
	@ansible-playbook -i inventory.ini server_toggle_autoupgrades.yml -e "enabled=yes"

disable-auto-upgrades: check_ansible ## Disable auto-updates
	@ansible-playbook -i inventory.ini server_toggle_autoupgrades.yml -e "enabled=no"

init: check_ansible ## Initialize the inventory file
	@read -p "Enter server host: " server_host; \
	read -p "Enter server username: " server_username; \
	read -p "Enter SSH port (default: 22): " ssh_port; \
	echo "[servers]" > inventory.ini; \
	echo "$$server_username ansible_host=$$server_host ansible_user=$$server_username ansible_ssh_private_key_file=~/.ssh/id_ed25519 ansible_port=$${ssh_port:-22}" >> inventory.ini

help: check_ansible ## show help
	@echo "Usage: make [command]\n"
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\t%-30s %s\n", $$1, $$2}'