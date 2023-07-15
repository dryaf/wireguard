.PHONY: clean_known_hosts vpn-server-setup vpn-server-status vpn-client-add vpn-client-qrcode vpn-client-remove vpn-client-list help init

.DEFAULT_GOAL := help

check_ansible:
	@which ansible >/dev/null || (echo "Ansible is not installed. Please install it before running these commands." && exit 1)

clean_known_hosts: check_ansible ## to play around with server_debug.yml
	 ansible-playbook -i inventory.ini server_clean_known_hosts.yml

vpn-server-setup: check_ansible ## Setup the WireGuard server
	@read -p "Enter DNS server (default: 10.99.0.1): " dns_server; \
	 ansible-playbook -i inventory.ini wireguard_server_setup.yml -e "dns_server=$${dns_server:-10.99.0.1}"

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
