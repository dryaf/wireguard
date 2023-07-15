# Wireguard DRY

This guide covers the setup process for a WireGuard VPN server and includes steps to add and manage VPN clients - using ansible.
When you add a client you get a zip file and the QR code in the terminal.

## Prerequisites
Ensure that you have the following software installed on your system:

- Ansible
- Homebrew (for macOS)
- Python's `netaddr` package
- `devsec.hardening` Ansible collection

If these are not installed, you can set them up with the following commands:

```shell
    # Install Homebrew (macOS)
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    
    # Install Ansible
    brew install ansible 
    
    # Install devsec.hardening Ansible collection
    ansible-galaxy collection install devsec.hardening --force
    
    # Install netaddr Python package
    pip install netaddr
```

## Setup

### Initialize
Initialize the server IP, username, and SSH port.

```shell
    make init
```
The `make init` command will prompt you for the server host, server username, and SSH port (default: 22).

### VPN Server Setup
To set up the WireGuard server, run the following command:

```shell
    make vpn-server-setup
```
This command will ask you to enter the DNS server (default: 10.99.0.1).

### Optional: Server Hardening
You can optionally harden your server with the `devsec.hardening` Ansible collection and the `server_hardening.yml` playbook.

```shell
    ansible-galaxy collection install devsec.hardening --force
    ansible-playbook -i inventory.ini server_hardening.yml
```

## Managing VPN Clients

To add, remove, list, or generate QR codes for VPN clients, use the following commands:

### Add a Client
```shell
  make vpn-client-add
```
The command will prompt you to enter the client name.

### Remove a Client
```shell
    make vpn-client-remove
```
You will need to enter the client name that you want to remove.

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

## License
GNU
