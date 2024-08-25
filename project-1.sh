#!/bin/bash

# Configuration file for custom security checks
CONFIG_FILE="/path/to/config-file"

# Function to list all users and groups
function user_group_audit() {
    echo "User and Group Audit:"
    echo "Listing all users and groups:"
    cat /etc/passwd /etc/group
    echo "Checking for users with UID 0 (root privileges):"
    awk -F: '($3 == 0) {print $1}' /etc/passwd
    echo "Checking for users without passwords or with weak passwords:"
    awk -F: '($2 == "" || $2 == "!") {print $1}' /etc/shadow
}

# Function to check file and directory permissions
function file_permission_audit() {
    echo "File and Directory Permissions Audit:"
    echo "Scanning for world-writable files and directories:"
    find / -type d -perm -0002 -ls 2>/dev/null
    find / -type f -perm -0002 -ls 2>/dev/null
    echo "Checking for .ssh directories with insecure permissions:"
    find /home -name ".ssh" -exec ls -ld {} \;
    echo "Checking for files with SUID or SGID bits set:"
    find / -perm /6000 -type f -exec ls -ld {} \;
}

# Function to audit running services
function service_audit() {
    echo "Service Audit:"
    echo "Listing all running services:"
    service --status-all
    echo "Checking for unnecessary or unauthorized services:"
    # Add custom logic to check for unauthorized services
    echo "Checking for critical services (e.g., sshd, iptables):"
    for service in sshd iptables; do
        systemctl is-active --quiet $service && echo "$service is running" || echo "$service is not running"
    done
    echo "Checking for services listening on non-standard or insecure ports:"
    netstat -tuln | grep -v ':22\|:80\|:443'
}

# Function to check firewall and network security
function firewall_network_audit() {
    echo "Firewall and Network Security Audit:"
    echo "Checking for active firewall (e.g., iptables, ufw):"
    ufw status || iptables -L
    echo "Listing open ports and associated services:"
    netstat -tuln
    echo "Checking for IP forwarding or insecure network configurations:"
    sysctl net.ipv4.ip_forward
    sysctl net.ipv6.conf.all.forwarding
}

# Function to check IP configuration
function ip_config_audit() {
    echo "IP and Network Configuration Audit:"
    echo "Public vs. Private IP Checks:"
    ip a | grep -w inet | awk '{print $2}'
    # Add logic to distinguish public vs. private IPs
    echo "Summary of IP addresses:"
    ip a | grep -w inet
}

# Function to check for security updates and patches
function security_updates_audit() {
    echo "Security Updates and Patching Audit:"
    echo "Checking for available security updates:"
    apt-get update && apt-get upgrade -s | grep -i security
    echo "Ensuring server is configured for regular updates:"
    cat /etc/apt/apt.conf.d/20auto-upgrades
}

# Function to monitor logs for suspicious activity
function log_monitoring() {
    echo "Log Monitoring:"
    echo "Checking for suspicious log entries:"
    grep 'Failed password' /var/log/auth.log
    grep 'error' /var/log/syslog
}

# Function to harden SSH configuration
function harden_ssh() {
    echo "Hardening SSH Configuration:"
    echo "Implementing SSH key-based authentication:"
    sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    echo "Disabling root login:"
    sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    systemctl restart sshd
}

# Function to disable IPv6
function disable_ipv6() {
    echo "Disabling IPv6:"
    sysctl -w net.ipv6.conf.all.disable_ipv6=1
    sysctl -w net.ipv6.conf.default.disable_ipv6=1
    echo "Updating services to listen on IPv4 addresses:"
    # Add logic for services like SafeSquid if needed
}

# Function to secure the bootloader
function secure_bootloader() {
    echo "Securing the Bootloader:"
    grub2-setpassword
    echo "GRUB password set."
}

# Function to configure firewall rules
function configure_firewall() {
    echo "Configuring Firewall Rules:"
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    # Add additional firewall rules as needed
}

# Function to configure automatic updates
function configure_auto_updates() {
    echo "Configuring Automatic Updates:"
    apt-get install unattended-upgrades
    dpkg-reconfigure --priority=low unattended-upgrades
}

# Function to run custom security checks
function custom_security_checks() {
    echo "Running Custom Security Checks:"
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
        # Execute custom checks defined in the config file
    fi
}

# Function to generate a summary report
function generate_report() {
    echo "Generating Security Audit and Hardening Report:"
    # Collect data from the previous functions and compile a report
    # Send report via email or store in a specific location
}

# Function to run all checks and hardening steps
function run_all_checks() {
    user_group_audit
    file_permission_audit
    service_audit
    firewall_network_audit
    ip_config_audit
    security_updates_audit
    log_monitoring
    harden_ssh
    disable_ipv6
    secure_bootloader
    configure_firewall
    configure_auto_updates
    custom_security_checks
    generate_report
}

# Main script logic

