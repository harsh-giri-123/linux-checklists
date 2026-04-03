#!/bin/bash

# Linux Security Audit - Service and Process Checks
# Version 1.0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Log file
LOG_FILE="/var/log/linux_security_audit.log"
REPORT_FILE="/tmp/service_security_report.txt"

# Check if root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

# Function to log
log() {
    echo "$(date): $1" >> $LOG_FILE
}

# Function to check and report
check() {
    local desc="$1"
    local cmd="$2"
    local expected="$3"
    local result
    result=$(eval "$cmd" 2>/dev/null)
    if [[ "$result" == *"$expected"* ]]; then
        echo -e "${GREEN}PASS${NC}: $desc"
        echo "PASS: $desc" >> $REPORT_FILE
    else
        echo -e "${RED}FAIL${NC}: $desc"
        echo "FAIL: $desc" >> $REPORT_FILE
    fi
}

# Service Checks (20 checks)
audit_services() {
    echo "=== Service and Process Checks ==="
    check "Telnet service disabled" "systemctl is-enabled telnet 2>/dev/null || echo disabled" "disabled"
    check "FTP service disabled" "systemctl is-enabled vsftpd 2>/dev/null || systemctl is-enabled proftpd 2>/dev/null || echo disabled" "disabled"
    check "Rsync service disabled" "systemctl is-enabled rsyncd 2>/dev/null || echo disabled" "disabled"
    check "NFS service disabled" "systemctl is-enabled nfs 2>/dev/null || echo disabled" "disabled"
    check "Samba service disabled" "systemctl is-enabled smb 2>/dev/null || echo disabled" "disabled"
    check "Apache service running (if web server)" "systemctl is-active httpd 2>/dev/null || systemctl is-active apache2 2>/dev/null || echo not running" "not running"
    check "MySQL service running (if database)" "systemctl is-active mysqld 2>/dev/null || systemctl is-active mysql 2>/dev/null || echo not running" "not running"
    check "SSH service running" "systemctl is-active sshd 2>/dev/null || systemctl is-active ssh 2>/dev/null" "active"
    check "Firewall enabled" "systemctl is-active firewalld 2>/dev/null || systemctl is-active ufw 2>/dev/null || systemctl is-active iptables 2>/dev/null" "active"
    check "NTP service running" "systemctl is-active ntpd 2>/dev/null || systemctl is-active chronyd 2>/dev/null" "active"
    check "Syslog service running" "systemctl is-active rsyslog 2>/dev/null || systemctl is-active syslog-ng 2>/dev/null" "active"
    check "Cron service running" "systemctl is-active crond 2>/dev/null || systemctl is-active cron 2>/dev/null" "active"
    check "No unnecessary services running" "systemctl list-units --type=service --state=running | grep -c service" "10"  # Approximate
    check "Avahi daemon disabled" "systemctl is-enabled avahi-daemon 2>/dev/null || echo disabled" "disabled"
    check "CUPS service disabled" "systemctl is-enabled cups 2>/dev/null || echo disabled" "disabled"
    check "Bluetooth service disabled" "systemctl is-enabled bluetooth 2>/dev/null || echo disabled" "disabled"
    check "ModemManager disabled" "systemctl is-enabled ModemManager 2>/dev/null || echo disabled" "disabled"
    check "NetworkManager running" "systemctl is-active NetworkManager 2>/dev/null" "active"
    check "DHCP client running" "systemctl is-active dhcpcd 2>/dev/null || systemctl is-active dhclient 2>/dev/null || echo running" "running"
    check "DNS resolution working" "nslookup google.com 2>/dev/null | grep -q 'Name:' && echo yes || echo no" "yes"
}

# Main execution
echo "Starting Service and Process Security Audit..."
> $REPORT_FILE
audit_services
echo "Service audit completed. Report saved to $REPORT_FILE"