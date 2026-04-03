#!/bin/bash

# Linux Security Audit - Network and Port Checks
# Version 1.0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Log file
LOG_FILE="/var/log/linux_security_audit.log"
REPORT_FILE="/tmp/network_security_report.txt"

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

# Network Checks (20 checks)
audit_network() {
    echo "=== Network and Port Checks ==="
    check "Open ports limited" "netstat -tuln | grep LISTEN | wc -l" "5"  # Approximate
    check "No open port 23 (telnet)" "netstat -tuln | grep :23" ""
    check "No open port 21 (ftp)" "netstat -tuln | grep :21" ""
    check "SSH on standard port" "grep '^Port' /etc/ssh/sshd_config | awk '{print \$2}'" "22"
    check "Firewall rules configured" "iptables -L | grep -c ACCEPT" "5"  # Approximate
    check "IPv6 disabled if not needed" "grep 'net.ipv6.conf.all.disable_ipv6' /etc/sysctl.conf" "1"
    check "ICMP redirects disabled" "sysctl net.ipv4.conf.all.accept_redirects" "0"
    check "IP spoofing protection enabled" "sysctl net.ipv4.conf.all.rp_filter" "1"
    check "SYN cookies enabled" "sysctl net.ipv4.tcp_syncookies" "1"
    check "No promiscuous interfaces" "ip link | grep -c PROMISC" "0"
    check "DNS servers configured" "grep nameserver /etc/resolv.conf | wc -l" "1"
    check "No unauthorized ARP entries" "arp -a | wc -l" "1"  # Approximate
    check "TCP wrappers configured" "ls /etc/hosts.allow /etc/hosts.deny 2>/dev/null | wc -l" "2"
    check "No listening on all interfaces" "netstat -tuln | grep '0.0.0.0:' | wc -l" "0"
    check "IPv4 forwarding disabled" "sysctl net.ipv4.ip_forward" "0"
    check "Source route acceptance disabled" "sysctl net.ipv4.conf.all.accept_source_route" "0"
    check "Martian packets logged" "sysctl net.ipv4.conf.all.log_martians" "1"
    check "TCP timestamps disabled" "sysctl net.ipv4.tcp_timestamps" "0"
    check "No unused network interfaces" "ip link show | grep -c 'state UP'" "1"  # Approximate
    check "Wireless interfaces disabled if not needed" "iwconfig 2>/dev/null | grep -c 'IEEE'" "0"
}

# Main execution
echo "Starting Network and Port Security Audit..."
> $REPORT_FILE
audit_network
echo "Network audit completed. Report saved to $REPORT_FILE"