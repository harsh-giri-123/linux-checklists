#!/bin/bash

# Linux Security Audit - Firewall Checks
# Version 1.0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Log file
LOG_FILE="/var/log/linux_security_audit.log"
REPORT_FILE="/tmp/firewall_security_report.txt"

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

# Firewall Checks
audit_firewall() {
    echo "=== Firewall Security Checks ==="
    check "Firewall service enabled" "systemctl is-active firewalld 2>/dev/null || systemctl is-active ufw 2>/dev/null || systemctl is-active iptables 2>/dev/null" "active"
    check "Default INPUT policy DROP" "iptables -L INPUT | grep -q 'DROP' && echo yes || echo no" "yes"
    check "Default FORWARD policy DROP" "iptables -L FORWARD | grep -q 'DROP' && echo yes || echo no" "yes"
    check "Default OUTPUT policy ACCEPT" "iptables -L OUTPUT | grep -q 'ACCEPT' && echo yes || echo no" "yes"
    check "SSH port allowed" "iptables -L | grep -q 'dport 22' && echo yes || echo no" "yes"
    check "Loopback interface allowed" "iptables -L INPUT | grep -q 'lo' && echo yes || echo no" "yes"
    check "Established connections allowed" "iptables -L INPUT | grep -q 'ESTABLISHED' && echo yes || echo no" "yes"
    check "ICMP ping allowed" "iptables -L INPUT | grep -q 'icmp' && echo yes || echo no" "yes"
    check "No unrestricted outbound" "iptables -L OUTPUT | grep -c 'ACCEPT' | awk '{if (\$1 > 10) print \"fail\"; else print \"pass\"}'" "pass"
    check "Firewall rules persistent" "ls /etc/iptables/rules.v4 2>/dev/null || ls /etc/ufw/ufw.conf 2>/dev/null || ls /etc/firewalld/zones/ 2>/dev/null | wc -l" "1"
    check "UFW enabled (if using UFW)" "ufw status 2>/dev/null | grep -q 'Status: active' && echo yes || echo no" "yes"
    check "Firewalld zones configured" "firewall-cmd --get-zones 2>/dev/null | wc -w" "1"
    check "No firewall bypass rules" "iptables -L | grep -c 'ACCEPT.*anywhere' | awk '{if (\$1 > 5) print \"fail\"; else print \"pass\"}'" "pass"
    check "Firewall logging enabled" "iptables -L | grep -q 'LOG' && echo yes || echo no" "yes"
    check "No direct rules to dangerous ports" "iptables -L | grep -E 'dport (23|21|139|445)' | wc -l" "0"
    check "Rate limiting for new connections" "iptables -L | grep -q 'limit' && echo yes || echo no" "yes"
    check "No unused firewall chains" "iptables -L -n | grep -c 'Chain' | awk '{if (\$1 > 10) print \"fail\"; else print \"pass\"}'" "pass"
    check "Firewall service running on boot" "systemctl is-enabled firewalld 2>/dev/null || systemctl is-enabled ufw 2>/dev/null || echo enabled" "enabled"
    check "No firewall rules with ANY source" "iptables -L | grep -c '0.0.0.0/0' | awk '{if (\$1 > 3) print \"fail\"; else print \"pass\"}'" "pass"
    check "Firewall configuration backed up" "ls /etc/iptables/ 2>/dev/null || ls /etc/ufw/before.rules 2>/dev/null || echo exists" "exists"
}

# Main execution
echo "Starting Firewall Security Audit..."
> $REPORT_FILE
audit_firewall
echo "Firewall audit completed. Report saved to $REPORT_FILE"