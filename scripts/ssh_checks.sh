#!/bin/bash

# Linux Security Audit - SSH Configuration Checks
# Version 1.0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Log file
LOG_FILE="/var/log/linux_security_audit.log"
REPORT_FILE="/tmp/ssh_security_report.txt"

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

# SSH Checks (20 checks)
audit_ssh() {
    echo "=== SSH Configuration Checks ==="
    check "SSH protocol version 2 only" "grep '^Protocol' /etc/ssh/sshd_config" "2"
    check "SSH root login disabled" "grep '^PermitRootLogin' /etc/ssh/sshd_config" "no"
    check "SSH password authentication disabled" "grep '^PasswordAuthentication' /etc/ssh/sshd_config" "no"
    check "SSH empty passwords disabled" "grep '^PermitEmptyPasswords' /etc/ssh/sshd_config" "no"
    check "SSH X11 forwarding disabled" "grep '^X11Forwarding' /etc/ssh/sshd_config" "no"
    check "SSH MaxAuthTries set" "grep '^MaxAuthTries' /etc/ssh/sshd_config | awk '{print \$2}'" "3"
    check "SSH LoginGraceTime set" "grep '^LoginGraceTime' /etc/ssh/sshd_config | awk '{print \$2}'" "60"
    check "SSH ClientAliveInterval set" "grep '^ClientAliveInterval' /etc/ssh/sshd_config | awk '{print \$2}'" "300"
    check "SSH ClientAliveCountMax set" "grep '^ClientAliveCountMax' /etc/ssh/sshd_config | awk '{print \$2}'" "0"
    check "SSH IgnoreRhosts enabled" "grep '^IgnoreRhosts' /etc/ssh/sshd_config" "yes"
    check "SSH HostbasedAuthentication disabled" "grep '^HostbasedAuthentication' /etc/ssh/sshd_config" "no"
    check "SSH PermitUserEnvironment disabled" "grep '^PermitUserEnvironment' /etc/ssh/sshd_config" "no"
    check "SSH StrictModes enabled" "grep '^StrictModes' /etc/ssh/sshd_config" "yes"
    check "SSH UsePrivilegeSeparation enabled" "grep '^UsePrivilegeSeparation' /etc/ssh/sshd_config" "yes"
    check "SSH Compression delayed" "grep '^Compression' /etc/ssh/sshd_config" "delayed"
    check "SSH TCPKeepAlive disabled" "grep '^TCPKeepAlive' /etc/ssh/sshd_config" "no"
    check "SSH AllowTcpForwarding disabled" "grep '^AllowTcpForwarding' /etc/ssh/sshd_config" "no"
    check "SSH GatewayPorts disabled" "grep '^GatewayPorts' /etc/ssh/sshd_config" "no"
    check "SSH AllowAgentForwarding disabled" "grep '^AllowAgentForwarding' /etc/ssh/sshd_config" "no"
    check "SSH PrintMotd disabled" "grep '^PrintMotd' /etc/ssh/sshd_config" "no"
}

# Main execution
echo "Starting SSH Configuration Security Audit..."
> $REPORT_FILE
audit_ssh
echo "SSH audit completed. Report saved to $REPORT_FILE"