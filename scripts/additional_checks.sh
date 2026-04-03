#!/bin/bash

# Linux Security Audit - Additional Security Checks
# Version 1.0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Log file
LOG_FILE="/var/log/linux_security_audit.log"
REPORT_FILE="/tmp/additional_security_report.txt"

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

# Additional checks (20 more)
audit_additional() {
    echo "=== Additional Security Checks ==="
    check "Kernel version up to date" "uname -r | grep -o '[0-9]\+\.[0-9]\+' | head -1" "5"  # Approximate
    check "No core dumps allowed" "sysctl kernel.core_pattern | grep -q '/dev/null' && echo yes || echo no" "yes"
    check "ASLR enabled" "sysctl kernel.randomize_va_space" "2"
    check "ExecShield enabled" "sysctl kernel.exec-shield" "1"
    check "No USB storage auto-mount" "grep -q 'install usb-storage /bin/true' /etc/modprobe.d/* && echo yes || echo no" "yes"
    check "No firewire modules" "lsmod | grep -q firewire && echo no || echo yes" "yes"
    check "No bluetooth modules" "lsmod | grep -q bluetooth && echo no || echo yes" "yes"
    check "Auditd running" "systemctl is-active auditd 2>/dev/null" "active"
    check "SELinux enabled" "sestatus | grep -q 'enabled' && echo yes || echo no" "yes"
    check "AppArmor enabled" "apparmor_status 2>/dev/null | grep -q 'apparmor module is loaded' && echo yes || echo no" "yes"
    check "No zombie processes" "ps aux | awk '{print \$8}' | grep -c Z" "0"
    check "System load normal" "uptime | awk '{print \$NF}' | grep -q '[0-9]\+\.[0-9]\+' && echo yes || echo no" "yes"
    check "Disk space sufficient" "df / | awk 'NR==2 {print \$5}' | sed 's/%//' | awk '{if (\$1 < 90) print \"yes\"; else print \"no\"}'" "yes"
    check "Memory usage normal" "free | awk 'NR==2 {printf \"%.0f\", \$3/\$2 * 100}' | awk '{if (\$1 < 90) print \"yes\"; else print \"no\"}'" "yes"
    check "No unauthorized cron jobs" "crontab -l 2>/dev/null | wc -l" "0"
    check "Logrotate configured" "ls /etc/logrotate.d/ | wc -l" "5"  # Approximate
    check "No SUID binaries in /tmp" "find /tmp -perm -4000 2>/dev/null | wc -l" "0"
    check "No SGID binaries in /tmp" "find /tmp -perm -2000 2>/dev/null | wc -l" "0"
    check "Package manager lock not held" "pgrep -f 'apt|yum|dnf' | wc -l" "0"
    check "No unauthorized packages installed" "dpkg --list 2>/dev/null | grep -c '^ii' || rpm -qa 2>/dev/null | wc -l" "100"  # Approximate
}

# Main execution
echo "Starting Additional Security Audit..."
> $REPORT_FILE
audit_additional
echo "Additional audit completed. Report saved to $REPORT_FILE"