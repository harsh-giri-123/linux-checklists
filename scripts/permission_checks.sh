#!/bin/bash

# Linux Security Audit - File and Directory Permission Checks
# Version 1.0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Log file
LOG_FILE="/var/log/linux_security_audit.log"
REPORT_FILE="/tmp/permission_security_report.txt"

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

# Permission Checks (20 checks)
audit_permissions() {
    echo "=== File and Directory Permission Checks ==="
    check "Root home directory permissions" "stat -c %a /root" "700"
    check "/etc/passwd permissions" "stat -c %a /etc/passwd" "644"
    check "/etc/shadow permissions" "stat -c %a /etc/shadow" "000"
    check "/etc/group permissions" "stat -c %a /etc/group" "644"
    check "/etc/gshadow permissions" "stat -c %a /etc/gshadow" "000"
    check "/etc/ssh/sshd_config permissions" "stat -c %a /etc/ssh/sshd_config" "600"
    check "No world-writable files in /etc" "find /etc -type f -perm -002 2>/dev/null | wc -l" "0"
    check "No SUID files except allowed" "find / -perm -4000 -type f ! -path '/usr/bin/sudo' ! -path '/usr/bin/su' 2>/dev/null | wc -l" "0"
    check "No SGID files except allowed" "find / -perm -2000 -type f 2>/dev/null | wc -l" "0"
    check "/boot/grub/grub.cfg permissions" "stat -c %a /boot/grub/grub.cfg 2>/dev/null || stat -c %a /boot/grub2/grub.cfg 2>/dev/null" "600"
    check "No executable files in /tmp" "find /tmp -type f -executable 2>/dev/null | wc -l" "0"
    check "/var/log permissions" "stat -c %a /var/log" "755"
    check "No files with no owner" "find / -nouser -o -nogroup 2>/dev/null | wc -l" "0"
    check "/etc/crontab permissions" "stat -c %a /etc/crontab" "600"
    check "/etc/cron.d permissions" "stat -c %a /etc/cron.d" "700"
    check "/etc/cron.hourly permissions" "stat -c %a /etc/cron.hourly" "700"
    check "/etc/cron.daily permissions" "stat -c %a /etc/cron.daily" "700"
    check "/etc/cron.weekly permissions" "stat -c %a /etc/cron.weekly" "700"
    check "/etc/cron.monthly permissions" "stat -c %a /etc/cron.monthly" "700"
    check "Sticky bit set on /tmp" "stat -c %a /tmp | grep -q 1 && echo yes || echo no" "yes"
    check "Sticky bit set on /var/tmp" "stat -c %a /var/tmp | grep -q 1 && echo yes || echo no" "yes"
}

# Main execution
echo "Starting File and Directory Permission Security Audit..."
> $REPORT_FILE
audit_permissions
echo "Permission audit completed. Report saved to $REPORT_FILE"