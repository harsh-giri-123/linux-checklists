#!/bin/bash

# Linux Security Audit - Partitioning and Disk Checks
# Version 1.0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Log file
LOG_FILE="/var/log/linux_security_audit.log"
REPORT_FILE="/tmp/partition_security_report.txt"

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

# Partitioning and Disk Checks
audit_partitioning() {
    echo "=== Partitioning and Disk Security Checks ==="
    check "/boot partition exists" "df /boot 2>/dev/null | wc -l" "2"
    check "/boot partition is separate" "mount | grep -q ' /boot ' && echo yes || echo no" "yes"
    check "/boot partition permissions" "stat -c %a /boot 2>/dev/null" "755"
    check "/home partition exists" "df /home 2>/dev/null | wc -l" "2"
    check "/home partition is separate" "mount | grep -q ' /home ' && echo yes || echo no" "yes"
    check "/tmp partition exists" "df /tmp 2>/dev/null | wc -l" "2"
    check "/tmp partition is separate" "mount | grep -q ' /tmp ' && echo yes || echo no" "yes"
    check "/var partition exists" "df /var 2>/dev/null | wc -l" "2"
    check "/var partition is separate" "mount | grep -q ' /var ' && echo yes || echo no" "yes"
    check "/var/log partition exists" "df /var/log 2>/dev/null | wc -l" "2"
    check "/var/log partition is separate" "mount | grep -q ' /var/log ' && echo yes || echo no" "yes"
    check "No world-writable mount points" "mount | grep -v ' /proc ' | grep -v ' /sys ' | awk '{print \$3}' | xargs -I {} sh -c 'stat -c %a {} 2>/dev/null | grep -q "777" && echo fail || echo ok' | grep -c fail" "0"
    check "Nodev option on /tmp" "mount | grep ' /tmp ' | grep -q nodev && echo yes || echo no" "yes"
    check "Nosuid option on /tmp" "mount | grep ' /tmp ' | grep -q nosuid && echo yes || echo no" "yes"
    check "Noexec option on /tmp" "mount | grep ' /tmp ' | grep -q noexec && echo yes || echo no" "yes"
    check "Nodev option on /home" "mount | grep ' /home ' | grep -q nodev && echo yes || echo no" "yes"
    check "Nodev option on /var" "mount | grep ' /var ' | grep -q nodev && echo yes || echo no" "yes"
    check "Noexec option on /var" "mount | grep ' /var ' | grep -q noexec && echo yes || echo no" "yes"
    check "Nodev option on /boot" "mount | grep ' /boot ' | grep -q nodev && echo yes || echo no" "yes"
    check "Nosuid option on /boot" "mount | grep ' /boot ' | grep -q nosuid && echo yes || echo no" "yes"
    check "Noexec option on /boot" "mount | grep ' /boot ' | grep -q noexec && echo yes || echo no" "yes"
}

# Main execution
echo "Starting Partitioning and Disk Security Audit..."
> $REPORT_FILE
audit_partitioning
echo "Partitioning audit completed. Report saved to $REPORT_FILE"