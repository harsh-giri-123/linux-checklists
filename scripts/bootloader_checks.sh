#!/bin/bash

# Linux Security Audit - Bootloader Security Checks
# Version 1.0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Log file
LOG_FILE="/var/log/linux_security_audit.log"
REPORT_FILE="/tmp/bootloader_security_report.txt"

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

# Bootloader Security Checks
audit_bootloader() {
    echo "=== Bootloader Security Checks ==="

    # Check GRUB config file permissions (try both locations)
    local grub_cfg="/boot/grub/grub.cfg"
    local grub_cfg2="/boot/grub2/grub.cfg"
    local legacy_grub="/etc/grub.conf"

    if [[ -f "$grub_cfg" ]]; then
        check "GRUB config file permissions (/boot/grub/grub.cfg)" "stat -c %a $grub_cfg" "600"
        check "GRUB config file owner (/boot/grub/grub.cfg)" "stat -c %U:%G $grub_cfg" "root:root"
    elif [[ -f "$grub_cfg2" ]]; then
        check "GRUB config file permissions (/boot/grub2/grub.cfg)" "stat -c %a $grub_cfg2" "600"
        check "GRUB config file owner (/boot/grub2/grub.cfg)" "stat -c %U:%G $grub_cfg2" "root:root"
    elif [[ -f "$legacy_grub" ]]; then
        check "Legacy GRUB config file permissions (/etc/grub.conf)" "stat -c %a $legacy_grub" "600"
        check "Legacy GRUB config file owner (/etc/grub.conf)" "stat -c %U:%G $legacy_grub" "root:root"
    else
        check "GRUB config file exists" "echo 'GRUB config not found'" "GRUB config not found"
    fi

    # Check GRUB directory permissions
    local grub_dir="/etc/grub.d"
    if [[ -d "$grub_dir" ]]; then
        check "GRUB directory permissions (/etc/grub.d)" "stat -c %a $grub_dir" "700"
        check "GRUB directory owner (/etc/grub.d)" "stat -c %U:%G $grub_dir" "root:root"
        check "No world-writable files in /etc/grub.d" "find $grub_dir -type f -perm -002 2>/dev/null | wc -l" "0"
        check "All files in /etc/grub.d owned by root" "find $grub_dir -type f ! -user root 2>/dev/null | wc -l" "0"
    else
        check "GRUB directory exists (/etc/grub.d)" "echo 'GRUB directory not found'" "GRUB directory not found"
    fi

    # Check /boot directory permissions
    check "/boot directory permissions" "stat -c %a /boot" "755"
    check "/boot directory owner" "stat -c %U:%G /boot" "root:root"

    # Check for GRUB password protection
    if [[ -f "$grub_cfg" ]] || [[ -f "$grub_cfg2" ]]; then
        local grub_file=${grub_cfg}
        [[ -f "$grub_cfg2" ]] && grub_file=$grub_cfg2
        check "GRUB password protection enabled" "grep -q 'password' $grub_file && echo yes || echo no" "yes"
    fi

    # Check for secure boot (if applicable)
    check "Secure Boot status" "mokutil --sb-state 2>/dev/null | grep -q 'SecureBoot enabled' && echo enabled || echo disabled" "enabled"

    # Check for EFI directory if it exists
    if [[ -d "/boot/efi" ]]; then
        check "/boot/efi directory permissions" "stat -c %a /boot/efi" "755"
        check "/boot/efi directory owner" "stat -c %U:%G /boot/efi" "root:root"
    fi

    # Check for initramfs/initrd permissions
    local initrd_files=$(find /boot -name "initrd*" -o -name "initramfs*" 2>/dev/null | head -5)
    if [[ -n "$initrd_files" ]]; then
        check "Initramfs/initrd files permissions" "stat -c %a $initrd_files 2>/dev/null | sort | uniq | grep -q '600' && echo yes || echo no" "yes"
        check "Initramfs/initrd files owner" "stat -c %U:%G $initrd_files 2>/dev/null | sort | uniq | grep -q 'root:root' && echo yes || echo no" "yes"
    fi

    # Check kernel image permissions
    local kernel_files=$(find /boot -name "vmlinuz*" -o -name "kernel*" 2>/dev/null | head -5)
    if [[ -n "$kernel_files" ]]; then
        check "Kernel image permissions" "stat -c %a $kernel_files 2>/dev/null | sort | uniq | grep -q '600' && echo yes || echo no" "yes"
        check "Kernel image owner" "stat -c %U:%G $kernel_files 2>/dev/null | sort | uniq | grep -q 'root:root' && echo yes || echo no" "yes"
    fi
}

# Main execution
echo "Starting Bootloader Security Audit..."
> $REPORT_FILE
audit_bootloader
echo "Bootloader audit completed. Report saved to $REPORT_FILE"