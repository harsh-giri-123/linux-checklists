#!/bin/bash

# Linux Security Audit - Kernel Security Checks
# Version 1.0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Log file
LOG_FILE="/var/log/linux_security_audit.log"
REPORT_FILE="/tmp/kernel_security_report.txt"

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

# Kernel Security Checks
audit_kernel() {
    echo "=== Kernel Security Checks ==="

    # Kernel logs restriction (dmesg_restrict)
    check "Kernel dmesg access restricted" "sysctl kernel.dmesg_restrict" "1"
    check "Dmesg restrict config file exists" "ls /etc/sysctl.d/50-dmesg-restrict.conf 2>/dev/null && grep -q 'kernel.dmesg_restrict = 1' /etc/sysctl.d/50-dmesg-restrict.conf && echo yes || echo no" "yes"

    # Kernel pointers restriction (kptr_restrict)
    check "Kernel pointer access restricted" "sysctl kernel.kptr_restrict" "1"
    check "Kptr restrict config file exists" "ls /etc/sysctl.d/50-kptr-restrict.conf 2>/dev/null && grep -q 'kernel.kptr_restrict = 1' /etc/sysctl.d/50-kptr-restrict.conf && echo yes || echo no" "yes"

    # ExecShield protection
    check "ExecShield protection enabled" "sysctl kernel.exec-shield 2>/dev/null || echo 'not supported'" "2"
    check "ExecShield config file exists" "ls /etc/sysctl.d/50-exec-shield.conf 2>/dev/null && grep -q 'kernel.exec-shield = 2' /etc/sysctl.d/50-exec-shield.conf && echo yes || echo no" "yes"

    # Memory space randomization (ASLR)
    check "Address Space Layout Randomization (ASLR) enabled" "sysctl kernel.randomize_va_space" "2"
    check "ASLR config file exists" "ls /etc/sysctl.d/50-rand-va-space.conf 2>/dev/null && grep -q 'kernel.randomize_va_space=2' /etc/sysctl.d/50-rand-va-space.conf && echo yes || echo no" "yes"

    # Additional kernel security checks
    check "Core dumps restricted" "sysctl kernel.core_pattern | grep -q '/dev/null' && echo yes || echo no" "yes"
    check "SysRq disabled" "sysctl kernel.sysrq" "0"
    check "Magic SysRq disabled" "grep -q 'kernel.sysrq=0' /etc/sysctl.d/* 2>/dev/null && echo yes || echo no" "yes"

    # Kernel module restrictions
    check "Unprivileged user namespaces disabled" "sysctl kernel.unprivileged_userns_clone 2>/dev/null || echo 'not supported'" "0"
    check "BPF JIT hardening enabled" "sysctl net.core.bpf_jit_harden 2>/dev/null || echo 'not supported'" "2"

    # Yama LSM (ptrace restrictions)
    check "Yama ptrace scope restricted" "sysctl kernel.yama.ptrace_scope 2>/dev/null || echo 'not supported'" "1"

    # Kernel stack protection
    check "Stack protector enabled" "grep -q 'CONFIG_STACKPROTECTOR=y' /boot/config-$(uname -r) 2>/dev/null && echo yes || echo 'check failed'" "yes"

    # SMEP/SMAP (if supported)
    check "SMEP enabled" "grep -q 'CONFIG_X86_SMEP=y' /boot/config-$(uname -r) 2>/dev/null && echo yes || echo 'not supported'" "yes"
    check "SMAP enabled" "grep -q 'CONFIG_X86_SMAP=y' /boot/config-$(uname -r) 2>/dev/null && echo yes || echo 'not supported'" "yes"

    # KASLR (Kernel Address Space Layout Randomization)
    check "KASLR enabled" "grep -q 'CONFIG_RANDOMIZE_BASE=y' /boot/config-$(uname -r) 2>/dev/null && echo yes || echo 'not supported'" "yes"

    # Module loading restrictions
    check "Module loading restricted" "sysctl kernel.modules_disabled 2>/dev/null || echo 'not supported'" "0"
    check "Unprivileged module loading disabled" "grep -q 'CONFIG_MODULE_SIG_FORCE=y' /boot/config-$(uname -r) 2>/dev/null && echo yes || echo 'not supported'" "yes"

    # CPU vulnerabilities mitigations
    check "Spectre v2 mitigation enabled" "grep -q 'spectre_v2=.*on' /proc/cmdline && echo yes || echo 'check cmdline'" "yes"
    check "Meltdown mitigation enabled" "grep -q 'pti=on' /proc/cmdline && echo yes || echo 'check cmdline'" "yes"

    # IOMMU protection
    check "IOMMU enabled" "dmesg | grep -q 'DMAR: IOMMU enabled' && echo yes || echo 'check dmesg'" "yes"

    # Kernel lockdown mode (if available)
    check "Kernel lockdown mode" "cat /sys/kernel/security/lockdown 2>/dev/null || echo 'not supported'" "none"
}

# Main execution
echo "Starting Kernel Security Audit..."
> $REPORT_FILE
audit_kernel
echo "Kernel audit completed. Report saved to $REPORT_FILE"