#!/bin/bash

# Linux Security Audit - User and Account Checks
# Version 1.0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Log file
LOG_FILE="/var/log/linux_security_audit.log"
REPORT_FILE="/tmp/user_security_report.txt"

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

# User and Account Checks (20 checks)
audit_users() {
    echo "=== User and Account Security Checks ==="
    check "Root account UID is 0" "awk -F: '(\$3 == \"0\") {print \$1}' /etc/passwd" "root"
    check "No non-root accounts have UID 0" "awk -F: '(\$3 == \"0\" && \$1 != \"root\") {print \$1}' /etc/passwd" ""
    check "Root login disabled in SSH" "grep '^PermitRootLogin' /etc/ssh/sshd_config" "no"
    check "Password aging enabled for users" "grep PASS_MAX_DAYS /etc/login.defs | awk '{print \$2}'" "90"
    check "No accounts with empty passwords" "awk -F: '(\$2 == \"\") {print \$1}' /etc/shadow" ""
    check "Password complexity enforced" "grep pam_pwquality /etc/pam.d/password-auth" "pam_pwquality"
    check "Account lockout after failed attempts" "grep pam_faillock /etc/pam.d/password-auth" "pam_faillock"
    check "No users with UID 0 except root" "awk -F: '(\$3 == 0 && \$1 != \"root\")' /etc/passwd" ""
    check "Home directories exist and are owned by user" "for user in \$(awk -F: '\$6 ~ /^\/home/ {print \$1\":\"\$6}' /etc/passwd); do user=\$(echo \$user | cut -d: -f1); dir=\$(echo \$user | cut -d: -f2); if [ -d \"\$dir\" ] && [ \"\$(stat -c %U \$dir)\" = \"\$user\" ]; then echo ok; else echo fail; fi; done | grep -c fail" "0"
    check "No world-writable files in /home" "find /home -type f -perm -002 2>/dev/null | wc -l" "0"
    check "Sudo requires password" "grep 'NOPASSWD' /etc/sudoers" ""
    check "No shared accounts" "awk -F: '\$3 >= 1000 && \$3 < 65534 {print \$1}' /etc/passwd | sort | uniq -d" ""
    check "User shells are valid" "for shell in \$(awk -F: '\$7 !~ /^\/(bin|usr\/bin|sbin|usr\/sbin)\/(bash|sh|zsh|fish|csh|tcsh)$/ && \$7 != \"/usr/sbin/nologin\" && \$7 != \"/bin/false\" {print \$7}' /etc/passwd); do if [ ! -x \"\$shell\" ]; then echo fail; fi; done | wc -l" "0"
    check "No users with expired passwords" "chage -l root | grep 'Password expires' | grep -v never" "Password expires"
    check "Minimum password length set" "grep PASS_MIN_LEN /etc/login.defs | awk '{print \$2}'" "8"
    check "Password history remembered" "grep remember /etc/pam.d/password-auth | awk '{print \$3}'" "5"
    check "No duplicate UIDs" "cut -d: -f3 /etc/passwd | sort | uniq -d" ""
    check "No duplicate GIDs" "cut -d: -f4 /etc/passwd | sort | uniq -d" ""
    check "Wheel group exists for sudo" "grep wheel /etc/group" "wheel"
}

# Main execution
echo "Starting User and Account Security Audit..."
> $REPORT_FILE
audit_users
echo "User audit completed. Report saved to $REPORT_FILE"