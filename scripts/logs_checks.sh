#!/bin/bash

# Linux Security Audit - Logs and Audit Checks
# Version 1.0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Log file
LOG_FILE="/var/log/linux_security_audit.log"
REPORT_FILE="/tmp/logs_security_report.txt"

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

# Logs and Audit Checks
audit_logs() {
    echo "=== Logs and Audit Security Checks ==="
    check "Syslog service running" "systemctl is-active rsyslog 2>/dev/null || systemctl is-active syslog-ng 2>/dev/null" "active"
    check "Auditd service running" "systemctl is-active auditd 2>/dev/null" "active"
    check "Log files exist" "ls /var/log/syslog /var/log/messages /var/log/auth.log 2>/dev/null | wc -l" "3"
    check "Log files have correct permissions" "stat -c %a /var/log/syslog 2>/dev/null || stat -c %a /var/log/messages 2>/dev/null" "640"
    check "Auth log has correct permissions" "stat -c %a /var/log/auth.log 2>/dev/null || stat -c %a /var/log/secure 2>/dev/null" "600"
    check "No world-readable log files" "find /var/log -type f -perm -004 2>/dev/null | wc -l" "0"
    check "Logrotate configured" "ls /etc/logrotate.d/ | wc -l" "5"  # Approximate
    check "Logrotate runs daily" "grep -r "daily" /etc/logrotate.d/ | wc -l" "1"
    check "System logs are not empty" "for log in /var/log/syslog /var/log/messages /var/log/auth.log; do if [ -f \$log ] && [ -s \$log ]; then echo ok; else echo fail; fi; done | grep -c fail" "0"
    check "No unauthorized log modifications" "ls -la /var/log/ | grep -v '^-' | wc -l" "0"  # Check for symlinks
    check "Audit rules configured" "auditctl -l | wc -l" "5"  # Approximate
    check "Audit logs exist" "ls /var/log/audit/audit.log 2>/dev/null | wc -l" "1"
    check "Audit log rotation configured" "grep -r "audit" /etc/logrotate.d/ | wc -l" "1"
    check "Journald configured" "systemctl is-active systemd-journald 2>/dev/null" "active"
    check "Journald persistent logging" "ls /var/log/journal/ 2>/dev/null | wc -l" "1"
    check "No log files in /tmp" "find /tmp -name "*.log" 2>/dev/null | wc -l" "0"
    check "Cron logs enabled" "grep -q "cron" /etc/rsyslog.conf 2>/dev/null && echo yes || echo no" "yes"
    check "Sudo logs commands" "grep -q "logfile" /etc/sudoers 2>/dev/null && echo yes || echo no" "yes"
    check "SSH logs connections" "grep -q "LogLevel" /etc/ssh/sshd_config && echo yes || echo no" "yes"
    check "Failed login attempts logged" "grep -i "failed" /var/log/auth.log 2>/dev/null | wc -l" "0"  # Should have some entries
    check "System boot logged" "journalctl --boot | head -1 | wc -l" "1"
}

# Main execution
echo "Starting Logs and Audit Security Audit..."
> $REPORT_FILE
audit_logs
echo "Logs audit completed. Report saved to $REPORT_FILE"