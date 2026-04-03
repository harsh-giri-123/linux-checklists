#!/bin/bash

# Linux Security Audit Tool - Main Script with TUI
# Version 1.0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/scripts"

# Check if root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

# Check if whiptail is available
if ! command -v whiptail &> /dev/null; then
    echo -e "${YELLOW}whiptail not found. Installing...${NC}"
    if command -v apt &> /dev/null; then
        apt update && apt install -y whiptail
    elif command -v yum &> /dev/null; then
        yum install -y newt
    elif command -v dnf &> /dev/null; then
        dnf install -y newt
    else
        echo -e "${RED}Please install whiptail manually${NC}"
        exit 1
    fi
fi

# Function to run a check script
run_check() {
    local script_name="$1"
    local script_path="$SCRIPT_DIR/${script_name}.sh"

    if [[ -f "$script_path" ]]; then
        echo -e "${YELLOW}Running $script_name checks...${NC}"
        bash "$script_path"
        echo -e "${GREEN}$script_name checks completed.${NC}"
        echo ""
    else
        echo -e "${RED}Script $script_path not found!${NC}"
    fi
}

# Function to generate combined report
generate_report() {
    local report_files=(
        "/tmp/user_security_report.txt"
        "/tmp/permission_security_report.txt"
        "/tmp/partition_security_report.txt"
        "/tmp/bootloader_security_report.txt"
        "/tmp/kernel_security_report.txt"
        "/tmp/service_security_report.txt"
        "/tmp/network_security_report.txt"
        "/tmp/ssh_security_report.txt"
        "/tmp/firewall_security_report.txt"
        "/tmp/logs_security_report.txt"
        "/tmp/additional_security_report.txt"
    )

    local combined_report="/tmp/combined_security_report.txt"
    > "$combined_report"

    echo "=== COMBINED LINUX SECURITY AUDIT REPORT ===" >> "$combined_report"
    echo "Generated on: $(date)" >> "$combined_report"
    echo "" >> "$combined_report"

    local total_pass=0
    local total_fail=0

    for report_file in "${report_files[@]}"; do
        if [[ -f "$report_file" ]]; then
            echo "=== $(basename "$report_file" .txt | sed 's/_security_report//') Checks ===" >> "$combined_report"
            cat "$report_file" >> "$combined_report"
            echo "" >> "$combined_report"

            local pass_count=$(grep -c "PASS:" "$report_file")
            local fail_count=$(grep -c "FAIL:" "$report_file")
            total_pass=$((total_pass + pass_count))
            total_fail=$((total_fail + fail_count))
        fi
    done

    echo "=== SUMMARY ===" >> "$combined_report"
    echo "Total Passed: $total_pass" >> "$combined_report"
    echo "Total Failed: $total_fail" >> "$combined_report"
    echo "Total Checks: $((total_pass + total_fail))" >> "$combined_report"

    echo -e "${GREEN}Combined report generated: $combined_report${NC}"
    echo "Summary:"
    echo "Total Passed: $total_pass"
    echo "Total Failed: $total_fail"
    echo "Total Checks: $((total_pass + total_fail))"
}

# Main menu
show_menu() {
    local choices=$(whiptail --title "Linux Security Audit Tool" --checklist \
        "Select the security checks to perform:" 20 60 15 \
        "user" "User and Account Checks" OFF \
        "permission" "File and Directory Permission Checks" OFF \
        "partitioning" "Partitioning and Disk Checks" OFF \
        "bootloader" "Bootloader Security Checks" OFF \
        "kernel" "Kernel Security Checks" OFF \
        "service" "Service and Process Checks" OFF \
        "network" "Network and Port Checks" OFF \
        "ssh" "SSH Configuration Checks" OFF \
        "firewall" "Firewall Checks" OFF \
        "logs" "Logs and Audit Checks" OFF \
        "additional" "Additional Security Checks" OFF \
        3>&1 1>&2 2>&3)

    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}Starting selected security audits...${NC}"
        echo ""

        for choice in $choices; do
            case $choice in
                \"user\") run_check "user_checks" ;;
                \"permission\") run_check "permission_checks" ;;
                \"partitioning\") run_check "partitioning_checks" ;;
                \"bootloader\") run_check "bootloader_checks" ;;
                \"kernel\") run_check "kernel_checks" ;;
                \"service\") run_check "service_checks" ;;
                \"network\") run_check "network_checks" ;;
                \"ssh\") run_check "ssh_checks" ;;
                \"firewall\") run_check "firewall_checks" ;;
                \"logs\") run_check "logs_checks" ;;
                \"additional\") run_check "additional_checks" ;;
            esac
        done

        # Generate combined report
        generate_report
    else
        echo "Audit cancelled."
        exit 0
    fi
}

# Run all checks
run_all() {
    echo -e "${GREEN}Running all security audits...${NC}"
    echo ""

    run_check "user_checks"
    run_check "permission_checks"
    run_check "partitioning_checks"
    run_check "bootloader_checks"
    run_check "kernel_checks"
    run_check "service_checks"
    run_check "network_checks"
    run_check "ssh_checks"
    run_check "firewall_checks"
    run_check "logs_checks"
    run_check "additional_checks"

    # Generate combined report
    generate_report
}

# Command line options
case "$1" in
    --all|-a)
        run_all
        ;;
    --user)
        run_check "user_checks"
        ;;
    --permission)
        run_check "permission_checks"
        ;;
    --partitioning)
        run_check "partitioning_checks"
        ;;
    --bootloader)
        run_check "bootloader_checks"
        ;;
    --kernel)
        run_check "kernel_checks"
        ;;
    --service)
        run_check "service_checks"
        ;;
    --network)
        run_check "network_checks"
        ;;
    --ssh)
        run_check "ssh_checks"
        ;;
    --firewall)
        run_check "firewall_checks"
        ;;
    --logs)
        run_check "logs_checks"
        ;;
    --additional)
        run_check "additional_checks"
        ;;
    --report)
        generate_report
        ;;
    *)
        show_menu
        ;;
esac