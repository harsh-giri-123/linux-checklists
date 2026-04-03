<<<<<<< HEAD
# Linux Security Audit Automation Tool

A terminal-based tool to audit, harden, and report Linux system security with modular check scripts and TUI interface.

## Features

- **Modular Design**: Separate scripts for different security check categories
- **Text User Interface (TUI)**: Interactive menu for selecting checks
- **Command Line Options**: Run specific checks or all checks
- **Automated 200+ Linux security checks** covering:
  - Users and accounts
  - File permissions
  - Partitioning and disk security
  - Bootloader security
  - Kernel security (logs, pointers, ExecShield, ASLR)
  - Services and processes
  - Network ports and configurations
  - SSH configurations
  - Firewall configurations
  - Logs and audit systems
  - Additional security checks (SELinux, etc.)
- **System hardening actions** (available in original script)
- **Comprehensive reporting** with combined results

## Project Structure

```
linux-checklist/
├── main.sh                    # Main script with TUI and CLI options
├── linux_security_audit.sh    # Original monolithic script
├── scripts/                   # Modular check scripts
│   ├── user_checks.sh         # User and account security
│   ├── permission_checks.sh   # File and directory permissions
│   ├── partitioning_checks.sh # Partitioning and disk security
│   ├── bootloader_checks.sh   # Bootloader security checks
│   ├── kernel_checks.sh       # Kernel security checks
│   ├── service_checks.sh      # Service and process checks
│   ├── network_checks.sh      # Network and port checks
│   ├── ssh_checks.sh          # SSH configuration checks
│   ├── firewall_checks.sh     # Firewall configuration checks
│   ├── logs_checks.sh         # Logs and audit checks
│   └── additional_checks.sh   # Additional security checks
└── README.md
```

## Usage

### Interactive TUI Mode (Default)
```bash
sudo ./main.sh
```
This launches a text-based menu where you can select which security checks to perform.

### Command Line Options
```bash
sudo ./main.sh [option]
```

Options:
- `--all` or `-a`: Run all security checks
- `--user`: Run only user and account checks
- `--permission`: Run only file permission checks
- `--partitioning`: Run only partitioning and disk checks
- `--bootloader`: Run only bootloader security checks
- `--kernel`: Run only kernel security checks
- `--service`: Run only service checks
- `--network`: Run only network checks
- `--ssh`: Run only SSH checks
- `--firewall`: Run only firewall checks
- `--logs`: Run only logs and audit checks
- `--additional`: Run only additional checks
- `--report`: Generate combined report from existing check results

### Original Script (Monolithic)
```bash
sudo ./linux_security_audit.sh audit    # Perform all checks
sudo ./linux_security_audit.sh harden   # Apply hardening actions
sudo ./linux_security_audit.sh report   # Generate report
```

## Requirements

- Bash shell
- whiptail (for TUI - will be auto-installed if missing)
- Standard Linux utilities (grep, awk, systemctl, etc.)
- Root privileges for all operations

## Installation

1. Clone or download the repository
2. Make scripts executable:
```bash
chmod +x main.sh linux_security_audit.sh scripts/*.sh
```

## Reports

Individual check scripts generate reports in `/tmp/`:
- `user_security_report.txt`
- `permission_security_report.txt`
- `service_security_report.txt`
- `network_security_report.txt`
- `ssh_security_report.txt`
- `additional_security_report.txt`

The main script combines all results into:
- `/tmp/combined_security_report.txt`

## Disclaimer

Use at your own risk. This tool is for educational and self-audit purposes. Always backup your system before applying hardening actions.
=======
# linux-checklists
modular linux security check scripts
>>>>>>> origin/main
