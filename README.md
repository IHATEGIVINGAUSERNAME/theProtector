# theProtector v2.3

A comprehensive host-based security monitoring framework that implements real-time threat detection through eBPF kernel monitoring, YARA pattern matching, network honeypots, and anti-evasion techniques.

## Overview

theProtector provides multi-layer security monitoring for Linux systems by combining user-space and kernel-space detection mechanisms. The framework operates continuously to detect suspicious activities, malware, and evasion attempts while maintaining minimal system overhead.

## Features

- **eBPF Kernel Monitoring**: Real-time process execution tracking and system call analysis
- **YARA Malware Detection**: Pattern-based scanning for webshells, reverse shells, and crypto miners
- **Network Honeypots**: Automated deployment of listeners on commonly targeted ports
- **Anti-Evasion Detection**: Cross-validation techniques to identify hidden processes and connections
- **Threat Intelligence Integration**: Automated updates with IP reputation checking
- **REST API Interface**: Web dashboard and programmatic access to monitoring data
- **Forensic Capabilities**: Detailed logging with integrity verification and quarantine functions
- **Container Support**: Optimized monitoring for containerized environments

## Requirements

### System Requirements
- Linux kernel 4.9+ (for eBPF functionality)
- Bash 4.0+

### Optional Dependencies
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install yara jq inotify-tools bcc-tools netcat-openbsd python3

# Fedora/RHEL
sudo dnf install yara jq inotify-tools bcc-tools nmap-ncat python3

# Arch Linux
sudo pacman -S yara jq inotify-tools bcc netcat python
```

### Dependency Functions
- **yara**: Advanced malware detection rules
- **jq**: Enhanced JSON processing and output formatting
- **inotify-tools**: Real-time file system monitoring
- **bcc-tools**: eBPF kernel instrumentation
- **netcat**: Network honeypot implementation
- **python3**: API server and advanced monitoring features

## Installation

### Quick Start
```bash
# Download
git clone https://github.com/IHATEGIVINGAUSERNAME/theprotector.git
cd theProtector/
chmod +x theprotector.sh

# Test installation
sudo ./theprotector.sh test

# Run basic scan
sudo ./theprotector.sh

# Run enhanced monitoring
sudo ./theprotector.sh enhanced
```

### Automated Installation
```bash
# Install scheduled monitoring (hourly cron job)
sudo ./theprotector.sh install

# Install systemd service (recommended for servers)
sudo ./theprotector.sh systemd
```

### Nix Flake Installation

> Note: the Nix flake bundles `theprotector.sh` as a wrapper script that includes all optional dependencies for `theprotector.sh`

Run the following command to install `theprotector.sh` with Nix:

```
nix profile install github:IHATEGIVINGAUSERNAME/theprotector
```

## Usage

### Basic Commands

> Unprivileged usage -- running without `sudo` -- is also supported

```bash
# Run standard security scan
sudo ./theprotector.sh

# Run enhanced monitoring with all features
sudo ./theprotector.sh enhanced

# Test installation and show capabilities
sudo ./theprotector.sh test

# Check system status
sudo ./theprotector.sh status
```

### Advanced Features

```bash
# Start web dashboard
sudo ./theprotector.sh dashboard
# Access at http://127.0.0.1:8080

# Run specific monitoring modules
sudo ./theprotector.sh yara        # YARA scanning only
sudo ./theprotector.sh honeypot    # Network honeypots only
sudo ./theprotector.sh ebpf        # eBPF monitoring only

# Performance mode (reduced overhead)
sudo ./theprotector.sh performance
```

### Maintenance Commands

```bash
# View real-time logs
sudo ./theprotector.sh logs

# View today's alerts
sudo ./theprotector.sh alerts

# View JSON output
sudo ./theprotector.sh json

# Update threat intelligence
sudo ./theprotector.sh enhanced  # Automatic during scan

# Create new baseline
sudo ./theprotector.sh baseline

# Clean up processes and fix issues
sudo ./theprotector.sh cleanup
```

## Configuration

### Configuration File
Create `sentinel.conf` in the same directory as the script:

```bash
# Monitoring modules
MONITOR_NETWORK=true
MONITOR_PROCESSES=true
MONITOR_FILES=true
MONITOR_USERS=true
MONITOR_ROOTKITS=true
MONITOR_MEMORY=true

# Advanced features
ENABLE_ANTI_EVASION=true
ENABLE_EBPF=true
ENABLE_HONEYPOTS=true
ENABLE_API_SERVER=true
ENABLE_YARA=true
ENABLE_THREAT_INTEL=true

# Performance tuning
PERFORMANCE_MODE=false
MAX_FIND_DEPTH=2
SCAN_TIMEOUT=180
PARALLEL_JOBS=2

# Notifications
SEND_EMAIL=false
EMAIL_RECIPIENT=""
WEBHOOK_URL=""
SLACK_WEBHOOK_URL=""
SYSLOG_ENABLED=true

# Threat intelligence
ABUSEIPDB_API_KEY=""
VIRUSTOTAL_API_KEY=""
THREAT_INTEL_UPDATE_HOURS=6

# Network settings
API_PORT=8080
HONEYPOT_PORTS=("2222" "8080" "23" "21" "3389")
```

### Environment Variables
```bash
# Override API port
export DASHBOARD_PORT=8081

# Custom log directory
export GHOST_SENTINEL_LOG_DIR="/custom/log/path"
```

### Whitelisting

Edit the configuration to whitelist known-good processes and connections:

```bash
# Process whitelist (exact matching)
WHITELIST_PROCESSES=("firefox" "chrome" "docker" "systemd" "ssh")

# Network whitelist
WHITELIST_CONNECTIONS=("127.0.0.1" "8.8.8.8" "1.1.1.1")

# Path exclusions
EXCLUDE_PATHS=("/opt/tools" "/var/lib/docker" "/snap")
```

## Output and Logging

### Log Locations
```bash
# Root user
/var/log/ghost-sentinel/

# Non-root user
$HOME/.ghost-sentinel/logs/
```

### Log Files
- `sentinel.log` - General activity log
- `alerts/YYYYMMDD.log` - Daily alert files
- `latest_scan.json` - Structured scan results
- `honeypot.log` - Network connection attempts
- `ebpf_events.log` - Kernel-level events
- `quarantine/` - Quarantined files with forensic data

### JSON Output Format
```json
{
  "version": "2.3",
  "scan_start": "2025-01-15T10:30:00Z",
  "scan_end": "2025-01-15T10:32:15Z",
  "hostname": "server-01",
  "summary": {
    "total_alerts": 3,
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 0
  },
  "alerts": [
    {
      "level": 2,
      "message": "Suspicious process detected",
      "timestamp": "2025-01-15T10:31:22Z"
    }
  ]
}
```

## API Interface

### Starting API Server
```bash
sudo ./theprotector.sh api
# Access dashboard at http://127.0.0.1:8080
```

### API Endpoints
```bash
# System status
curl http://127.0.0.1:8080/api/status

# Recent alerts
curl http://127.0.0.1:8080/api/alerts

# Latest scan results
curl http://127.0.0.1:8080/api/scan

# Honeypot activity
curl http://127.0.0.1:8080/api/honeypot
```

## Integration Examples

### SIEM Integration
```bash
# Syslog output (automatic if SYSLOG_ENABLED=true)
logger -t "theprotector" -p security.alert "Alert message"

# JSON log parsing
tail -f /var/log/ghost-sentinel/latest_scan.json | jq '.alerts[]'
```

### Webhook Notifications
```bash
# Configure webhook URL in sentinel.conf
WEBHOOK_URL="https://your-siem.com/webhook"
SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
```

### Cron Scheduling
```bash
# Manual cron entry (automatic with 'install' command)
0 * * * * /path/to/theprotector.sh enhanced >/dev/null 2>&1
```

## Troubleshooting

### Common Issues

**Permission Denied**
```bash
chmod +x ./theprotector.sh
sudo ././theprotector.sh test
```

**eBPF Not Working**
```bash
# Check kernel version
uname -r  # Should be 4.9+

# Install BCC tools
sudo apt install bcc-tools  # Ubuntu
sudo dnf install bcc-tools  # Fedora
```

**Port Already in Use**
```bash
# Check what's using the port
sudo ss -tulnp | grep :8080

# Use different port
export DASHBOARD_PORT=8081
sudo ./theprotector.sh api
```

**High Resource Usage**
```bash
# Enable performance mode
sudo ./theprotector.sh performance

# Or configure limits in sentinel.conf
PERFORMANCE_MODE=true
MAX_FIND_DEPTH=1
PARALLEL_JOBS=1
```

### Debug Mode
```bash
# Enable verbose output
sudo ./theprotector.sh --verbose enhanced
```

### Reset and Cleanup
```bash
# Fix common issues
sudo ./theprotector.sh cleanup

# Reset integrity checks after updates
sudo ./theprotector.sh reset-integrity

# Recreate baseline
sudo ./theprotector.sh baseline
```

## Performance Considerations

### Resource Usage
- **CPU**: 2-5% during normal operation, 8-12% during active scanning
- **Memory**: 15-40MB resident memory
- **Disk**: 1-3MB/hour log generation
- **Network**: 500KB every 6 hours for threat intelligence updates

### Optimization Settings
```bash
# Production environments
PERFORMANCE_MODE=true
MAX_FIND_DEPTH=1
SCAN_TIMEOUT=60
PARALLEL_JOBS=1

# High-security environments
MAX_FIND_DEPTH=3
SCAN_TIMEOUT=300
ENABLE_ANTI_EVASION=true
ENABLE_EBPF=true
```

## Security Considerations

### Privilege Requirements
- Root access required for eBPF monitoring and honeypots
- Non-root operation available with limited functionality
- API server binds to localhost only by default

### Log Security
- Alert logs include integrity checksums
- Quarantined files preserve forensic metadata
- Structured logging enables SIEM integration

### Network Security
- Honeypots bind to localhost by default
- API authentication can be implemented for remote access
- Threat intelligence uses HTTPS with timeout controls

## Contributing

### Development Setup
```bash
git clone https://github.com/yourusername/theprotector.git
cd theprotector

# Run shellcheck for code quality
shellcheck theprotector.sh

# Test across environments
sudo ./theprotector.sh test
```

### Adding Detection Rules
Edit YARA rules in the `init_yara_rules()` function or add new rule files to the YARA rules directory.

### Extending Functionality
The modular design allows for easy extension:
- Add new monitoring modules in the main detection loop
- Implement additional API endpoints in the Python server
- Create new alert notification methods

## License

This project is released under the MIT License. See LICENSE file for details.

## Changelog

### v2.3
- Added eBPF kernel monitoring
- Implemented network honeypots
- Enhanced anti-evasion detection
- Added REST API and web dashboard
- Improved threat intelligence integration
- Added forensic quarantine capabilities

### v2.2
- YARA integration for malware detection
- Performance optimizations
- Container environment support

### v2.1
- Multi-environment detection
- Enhanced logging and JSON output
- Baseline comparison system

### v2.0
- Complete rewrite with modular architecture
- Advanced configuration system
- Comprehensive alert management

## Support

For issues, questions, or contributions:
- Create GitHub issues for bug reports
- Submit pull requests for improvements
- Review documentation for common solutions

## Acknowledgments

This project incorporates techniques and patterns from various open-source security tools and research papers in the host-based monitoring field.

# Setting Up Slack Alerts for TheProtector

## Create Your Slack Webhook

### Step 1: Get a Slack Account
1. Go to `slack.com` and create a free workspace
2. Name it something like "Security Alerts" 
3. Create a channel called `#security-alerts`

### Step 2: Create Webhook
1. Go to `https://api.slack.com/apps`
2. Click "Create New App" → "From scratch"
3. Name it "Security Monitor" and select your workspace
4. Click "Incoming Webhooks" → Toggle "On"
5. Click "Add New Webhook to Workspace"
6. Choose your `#security-alerts` channel
7. Copy the webhook URL (starts with `https://hooks.slack.com/services/`)

## Configure TheProtector Integration

### Step 3: Setup Monitor
```bash
# Save the script as monitor.sh
chmod +x monitor.sh

# Initialize
./monitor.sh init

# Configure
./monitor.sh config
```

### Step 4: Edit Configuration
In the config file, change these two lines:
```bash
SLACK_ENABLED=true
SLACK_WEBHOOK_URL="paste_your_webhook_url_here"
```
Save and exit.

### Step 5: Test and Install
```bash
# Test it works
./monitor.sh test

# Install monitoring
./monitor.sh install
```

Done. You'll now get security alerts in Slack automatically.

## Commands
```bash
./monitor.sh config    # Edit settings
./monitor.sh test      # Test connection
./monitor.sh status    # Check if working
./monitor.sh install   # Enable monitoring
```

That's it. The monitor checks TheProtector logs every minute and sends new alerts to Slack.

