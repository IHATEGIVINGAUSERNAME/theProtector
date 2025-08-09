#!/usr/bin/env bash

# TheProtector Slack Integration - Standalone Version
# Monitors TheProtector logs and sends alerts to Slack
# Opttional use - not required - I won't use it at all 

set -euo pipefail

# === CONFIGURATION ===
SLACK_CONFIG_FILE="${SLACK_CONFIG_FILE:-$HOME/.theprotector/slack.conf}"
SLACK_STATE_DIR="${SLACK_STATE_DIR:-$HOME/.theprotector/slack}"
SLACK_QUEUE_DIR="$SLACK_STATE_DIR/queue"
SLACK_RATE_LIMIT_FILE="$SLACK_STATE_DIR/rate_limit"

# TheProtector paths (auto-detect or configure)
THEPROTECTOR_SCRIPT_DIR="${THEPROTECTOR_SCRIPT_DIR:-$(dirname "$0")}"
THEPROTECTOR_LOG_DIR="${THEPROTECTOR_LOG_DIR:-/var/log/ghost-sentinel}"
THEPROTECTOR_ALERTS_DIR="${THEPROTECTOR_ALERTS_DIR:-$THEPROTECTOR_LOG_DIR/alerts}"
THEPROTECTOR_JSON_FILE="${THEPROTECTOR_JSON_FILE:-$THEPROTECTOR_LOG_DIR/latest_scan.json}"

# Default configuration
SLACK_ENABLED="${SLACK_ENABLED:-false}"
SLACK_WEBHOOK_URL="${SLACK_WEBHOOK_URL:-}"
SLACK_ALERT_SEVERITIES="${SLACK_ALERT_SEVERITIES:-critical high medium}"
SLACK_RATE_LIMIT_HOUR="${SLACK_RATE_LIMIT_HOUR:-50}"
SLACK_RATE_LIMIT_BURST="${SLACK_RATE_LIMIT_BURST:-10}"
SLACK_REPORTS_ENABLED="${SLACK_REPORTS_ENABLED:-true}"
SLACK_DAILY_REPORT_TIME="${SLACK_DAILY_REPORT_TIME:-08:00}"
SLACK_WEEKLY_REPORT_DAY="${SLACK_WEEKLY_REPORT_DAY:-monday}"

# Monitoring settings
MONITOR_INTERVAL="${MONITOR_INTERVAL:-60}"  # Check for new alerts every 60 seconds
LAST_PROCESSED_FILE="$SLACK_STATE_DIR/last_processed"

# Colors and emojis
declare -A SLACK_COLORS
SLACK_COLORS[critical]="danger"
SLACK_COLORS[high]="warning"
SLACK_COLORS[medium]="#36a64f"
SLACK_COLORS[low]="#439FE0"

declare -A SLACK_EMOJIS
SLACK_EMOJIS[critical]="4"
SLACK_EMOJIS[high]="3"
SLACK_EMOJIS[medium]="2"
SLACK_EMOJIS[low]="1"

# === UTILITY FUNCTIONS ===

log_info() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] INFO: $1"
}

log_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1" >&2
}

# Check dependencies
check_dependencies() {
    local missing_deps=()
    
    if ! command -v curl >/dev/null 2>&1; then
        missing_deps+=("curl")
    fi
    
    if [ ${#missing_deps[@]} -gt 0 ]; then
        log_error "Missing required dependencies: ${missing_deps[*]}"
        echo "Install with your package manager:"
        echo "  Ubuntu/Debian: sudo apt-get install curl jq"
        echo "  RHEL/Fedora: sudo dnf install curl jq"
        echo "  SUSE: sudo zypper install curl jq"
        echo "  Alpine: sudo apk add curl jq"
        echo "  Arch: sudo pacman -S curl jq"
        return 1
    fi
    
    return 0
}

# Initialize directories and config
init_slack() {
    mkdir -p "$SLACK_STATE_DIR" "$SLACK_QUEUE_DIR"
    
    if [ ! -f "$SLACK_CONFIG_FILE" ]; then
        create_default_config
    fi
    
    load_config
    touch "$SLACK_RATE_LIMIT_FILE" "$LAST_PROCESSED_FILE"
}

# Create default configuration
create_default_config() {
    mkdir -p "$(dirname "$SLACK_CONFIG_FILE")"
    
    cat > "$SLACK_CONFIG_FILE" << EOF
# TheProtector Slack Integration - Standalone Configuration

# Basic Settings
SLACK_ENABLED=false
SLACK_WEBHOOK_URL=""  # Your Slack webhook URL

# Alert Configuration
SLACK_ALERT_SEVERITIES="critical high medium"  # Space-separated list

# Rate Limiting
SLACK_RATE_LIMIT_HOUR=50    # Max messages per hour
SLACK_RATE_LIMIT_BURST=10   # Max burst messages

# Reports
SLACK_REPORTS_ENABLED=true
SLACK_DAILY_REPORT_TIME="08:00"     # UTC time HH:MM
SLACK_WEEKLY_REPORT_DAY="monday"    # Day of week

# Monitoring (Standalone Mode)
MONITOR_INTERVAL=60                 # Check for new alerts every N seconds
THEPROTECTOR_LOG_DIR="/var/log/ghost-sentinel"
THEPROTECTOR_ALERTS_DIR="\$THEPROTECTOR_LOG_DIR/alerts"

# Advanced Options
SLACK_DEBUG=false
EOF

    log_info "Created configuration file: $SLACK_CONFIG_FILE"
    echo ""
    echo "IMPORTANT: Edit the configuration file and set your Slack webhook URL:"
    echo "  $0 config"
    echo ""
    echo "Then test the integration:"
    echo "  $0 test"
}

# Load configuration
load_config() {
    if [ -f "$SLACK_CONFIG_FILE" ]; then
        set +u
        source "$SLACK_CONFIG_FILE"
        set -u
        
        if [ "$SLACK_ENABLED" = "true" ] && [ -z "$SLACK_WEBHOOK_URL" ]; then
            log_error "SLACK_ENABLED=true but SLACK_WEBHOOK_URL is empty"
            log_error "Please configure your webhook URL in $SLACK_CONFIG_FILE"
            SLACK_ENABLED=false
        fi
    else
        log_error "Configuration file not found: $SLACK_CONFIG_FILE"
        return 1
    fi
}

# === RATE LIMITING ===

can_send_message() {
    local now=$(date +%s)
    local hour_ago=$((now - 3600))
    
   
    local temp_file=$(mktemp)
    awk -v hour_ago="$hour_ago" '$1 > hour_ago' "$SLACK_RATE_LIMIT_FILE" > "$temp_file" 2>/dev/null || true
    mv "$temp_file" "$SLACK_RATE_LIMIT_FILE"
    
    local count=$(wc -l < "$SLACK_RATE_LIMIT_FILE" 2>/dev/null || echo 0)
    
    # Check hourly limit
    if [ "$count" -ge "$SLACK_RATE_LIMIT_HOUR" ]; then
        return 1
    fi
    
    # Check ing the burst limit again....stupid as hell
    local five_min_ago=$((now - 300))
    local burst_count=$(awk -v five_min_ago="$five_min_ago" '$1 > five_min_ago' "$SLACK_RATE_LIMIT_FILE" | wc -l)
    
    if [ "$burst_count" -ge "$SLACK_RATE_LIMIT_BURST" ]; then
        return 1
    fi
    
    return 0
}

record_message() {
    echo "$(date +%s)" >> "$SLACK_RATE_LIMIT_FILE"
}

# === MESSAGE FORMATTING ===

format_alert() {
    local severity="$1"
    local message="$2"
    local timestamp="${3:-$(date -Iseconds)}"
    local hostname="${4:-$(hostname)}"
    
    local emoji="${SLACK_EMOJIS[$severity]:-🔔}"
    local color="${SLACK_COLORS[$severity]:-good}"
    local severity_upper=$(echo "$severity" | tr '[:lower:]' '[:upper:]')
    

    message=$(echo "$message" | sed 's/[<>&"]/·/g' | head -c 1000)
    
    if command -v jq >/dev/null 2>&1; then
        jq -n \
            --arg emoji "$emoji" \
            --arg severity_upper "$severity_upper" \
            --arg message "$message" \
            --arg hostname "$hostname" \
            --arg timestamp "$timestamp" \
            --arg color "$color" \
            '{
                "attachments": [
                    {
                        "color": $color,
                        "title": ($emoji + " TheProtector " + $severity_upper + " Alert"),
                        "text": $message,
                        "fields": [
                            {
                                "title": "Hostname",
                                "value": $hostname,
                                "short": true
                            },
                            {
                                "title": "Timestamp",
                                "value": $timestamp,
                                "short": true
                            }
                        ],
                        "footer": "TheProtector Slack Integration",
                        "ts": (now | floor)
                    }
                ]
            }'
    else
        local ts=$(date +%s)
        echo "{\"attachments\":[{\"color\":\"$color\",\"title\":\"$emoji TheProtector $severity_upper Alert\",\"text\":\"$message\",\"fields\":[{\"title\":\"Hostname\",\"value\":\"$hostname\",\"short\":true},{\"title\":\"Timestamp\",\"value\":\"$timestamp\",\"short\":true}],\"footer\":\"TheProtector Slack Integration\",\"ts\":$ts}]}"
    fi
}

# === MESSAGE SENDING ===

send_to_slack() {
    local payload="$1"
    local max_retries=3
    local delay=5
    
    for ((i=1; i<=max_retries; i++)); do
        local response=$(curl -s -w "%{http_code}" \
            -X POST \
            -H "Content-type: application/json" \
            --data "$payload" \
            --max-time 30 \
            "$SLACK_WEBHOOK_URL" 2>/dev/null)
        
        local http_code="${response: -3}"
        
        case "$http_code" in
            200)
                record_message
                return 0
                ;;
            429)
                log_info "Rate limited by Slack, waiting ${delay}s..."
                sleep $delay
                delay=$((delay * 2))
                ;;
            4[0-9][0-9])
                log_error "Client error ($http_code): ${response%???}"
                return 1
                ;;
            5[0-9][0-9])
                log_info "Server error ($http_code), retrying..."
                sleep $delay
                ;;
        esac
    done
    
    log_error "Failed to send message after $max_retries attempts"
    return 1
}

send_alert() {
    local severity="$1"
    local message="$2"
    
    if [ "$SLACK_ENABLED" != "true" ]; then
        return 0
    fi
    
    # Check if severity should be sent
    if ! echo "$SLACK_ALERT_SEVERITIES" | grep -q "\b$severity\b"; then
        [ "${SLACK_DEBUG:-false}" = "true" ] && log_info "Skipping severity: $severity"
        return 0
    fi
    
    local payload=$(format_alert "$severity" "$message")
    
    if can_send_message; then
        send_to_slack "$payload"
    else
        log_info "Rate limited - alert dropped: $severity: $message"
    fi
}

# === LOG MONITORING ===

# Convert TheProtector alert level to severity
map_alert_level() {
    case "$1" in
        1) echo "critical" ;;
        2) echo "high" ;;
        3) echo "medium" ;;
        4) echo "low" ;;
        *) echo "unknown" ;;
    esac
}

# Monitor TheProtector alert files for new alerts
monitor_alerts() {
    local last_processed=$(cat "$LAST_PROCESSED_FILE" 2>/dev/null || echo 0)
    local current_time=$(date +%s)
    local new_alerts=0
    
    if [ ! -d "$THEPROTECTOR_ALERTS_DIR" ]; then
        log_info "TheProtector alerts directory not found: $THEPROTECTOR_ALERTS_DIR"
        log_info "Make sure TheProtector has run at least once"
        return 0
    fi
    
    # Process alert files
    for alert_file in "$THEPROTECTOR_ALERTS_DIR"/*.log; do
        [ ! -f "$alert_file" ] && continue
        
        local file_mod_time=$(stat -c %Y "$alert_file" 2>/dev/null || echo 0)
        
        # Only process files modified since last check
        if [ "$file_mod_time" -gt "$last_processed" ]; then
            while IFS= read -r line; do
                if [[ "$line" =~ ^\[([0-9-]+\ [0-9:]+)\]\ \[LEVEL:([0-9])\]\ (.+)$ ]]; then
                    local timestamp="${BASH_REMATCH[1]}"
                    local level="${BASH_REMATCH[2]}"
                    local message="${BASH_REMATCH[3]}"
                    local severity=$(map_alert_level "$level")
                    
                    # Convert timestamp to epoch for comparison
                    local alert_time=$(date -d "$timestamp" +%s 2>/dev/null || echo 0)
                    
                    # Only send alerts newer than last processed time
                    if [ "$alert_time" -gt "$last_processed" ]; then
                        log_info "Sending $severity alert: $message"
                        send_alert "$severity" "$message"
                        new_alerts=$((new_alerts + 1))
                    fi
                fi
            done < "$alert_file"
        fi
    done
    
    
    echo "$current_time" > "$LAST_PROCESSED_FILE"
    
    if [ $new_alerts -gt 0 ]; then
        log_info "Processed $new_alerts new alerts"
    fi
}

# === REPORTING ===

generate_report_data() {
    local report_type="$1"
    local today=$(date +%Y%m%d)
    local start_date=""
    
    case "$report_type" in
        "daily") start_date="$today" ;;
        "weekly") start_date=$(date -d "7 days ago" +%Y%m%d) ;;
    esac
    
    local critical=0 high=0 medium=0 low=0
    
    if [ -d "$THEPROTECTOR_ALERTS_DIR" ]; then
        for alert_file in "$THEPROTECTOR_ALERTS_DIR"/*.log; do
            [ ! -f "$alert_file" ] && continue
            
            local file_date=$(basename "$alert_file" .log)
            if [[ "$file_date" -ge "$start_date" ]]; then
                critical=$((critical + $(grep -c "\[LEVEL:1\]" "$alert_file" 2>/dev/null || echo 0)))
                high=$((high + $(grep -c "\[LEVEL:2\]" "$alert_file" 2>/dev/null || echo 0)))
                medium=$((medium + $(grep -c "\[LEVEL:3\]" "$alert_file" 2>/dev/null || echo 0)))
                low=$((low + $(grep -c "\[LEVEL:4\]" "$alert_file" 2>/dev/null || echo 0)))
            fi
        done
    fi
    
    local total=$((critical + high + medium + low))
    echo "{\"critical\":$critical,\"high\":$high,\"medium\":$medium,\"low\":$low,\"total\":$total}"
}

send_report() {
    local report_type="$1"
    local report_data=$(generate_report_data "$report_type")
    
    # Parse data
    local critical=0 high=0 medium=0 low=0 total=0
    if command -v jq >/dev/null 2>&1; then
        critical=$(echo "$report_data" | jq -r '.critical')
        high=$(echo "$report_data" | jq -r '.high')
        medium=$(echo "$report_data" | jq -r '.medium')
        low=$(echo "$report_data" | jq -r '.low')
        total=$(echo "$report_data" | jq -r '.total')
    else
        critical=$(echo "$report_data" | grep -o '"critical":[0-9]*' | cut -d: -f2)
        high=$(echo "$report_data" | grep -o '"high":[0-9]*' | cut -d: -f2)
        medium=$(echo "$report_data" | grep -o '"medium":[0-9]*' | cut -d: -f2)
        low=$(echo "$report_data" | grep -o '"low":[0-9]*' | cut -d: -f2)
        total=$(echo "$report_data" | grep -o '"total":[0-9]*' | cut -d: -f2)
    fi
    
    local title=" TheProtector ${report_type^} Security Report - $(date '+%b %d, %Y')"
    local text="*Threat Summary (Last ${report_type^}):*
•  Critical: $critical threats
•  High: $high threats
•  Medium: $medium threats
•  Low: $low threats

*Total Threats:* $total
*System Status:*  Operational
*Protection Active:* TheProtector monitoring"
    
    local payload=""
    if command -v jq >/dev/null 2>&1; then
        payload=$(jq -n \
            --arg title "$title" \
            --arg text "$text" \
            '{
                "attachments": [
                    {
                        "color": "good",
                        "title": $title,
                        "text": $text,
                        "footer": "TheProtector Slack Integration",
                        "ts": (now | floor)
                    }
                ]
            }')
    else
        local ts=$(date +%s)
        payload="{\"attachments\":[{\"color\":\"good\",\"title\":\"$title\",\"text\":\"$text\",\"footer\":\"TheProtector Slack Integration\",\"ts\":$ts}]}"
    fi
    
    if [ "$SLACK_REPORTS_ENABLED" = "true" ]; then
        send_to_slack "$payload"
        log_info "${report_type^} report sent to Slack"
    fi
}

# === CRON INSTALLATION ===

install_cron() {
    local script_path="$(readlink -f "$0")"
    
    # Parse time for cron
    local hour=$(echo "$SLACK_DAILY_REPORT_TIME" | cut -d: -f1)
    local minute=$(echo "$SLACK_DAILY_REPORT_TIME" | cut -d: -f2)
    
    # Convert day to number
    local day_num=1  # Default Monday
    case "${SLACK_WEEKLY_REPORT_DAY,,}" in
        sunday) day_num=0 ;;
        monday) day_num=1 ;;
        tuesday) day_num=2 ;;
        wednesday) day_num=3 ;;
        thursday) day_num=4 ;;
        friday) day_num=5 ;;
        saturday) day_num=6 ;;
    esac
    
    # Create cron entries
    local monitor_cron="* * * * * $script_path monitor >/dev/null 2>&1"
    local daily_cron="$minute $hour * * * $script_path daily-report >/dev/null 2>&1"
    local weekly_cron="$minute $hour * * $day_num $script_path weekly-report >/dev/null 2>&1"
    
    # Install cron jobs
    (crontab -l 2>/dev/null | grep -v "theprotector.*slack"; echo "$monitor_cron"; echo "$daily_cron"; echo "$weekly_cron") | crontab -
    
    log_info "Cron jobs installed:"
    log_info "  Alert monitoring: Every minute"
    log_info "  Daily reports: $SLACK_DAILY_REPORT_TIME UTC"
    log_info "  Weekly reports: $SLACK_WEEKLY_REPORT_DAY at $SLACK_DAILY_REPORT_TIME UTC"
}

# === MAIN COMMANDS ===

case "${1:-help}" in
    "init")
        check_dependencies && init_slack
        echo ""
        echo "Next steps:"
        echo "1. Configure Slack webhook: $0 config"
        echo "2. Test integration: $0 test"
        echo "3. Install monitoring: $0 install"
        ;;
    
    "config")
        init_slack
        ${EDITOR:-nano} "$SLACK_CONFIG_FILE"
        ;;
    
    "test")
        check_dependencies || exit 1
        init_slack
        
        if [ "$SLACK_ENABLED" != "true" ]; then
            echo " Slack integration disabled in config"
            exit 1
        fi
        
        if [ -z "$SLACK_WEBHOOK_URL" ]; then
            echo " Slack webhook URL not configured"
            exit 1
        fi
        
        echo " Configuration looks good"
        echo "Sending test message..."
        
        if send_alert "medium" "TheProtector Slack integration test - $(date)"; then
            echo " Test message sent successfully!"
        else
            echo " Failed to send test message"
            exit 1
        fi
        ;;
    
    "monitor")
        init_slack
        monitor_alerts
        ;;
    
    "daemon")
        log_info "Starting TheProtector Slack monitoring daemon..."
        init_slack
        
        while true; do
            monitor_alerts
            sleep "$MONITOR_INTERVAL"
        done
        ;;
    
    "send")
        severity="${2:-medium}"
        message="${3:-Test alert from TheProtector}"
        init_slack
        send_alert "$severity" "$message"
        ;;
    
    "daily-report")
        init_slack
        send_report "daily"
        ;;
    
    "weekly-report")
        init_slack
        send_report "weekly"
        ;;
    
    "install")
        init_slack
        install_cron
        echo ""
        echo "TheProtector Slack integration installed!"
        echo ""
        echo "The integration will now:"
        echo "• Monitor TheProtector alerts every minute"
        echo "• Send alerts to Slack based on your configuration"
        echo "• Send daily and weekly reports"
        echo ""
        echo "Check status with: $0 status"
        ;;
    
    "status")
        init_slack
        echo "TheProtector Slack Integration Status"
        echo "===================================="
        echo "Enabled: $SLACK_ENABLED"
        echo "Config: $SLACK_CONFIG_FILE"
        echo "Webhook: ${SLACK_WEBHOOK_URL:0:50}..."
        echo "Alert severities: $SLACK_ALERT_SEVERITIES"
        echo ""
        echo "TheProtector Integration:"
        echo "Log directory: $THEPROTECTOR_LOG_DIR"
        echo "Alerts directory: $THEPROTECTOR_ALERTS_DIR"
        if [ -d "$THEPROTECTOR_ALERTS_DIR" ]; then
            echo "Alert files: $(ls -1 "$THEPROTECTOR_ALERTS_DIR"/*.log 2>/dev/null | wc -l)"
        else
            echo "Alert files: Directory not found"
        fi
        echo ""
        echo "Monitoring:"
        echo "Last processed: $(date -d @$(cat "$LAST_PROCESSED_FILE" 2>/dev/null || echo 0) 2>/dev/null || echo 'Never')"
        echo "Rate limit: $(wc -l < "$SLACK_RATE_LIMIT_FILE" 2>/dev/null || echo 0)/$SLACK_RATE_LIMIT_HOUR this hour"
        ;;
    
    "uninstall")
        log_info "Removing cron jobs..."
        crontab -l 2>/dev/null | grep -v "theprotector.*slack" | crontab -
        echo "Cron jobs removed"
        echo ""
        echo "Configuration and logs preserved in: $SLACK_STATE_DIR"
        echo "To completely remove: rm -rf $SLACK_STATE_DIR ~/.theprotector"
        ;;
    
    "help"|*)
        echo "TheProtector Slack Integration - Standalone Mode"
        echo "================================================"
        echo ""
        echo "This script monitors TheProtector logs and sends alerts to Slack"
        echo "without requiring any modifications to theprotector.sh"
        echo ""
        echo "Usage: $0 <command> [options]"
        echo ""
        echo "Setup Commands:"
        echo "  init                 Initialize and create configuration"
        echo "  config               Edit configuration file"
        echo "  test                 Test Slack integration"
        echo "  install              Install cron jobs for monitoring"
        echo "  uninstall            Remove cron jobs"
        echo ""
        echo "Manual Commands:"
        echo "  monitor              Check for new alerts once"
        echo "  daemon               Run continuous monitoring (foreground)"
        echo "  send <sev> <msg>     Send test alert"
        echo "  daily-report         Send daily report now"
        echo "  weekly-report        Send weekly report now"
        echo "  status               Show integration status"
        echo ""
        echo "Examples:"
        echo "  $0 init                          # Initial setup"
        echo "  $0 test                          # Test configuration"
        echo "  $0 install                       # Install monitoring"
        echo "  $0 send critical 'Server down!'  # Send test alert"
        echo ""
        echo "After installation, alerts will be sent automatically when"
        echo "TheProtector detects threats. No changes to theprotector.sh needed!"
        ;;
esac
