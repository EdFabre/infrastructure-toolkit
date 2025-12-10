#!/bin/bash
#
# USB Device Monitor for Proxmox VE
# Monitors USB passthrough devices and auto-fixes when issues detected
#
# Usage:
#   ./usb-monitor.sh [--check|--fix|--status] [VM_ID]
#
# Install as cron job:
#   */5 * * * * /root/usb-monitor.sh --fix 301 >> /var/log/usb-monitor.log 2>&1
#

set -euo pipefail

# Configuration
VM_ID="${2:-301}"
LOG_FILE="/var/log/usb-monitor.log"

# Logitech Unifying Receiver config
LOGITECH_VENDOR_ID="046d"
LOGITECH_PRODUCT_ID="c52b"
LOGITECH_HOST_BUS=3
LOGITECH_HOST_PORT="4.1.1.3.3.3"
LOGITECH_DEVICE_ID="usb0"

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

log_color() {
    local color=$1
    local msg=$2
    if [ -t 1 ]; then
        echo -e "${color}${msg}${NC}"
    else
        echo "$msg"
    fi
}

# Send QMP command to VM
qmp_command() {
    local vm_id=$1
    local cmd=$2
    local args="${3:-}"

    local socket="/var/run/qemu-server/${vm_id}.qmp"

    if [ -n "$args" ]; then
        local payload="{\"execute\": \"qmp_capabilities\"}\n{\"execute\": \"${cmd}\", \"arguments\": ${args}}"
    else
        local payload="{\"execute\": \"qmp_capabilities\"}\n{\"execute\": \"${cmd}\"}"
    fi

    echo -e "$payload" | socat - UNIX-CONNECT:${socket} 2>/dev/null
}

# Get USB device info via HMP command
get_usb_info() {
    local vm_id=$1
    qmp_command "$vm_id" "human-monitor-command" '{"command-line": "info usb"}' | \
        grep -o '"return": "[^"]*"' | \
        sed 's/"return": "//;s/"$//' | \
        sed 's/\\r\\n/\n/g'
}

# Check if Logitech receiver is healthy
check_logitech_health() {
    local vm_id=$1
    local usb_info

    usb_info=$(get_usb_info "$vm_id")

    # Look for usb0 device
    local usb0_line
    usb0_line=$(echo "$usb_info" | grep "ID: ${LOGITECH_DEVICE_ID}" || true)

    if [ -z "$usb0_line" ]; then
        echo "MISSING"
        return 1
    fi

    # Check speed - should be 12 Mb/s, not 1.5 Mb/s
    if echo "$usb0_line" | grep -q "1.5 Mb/s"; then
        echo "SLOW"
        return 1
    fi

    # Check product name - should be "USB Receiver", not "USB Host Device"
    if echo "$usb0_line" | grep -q "USB Host Device"; then
        echo "NOT_ENUMERATED"
        return 1
    fi

    if echo "$usb0_line" | grep -q "12 Mb/s"; then
        echo "HEALTHY"
        return 0
    fi

    echo "UNKNOWN"
    return 1
}

# Reset USB device using hostbus/hostport method
reset_usb_device() {
    local vm_id=$1
    local device_id=$2

    log "Removing device ${device_id}..."
    qmp_command "$vm_id" "device_del" "{\"id\": \"${device_id}\"}" > /dev/null 2>&1 || true

    sleep 1

    log "Unbinding USB from host..."
    echo "${LOGITECH_HOST_PORT}" > /sys/bus/usb/drivers/usb/unbind 2>/dev/null || true

    sleep 1

    log "Rebinding USB to host..."
    echo "${LOGITECH_HOST_PORT}" > /sys/bus/usb/drivers/usb/bind 2>/dev/null || true

    sleep 2

    log "Re-adding device ${device_id} using hostbus/hostport..."
    local add_args="{\"driver\": \"usb-host\", \"id\": \"${device_id}\", \"bus\": \"xhci.0\", \"port\": \"1\", \"hostbus\": ${LOGITECH_HOST_BUS}, \"hostport\": \"${LOGITECH_HOST_PORT}\"}"

    local result
    result=$(qmp_command "$vm_id" "device_add" "$add_args")

    if echo "$result" | grep -q '"error"'; then
        log "ERROR: Failed to add device"
        echo "$result"
        return 1
    fi

    log "Device ${device_id} reset complete"
    return 0
}

# Show current USB status
show_status() {
    local vm_id=$1

    log_color "$CYAN" "USB Status for VM ${vm_id}"
    echo ""

    local usb_info
    usb_info=$(get_usb_info "$vm_id")

    echo "$usb_info" | while read -r line; do
        if [ -n "$line" ]; then
            if echo "$line" | grep -q "1.5 Mb/s"; then
                log_color "$RED" "  ✗ $line"
            elif echo "$line" | grep -q "USB Host Device"; then
                log_color "$YELLOW" "  ⚠ $line"
            else
                log_color "$GREEN" "  ✓ $line"
            fi
        fi
    done

    echo ""

    local health
    health=$(check_logitech_health "$vm_id")

    case "$health" in
        HEALTHY)
            log_color "$GREEN" "Logitech Receiver: HEALTHY"
            ;;
        SLOW)
            log_color "$RED" "Logitech Receiver: UNHEALTHY (wrong speed - 1.5 Mb/s instead of 12 Mb/s)"
            ;;
        NOT_ENUMERATED)
            log_color "$RED" "Logitech Receiver: UNHEALTHY (not properly enumerated)"
            ;;
        MISSING)
            log_color "$RED" "Logitech Receiver: MISSING"
            ;;
        *)
            log_color "$YELLOW" "Logitech Receiver: UNKNOWN ($health)"
            ;;
    esac
}

# Main check function
do_check() {
    local vm_id=$1

    if ! qm status "$vm_id" > /dev/null 2>&1; then
        log "ERROR: VM ${vm_id} not found or not running"
        exit 1
    fi

    local health
    health=$(check_logitech_health "$vm_id")

    if [ "$health" = "HEALTHY" ]; then
        log "USB health check passed for VM ${vm_id}"
        exit 0
    else
        log "USB health check FAILED for VM ${vm_id}: $health"
        exit 1
    fi
}

# Main fix function
do_fix() {
    local vm_id=$1

    if ! qm status "$vm_id" > /dev/null 2>&1; then
        log "ERROR: VM ${vm_id} not found or not running"
        exit 1
    fi

    local health
    health=$(check_logitech_health "$vm_id")

    if [ "$health" = "HEALTHY" ]; then
        log "USB devices healthy, no action needed"
        exit 0
    fi

    log "USB issue detected: $health - attempting fix..."

    if reset_usb_device "$vm_id" "${LOGITECH_DEVICE_ID}"; then
        sleep 2

        # Verify fix
        health=$(check_logitech_health "$vm_id")

        if [ "$health" = "HEALTHY" ]; then
            log "✓ USB device fixed successfully!"

            # Optional: Send notification
            # curl -X POST "your-notification-url" -d "USB device fixed on VM ${vm_id}"

            exit 0
        else
            log "✗ Fix attempted but device still unhealthy: $health"
            exit 1
        fi
    else
        log "✗ Failed to reset USB device"
        exit 1
    fi
}

# Help
show_help() {
    echo "USB Device Monitor for Proxmox VE"
    echo ""
    echo "Usage: $0 [--check|--fix|--status] [VM_ID]"
    echo ""
    echo "Commands:"
    echo "  --status  Show current USB device status (default)"
    echo "  --check   Check USB health (exit 0 if healthy, 1 if not)"
    echo "  --fix     Check and auto-fix if unhealthy"
    echo ""
    echo "Options:"
    echo "  VM_ID     VM ID to check (default: 301)"
    echo ""
    echo "Examples:"
    echo "  $0 --status 301       # Show USB status for VM 301"
    echo "  $0 --check 301        # Check health (for monitoring)"
    echo "  $0 --fix 301          # Auto-fix if broken"
    echo ""
    echo "Cron example (check every 5 minutes):"
    echo "  */5 * * * * /root/usb-monitor.sh --fix 301 >> /var/log/usb-monitor.log 2>&1"
}

# Main
case "${1:-}" in
    --check)
        do_check "$VM_ID"
        ;;
    --fix)
        do_fix "$VM_ID"
        ;;
    --status)
        show_status "$VM_ID"
        ;;
    --help|-h)
        show_help
        ;;
    *)
        if [ -n "${1:-}" ] && [[ "${1:-}" =~ ^[0-9]+$ ]]; then
            # If first arg is a number, treat as VM_ID
            VM_ID="$1"
            show_status "$VM_ID"
        else
            show_status "$VM_ID"
        fi
        ;;
esac
