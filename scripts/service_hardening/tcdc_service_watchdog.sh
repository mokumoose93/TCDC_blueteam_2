#!/bin/bash
# =============================================================
# TCDC SERVICE WATCHDOG
# Continuously monitors scored services and alerts on downtime.
# Auto-restarts services if they go down.
# Usage: sudo bash tcdc_service_watchdog.sh
# Leave running in a dedicated terminal throughout competition.
# =============================================================

RED='\033[0;31m'
YLW='\033[0;33m'
GRN='\033[0;32m'
BLU='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

ALERT() { echo -e "$(date '+%H:%M:%S') ${BOLD}${RED}[ALERT] $1${NC}"; }
WARN()  { echo -e "$(date '+%H:%M:%S') ${YLW}[WARN]  $1${NC}"; }
OK()    { echo -e "$(date '+%H:%M:%S') ${GRN}[OK]    $1${NC}"; }
INFO()  { echo -e "$(date '+%H:%M:%S') ${BLU}[INFO]  $1${NC}"; }

[ "$(id -u)" -ne 0 ] && echo "Must be run as root." && exit 1

LOG_FILE="/var/log/tcdc_service_watchdog.log"
INTERVAL=20   # Check every 20 seconds (TCDC ticks every 30s)

# =============================================================
# BOX DETECTION — auto-detect which scored service is on this box
# =============================================================
detect_services() {
    SERVICES_TO_WATCH=()

    # Apache/Nginx (centurytree or bonfire)
    if systemctl list-units --type=service | grep -qE 'apache2|nginx|httpd'; then
        systemctl is-active --quiet apache2 2>/dev/null && SERVICES_TO_WATCH+=("apache2")
        systemctl is-active --quiet nginx 2>/dev/null && SERVICES_TO_WATCH+=("nginx")
        systemctl is-active --quiet httpd 2>/dev/null && SERVICES_TO_WATCH+=("httpd")
    fi

    # vsftpd (aggiedrop)
    systemctl list-units --type=service | grep -q vsftpd && SERVICES_TO_WATCH+=("vsftpd")

    # SSH (reveille-remote — SSH is the scored service here)
    systemctl list-units --type=service | grep -qE 'ssh$|sshd' && SERVICES_TO_WATCH+=("sshd")

    # PostgreSQL (excel)
    systemctl list-units --type=service | grep -q postgresql && SERVICES_TO_WATCH+=("postgresql")

    # Node.js — tracked by process, not systemd
    pgrep -x node &>/dev/null && SERVICES_TO_WATCH+=("node")
    command -v pm2 &>/dev/null && SERVICES_TO_WATCH+=("pm2")
}

# =============================================================
# SERVICE CHECK FUNCTIONS
# =============================================================

check_systemd_service() {
    local svc="$1"
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

check_port() {
    local port="$1"
    ss -tulnp | grep -q ":${port} " && return 0 || return 1
}

check_http() {
    local url="$1"
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "$url" 2>/dev/null)
    [ "$code" -ge 200 ] && [ "$code" -lt 500 ] && return 0 || return 1
}

check_ftp() {
    local host="$1"
    timeout 5 bash -c "echo '' | ftp -n $host 21" &>/dev/null
    return $?
}

check_postgres() {
    sudo -u postgres psql -c "SELECT 1;" &>/dev/null
    return $?
}

check_node() {
    pgrep -x node &>/dev/null || pgrep -x nodejs &>/dev/null
    return $?
}

# =============================================================
# AUTO-RESTART FUNCTION
# =============================================================
attempt_restart() {
    local svc="$1"
    ALERT "Attempting to restart $svc..."

    case "$svc" in
        apache2|httpd)
            apache2ctl configtest 2>/dev/null && systemctl restart apache2 \
                && OK "apache2 restarted" || ALERT "apache2 restart FAILED"
            ;;
        nginx)
            nginx -t 2>/dev/null && systemctl restart nginx \
                && OK "nginx restarted" || ALERT "nginx restart FAILED"
            ;;
        vsftpd)
            systemctl restart vsftpd \
                && OK "vsftpd restarted" || ALERT "vsftpd restart FAILED"
            ;;
        sshd|ssh)
            sshd -t 2>/dev/null && systemctl restart sshd \
                && OK "sshd restarted" || ALERT "sshd restart FAILED"
            ;;
        postgresql)
            systemctl restart postgresql \
                && OK "postgresql restarted" || ALERT "postgresql restart FAILED"
            ;;
        node|pm2)
            if command -v pm2 &>/dev/null; then
                pm2 restart all && OK "PM2 apps restarted" || ALERT "PM2 restart FAILED"
            else
                WARN "Node down but no PM2 — find start command manually"
                INFO "Try: ps aux | grep node or check /etc/systemd/system/"
            fi
            ;;
    esac
}

# =============================================================
# PER-SERVICE MONITORING LOGIC
# =============================================================

# Track consecutive failures to avoid spam
declare -A FAIL_COUNT

monitor_service() {
    local svc="$1"
    local is_down=false

    case "$svc" in
        apache2|httpd)
            check_systemd_service "$svc" || is_down=true
            check_port 80 || is_down=true
            ;;
        nginx)
            check_systemd_service "nginx" || is_down=true
            check_port 80 || check_port 443 || is_down=true
            ;;
        vsftpd)
            check_systemd_service "vsftpd" || is_down=true
            check_port 21 || is_down=true
            ;;
        sshd|ssh)
            check_systemd_service "sshd" 2>/dev/null || check_systemd_service "ssh" 2>/dev/null || is_down=true
            check_port 22 || is_down=true
            ;;
        postgresql)
            check_systemd_service "postgresql" || is_down=true
            check_port 5432 || is_down=true
            check_postgres || is_down=true
            ;;
        node)
            check_node || is_down=true
            ;;
        pm2)
            command -v pm2 &>/dev/null && pm2 list &>/dev/null || is_down=true
            ;;
    esac

    if $is_down; then
        FAIL_COUNT[$svc]=$(( ${FAIL_COUNT[$svc]:-0} + 1 ))
        ALERT "SERVICE DOWN: $svc (failure #${FAIL_COUNT[$svc]})"
        echo "[$(date)] ALERT: $svc is DOWN (failure #${FAIL_COUNT[$svc]})" >> "$LOG_FILE"

        # Auto-restart on first failure
        if [ "${FAIL_COUNT[$svc]}" -eq 1 ]; then
            attempt_restart "$svc"
        elif [ "${FAIL_COUNT[$svc]}" -ge 3 ]; then
            ALERT "$svc has been down for 3+ checks — manual intervention needed"
        fi
        return 1
    else
        # Reset fail count on recovery
        if [ "${FAIL_COUNT[$svc]:-0}" -gt 0 ]; then
            OK "$svc RECOVERED after ${FAIL_COUNT[$svc]} failure(s)"
            echo "[$(date)] OK: $svc recovered" >> "$LOG_FILE"
        fi
        FAIL_COUNT[$svc]=0
        return 0
    fi
}

# =============================================================
# ADDITIONAL CHECKS
# =============================================================

check_suspicious_new_listeners() {
    local snap_file="/tmp/.tcdc_port_snap"
    local current
    current=$(ss -tulnp | grep LISTEN | sort)

    if [ ! -f "$snap_file" ]; then
        echo "$current" > "$snap_file"
        return
    fi

    local new_ports
    new_ports=$(diff "$snap_file" <(echo "$current") | grep '^>' | grep -v '^---')
    if [ -n "$new_ports" ]; then
        while read -r line; do
            WARN "NEW LISTENER DETECTED: $line"
            echo "[$(date)] WARN: New listener: $line" >> "$LOG_FILE"
        done <<< "$new_ports"
    fi
    echo "$current" > "$snap_file"
}

check_disk_space() {
    local usage
    usage=$(df / | awk 'NR==2 {print $5}' | tr -d '%')
    if [ "$usage" -gt 90 ]; then
        ALERT "Disk usage critical: ${usage}% — logs or uploads may be filling disk"
    elif [ "$usage" -gt 75 ]; then
        WARN "Disk usage high: ${usage}%"
    fi
}

check_load() {
    local load
    load=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | tr -d ',')
    local cores
    cores=$(nproc)
    local load_int
    load_int=$(echo "$load" | cut -d. -f1)
    if [ "$load_int" -gt "$((cores * 2))" ]; then
        WARN "High system load: $load (${cores} cores) — possible DoS or crypto miner"
    fi
}

# =============================================================
# MAIN LOOP
# =============================================================
echo -e "${BOLD}TCDC SERVICE WATCHDOG — $(hostname)${NC}"
echo -e "Log: $LOG_FILE | Interval: ${INTERVAL}s"
echo ""

detect_services

if [ ${#SERVICES_TO_WATCH[@]} -eq 0 ]; then
    WARN "No scored services detected on this box."
    INFO "Running in generic monitoring mode..."
    SERVICES_TO_WATCH=("apache2" "nginx" "vsftpd" "sshd" "postgresql")
fi

INFO "Monitoring: ${SERVICES_TO_WATCH[*]}"
echo ""

TICK=0
while true; do
    TICK=$((TICK + 1))
    all_ok=true

    for svc in "${SERVICES_TO_WATCH[@]}"; do
        monitor_service "$svc" || all_ok=false
    done

    # Additional checks every 5 ticks (~100s)
    if [ $((TICK % 5)) -eq 0 ]; then
        check_suspicious_new_listeners
        check_disk_space
        check_load
    fi

    # Heartbeat every 15 ticks (~5 min)
    if [ $((TICK % 15)) -eq 0 ]; then
        if $all_ok; then
            OK "All services nominal — tick $TICK — $(date '+%H:%M:%S')"
        fi
    fi

    sleep "$INTERVAL"
done
