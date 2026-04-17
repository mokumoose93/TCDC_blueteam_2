#!/bin/bash
# =============================================================
# TCDC IAM WATCHDOG
# Runs continuously during competition, alerting on suspicious
# IAM changes in real time (new users, sudo changes, new keys,
# active sessions from unexpected sources).
# Usage: sudo bash tcdc_iam_watchdog.sh
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

if [ "$(id -u)" -ne 0 ]; then
    echo "Must be run as root."
    exit 1
fi

# Snapshot directory
SNAP_DIR="/tmp/.tcdc_watchdog"
mkdir -p "$SNAP_DIR"
LOG_FILE="/var/log/tcdc_watchdog.log"

# Known TCDC users
KNOWN_USERS="root alice bob craig chad trudy mallory mike yves judy sybil walter wendy checker blackteam"

# Interval in seconds between checks
INTERVAL=15

# -------------------------------------------------------------
# INITIALIZE SNAPSHOTS
# -------------------------------------------------------------
init_snapshots() {
    INFO "Initializing baseline snapshots..."

    # User list snapshot
    cut -d: -f1,3,7 /etc/passwd | sort > "$SNAP_DIR/passwd.snap"

    # Shadow file hash snapshot (detect password changes)
    md5sum /etc/shadow > "$SNAP_DIR/shadow.snap"

    # Sudoers snapshot
    md5sum /etc/sudoers > "$SNAP_DIR/sudoers.snap"
    find /etc/sudoers.d -type f 2>/dev/null -exec md5sum {} \; | sort > "$SNAP_DIR/sudoersd.snap"

    # SSH authorized_keys snapshot
    find / -name "authorized_keys" -exec md5sum {} \; 2>/dev/null | sort > "$SNAP_DIR/keys.snap"

    # Active sessions snapshot
    who | awk '{print $1,$2,$5}' | sort > "$SNAP_DIR/sessions.snap"

    # Listening ports snapshot
    ss -tulnp | sort > "$SNAP_DIR/ports.snap"

    OK "Baseline snapshots taken"
    INFO "Monitoring every ${INTERVAL}s — press Ctrl+C to stop"
    echo ""
}

# -------------------------------------------------------------
# CHECK FUNCTIONS
# -------------------------------------------------------------

check_new_users() {
    current=$(cut -d: -f1,3,7 /etc/passwd | sort)
    previous=$(cat "$SNAP_DIR/passwd.snap")

    # New users added
    new_users=$(diff <(echo "$previous") <(echo "$current") | grep '^>' | sed 's/^> //')
    while read -r entry; do
        [ -z "$entry" ] && continue
        username=$(echo "$entry" | cut -d: -f1)
        uid=$(echo "$entry" | cut -d: -f2)
        shell=$(echo "$entry" | cut -d: -f3)
        ALERT "NEW USER ADDED: $username (UID=$uid, shell=$shell)"
        echo "[$(date)] ALERT: New user added: $username UID=$uid shell=$shell" >> "$LOG_FILE"
    done <<< "$new_users"

    # Users removed
    removed=$(diff <(echo "$previous") <(echo "$current") | grep '^<' | sed 's/^< //')
    while read -r entry; do
        [ -z "$entry" ] && continue
        username=$(echo "$entry" | cut -d: -f1)
        WARN "USER REMOVED: $username"
    done <<< "$removed"

    # Check for UID 0 that isn't root
    awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd | while read -r u; do
        ALERT "UID 0 BACKDOOR ACCOUNT: $u"
        echo "[$(date)] ALERT: UID 0 backdoor account: $u" >> "$LOG_FILE"
    done

    # Update snapshot
    echo "$current" > "$SNAP_DIR/passwd.snap"
}

check_password_changes() {
    current=$(md5sum /etc/shadow)
    previous=$(cat "$SNAP_DIR/shadow.snap")
    if [ "$current" != "$previous" ]; then
        WARN "/etc/shadow has changed — a password was modified"
        echo "[$(date)] WARN: /etc/shadow changed" >> "$LOG_FILE"
        echo "$current" > "$SNAP_DIR/shadow.snap"
    fi
}

check_sudoers() {
    current_main=$(md5sum /etc/sudoers)
    previous_main=$(cat "$SNAP_DIR/sudoers.snap")
    if [ "$current_main" != "$previous_main" ]; then
        ALERT "/etc/sudoers HAS BEEN MODIFIED"
        echo "[$(date)] ALERT: /etc/sudoers modified" >> "$LOG_FILE"
        echo "$current_main" > "$SNAP_DIR/sudoers.snap"
    fi

    current_d=$(find /etc/sudoers.d -type f 2>/dev/null -exec md5sum {} \; | sort)
    previous_d=$(cat "$SNAP_DIR/sudoersd.snap")
    if [ "$current_d" != "$previous_d" ]; then
        ALERT "/etc/sudoers.d HAS BEEN MODIFIED"
        echo "[$(date)] ALERT: /etc/sudoers.d modified" >> "$LOG_FILE"
        echo "$current_d" > "$SNAP_DIR/sudoersd.snap"
    fi
}

check_authorized_keys() {
    current=$(find / -name "authorized_keys" -exec md5sum {} \; 2>/dev/null | sort)
    previous=$(cat "$SNAP_DIR/keys.snap")
    if [ "$current" != "$previous" ]; then
        ALERT "AUTHORIZED_KEYS FILE CHANGED — possible SSH backdoor planted"
        diff <(echo "$previous") <(echo "$current") | grep '^[<>]' | while read -r line; do
            echo "    $line"
        done
        echo "[$(date)] ALERT: authorized_keys changed" >> "$LOG_FILE"
        echo "$current" > "$SNAP_DIR/keys.snap"
    fi
}

check_sessions() {
    current=$(who | awk '{print $1,$2,$5}' | sort)
    previous=$(cat "$SNAP_DIR/sessions.snap")

    new_sessions=$(diff <(echo "$previous") <(echo "$current") | grep '^>' | sed 's/^> //')
    while read -r session; do
        [ -z "$session" ] && continue
        WARN "NEW SESSION: $session"
        echo "[$(date)] WARN: New session: $session" >> "$LOG_FILE"
    done <<< "$new_sessions"

    # Update snapshot
    echo "$current" > "$SNAP_DIR/sessions.snap"
}

check_listening_ports() {
    current=$(ss -tulnp | sort)
    previous=$(cat "$SNAP_DIR/ports.snap")

    new_ports=$(diff <(echo "$previous") <(echo "$current") | grep '^>' | grep -v '^---')
    while read -r port_line; do
        [ -z "$port_line" ] && continue
        ALERT "NEW LISTENING PORT DETECTED: $port_line"
        echo "[$(date)] ALERT: New listening port: $port_line" >> "$LOG_FILE"
    done <<< "$new_ports"

    echo "$current" > "$SNAP_DIR/ports.snap"
}

check_sudo_group() {
    current_sudo=$(getent group sudo wheel admin 2>/dev/null | grep -oP ':[^:]*$' | tr ':,' '\n' | grep -v '^$' | sort)
    snap_file="$SNAP_DIR/sudo_group.snap"

    if [ ! -f "$snap_file" ]; then
        echo "$current_sudo" > "$snap_file"
        return
    fi

    previous_sudo=$(cat "$snap_file")
    new_members=$(diff <(echo "$previous_sudo") <(echo "$current_sudo") | grep '^>' | sed 's/^> //')
    while read -r member; do
        [ -z "$member" ] && continue
        ALERT "NEW SUDO GROUP MEMBER: $member"
        echo "[$(date)] ALERT: New sudo member: $member" >> "$LOG_FILE"
    done <<< "$new_members"

    echo "$current_sudo" > "$snap_file"
}

check_suspicious_processes() {
    # Look for classic reverse shell indicators
    ps aux | grep -E 'nc -|ncat|/dev/tcp|/dev/udp|bash -i' | grep -v grep | while read -r proc; do
        ALERT "SUSPICIOUS PROCESS: $proc"
        echo "[$(date)] ALERT: Suspicious process: $proc" >> "$LOG_FILE"
    done

    # Look for processes listening on unusual ports (not standard services)
    ss -tulnp | grep -vE ':22 |:80 |:443 |:21 |:20 |:3000 |:5432 |:25 |:53 ' | grep LISTEN | while read -r line; do
        WARN "UNUSUAL LISTENER: $line"
    done
}

# -------------------------------------------------------------
# MAIN LOOP
# -------------------------------------------------------------
echo -e "${BOLD}TCDC IAM WATCHDOG — $(hostname)${NC}"
echo -e "Log file: $LOG_FILE"
echo -e "Check interval: ${INTERVAL}s"
echo ""

init_snapshots

TICK=0
while true; do
    TICK=$((TICK + 1))

    # Run all checks
    check_new_users
    check_password_changes
    check_sudoers
    check_authorized_keys
    check_sessions
    check_listening_ports
    check_sudo_group
    check_suspicious_processes

    # Heartbeat every 10 ticks (2.5 minutes)
    if [ $((TICK % 10)) -eq 0 ]; then
        INFO "Watchdog running — tick $TICK — $(date '+%H:%M:%S') — all systems nominal"
    fi

    sleep "$INTERVAL"
done
