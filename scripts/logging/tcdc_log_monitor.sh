#!/bin/bash
# =============================================================
# TCDC REAL-TIME LOG MONITOR
# Watches all critical logs simultaneously and highlights
# suspicious events with color-coded alerts.
# Usage: sudo bash tcdc_log_monitor.sh [mode]
# Modes: all (default), auth, web, ftp, db, audit
# =============================================================

RED='\033[0;31m'
YLW='\033[0;33m'
GRN='\033[0;32m'
BLU='\033[0;34m'
CYN='\033[0;36m'
MAG='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

MODE="${1:-all}"

# =============================================================
# COLOR-CODED LOG PATTERN MATCHING
# =============================================================

colorize_line() {
    local line="$1"
    local source="$2"

    # CRITICAL — immediate action needed
    if echo "$line" | grep -qiE \
        'useradd|new user|userdel|UID=0|NOPASSWD|pam_permit|Invalid user root|Accepted.*root|authorized_keys|sudoers'; then
        echo -e "${BOLD}${RED}[CRITICAL][$source] $line${NC}"
        return
    fi

    # HIGH — likely attack in progress
    if echo "$line" | grep -qiE \
        'Failed password|authentication failure|BREAK-IN|Invalid user|refused connect|bad protocol|sudo.*COMMAND=/bin/bash|/tmp/.*exec|/dev/shm|base64.*bash|/dev/tcp'; then
        echo -e "${RED}[HIGH][$source] $line${NC}"
        return
    fi

    # MEDIUM — suspicious, worth noting
    if echo "$line" | grep -qiE \
        'sudo|su\[|session opened for user root|CRON.*root|new group|passwd\[|chpasswd|usermod|groupmod|chmod.*777|suid|setuid'; then
        echo -e "${YLW}[MED][$source] $line${NC}"
        return
    fi

    # SUCCESS — good events to track
    if echo "$line" | grep -qiE \
        'Accepted password|Accepted publickey|session opened|Started|Active: active'; then
        echo -e "${GRN}[OK][$source] $line${NC}"
        return
    fi

    # SERVICE EVENTS — web/ftp/db specific
    if echo "$line" | grep -qiE \
        'GET.*\.\./|POST.*\.\./|\.git|\.env|TRACE|PUT /|DELETE /|UNION SELECT|1=1|script>|<iframe'; then
        echo -e "${MAG}[WEB-ATTACK][$source] $line${NC}"
        return
    fi

    # DEFAULT — dim for non-notable lines
    echo -e "${BLU}[INFO][$source]${NC} $line"
}

# =============================================================
# LOG FILE DEFINITIONS PER MODE
# =============================================================

LOG_FILES=()
LOG_LABELS=()

add_log() {
    local file="$1"
    local label="$2"
    [ -f "$file" ] && LOG_FILES+=("$file") && LOG_LABELS+=("$label")
}

case "$MODE" in
    auth)
        add_log "/var/log/auth.log" "AUTH"
        add_log "/var/log/audit/audit.log" "AUDIT"
        ;;
    web)
        add_log "/var/log/apache2/access.log" "APACHE-ACC"
        add_log "/var/log/apache2/error.log" "APACHE-ERR"
        add_log "/var/log/nginx/access.log" "NGINX-ACC"
        add_log "/var/log/nginx/error.log" "NGINX-ERR"
        ;;
    ftp)
        add_log "/var/log/vsftpd.log" "FTP"
        add_log "/var/log/auth.log" "AUTH"
        ;;
    db)
        for f in /var/log/postgresql/postgresql-*.log; do
            add_log "$f" "POSTGRES"
        done
        ;;
    audit)
        add_log "/var/log/audit/audit.log" "AUDIT"
        ;;
    all|*)
        add_log "/var/log/auth.log" "AUTH"
        add_log "/var/log/syslog" "SYSLOG"
        add_log "/var/log/audit/audit.log" "AUDIT"
        add_log "/var/log/fail2ban.log" "F2BAN"
        add_log "/var/log/apache2/access.log" "APACHE-ACC"
        add_log "/var/log/apache2/error.log" "APACHE-ERR"
        add_log "/var/log/nginx/access.log" "NGINX-ACC"
        add_log "/var/log/nginx/error.log" "NGINX-ERR"
        add_log "/var/log/vsftpd.log" "FTP"
        for f in /var/log/postgresql/postgresql-*.log; do
            add_log "$f" "POSTGRES"
        done
        add_log "/var/log/tcdc_errors.log" "ERRORS"
        ;;
esac

# =============================================================
# BUILD TAIL COMMAND
# =============================================================

if [ ${#LOG_FILES[@]} -eq 0 ]; then
    echo "No log files found for mode: $MODE"
    echo "Usage: $0 [all|auth|web|ftp|db|audit]"
    exit 1
fi

echo -e "${BOLD}TCDC REAL-TIME LOG MONITOR — $(hostname)${NC}"
echo -e "Mode: $MODE | Time: $(date)"
echo ""
echo -e "Watching:"
for i in "${!LOG_FILES[@]}"; do
    echo -e "  ${BLU}${LOG_LABELS[$i]}${NC} → ${LOG_FILES[$i]}"
done
echo ""
echo -e "Color key:"
echo -e "  ${BOLD}${RED}[CRITICAL]${NC} — User created, UID 0, sudoers change, SSH key planted"
echo -e "  ${RED}[HIGH]${NC}     — Brute force, auth failure, reverse shell indicator"
echo -e "  ${YLW}[MED]${NC}      — sudo use, session as root, cron jobs"
echo -e "  ${GRN}[OK]${NC}       — Successful logins, service starts"
echo -e "  ${MAG}[WEB-ATTACK]${NC}— Directory traversal, SQLi, XSS attempts"
echo -e "  ${BLU}[INFO]${NC}     — All other events"
echo ""
echo -e "${BOLD}Press Ctrl+C to stop${NC}"
echo "========================================"

# =============================================================
# MAIN TAIL LOOP
# Uses process substitution to merge multiple log streams
# =============================================================

# Build the tail arguments
TAIL_ARGS=()
for file in "${LOG_FILES[@]}"; do
    TAIL_ARGS+=("-f" "$file")
done

# Run tail on all files and process each line
tail --follow=name --retry "${TAIL_ARGS[@]}" 2>/dev/null | \
    awk -v labels="$(IFS=':'; echo "${LOG_LABELS[*]}")" \
        -v files="$(IFS=':'; echo "${LOG_FILES[*]}")" '
    /^==> .* <==$/ {
        # Extract filename from tail header
        match($0, /==> (.*) <==/, arr)
        current_file = arr[1]

        # Find matching label
        n = split(files, farray, ":")
        split(labels, larray, ":")
        for (i=1; i<=n; i++) {
            if (farray[i] == current_file) {
                current_label = larray[i]
                break
            }
        }
        next
    }
    {
        if (current_label == "") current_label = "UNKNOWN"
        print current_label "|" $0
    }
' | while IFS='|' read -r label line; do
    colorize_line "$line" "$label"
done
