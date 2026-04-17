#!/bin/bash
# =============================================================
# TCDC LOG ANALYSIS SCRIPT
# Analyzes logs for the past N hours and produces a threat
# summary — useful for catching up after being away from a box.
# Usage: sudo bash tcdc_log_analysis.sh [hours]
# Default: last 2 hours
# =============================================================

RED='\033[0;31m'
YLW='\033[0;33m'
GRN='\033[0;32m'
BLU='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

flag() { echo -e "  ${RED}[!] $1${NC}"; }
warn() { echo -e "  ${YLW}[~] $1${NC}"; }
ok()   { echo -e "  ${GRN}[+] $1${NC}"; }
info() { echo -e "  ${BLU}[*] $1${NC}"; }
banner() {
    echo -e "\n${BOLD}${BLU}========================================${NC}"
    echo -e "${BOLD}${BLU}  $1${NC}"
    echo -e "${BOLD}${BLU}========================================${NC}"
}

HOURS="${1:-2}"
SINCE="$HOURS hours ago"

echo -e "${BOLD}TCDC LOG ANALYSIS — $(hostname)${NC}"
echo -e "Analyzing: last $HOURS hour(s) | Time: $(date)"

# =============================================================
banner "1. AUTHENTICATION EVENTS"
# =============================================================

AUTH_LOG="/var/log/auth.log"
[ -f "$AUTH_LOG" ] || AUTH_LOG="/var/log/secure"

if [ -f "$AUTH_LOG" ]; then

    # Failed SSH attempts
    echo ""
    info "Failed SSH login attempts (top attackers):"
    grep "Failed password" "$AUTH_LOG" | \
        awk -v since="$(date -d "$SINCE" '+%b %e %H:%M:%S' 2>/dev/null)" '$0 > since' | \
        awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -10 | \
        while read -r count ip; do
            if [ "$count" -gt 10 ]; then
                flag "$count attempts from $ip"
            else
                warn "$count attempts from $ip"
            fi
        done

    # Successful logins
    echo ""
    info "Successful logins:"
    grep "Accepted" "$AUTH_LOG" | \
        awk -v since="$(date -d "$SINCE" '+%b %e %H:%M:%S' 2>/dev/null)" '$0 > since' | \
        while read -r line; do
            user=$(echo "$line" | grep -oP 'for \K\S+')
            ip=$(echo "$line" | grep -oP 'from \K[\d.]+')
            time=$(echo "$line" | awk '{print $1,$2,$3}')
            if [ "$user" = "root" ]; then
                flag "Root login: $user from $ip at $time"
            else
                ok "Login: $user from $ip at $time"
            fi
        done

    # Sudo usage
    echo ""
    info "Sudo commands executed:"
    grep "sudo.*COMMAND" "$AUTH_LOG" | \
        awk -v since="$(date -d "$SINCE" '+%b %e %H:%M:%S' 2>/dev/null)" '$0 > since' | \
        while read -r line; do
            user=$(echo "$line" | grep -oP '\w+ : TTY' | awk '{print $1}')
            cmd=$(echo "$line" | grep -oP 'COMMAND=\K.*')
            if echo "$cmd" | grep -qE '/bin/bash|/bin/sh|/bin/dash'; then
                flag "SHELL via sudo: $user ran $cmd"
            else
                warn "sudo: $user ran $cmd"
            fi
        done

    # New users created
    echo ""
    info "User account changes:"
    grep -E "useradd|userdel|usermod|new user|new group" "$AUTH_LOG" | \
        awk -v since="$(date -d "$SINCE" '+%b %e %H:%M:%S' 2>/dev/null)" '$0 > since' | \
        while read -r line; do
            flag "$line"
        done

    # Password changes
    echo ""
    info "Password change events:"
    grep -E "passwd\[|chpasswd|password changed" "$AUTH_LOG" | \
        awk -v since="$(date -d "$SINCE" '+%b %e %H:%M:%S' 2>/dev/null)" '$0 > since' | \
        while read -r line; do
            warn "$line"
        done

    # Session events
    echo ""
    info "Root session opens:"
    grep "session opened for user root" "$AUTH_LOG" | \
        awk -v since="$(date -d "$SINCE" '+%b %e %H:%M:%S' 2>/dev/null)" '$0 > since' | \
        while read -r line; do
            flag "$line"
        done

else
    warn "Auth log not found"
fi

# =============================================================
banner "2. AUDITD EVENTS"
# =============================================================

if [ -f /var/log/audit/audit.log ]; then

    # Sudoers changes
    echo ""
    info "Sudoers file changes:"
    ausearch -k sudoers_change --start recent 2>/dev/null | grep -A3 "type=PATH" | \
        grep "name=" | while read -r line; do
            flag "Sudoers change: $line"
        done

    # New user creation via auditd
    echo ""
    info "User management events (auditd):"
    ausearch -k user_mgmt --start recent 2>/dev/null | grep "type=SYSCALL" | head -10 | \
        while read -r line; do
            warn "$line"
        done

    # Execution from /tmp
    echo ""
    info "Executions from /tmp or /dev/shm:"
    ausearch -k tmp_execution --start recent 2>/dev/null | grep "type=EXECVE" | head -10 | \
        while read -r line; do
            flag "$line"
        done

    # SSH key changes
    echo ""
    info "SSH authorized_keys changes:"
    ausearch -k ssh_keys --start recent 2>/dev/null | grep "type=PATH" | grep "authorized_keys" | \
        while read -r line; do
            flag "$line"
        done

    # Privilege escalation
    echo ""
    info "Privilege escalation attempts:"
    ausearch -k priv_escalation --start recent 2>/dev/null | grep "type=SYSCALL" | head -5 | \
        while read -r line; do
            warn "$line"
        done

else
    warn "auditd log not found — run tcdc_logging_setup.sh first"
fi

# =============================================================
banner "3. WEB SERVER EVENTS"
# =============================================================

# Apache access log
for access_log in /var/log/apache2/access.log /var/log/nginx/access.log; do
    [ -f "$access_log" ] || continue
    svc=$(echo "$access_log" | grep -oP 'apache2|nginx')

    echo ""
    info "Top requesting IPs ($svc):"
    find "$access_log" -newer /tmp -exec true \; 2>/dev/null
    tail -n 5000 "$access_log" | awk '{print $1}' | sort | uniq -c | sort -rn | head -5 | \
        while read -r count ip; do
            if [ "$count" -gt 500 ]; then
                flag "$count requests from $ip (possible scan/DoS)"
            else
                info "$count requests from $ip"
            fi
        done

    echo ""
    info "Suspicious requests ($svc):"
    tail -n 5000 "$access_log" | grep -iE \
        '\.\./|etc/passwd|etc/shadow|\.git|\.env|union.*select|<script|base64|/proc/self|cmd=|exec\(' | \
        head -10 | while read -r line; do
            flag "$line"
        done

    echo ""
    info "404/403 errors ($svc — scanning indicator):"
    tail -n 5000 "$access_log" | awk '$9 == "404" || $9 == "403"' | \
        awk '{print $1}' | sort | uniq -c | sort -rn | head -5 | \
        while read -r count ip; do
            [ "$count" -gt 20 ] && warn "$count errors from $ip (scanning?)"
        done
done

# Apache error log
for error_log in /var/log/apache2/error.log /var/log/nginx/error.log; do
    [ -f "$error_log" ] || continue
    svc=$(echo "$error_log" | grep -oP 'apache2|nginx')
    echo ""
    info "Recent errors ($svc):"
    tail -n 50 "$error_log" | grep -iE 'error|crit|alert|emerg' | tail -10 | \
        while read -r line; do warn "$line"; done
done

# =============================================================
banner "4. FTP EVENTS"
# =============================================================

if [ -f /var/log/vsftpd.log ]; then
    echo ""
    info "FTP login failures:"
    grep "FAIL LOGIN" /var/log/vsftpd.log | tail -10 | \
        while read -r line; do warn "$line"; done

    echo ""
    info "FTP successful uploads (write events):"
    grep "OK UPLOAD\|OK STOR" /var/log/vsftpd.log | tail -10 | \
        while read -r line; do warn "$line"; done

    echo ""
    info "Anonymous FTP attempts:"
    grep -i "anonymous\|ftp@" /var/log/vsftpd.log | tail -5 | \
        while read -r line; do flag "$line"; done
else
    info "FTP log not found on this box"
fi

# =============================================================
banner "5. POSTGRESQL EVENTS"
# =============================================================

PG_LOG=$(find /var/log/postgresql -name "*.log" 2>/dev/null | sort | tail -1)
if [ -n "$PG_LOG" ]; then
    echo ""
    info "PostgreSQL authentication failures:"
    grep "FATAL.*password\|FATAL.*authentication\|FATAL.*no pg_hba" "$PG_LOG" | tail -10 | \
        while read -r line; do warn "$line"; done

    echo ""
    info "PostgreSQL connections from outside localhost:"
    grep "connection received" "$PG_LOG" | grep -v "127.0.0.1\|::1\|localhost" | tail -5 | \
        while read -r line; do warn "$line"; done
else
    info "PostgreSQL log not found on this box"
fi

# =============================================================
banner "6. FAIL2BAN STATUS"
# =============================================================

if systemctl is-active --quiet fail2ban; then
    ok "fail2ban is running"
    echo ""
    info "Current bans:"
    fail2ban-client status 2>/dev/null | grep "Jail list" | tr ',' '\n' | grep -v "Jail" | \
        while read -r jail; do
            jail=$(echo "$jail" | tr -d ' ')
            [ -z "$jail" ] && continue
            banned=$(fail2ban-client status "$jail" 2>/dev/null | grep "Banned IP list:" | cut -d: -f2)
            if [ -n "$(echo "$banned" | tr -d ' ')" ]; then
                warn "Jail $jail — Banned: $banned"
            else
                ok "Jail $jail — no active bans"
            fi
        done
else
    flag "fail2ban is NOT running"
fi

# =============================================================
banner "7. RECENTLY MODIFIED CRITICAL FILES"
# =============================================================

info "Critical files modified in last $HOURS hour(s):"
find \
    /etc/passwd /etc/shadow /etc/sudoers /etc/ssh/sshd_config \
    /etc/crontab /etc/cron.d /etc/pam.d /etc/hosts \
    /etc/vsftpd.conf /etc/apache2 /etc/nginx /etc/postgresql \
    -newer "/proc/$(date -d "$SINCE" +%s 2>/dev/null || echo 1)/status" \
    2>/dev/null | while read -r f; do
        flag "Recently modified: $f ($(stat -c '%y' "$f" 2>/dev/null | cut -d. -f1))"
    done

# Alternative approach using find -mmin
MINUTES=$((HOURS * 60))
find /etc /home /root /tmp /var/spool/cron \
    -mmin -"$MINUTES" -type f 2>/dev/null | \
    grep -v "/proc\|/sys\|/run\|\.pyc\|__pycache__" | \
    while read -r f; do
        warn "Modified: $f"
    done

# =============================================================
banner "8. CRON JOB AUDIT"
# =============================================================

info "All active cron jobs:"
for user in root alice bob craig chad trudy mallory mike yves judy sybil walter wendy; do
    crontab_entry=$(crontab -l -u "$user" 2>/dev/null | grep -v '^#\|^$')
    if [ -n "$crontab_entry" ]; then
        warn "Cron for $user:"
        echo "$crontab_entry" | while read -r line; do
            echo "    $line"
            if echo "$line" | grep -qiE '/tmp|/dev/shm|base64|curl|wget|bash -i'; then
                flag "Suspicious cron: $line"
            fi
        done
    fi
done

echo ""
info "System cron files:"
for crondir in /etc/cron.d /etc/cron.hourly /etc/cron.daily; do
    [ -d "$crondir" ] || continue
    ls "$crondir" | while read -r f; do
        echo "    $crondir/$f"
    done
done

# =============================================================
banner "ANALYSIS SUMMARY"
# =============================================================
echo ""
echo -e "${BOLD}Analysis complete for $(hostname) — last $HOURS hour(s)${NC}"
echo ""
echo "Next steps:"
info "  1. Investigate all [!] FLAG items immediately"
info "  2. Ban persistent attacker IPs: fail2ban-client set sshd banip <IP>"
info "  3. Kill suspicious processes: kill -9 <PID>"
info "  4. Run tcdc_iam_audit.sh if user changes were detected"
