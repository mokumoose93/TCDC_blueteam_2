#!/bin/bash
# =============================================================
# TCDC SERVICE AUDIT SCRIPT
# Run on any box to inventory all services, detect issues,
# and flag anything that needs hardening.
# Read-only — nothing is modified.
# Usage: sudo bash tcdc_service_audit.sh | tee /tmp/svc_audit.txt
# =============================================================

RED='\033[0;31m'
YLW='\033[0;33m'
GRN='\033[0;32m'
BLU='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

flag() { echo -e "  ${RED}[!] FLAG: $1${NC}"; }
warn() { echo -e "  ${YLW}[~] WARN: $1${NC}"; }
ok()   { echo -e "  ${GRN}[+] OK:   $1${NC}"; }
info() { echo -e "  ${BLU}[*] INFO: $1${NC}"; }

banner() {
    echo -e "\n${BOLD}${BLU}========================================${NC}"
    echo -e "${BOLD}${BLU}  $1${NC}"
    echo -e "${BOLD}${BLU}========================================${NC}"
}

HOSTNAME=$(hostname)
echo -e "${BOLD}TCDC SERVICE AUDIT — $HOSTNAME${NC}"
echo -e "Time: $(date)"

# -------------------------------------------------------------
banner "1. PORT & SERVICE INVENTORY"
# -------------------------------------------------------------
info "All listening ports and owning processes:"
ss -tulnp | grep LISTEN | while read -r line; do
    echo "    $line"
done

echo ""
info "All established connections:"
ss -tnp state established | while read -r line; do
    echo "    $line"
done

# -------------------------------------------------------------
banner "2. APACHE / NGINX AUDIT"
# -------------------------------------------------------------

# --- Apache ---
if systemctl is-active --quiet apache2 2>/dev/null || systemctl is-active --quiet httpd 2>/dev/null; then
    SVC=$(systemctl is-active apache2 &>/dev/null && echo "apache2" || echo "httpd")
    ok "Apache ($SVC) is running"
    apache2 -v 2>/dev/null || httpd -v 2>/dev/null

    # Check ServerTokens
    if grep -rE "^ServerTokens\s+Prod" /etc/apache2/ /etc/httpd/ 2>/dev/null | grep -q .; then
        ok "ServerTokens set to Prod"
    else
        warn "ServerTokens not set to Prod — version info may be exposed"
    fi

    # Check ServerSignature
    if grep -rE "^ServerSignature\s+Off" /etc/apache2/ /etc/httpd/ 2>/dev/null | grep -q .; then
        ok "ServerSignature Off"
    else
        warn "ServerSignature not Off"
    fi

    # Directory listing
    if grep -rE "Options.*Indexes" /etc/apache2/sites-enabled/ /etc/httpd/conf.d/ 2>/dev/null | grep -v '\-Indexes' | grep -q .; then
        flag "Directory listing (Indexes) may be enabled"
    else
        ok "No obvious directory listing enabled"
    fi

    # Check for TRACE method
    if grep -rE "^TraceEnable\s+Off" /etc/apache2/ /etc/httpd/ 2>/dev/null | grep -q .; then
        ok "TraceEnable Off"
    else
        warn "TraceEnable not explicitly disabled"
    fi

    # Check for exposed sensitive files in webroot
    for webroot in /var/www/html /var/www /srv/www; do
        [ -d "$webroot" ] || continue
        find "$webroot" -name ".git" -type d 2>/dev/null | while read -r f; do
            flag "Exposed .git directory: $f"
        done
        find "$webroot" -name ".env" 2>/dev/null | while read -r f; do
            flag "Exposed .env file: $f"
        done
        find "$webroot" -name "*.bak" -o -name "*.old" -o -name "*.swp" 2>/dev/null | while read -r f; do
            warn "Backup file in webroot: $f"
        done
    done

    # Config test
    echo ""
    info "Apache config test:"
    apache2ctl configtest 2>&1 | while read -r line; do echo "    $line"; done
else
    info "Apache not running on this box"
fi

# --- Nginx ---
if systemctl is-active --quiet nginx 2>/dev/null; then
    ok "Nginx is running"
    nginx -v 2>&1

    if grep -rE "server_tokens\s+off" /etc/nginx/ 2>/dev/null | grep -q .; then
        ok "server_tokens off"
    else
        warn "server_tokens not set to off — version may be exposed"
    fi

    if grep -rE "autoindex\s+on" /etc/nginx/ 2>/dev/null | grep -q .; then
        flag "autoindex on found — directory listing enabled"
    else
        ok "No autoindex on found"
    fi

    echo ""
    info "Nginx config test:"
    nginx -t 2>&1 | while read -r line; do echo "    $line"; done
else
    info "Nginx not running on this box"
fi

# -------------------------------------------------------------
banner "3. FTP (vsftpd) AUDIT"
# -------------------------------------------------------------
if systemctl is-active --quiet vsftpd 2>/dev/null; then
    ok "vsftpd is running"

    VSFTPD_CONF="/etc/vsftpd.conf"
    [ -f "$VSFTPD_CONF" ] || VSFTPD_CONF=$(find /etc -name "vsftpd.conf" 2>/dev/null | head -1)

    if [ -f "$VSFTPD_CONF" ]; then
        info "Config: $VSFTPD_CONF"

        # Anonymous login
        anon=$(grep -E "^anonymous_enable" "$VSFTPD_CONF" | cut -d= -f2 | tr -d ' ')
        if [ "$anon" = "YES" ]; then
            flag "anonymous_enable=YES — anonymous FTP login is ON"
        else
            ok "anonymous_enable=NO"
        fi

        # Chroot
        chroot=$(grep -E "^chroot_local_user" "$VSFTPD_CONF" | cut -d= -f2 | tr -d ' ')
        if [ "$chroot" = "YES" ]; then
            ok "chroot_local_user=YES — users jailed to home"
        else
            warn "chroot_local_user not YES — users can browse filesystem"
        fi

        # Write enable
        write=$(grep -E "^write_enable" "$VSFTPD_CONF" | cut -d= -f2 | tr -d ' ')
        if [ "$write" = "YES" ]; then
            warn "write_enable=YES — users can upload files"
        else
            ok "write_enable=NO"
        fi

        # SSL
        ssl=$(grep -E "^ssl_enable" "$VSFTPD_CONF" | cut -d= -f2 | tr -d ' ')
        if [ "$ssl" = "YES" ]; then
            ok "ssl_enable=YES — TLS enabled"
        else
            warn "ssl_enable=NO — credentials sent in plaintext"
        fi

        # Passive port range
        pasv_min=$(grep -E "^pasv_min_port" "$VSFTPD_CONF" | cut -d= -f2 | tr -d ' ')
        pasv_max=$(grep -E "^pasv_max_port" "$VSFTPD_CONF" | cut -d= -f2 | tr -d ' ')
        if [ -n "$pasv_min" ] && [ -n "$pasv_max" ]; then
            ok "Passive port range: $pasv_min - $pasv_max"
        else
            warn "Passive port range not configured — may cause connection issues"
        fi

        # Logging
        xfer_log=$(grep -E "^xferlog_enable" "$VSFTPD_CONF" | cut -d= -f2 | tr -d ' ')
        if [ "$xfer_log" = "YES" ]; then
            ok "xferlog_enable=YES — transfer logging on"
        else
            warn "xferlog_enable not YES — FTP transfers not being logged"
        fi
    fi

    info "Active FTP connections:"
    ss -tnp | grep ':21' | while read -r line; do echo "    $line"; done
else
    info "vsftpd not running on this box"
fi

# -------------------------------------------------------------
banner "4. SSH AUDIT"
# -------------------------------------------------------------
if systemctl is-active --quiet sshd 2>/dev/null || systemctl is-active --quiet ssh 2>/dev/null; then
    ok "SSH is running"

    SSHD_CONF="/etc/ssh/sshd_config"

    check_ssh_opt() {
        local key="$1"
        local good_val="$2"
        local actual
        actual=$(grep -E "^${key}\s" "$SSHD_CONF" 2>/dev/null | awk '{print $2}')
        if [ -z "$actual" ]; then
            warn "$key not explicitly set (using default)"
        elif [ "$actual" = "$good_val" ]; then
            ok "$key = $actual"
        else
            flag "$key = $actual (expected: $good_val)"
        fi
    }

    check_ssh_opt "PermitRootLogin" "no"
    check_ssh_opt "PermitEmptyPasswords" "no"
    check_ssh_opt "X11Forwarding" "no"
    check_ssh_opt "Protocol" "2"

    # MaxAuthTries
    max_tries=$(grep -E "^MaxAuthTries" "$SSHD_CONF" | awk '{print $2}')
    if [ -z "$max_tries" ]; then
        warn "MaxAuthTries not set (default is 6)"
    elif [ "$max_tries" -le 3 ]; then
        ok "MaxAuthTries = $max_tries"
    else
        warn "MaxAuthTries = $max_tries (consider setting to 3)"
    fi

    # AllowUsers
    if grep -qE "^AllowUsers" "$SSHD_CONF"; then
        allow=$(grep -E "^AllowUsers" "$SSHD_CONF")
        ok "AllowUsers is set: $allow"
        # Check checker is included
        if echo "$allow" | grep -q "checker"; then
            ok "checker user is in AllowUsers"
        else
            flag "checker NOT in AllowUsers — uptime check may fail!"
        fi
    else
        warn "AllowUsers not set — all users can SSH"
    fi

    # Password auth
    pw_auth=$(grep -E "^PasswordAuthentication" "$SSHD_CONF" | awk '{print $2}')
    if [ "$pw_auth" = "no" ]; then
        ok "PasswordAuthentication = no (key only)"
    elif [ "$pw_auth" = "yes" ]; then
        warn "PasswordAuthentication = yes — passwords accepted over SSH"
    else
        warn "PasswordAuthentication not explicitly set"
    fi

    echo ""
    info "Active SSH sessions:"
    ss -tnp | grep ':22' | while read -r line; do echo "    $line"; done

    echo ""
    info "Recent SSH auth events:"
    grep "sshd" /var/log/auth.log 2>/dev/null | tail -10 | while read -r line; do echo "    $line"; done

    echo ""
    info "fail2ban SSH status:"
    fail2ban-client status sshd 2>/dev/null || warn "fail2ban not running or sshd jail not configured"
else
    info "SSH not running on this box"
fi

# -------------------------------------------------------------
banner "5. POSTGRESQL AUDIT"
# -------------------------------------------------------------
if systemctl is-active --quiet postgresql 2>/dev/null; then
    ok "PostgreSQL is running"

    PG_CONF=$(find /etc/postgresql -name "postgresql.conf" 2>/dev/null | head -1)
    HBA_CONF=$(find /etc/postgresql -name "pg_hba.conf" 2>/dev/null | head -1)

    if [ -n "$PG_CONF" ]; then
        # listen_addresses
        listen=$(grep -E "^listen_addresses" "$PG_CONF" | cut -d= -f2 | tr -d " '")
        if [ "$listen" = "*" ]; then
            flag "listen_addresses = * — PostgreSQL listening on ALL interfaces"
        elif [ -n "$listen" ]; then
            ok "listen_addresses = $listen"
        else
            warn "listen_addresses not explicitly set"
        fi

        # Port
        pg_port=$(grep -E "^port" "$PG_CONF" | awk '{print $3}' | tr -d '#')
        info "PostgreSQL port: ${pg_port:-5432 (default)}"

        # Logging
        log_conn=$(grep -E "^log_connections" "$PG_CONF" | awk '{print $3}')
        log_disconn=$(grep -E "^log_disconnections" "$PG_CONF" | awk '{print $3}')
        [ "$log_conn" = "on" ] && ok "log_connections = on" || warn "log_connections not enabled"
        [ "$log_disconn" = "on" ] && ok "log_disconnections = on" || warn "log_disconnections not enabled"
    fi

    if [ -n "$HBA_CONF" ]; then
        echo ""
        info "pg_hba.conf contents (access control):"
        grep -v '^#\|^$' "$HBA_CONF" | while read -r line; do
            echo "    $line"
            # Flag wildcard access
            if echo "$line" | grep -qE '0\.0\.0\.0/0|all\s+all\s+all'; then
                flag "Wildcard access in pg_hba.conf: $line"
            fi
        done
    fi

    echo ""
    info "PostgreSQL roles:"
    sudo -u postgres psql -c "\du" 2>/dev/null || warn "Could not connect to PostgreSQL as postgres"

    info "Active connections:"
    sudo -u postgres psql -c "SELECT usename, application_name, client_addr, state FROM pg_stat_activity;" 2>/dev/null

else
    info "PostgreSQL not running on this box"
fi

# -------------------------------------------------------------
banner "6. NODE.JS / REACT AUDIT"
# -------------------------------------------------------------
if pgrep -x node &>/dev/null || pgrep -x nodejs &>/dev/null; then
    ok "Node.js process is running"

    echo ""
    info "Node process details:"
    ps aux | grep -E '[n]ode|[n]odejs' | while read -r line; do echo "    $line"; done

    echo ""
    info "Checking for debug/inspect flags (dangerous if exposed):"
    if ps aux | grep -E '[n]ode' | grep -qE '\-\-inspect|\-\-debug'; then
        flag "Node running with --inspect or --debug flag — debug port may be exposed"
    else
        ok "No debug flags detected"
    fi

    echo ""
    info "Checking NODE_ENV:"
    node_env=$(ps aux | grep '[n]ode' | grep -oE 'NODE_ENV=[^ ]+')
    if echo "$node_env" | grep -qi "production"; then
        ok "NODE_ENV=production"
    elif [ -n "$node_env" ]; then
        warn "NODE_ENV=$node_env — not production mode"
    else
        warn "NODE_ENV not set in process args — check app config"
    fi

    echo ""
    info "Exposed .env files:"
    find / -name ".env" -not -path "*/node_modules/*" 2>/dev/null | while read -r f; do
        warn ".env file found: $f"
        ls -la "$f"
    done

    echo ""
    info "Node listening ports:"
    ss -tulnp | grep node | while read -r line; do echo "    $line"; done

    echo ""
    info "Checking PM2 (process manager):"
    pm2 list 2>/dev/null || info "PM2 not installed or not in PATH"
else
    info "No Node.js process found on this box"
fi

# -------------------------------------------------------------
banner "7. WEBROOT & FILE EXPOSURE AUDIT"
# -------------------------------------------------------------
info "Scanning common webroots for sensitive files..."
for webroot in /var/www /srv/www /opt /home/*/public_html; do
    [ -d "$webroot" ] || continue
    info "Scanning: $webroot"

    # Sensitive file patterns
    find "$webroot" \( \
        -name "*.sql" -o \
        -name "*.bak" -o \
        -name "*.old" -o \
        -name "*.log" -o \
        -name "*.env" -o \
        -name "config.php" -o \
        -name "wp-config.php" -o \
        -name "*.key" -o \
        -name "*.pem" \
    \) 2>/dev/null | while read -r f; do
        warn "Sensitive file in webroot: $f"
    done
done

# -------------------------------------------------------------
banner "8. RUNNING SERVICES SUMMARY"
# -------------------------------------------------------------
info "All active systemd services:"
systemctl list-units --type=service --state=running 2>/dev/null | grep -v "^$\|UNIT\|LOAD\|ACTIVE\|loaded units" | while read -r line; do
    echo "    $line"
done

echo ""
info "Services enabled at boot:"
systemctl list-unit-files --type=service --state=enabled 2>/dev/null | while read -r line; do
    echo "    $line"
done

# -------------------------------------------------------------
echo ""
echo -e "${BOLD}========================================${NC}"
echo -e "${BOLD}SERVICE AUDIT COMPLETE — $HOSTNAME${NC}"
echo -e "${BOLD}========================================${NC}"
echo ""
echo "Review all [!] FLAG and [~] WARN items."
echo "Run the appropriate hardening scripts based on this box's service."
