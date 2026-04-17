#!/bin/bash
# =============================================================
# TCDC APACHE / NGINX HARDENING SCRIPT
# For: centurytree (Directory Search HTTP) and bonfire (React HTTP)
# Hardens web server config without breaking the scored service.
# Usage: sudo bash tcdc_harden_web.sh
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

[ "$(id -u)" -ne 0 ] && echo "Must be run as root." && exit 1

BACKUP_DIR="/root/tcdc_backups/web_$(date +%s)"
mkdir -p "$BACKUP_DIR"

echo -e "${BOLD}TCDC WEB SERVER HARDENING — $(hostname)${NC}"
echo -e "Time: $(date)"
echo ""

# Auto-detect which web server is running
APACHE_RUNNING=false
NGINX_RUNNING=false
systemctl is-active --quiet apache2 && APACHE_RUNNING=true
systemctl is-active --quiet nginx && NGINX_RUNNING=true

info "Apache running: $APACHE_RUNNING"
info "Nginx running:  $NGINX_RUNNING"

# =============================================================
# APACHE HARDENING
# =============================================================
if $APACHE_RUNNING; then
    banner "APACHE HARDENING"

    APACHE_CONF="/etc/apache2/apache2.conf"
    SECURITY_CONF="/etc/apache2/conf-available/security.conf"

    # Backup
    cp -r /etc/apache2 "$BACKUP_DIR/apache2_backup"
    ok "Backed up Apache config to $BACKUP_DIR/apache2_backup"

    # --- ServerTokens & ServerSignature ---
    info "Setting ServerTokens and ServerSignature..."
    if [ -f "$SECURITY_CONF" ]; then
        sed -i 's/^ServerTokens .*/ServerTokens Prod/' "$SECURITY_CONF"
        sed -i 's/^ServerSignature .*/ServerSignature Off/' "$SECURITY_CONF"
        grep -q "^ServerTokens" "$SECURITY_CONF" || echo "ServerTokens Prod" >> "$SECURITY_CONF"
        grep -q "^ServerSignature" "$SECURITY_CONF" || echo "ServerSignature Off" >> "$SECURITY_CONF"
        ok "ServerTokens Prod | ServerSignature Off"
    else
        echo "ServerTokens Prod" >> "$APACHE_CONF"
        echo "ServerSignature Off" >> "$APACHE_CONF"
        ok "Added ServerTokens/ServerSignature to apache2.conf"
    fi

    # --- Disable TRACE ---
    info "Disabling TRACE method..."
    if [ -f "$SECURITY_CONF" ]; then
        sed -i 's/^TraceEnable .*/TraceEnable Off/' "$SECURITY_CONF"
        grep -q "^TraceEnable" "$SECURITY_CONF" || echo "TraceEnable Off" >> "$SECURITY_CONF"
    else
        grep -q "^TraceEnable" "$APACHE_CONF" || echo "TraceEnable Off" >> "$APACHE_CONF"
    fi
    ok "TraceEnable Off"

    # --- Disable directory listing globally ---
    info "Disabling directory listing..."
    # In main config
    if grep -q "Options Indexes" "$APACHE_CONF"; then
        sed -i 's/Options Indexes/Options -Indexes/g' "$APACHE_CONF"
        ok "Disabled Indexes in apache2.conf"
    fi
    # In all virtual hosts
    for vhost in /etc/apache2/sites-enabled/*.conf; do
        [ -f "$vhost" ] || continue
        if grep -q "Options.*Indexes" "$vhost"; then
            sed -i 's/Options Indexes/Options -Indexes/g' "$vhost"
            sed -i 's/Options FollowSymLinks Indexes/Options FollowSymLinks -Indexes/g' "$vhost"
            ok "Disabled Indexes in $vhost"
        fi
    done

    # --- Security Headers ---
    info "Adding security headers..."
    HEADERS_CONF="/etc/apache2/conf-available/security-headers.conf"
    cat > "$HEADERS_CONF" << 'EOF'
# TCDC Security Headers
<IfModule mod_headers.c>
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header unset Server
    Header unset X-Powered-By
</IfModule>
EOF
    a2enconf security-headers 2>/dev/null
    a2enmod headers 2>/dev/null
    ok "Security headers configured"

    # --- Disable autoindex module ---
    info "Disabling autoindex module..."
    a2dismod autoindex 2>/dev/null && ok "autoindex module disabled" || warn "autoindex may not be enabled"

    # --- Disable unnecessary modules ---
    info "Disabling status/info modules..."
    a2dismod status 2>/dev/null && ok "status module disabled" || true
    a2dismod info 2>/dev/null && ok "info module disabled" || true
    a2dismod userdir 2>/dev/null && ok "userdir module disabled" || true

    # --- Enable security conf ---
    a2enconf security 2>/dev/null

    # --- Remove sensitive files from webroot ---
    info "Scanning webroot for sensitive files..."
    for webroot in /var/www/html /var/www; do
        [ -d "$webroot" ] || continue
        find "$webroot" -name ".git" -type d 2>/dev/null | while read -r gitdir; do
            warn "Removing .git directory: $gitdir"
            rm -rf "$gitdir"
        done
        find "$webroot" \( -name "*.bak" -o -name "*.old" -o -name "*.swp" \) 2>/dev/null | while read -r f; do
            warn "Removing backup file: $f"
            rm -f "$f"
        done
    done

    # --- Test and reload ---
    echo ""
    info "Testing Apache config..."
    if apache2ctl configtest 2>&1; then
        systemctl reload apache2
        ok "Apache reloaded successfully"
    else
        flag "Apache config test FAILED — restoring backup"
        cp -r "$BACKUP_DIR/apache2_backup/"* /etc/apache2/
        systemctl reload apache2
        flag "Backup restored — review config manually"
    fi

    # --- Verify service is up ---
    sleep 2
    if systemctl is-active --quiet apache2; then
        ok "Apache is still running after hardening"
    else
        flag "Apache is DOWN after hardening — investigate immediately"
    fi
fi

# =============================================================
# NGINX HARDENING
# =============================================================
if $NGINX_RUNNING; then
    banner "NGINX HARDENING"

    NGINX_CONF="/etc/nginx/nginx.conf"

    # Backup
    cp -r /etc/nginx "$BACKUP_DIR/nginx_backup"
    ok "Backed up Nginx config to $BACKUP_DIR/nginx_backup"

    # --- server_tokens off ---
    info "Disabling server tokens..."
    if grep -q "server_tokens" "$NGINX_CONF"; then
        sed -i 's/.*server_tokens.*/    server_tokens off;/' "$NGINX_CONF"
    else
        sed -i '/http {/a\    server_tokens off;' "$NGINX_CONF"
    fi
    ok "server_tokens off"

    # --- Security headers in all server blocks ---
    info "Adding security headers to virtual hosts..."
    for site in /etc/nginx/sites-enabled/*; do
        [ -f "$site" ] || continue
        if ! grep -q "X-Content-Type-Options" "$site"; then
            # Insert after each server { block
            sed -i '/server {/a\    add_header X-Content-Type-Options "nosniff";\n    add_header X-Frame-Options "SAMEORIGIN";\n    add_header X-XSS-Protection "1; mode=block";\n    server_tokens off;' "$site"
            ok "Added headers to $site"
        fi
    done

    # --- Disable autoindex ---
    info "Disabling autoindex in all configs..."
    find /etc/nginx -name "*.conf" | xargs sed -i 's/autoindex on/autoindex off/g' 2>/dev/null
    ok "autoindex off in all nginx configs"

    # --- Test and reload ---
    echo ""
    info "Testing Nginx config..."
    if nginx -t 2>&1; then
        systemctl reload nginx
        ok "Nginx reloaded successfully"
    else
        flag "Nginx config test FAILED — restoring backup"
        cp -r "$BACKUP_DIR/nginx_backup/"* /etc/nginx/
        systemctl reload nginx
        flag "Backup restored — review config manually"
    fi

    # --- Verify ---
    sleep 2
    if systemctl is-active --quiet nginx; then
        ok "Nginx is still running after hardening"
    else
        flag "Nginx is DOWN — investigate immediately"
    fi
fi

# =============================================================
# NODE.JS / REACT CHECK (bonfire)
# =============================================================
banner "NODE.JS / REACT HARDENING CHECK"

if pgrep -x node &>/dev/null || pgrep -x nodejs &>/dev/null; then
    ok "Node.js is running"

    # Check for debug flags
    if ps aux | grep '[n]ode' | grep -qE '\-\-inspect|\-\-debug'; then
        flag "Node running with debug flag — attempting to restart without it"
        # Try PM2 first
        if command -v pm2 &>/dev/null; then
            warn "PM2 detected — review pm2 ecosystem config to remove --inspect"
            pm2 list
        fi
    else
        ok "No debug flags on Node process"
    fi

    # Find and secure .env files
    find / -name ".env" -not -path "*/node_modules/*" 2>/dev/null | while read -r envfile; do
        warn "Securing .env file permissions: $envfile"
        chmod 600 "$envfile"
        ok "chmod 600 on $envfile"
    done

    # Check if reverse proxied through Apache/Nginx
    if $APACHE_RUNNING || $NGINX_RUNNING; then
        ok "Node appears to be behind Apache/Nginx reverse proxy"
    else
        warn "Node may be directly exposed — consider placing behind reverse proxy"
    fi
else
    info "No Node.js process found"
fi

# =============================================================
echo ""
echo -e "${BOLD}========================================${NC}"
echo -e "${BOLD}WEB HARDENING COMPLETE — $(hostname)${NC}"
echo -e "${BOLD}========================================${NC}"
echo ""
ok "Backups at: $BACKUP_DIR"
info "Verify your scored service is still responding:"
info "  curl -I http://$(hostname -I | awk '{print $1}')"
