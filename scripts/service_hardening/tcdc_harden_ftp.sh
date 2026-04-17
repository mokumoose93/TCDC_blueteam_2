#!/bin/bash
# =============================================================
# TCDC FTP (vsftpd) HARDENING SCRIPT
# For: aggiedrop (FTP + Custom scored service)
# Usage: sudo bash tcdc_harden_ftp.sh
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

BACKUP_DIR="/root/tcdc_backups/ftp_$(date +%s)"
mkdir -p "$BACKUP_DIR"

echo -e "${BOLD}TCDC FTP HARDENING — $(hostname)${NC}"

# Find vsftpd config
VSFTPD_CONF="/etc/vsftpd.conf"
[ -f "$VSFTPD_CONF" ] || VSFTPD_CONF=$(find /etc -name "vsftpd.conf" 2>/dev/null | head -1)

if [ -z "$VSFTPD_CONF" ] || [ ! -f "$VSFTPD_CONF" ]; then
    flag "vsftpd.conf not found. Is vsftpd installed?"
    exit 1
fi

# Backup
cp "$VSFTPD_CONF" "$BACKUP_DIR/vsftpd.conf.bak"
ok "Backed up vsftpd.conf"

# Helper to set or update a vsftpd config value
set_vsftpd() {
    local key="$1"
    local value="$2"
    if grep -qE "^#?${key}=" "$VSFTPD_CONF"; then
        sed -i "s|^#\?${key}=.*|${key}=${value}|" "$VSFTPD_CONF"
    else
        echo "${key}=${value}" >> "$VSFTPD_CONF"
    fi
    ok "Set ${key}=${value}"
}

# -------------------------------------------------------------
banner "1. ANONYMOUS ACCESS"
# -------------------------------------------------------------
set_vsftpd "anonymous_enable" "NO"
set_vsftpd "no_anon_password" "NO"
set_vsftpd "anon_upload_enable" "NO"
set_vsftpd "anon_mkdir_write_enable" "NO"

# -------------------------------------------------------------
banner "2. LOCAL USER SECURITY"
# -------------------------------------------------------------
set_vsftpd "local_enable" "YES"
set_vsftpd "chroot_local_user" "YES"
set_vsftpd "allow_writeable_chroot" "YES"  # Required if home dir is writeable
set_vsftpd "local_umask" "022"
set_vsftpd "userlist_enable" "YES"
set_vsftpd "userlist_deny" "NO"   # whitelist mode — only listed users can connect

# Whitelist only FTP-relevant users
info "Setting up FTP user whitelist..."
FTP_USERLIST="/etc/vsftpd.userlist"
cat > "$FTP_USERLIST" << 'EOF'
mike
checker
EOF
set_vsftpd "userlist_file" "/etc/vsftpd.userlist"
ok "FTP user whitelist: mike, checker"
warn "Add other users to $FTP_USERLIST if scored service needs them"

# Ban root and system accounts from FTP
info "Updating /etc/ftpusers to ban root and service accounts..."
cat > /etc/ftpusers << 'EOF'
root
daemon
bin
sys
sync
games
man
lp
mail
news
uucp
nobody
www-data
backup
list
irc
gnats
systemd-network
systemd-resolve
sshd
postgres
ftp
EOF
ok "ftpusers updated"

# -------------------------------------------------------------
banner "3. PASSIVE MODE PORT RANGE"
# -------------------------------------------------------------
info "Configuring passive mode port range..."
set_vsftpd "pasv_enable" "YES"
set_vsftpd "pasv_min_port" "49152"
set_vsftpd "pasv_max_port" "49200"

# Get this box's IP for pasv_address
MY_IP=$(hostname -I | awk '{print $1}')
set_vsftpd "pasv_address" "$MY_IP"
warn "Passive ports 49152-49200 must be open in your firewall!"
info "Run: iptables -A INPUT -p tcp --dport 49152:49200 -j ACCEPT"

# -------------------------------------------------------------
banner "4. LOGGING"
# -------------------------------------------------------------
set_vsftpd "xferlog_enable" "YES"
set_vsftpd "xferlog_std_format" "YES"
set_vsftpd "log_ftp_protocol" "YES"
set_vsftpd "vsftpd_log_file" "/var/log/vsftpd.log"
ok "FTP logging enabled → /var/log/vsftpd.log"

# -------------------------------------------------------------
banner "5. CONNECTION LIMITS"
# -------------------------------------------------------------
set_vsftpd "max_clients" "20"
set_vsftpd "max_per_ip" "3"
set_vsftpd "idle_session_timeout" "300"
set_vsftpd "data_connection_timeout" "120"
ok "Connection limits applied"

# -------------------------------------------------------------
banner "6. BANNER"
# -------------------------------------------------------------
set_vsftpd "ftpd_banner" "Authorized users only. All activity logged."
ok "FTP banner set"

# -------------------------------------------------------------
banner "7. RESTART & VERIFY"
# -------------------------------------------------------------
info "Testing vsftpd config..."
vsftpd "$VSFTPD_CONF" &>/dev/null
if [ $? -ne 0 ]; then
    flag "vsftpd config test failed — check $VSFTPD_CONF"
fi

systemctl restart vsftpd
sleep 2

if systemctl is-active --quiet vsftpd; then
    ok "vsftpd is running after hardening"
    info "Test with: ftp $MY_IP"
else
    flag "vsftpd is DOWN after hardening"
    warn "Restoring backup..."
    cp "$BACKUP_DIR/vsftpd.conf.bak" "$VSFTPD_CONF"
    systemctl restart vsftpd
    flag "Backup restored — review config manually"
fi

echo ""
echo -e "${BOLD}FTP HARDENING COMPLETE — $(hostname)${NC}"
echo "Backup: $BACKUP_DIR"
