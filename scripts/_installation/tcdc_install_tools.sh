#!/bin/bash
# =============================================================
# TCDC TOOL INSTALLATION & CONFIGURATION SCRIPT
# Installs and configures all Tier 1 + optional Tier 2 tools
# for TCDC competition. Safe on all 5 boxes.
#
# Tools covered:
#   Tier 1: fail2ban, auditd, lynis, chkrootkit, rkhunter,
#           debsums, aide, rsyslog, lsof, psad, logwatch,
#           libpam-pwquality, tcpdump, net-tools, htop
#   Tier 2: suricata (IDS mode only), clamav
#
# Usage: sudo bash tcdc_install_tools.sh
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
    echo -e "\n${BOLD}${BLU}============================================${NC}"
    echo -e "${BOLD}${BLU}  $1${NC}"
    echo -e "${BOLD}${BLU}============================================${NC}"
}

[ "$(id -u)" -ne 0 ] && echo "Must be run as root." && exit 1

HOSTNAME=$(hostname)
LOG_FILE="/var/log/tcdc_install.log"
BACKUP_DIR="/root/tcdc_backups/install_$(date +%s)"
mkdir -p "$BACKUP_DIR"

echo -e "${BOLD}TCDC TOOL INSTALLATION — $HOSTNAME${NC}"
echo -e "Time: $(date)"
echo -e "Log:  $LOG_FILE"
echo ""

log() { echo "[$(date '+%H:%M:%S')] $1" >> "$LOG_FILE"; }

# =============================================================
# PRE-FLIGHT CHECKS
# =============================================================
banner "PRE-FLIGHT CHECKS"

# Check internet access (tools need to download)
if curl -s --connect-timeout 5 https://archive.ubuntu.com > /dev/null 2>&1; then
    ok "Internet connectivity confirmed"
else
    flag "No internet access detected — apt installs may fail"
    warn "You may need to use a local mirror or pre-downloaded packages"
fi

# Check disk space (need at least 500MB)
FREE_MB=$(df / | awk 'NR==2 {print int($4/1024)}')
if [ "$FREE_MB" -lt 500 ]; then
    flag "Low disk space: ${FREE_MB}MB free — installs may fail"
else
    ok "Disk space OK: ${FREE_MB}MB free"
fi

# Check if Wazuh is already running (don't conflict with it)
if systemctl is-active --quiet wazuh-agent 2>/dev/null || \
   systemctl is-active --quiet wazuh-manager 2>/dev/null; then
    warn "Wazuh is already running on this box — skipping OSSEC/conflicting tools"
    warn "Per TCDC rules: do not impersonate or attack Wazuh"
    WAZUH_RUNNING=true
else
    info "Wazuh not detected — safe to install independent HIDS tools"
    WAZUH_RUNNING=false
fi

# Ask about optional tools
echo ""
info "Installation options:"
read -rp "Install Suricata IDS? (yes/no) [recommended if you know it]: " INSTALL_SURICATA
read -rp "Install ClamAV antivirus? (yes/no) [slow on large dirs]: " INSTALL_CLAMAV
read -rp "Enter checker's IP to whitelist (or press Enter to skip): " CHECKER_IP

echo ""
info "Starting installation..."

# =============================================================
banner "1. SYSTEM UPDATE"
# =============================================================
info "Updating package lists..."
apt-get update -qq 2>&1 | tail -1
ok "Package lists updated"
log "Package lists updated"

# =============================================================
banner "2. TIER 1 — CORE SECURITY TOOLS"
# =============================================================

install_pkg() {
    local pkg="$1"
    local desc="$2"
    info "Installing $pkg ($desc)..."
    if apt-get install -y "$pkg" -qq 2>/dev/null; then
        ok "$pkg installed"
        log "Installed: $pkg"
    else
        flag "Failed to install $pkg"
        log "FAILED: $pkg"
    fi
}

install_pkg "fail2ban"          "brute-force protection"
install_pkg "auditd"            "syscall-level audit logging"
install_pkg "audispd-plugins"   "auditd plugins"
install_pkg "lynis"             "security auditing scanner"
install_pkg "chkrootkit"        "rootkit detection"
install_pkg "rkhunter"          "rootkit and backdoor hunter"
install_pkg "debsums"           "package file integrity checker"
install_pkg "aide"              "file integrity monitoring"
install_pkg "rsyslog"           "enhanced system logging"
install_pkg "net-tools"         "netstat, ifconfig"
install_pkg "lsof"              "open files and port inspection"
install_pkg "htop"              "interactive process viewer"
install_pkg "tcpdump"           "packet capture"
install_pkg "psad"              "port scan attack detector"
install_pkg "logwatch"          "log summarizer"
install_pkg "libpam-pwquality"  "password quality enforcement"
install_pkg "curl"              "HTTP client"
install_pkg "wget"              "file downloader"

# =============================================================
banner "3. CONFIGURE FAIL2BAN"
# =============================================================
info "Configuring fail2ban jails..."

# Backup existing config
[ -f /etc/fail2ban/jail.local ] && cp /etc/fail2ban/jail.local "$BACKUP_DIR/jail.local.bak"

# Build ignoreip list
IGNORE_IPS="127.0.0.1/8 ::1"
if [ -n "$CHECKER_IP" ]; then
    IGNORE_IPS="$IGNORE_IPS $CHECKER_IP"
    ok "Checker IP $CHECKER_IP will be whitelisted in fail2ban"
fi

cat > /etc/fail2ban/jail.local << EOF
# TCDC fail2ban configuration
# Generated by tcdc_install_tools.sh on $(date)

[DEFAULT]
bantime   = 3600
findtime  = 300
maxretry  = 3
backend   = systemd
ignoreip  = $IGNORE_IPS

# -----------------------------------------------
[sshd]
enabled   = true
port      = ssh
logpath   = %(sshd_log)s
maxretry  = 3
bantime   = 3600

# -----------------------------------------------
[apache-auth]
enabled   = true
port      = http,https
logpath   = %(apache_error_log)s
maxretry  = 5

# -----------------------------------------------
[apache-noscript]
enabled   = true
port      = http,https
logpath   = %(apache_access_log)s

# -----------------------------------------------
[apache-overflows]
enabled   = true
port      = http,https
logpath   = %(apache_error_log)s
maxretry  = 2

# -----------------------------------------------
[apache-badbots]
enabled   = true
port      = http,https
logpath   = %(apache_access_log)s
maxretry  = 2

# -----------------------------------------------
[nginx-http-auth]
enabled   = true
port      = http,https
logpath   = %(nginx_error_log)s

# -----------------------------------------------
[nginx-noscript]
enabled   = true
port      = http,https
logpath   = %(nginx_access_log)s

# -----------------------------------------------
[vsftpd]
enabled   = true
port      = ftp,ftp-data,ftps,ftps-data
logpath   = %(vsftpd_log)s
maxretry  = 3

# -----------------------------------------------
[postgresql]
enabled   = true
port      = 5432
logpath   = /var/log/postgresql/postgresql-*.log
maxretry  = 5
EOF

systemctl enable --now fail2ban
systemctl restart fail2ban
sleep 2

if systemctl is-active --quiet fail2ban; then
    ok "fail2ban running with TCDC jails"
    fail2ban-client status 2>/dev/null | grep "Jail list" | while read -r line; do
        info "  $line"
    done
else
    flag "fail2ban failed to start — check /var/log/fail2ban.log"
fi

# =============================================================
banner "4. CONFIGURE AUDITD"
# =============================================================
info "Writing auditd rules..."

AUDIT_RULES="/etc/audit/rules.d/tcdc.rules"
[ -f "$AUDIT_RULES" ] && cp "$AUDIT_RULES" "$BACKUP_DIR/tcdc_audit.rules.bak"

cat > "$AUDIT_RULES" << 'EOF'
# TCDC auditd rules
-D
-b 8192
-f 1

# Identity changes
-w /etc/passwd -p wa -k identity_change
-w /etc/shadow -p wa -k identity_change
-w /etc/group -p wa -k identity_change
-w /etc/gshadow -p wa -k identity_change

# Sudoers
-w /etc/sudoers -p wa -k sudoers_change
-w /etc/sudoers.d/ -p wa -k sudoers_change

# SSH keys
-w /root/.ssh -p wa -k ssh_keys
-w /home -p wa -k ssh_keys

# Privilege escalation commands
-w /usr/bin/sudo -p x -k priv_escalation
-w /usr/bin/su -p x -k priv_escalation
-w /bin/su -p x -k priv_escalation

# User/group management
-w /usr/sbin/useradd -p x -k user_mgmt
-w /usr/sbin/userdel -p x -k user_mgmt
-w /usr/sbin/usermod -p x -k user_mgmt
-w /usr/bin/passwd -p x -k password_change
-w /usr/sbin/chpasswd -p x -k password_change

# Cron persistence
-w /etc/cron.d/ -p wa -k cron_change
-w /etc/cron.daily/ -p wa -k cron_change
-w /etc/cron.hourly/ -p wa -k cron_change
-w /etc/crontab -p wa -k cron_change
-w /var/spool/cron/ -p wa -k cron_change

# Systemd persistence
-w /etc/systemd/system/ -p wa -k systemd_change

# Temp execution (common attacker staging area)
-w /tmp -p xwa -k tmp_exec
-w /dev/shm -p xwa -k shm_exec
-w /var/tmp -p xwa -k tmp_exec

# PAM backdoor detection
-w /etc/pam.d/ -p wa -k pam_change

# SSH config
-w /etc/ssh/sshd_config -p wa -k ssh_config

# Network config
-w /etc/hosts -p wa -k hosts_change
-w /etc/netplan/ -p wa -k network_change

# Firewall changes
-w /sbin/iptables -p x -k firewall_change
-w /usr/sbin/ufw -p x -k firewall_change

# Kernel modules (rootkit indicator)
-w /sbin/insmod -p x -k kernel_module
-w /sbin/rmmod -p x -k kernel_module
-w /sbin/modprobe -p x -k kernel_module

# Privilege exec (SUID usage)
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -k priv_exec
-a always,exit -F arch=b32 -S execve -F euid=0 -F auid>=1000 -k priv_exec
EOF

augenrules --load 2>/dev/null || auditctl -R "$AUDIT_RULES" 2>/dev/null
systemctl enable --now auditd
systemctl restart auditd

if systemctl is-active --quiet auditd; then
    ok "auditd running with TCDC rules"
    RULE_COUNT=$(auditctl -l 2>/dev/null | wc -l)
    info "  $RULE_COUNT audit rules loaded"
else
    flag "auditd failed to start"
fi

# =============================================================
banner "5. CONFIGURE PSAD (Port Scan Attack Detector)"
# =============================================================
info "Configuring psad..."

PSAD_CONF="/etc/psad/psad.conf"
[ -f "$PSAD_CONF" ] && cp "$PSAD_CONF" "$BACKUP_DIR/psad.conf.bak"

if [ -f "$PSAD_CONF" ]; then
    # Set email to root (no external email needed)
    sed -i 's/^EMAIL_ADDRESSES.*/EMAIL_ADDRESSES             root@localhost;/' "$PSAD_CONF"

    # Set hostname
    sed -i "s/^HOSTNAME.*/HOSTNAME                    $HOSTNAME;/" "$PSAD_CONF"

    # Whitelist checker IP if provided
    if [ -n "$CHECKER_IP" ]; then
        PSAD_WHITELIST="/etc/psad/auto_dl"
        echo "$CHECKER_IP  0;" >> "$PSAD_WHITELIST"
        ok "Whitelisted checker IP $CHECKER_IP in psad"
    fi

    # Enable email alerts for scans
    sed -i 's/^ENABLE_AUTO_IDS.*/ENABLE_AUTO_IDS             N;/' "$PSAD_CONF"  # No auto-block

    # Update iptables to log (required for psad)
    iptables -A INPUT -j LOG --log-prefix "iptables: " --log-level 4 2>/dev/null
    iptables -A FORWARD -j LOG --log-prefix "iptables: " --log-level 4 2>/dev/null

    systemctl enable --now psad
    systemctl restart psad

    if systemctl is-active --quiet psad; then
        ok "psad running (detection only — no auto-block)"
    else
        warn "psad failed to start — non-critical, continuing"
    fi
else
    warn "psad config not found — skipping psad configuration"
fi

# =============================================================
banner "6. CONFIGURE AIDE (File Integrity)"
# =============================================================
info "Initializing AIDE database (this takes ~2 minutes)..."

if command -v aide &>/dev/null; then
    # Backup existing AIDE config
    [ -f /etc/aide/aide.conf ] && cp /etc/aide/aide.conf "$BACKUP_DIR/aide.conf.bak"

    # Initialize the AIDE database in background
    # (takes time — don't wait for it, let it run)
    aide --init --config /etc/aide/aide.conf > /var/log/tcdc_aide_init.log 2>&1 &
    AIDE_PID=$!
    ok "AIDE initialization started in background (PID: $AIDE_PID)"
    ok "Database will be ready at: /var/lib/aide/aide.db.new"
    warn "Run after init completes: cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db"
    warn "Then check with: aide --check"
else
    warn "AIDE not installed — skipping"
fi

# =============================================================
banner "7. CONFIGURE RKHUNTER"
# =============================================================
info "Updating rkhunter and building baseline..."

if command -v rkhunter &>/dev/null; then
    rkhunter --update --nocolors 2>/dev/null | tail -5
    rkhunter --propupd --nocolors 2>/dev/null  # Build property database
    ok "rkhunter database updated"
    info "Run anytime: rkhunter --check --report-warnings-only"
else
    warn "rkhunter not found"
fi

# =============================================================
banner "8. CONFIGURE PAM PASSWORD QUALITY"
# =============================================================
info "Setting password quality policy..."

PQ_CONF="/etc/security/pwquality.conf"
[ -f "$PQ_CONF" ] && cp "$PQ_CONF" "$BACKUP_DIR/pwquality.conf.bak"

cat > "$PQ_CONF" << 'EOF'
# TCDC password quality settings
minlen   = 12
dcredit  = -1
ucredit  = -1
ocredit  = -1
lcredit  = -1
maxrepeat = 3
EOF

ok "Password quality policy applied (min 12 chars, requires upper/lower/digit/special)"

# =============================================================
banner "9. CONFIGURE RSYSLOG"
# =============================================================
info "Configuring enhanced rsyslog..."

cat > /etc/rsyslog.d/49-tcdc.conf << 'EOF'
# TCDC Enhanced rsyslog
auth,authpriv.*                 /var/log/auth.log
kern.*                          /var/log/kern.log
cron.*                          /var/log/cron.log
*.err;kern.none;mail.none       /var/log/tcdc_errors.log
*.emerg                         :omusrmsg:*
EOF

systemctl restart rsyslog
ok "rsyslog enhanced logging configured"

# =============================================================
banner "10. OPTIONAL — CLAMAV ANTIVIRUS"
# =============================================================
if [ "$INSTALL_CLAMAV" = "yes" ]; then
    info "Installing ClamAV..."
    apt-get install -y clamav clamav-daemon -qq

    info "Updating virus definitions (this takes a moment)..."
    systemctl stop clamav-freshclam 2>/dev/null
    freshclam --quiet 2>/dev/null &
    CLAM_PID=$!
    ok "ClamAV virus definition update started (PID: $CLAM_PID)"
    ok "Scan command: clamscan -r --bell -i /home /tmp /var/www"
    warn "Full system scan is slow — target specific directories"
else
    info "ClamAV skipped"
fi

# =============================================================
banner "11. OPTIONAL — SURICATA IDS"
# =============================================================
if [ "$INSTALL_SURICATA" = "yes" ]; then
    info "Installing Suricata..."
    apt-get install -y suricata suricata-update -qq

    if command -v suricata &>/dev/null; then
        ok "Suricata installed"
        info "Running Suricata rule update..."
        suricata-update 2>/dev/null | tail -5

        # Detect primary interface
        PRIMARY_IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
        info "Detected primary interface: $PRIMARY_IFACE"

        ok "Suricata installed — configure with: sudo bash tcdc_suricata_config.sh"
        warn "DO NOT start Suricata until tcdc_suricata_config.sh has been run"
        warn "IDS mode only — never use nfqueue/IPS mode in TCDC"
    else
        flag "Suricata installation failed"
    fi
else
    info "Suricata skipped — run tcdc_suricata_config.sh separately if needed"
fi

# =============================================================
banner "12. CHECKER IP WHITELIST (All Tools)"
# =============================================================
if [ -n "$CHECKER_IP" ]; then
    info "Whitelisting checker IP $CHECKER_IP across all tools..."

    # iptables — allow checker before any DROP rules
    iptables -I INPUT 1 -s "$CHECKER_IP" -j ACCEPT
    ok "iptables: checker $CHECKER_IP whitelisted"

    # fail2ban already configured above

    # rkhunter — add to whitelist
    if [ -f /etc/rkhunter.conf ]; then
        echo "ALLOWHIDDENDIR=/proc" >> /etc/rkhunter.conf
    fi

    # Record checker IP for other scripts
    echo "$CHECKER_IP" > /root/tcdc_backups/checker_ip.txt
    ok "Checker IP saved to /root/tcdc_backups/checker_ip.txt"
else
    warn "No checker IP provided — whitelist manually once you identify it:"
    warn "  tail -f /var/log/auth.log | grep checker"
    warn "  Then: iptables -I INPUT 1 -s <IP> -j ACCEPT"
    warn "  And: fail2ban-client set sshd unbanip <IP>"
fi

# =============================================================
banner "RUNNING INITIAL SCANS"
# =============================================================
info "Running Lynis quick audit..."
lynis audit system --quiet --no-colors 2>/dev/null | \
    grep -E "Warning|Suggestion|Danger" | head -15 | while read -r line; do
    warn "Lynis: $line"
done
ok "Full Lynis log: /var/log/lynis.log"

echo ""
info "Running chkrootkit..."
chkrootkit 2>/dev/null | grep -v "not found\|not infected\|nothing found" | \
    grep -E "INFECTED|Suspect|WARNING" | while read -r line; do
    flag "chkrootkit: $line"
done
ok "chkrootkit scan complete"

echo ""
info "Running rkhunter..."
rkhunter --check --skip-keypress --report-warnings-only --nocolors 2>/dev/null | \
    head -20 | while read -r line; do
    [ -n "$line" ] && warn "rkhunter: $line"
done
ok "rkhunter scan complete"

echo ""
info "Running debsums integrity check..."
DEBSUMS_FAILS=$(debsums -s 2>/dev/null | wc -l)
if [ "$DEBSUMS_FAILS" -gt 0 ]; then
    flag "$DEBSUMS_FAILS package files failed integrity check:"
    debsums -s 2>/dev/null | while read -r line; do
        flag "  $line"
    done
else
    ok "debsums: all package files intact"
fi

# =============================================================
banner "INSTALLATION SUMMARY"
# =============================================================
echo ""
echo -e "${BOLD}Tools installed on $HOSTNAME:${NC}"
echo ""

for tool in fail2ban auditd lynis chkrootkit rkhunter debsums aide \
            rsyslog lsof psad logwatch tcpdump suricata clamav; do
    if command -v "$tool" &>/dev/null || systemctl list-units --type=service | grep -q "$tool"; then
        ok "$tool"
    else
        info "$tool — not installed (optional or failed)"
    fi
done

echo ""
echo -e "${BOLD}Services running:${NC}"
for svc in fail2ban auditd rsyslog psad suricata clamav-daemon; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        ok "$svc — active"
    else
        info "$svc — not running"
    fi
done

echo ""
warn "NEXT STEPS:"
info "  1. Run: sudo bash tcdc_suricata_config.sh  (if Suricata was installed)"
info "  2. Run: sudo bash tcdc_iam_harden.sh"
info "  3. Run: sudo bash tcdc_harden_web.sh / tcdc_harden_ftp.sh / tcdc_harden_postgres.sh"
info "  4. Run: sudo bash tcdc_vuln_scan.sh"
info "  5. Start watchdogs: tcdc_iam_watchdog.sh, tcdc_service_watchdog.sh, tcdc_vuln_watchdog.sh"
echo ""
ok "Installation complete — log saved to $LOG_FILE"
