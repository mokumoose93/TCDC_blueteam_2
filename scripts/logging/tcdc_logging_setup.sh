#!/bin/bash
# =============================================================
# TCDC LOGGING SETUP SCRIPT
# Configures auditd, rsyslog enhanced logging, and fail2ban
# for maximum visibility during competition.
# Usage: sudo bash tcdc_logging_setup.sh
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

echo -e "${BOLD}TCDC LOGGING SETUP — $(hostname)${NC}"
echo -e "Time: $(date)"

# =============================================================
banner "1. INSTALL LOGGING TOOLS"
# =============================================================
info "Installing auditd, fail2ban, rsyslog..."
apt-get install -y auditd audispd-plugins fail2ban rsyslog -qq 2>/dev/null
ok "Logging tools installed"

# =============================================================
banner "2. AUDITD CONFIGURATION"
# =============================================================
info "Configuring auditd rules..."

AUDIT_RULES="/etc/audit/rules.d/tcdc.rules"
cp /etc/audit/rules.d/audit.rules /root/tcdc_backups/audit.rules.bak 2>/dev/null || true

cat > "$AUDIT_RULES" << 'EOF'
# ==============================================
# TCDC auditd rules
# Watches for the most critical events during
# a cyber defense competition
# ==============================================

# Buffer size — increase for busy systems
-b 8192

# Failure mode: 1 = log, 2 = panic
-f 1

# -----------------------------------------------
# IDENTITY & ACCESS CHANGES
# -----------------------------------------------

# Watch /etc/passwd and /etc/shadow for modifications
-w /etc/passwd -p wa -k identity_change
-w /etc/shadow -p wa -k identity_change
-w /etc/group -p wa -k identity_change
-w /etc/gshadow -p wa -k identity_change

# Watch sudoers
-w /etc/sudoers -p wa -k sudoers_change
-w /etc/sudoers.d/ -p wa -k sudoers_change

# Watch SSH authorized_keys (catch planted keys)
-w /root/.ssh -p wa -k ssh_keys
-w /home -p wa -k ssh_keys

# -----------------------------------------------
# PRIVILEGE ESCALATION
# -----------------------------------------------

# Monitor sudo and su usage
-w /usr/bin/sudo -p x -k priv_escalation
-w /usr/bin/su -p x -k priv_escalation
-w /bin/su -p x -k priv_escalation

# Monitor user/group management commands
-w /usr/sbin/useradd -p x -k user_mgmt
-w /usr/sbin/userdel -p x -k user_mgmt
-w /usr/sbin/usermod -p x -k user_mgmt
-w /usr/sbin/groupadd -p x -k user_mgmt
-w /usr/sbin/groupdel -p x -k user_mgmt
-w /usr/sbin/groupmod -p x -k user_mgmt
-w /usr/bin/passwd -p x -k password_change
-w /usr/sbin/chpasswd -p x -k password_change

# -----------------------------------------------
# FILE SYSTEM — SENSITIVE LOCATIONS
# -----------------------------------------------

# Watch cron directories (persistence)
-w /etc/cron.d/ -p wa -k cron_change
-w /etc/cron.daily/ -p wa -k cron_change
-w /etc/cron.hourly/ -p wa -k cron_change
-w /etc/cron.weekly/ -p wa -k cron_change
-w /etc/crontab -p wa -k cron_change
-w /var/spool/cron/ -p wa -k cron_change

# Watch systemd service files (new persistence mechanisms)
-w /etc/systemd/system/ -p wa -k systemd_change
-w /usr/lib/systemd/system/ -p wa -k systemd_change

# Watch /tmp and /dev/shm (common attacker staging areas)
-w /tmp -p xwa -k tmp_exec
-w /dev/shm -p xwa -k shm_exec
-w /var/tmp -p xwa -k tmp_exec

# Watch PAM config (backdoor auth)
-w /etc/pam.d/ -p wa -k pam_change

# Watch SSH config
-w /etc/ssh/sshd_config -p wa -k ssh_config

# -----------------------------------------------
# NETWORK CONFIGURATION
# -----------------------------------------------

# Watch hosts file (DNS poisoning)
-w /etc/hosts -p wa -k hosts_change

# Watch network config
-w /etc/network/ -p wa -k network_change
-w /etc/netplan/ -p wa -k network_change

# Monitor iptables usage
-w /sbin/iptables -p x -k firewall_change
-w /sbin/ip6tables -p x -k firewall_change
-w /usr/sbin/ufw -p x -k firewall_change

# -----------------------------------------------
# EXECUTION MONITORING
# -----------------------------------------------

# Watch for execution from suspicious locations
-a always,exit -F dir=/tmp -F perm=x -F auid>=1000 -k tmp_execution
-a always,exit -F dir=/dev/shm -F perm=x -k shm_execution

# Privilege escalation via SUID
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -k priv_exec
-a always,exit -F arch=b32 -S execve -F euid=0 -F auid>=1000 -k priv_exec

# -----------------------------------------------
# KERNEL MODULE CHANGES (rootkit indicator)
# -----------------------------------------------
-w /sbin/insmod -p x -k kernel_module
-w /sbin/rmmod -p x -k kernel_module
-w /sbin/modprobe -p x -k kernel_module
-a always,exit -F arch=b64 -S init_module -S delete_module -k kernel_module

# Make rules immutable (can't be changed until reboot)
# UNCOMMENT THIS AFTER TESTING — prevents attacker from disabling audit
# -e 2
EOF

ok "auditd rules written to $AUDIT_RULES"

# Load rules and enable service
augenrules --load 2>/dev/null || auditctl -R "$AUDIT_RULES" 2>/dev/null
systemctl enable --now auditd
systemctl restart auditd

if systemctl is-active --quiet auditd; then
    ok "auditd running with TCDC rules"
else
    flag "auditd failed to start — check rules"
fi

# =============================================================
banner "3. FAIL2BAN CONFIGURATION"
# =============================================================
info "Configuring fail2ban jails..."

mkdir -p /etc/fail2ban
cat > /etc/fail2ban/jail.local << 'EOF'
# TCDC fail2ban config
# Aggressive settings for competition environment

[DEFAULT]
bantime  = 3600
findtime = 300
maxretry = 3
backend  = systemd

# -----------------------------------------------
[sshd]
enabled  = true
port     = ssh
logpath  = %(sshd_log)s
maxretry = 3
bantime  = 3600

# -----------------------------------------------
[apache-auth]
enabled  = true
port     = http,https
logpath  = %(apache_error_log)s
maxretry = 5

# -----------------------------------------------
[apache-noscript]
enabled  = true
port     = http,https
logpath  = %(apache_access_log)s

# -----------------------------------------------
[apache-overflows]
enabled  = true
port     = http,https
logpath  = %(apache_error_log)s
maxretry = 2

# -----------------------------------------------
[nginx-http-auth]
enabled  = true
port     = http,https
logpath  = %(nginx_error_log)s

# -----------------------------------------------
[nginx-noscript]
enabled  = true
port     = http,https
logpath  = %(nginx_access_log)s

# -----------------------------------------------
[vsftpd]
enabled  = true
port     = ftp,ftp-data,ftps,ftps-data
logpath  = %(vsftpd_log)s
maxretry = 3

# -----------------------------------------------
[postgresql]
enabled  = true
port     = 5432
logpath  = /var/log/postgresql/postgresql-*.log
maxretry = 5
EOF

systemctl enable --now fail2ban
systemctl restart fail2ban

sleep 2
if systemctl is-active --quiet fail2ban; then
    ok "fail2ban running"
    fail2ban-client status 2>/dev/null | grep "Jail list" | while read -r line; do
        info "$line"
    done
else
    flag "fail2ban failed to start"
fi

# =============================================================
banner "4. RSYSLOG ENHANCED LOGGING"
# =============================================================
info "Configuring rsyslog for enhanced logging..."

cat > /etc/rsyslog.d/49-tcdc.conf << 'EOF'
# TCDC Enhanced rsyslog rules
# Captures auth events, cron, kernel, and all errors

# Auth events (SSH, sudo, PAM, login)
auth,authpriv.*                 /var/log/auth.log

# All kernel messages
kern.*                          /var/log/kern.log

# Cron activity
cron.*                          /var/log/cron.log

# Emergency messages to all logged-in users
*.emerg                         :omusrmsg:*

# All errors and above to a dedicated file
*.err;kern.none;mail.none       /var/log/tcdc_errors.log

# Everything to syslog
*.*                             /var/log/syslog
EOF

systemctl restart rsyslog
ok "rsyslog enhanced logging configured"

# =============================================================
banner "5. BASH HISTORY HARDENING"
# =============================================================
info "Configuring enhanced bash history for all users..."

HISTORY_CONFIG='
# TCDC — Enhanced bash history
export HISTSIZE=10000
export HISTFILESIZE=20000
export HISTTIMEFORMAT="%Y-%m-%d %H:%M:%S "
export HISTCONTROL=""          # Log everything including duplicates
shopt -s histappend            # Append instead of overwrite
PROMPT_COMMAND="history -a"   # Write every command immediately
'

# Apply to all relevant users
for user in root alice bob craig chad trudy mallory mike yves judy sybil walter wendy; do
    homedir=$(getent passwd "$user" 2>/dev/null | cut -d: -f6)
    [ -z "$homedir" ] || [ ! -d "$homedir" ] && continue
    rcfile="$homedir/.bashrc"
    if [ -f "$rcfile" ]; then
        if ! grep -q "TCDC — Enhanced bash history" "$rcfile"; then
            echo "$HISTORY_CONFIG" >> "$rcfile"
            ok "Enhanced history for $user"
        fi
    fi
done

# Apply to /etc/profile for all future sessions
if ! grep -q "TCDC" /etc/profile; then
    echo "$HISTORY_CONFIG" >> /etc/profile
    ok "Enhanced history added to /etc/profile"
fi

# =============================================================
banner "6. LOG ROTATION CHECK"
# =============================================================
info "Verifying logrotate is configured..."
if [ -f /etc/logrotate.conf ]; then
    ok "logrotate.conf exists"
else
    warn "logrotate.conf not found"
fi

# Add rotation for TCDC-specific logs
cat > /etc/logrotate.d/tcdc << 'EOF'
/var/log/tcdc_*.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
    copytruncate
}
EOF
ok "Log rotation configured for TCDC logs"

# =============================================================
banner "SETUP COMPLETE"
# =============================================================
echo ""
ok "Logging stack configured on $(hostname):"
info "  auditd  → /var/log/audit/audit.log"
info "  auth    → /var/log/auth.log"
info "  syslog  → /var/log/syslog"
info "  errors  → /var/log/tcdc_errors.log"
info "  fail2ban→ /var/log/fail2ban.log"
echo ""
info "Use tcdc_log_monitor.sh to watch all logs in real time."
