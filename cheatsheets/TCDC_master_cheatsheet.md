# TCDC Tools & Commands Cheat Sheet

> **Competition:** Texas Cyber Defense Challenge (TCDC) 2026
> **Environment:** Ubuntu Server 24 | 5 Boxes | Red vs. Blue
> **Scoring:** 80% Uptime / 20% Injects | Ticks every 30 seconds

---

## ⚡ First 5 Minutes Checklist

Run these on **every box** the moment you get access:

```bash
# 1. Change all passwords immediately
sudo bash tcdc_passwd_reset.sh

# 2. Audit users and sudoers
sudo bash tcdc_iam_audit.sh | tee /tmp/iam_$(hostname).txt

# 3. Audit all services
sudo bash tcdc_service_audit.sh | tee /tmp/svc_$(hostname).txt

# 4. Check open ports
ss -tulnp

# 5. Check who is logged in
who && w && last | head -10

# 6. Check for UID 0 backdoors
awk -F: '($3==0){print}' /etc/passwd

# 7. Check sudoers
cat /etc/sudoers && ls /etc/sudoers.d/

# 8. Audit SSH keys
find / -name "authorized_keys" 2>/dev/null -exec cat {} \;

# 9. Start watchdogs
sudo bash tcdc_iam_watchdog.sh &
sudo bash tcdc_service_watchdog.sh &
sudo bash tcdc_vuln_watchdog.sh &
sudo bash tcdc_log_monitor.sh all &
```

---

## 🖥️ Terminal Layout for Competition Day

```
Terminal 1 → sudo bash tcdc_log_monitor.sh all        # Live log events
Terminal 2 → sudo bash tcdc_service_watchdog.sh       # Scored service uptime
Terminal 3 → sudo bash tcdc_iam_watchdog.sh           # IAM changes
Terminal 4 → sudo bash tcdc_vuln_watchdog.sh          # New vulnerabilities
Terminal 5 → Free for manual work / injects
```

---

## 📦 TCDC Script Reference

All custom scripts written for this competition. Run as root.

| Script | Category | Purpose | Run When |
|---|---|---|---|
| `tcdc_iam_audit.sh` | IAM | Read-only IAM snapshot — users, sudo, SSH keys, PAM | First thing on every box |
| `tcdc_iam_harden.sh` | IAM | Applies IAM fixes — unknown users, sudo, SSH keys, PAM | After audit |
| `tcdc_passwd_reset.sh` | IAM | Bulk password reset for all 12 TCDC users | **Absolute first action** |
| `tcdc_iam_watchdog.sh` | IAM | Continuous monitor — new users, sudo changes, SSH keys | Leave running all day |
| `tcdc_service_audit.sh` | Services | Audits all 5 scored services for misconfigs | After IAM hardening |
| `tcdc_harden_web.sh` | Services | Hardens Apache/Nginx — headers, modules, directory listing | centurytree & bonfire |
| `tcdc_harden_ftp.sh` | Services | Hardens vsftpd — anon login, chroot, passive ports | aggiedrop |
| `tcdc_harden_postgres.sh` | Services | Hardens PostgreSQL — pg_hba, listen_addresses, passwords | excel |
| `tcdc_service_watchdog.sh` | Services | Monitors scored services, auto-restarts on failure | Leave running all day |
| `tcdc_logging_setup.sh` | Logging | Configures auditd, fail2ban, rsyslog, bash history | Once, early in competition |
| `tcdc_log_monitor.sh` | Logging | Color-coded real-time multi-log viewer | Leave running all day |
| `tcdc_log_analysis.sh` | Logging | Analyzes last N hours of logs for threats | After an incident, or periodically |
| `tcdc_log_cheatsheet.sh` | Logging | Prints all log one-liners to terminal | Reference / print before competition |
| `tcdc_vuln_scan.sh` | Vuln Mgmt | Full vulnerability scan — SUID, world-write, kernel, packages | After initial hardening |
| `tcdc_vuln_fix.sh` | Vuln Mgmt | Applies automated fixes from scan results | After vuln scan |
| `tcdc_vuln_watchdog.sh` | Vuln Mgmt | Watches for new vulns introduced during competition | Leave running all day |

---

---

# 🔐 Category 1: Identity & Access Management

## User Auditing

```bash
# Full /etc/passwd contents
cat /etc/passwd

# Find ALL UID 0 accounts (should only be root)
awk -F: '($3==0){print}' /etc/passwd

# List users with real login shells
grep -v '/nologin\|/false\|/sync' /etc/passwd

# List all users and their last login
lastlog

# Who is logged in right now?
who
w

# Full login history
last | head -30

# Failed login history
lastb | head -20

# Check account lock status (! = locked)
grep username /etc/shadow

# Full IAM snapshot one-liner
echo "=UID0=" && awk -F:'($3==0){print}' /etc/passwd; \
echo "=SUDO=" && getent group sudo wheel; \
echo "=SHELLS=" && grep -v 'nologin\|false' /etc/passwd; \
echo "=KEYS=" && find / -name "authorized_keys" 2>/dev/null
```

## User Management

```bash
# Lock an account
usermod -L username
passwd -l username

# Unlock an account
usermod -U username

# Delete a user and their home directory
userdel -r username

# Change a user's shell to nologin
usermod -s /usr/sbin/nologin username

# Change a user's UID (move away from 0)
usermod -u 1500 username

# Force password change on next login
chage -d 0 username

# View password aging info
chage -l username

# Set max password age
chage -M 90 username

# Kick an active session by TTY
pkill -kill -t pts/1

# Find and kill a session by PID
ps aux | grep pts/1
kill -9 <PID>
```

## Password Management

```bash
# Change a single password
passwd username

# Bulk change via chpasswd
echo "username:newpassword" | chpasswd

# Bulk change multiple users
for user in alice bob craig; do
    echo "$user:NewPass2026!" | chpasswd
done
```

## Sudo & Privilege Management

```bash
# View sudoers safely
visudo -c          # Check for syntax errors
cat /etc/sudoers

# List drop-in sudoers files
ls -la /etc/sudoers.d/
cat /etc/sudoers.d/*

# Check a specific user's sudo rights
sudo -l -U alice

# Check sudo group membership
getent group sudo
getent group wheel
getent group admin

# Remove user from sudo group
gpasswd -d username sudo

# Check all privileged group memberships at once
cat /etc/group | grep -E 'sudo|wheel|admin|root'
```

## SSH Key Management

```bash
# Find ALL authorized_keys files
find / -name "authorized_keys" 2>/dev/null

# View root's keys
cat /root/.ssh/authorized_keys

# Audit all users' keys
for user in alice bob craig mike; do
    file="/home/$user/.ssh/authorized_keys"
    [ -f "$file" ] && echo "==$user==" && cat "$file"
done

# Clear a user's authorized keys
> /home/username/.ssh/authorized_keys

# Fix SSH directory permissions
chmod 700 /home/username/.ssh
chmod 600 /home/username/.ssh/authorized_keys

# Test sshd config before restarting (ALWAYS do this)
sshd -t

# Reload SSH without dropping connections
systemctl reload sshd
```

## PAM

```bash
# View PAM configs
ls /etc/pam.d/
cat /etc/pam.d/sshd
cat /etc/pam.d/common-auth

# Check for dangerous pam_permit.so entries
grep -r 'pam_permit.so' /etc/pam.d/ | grep 'sufficient'

# View password quality settings
cat /etc/security/pwquality.conf
```

---

---

# 🌐 Category 2: Networking & Firewall

## Network Reconnaissance

```bash
# All listening ports with process names
ss -tulnp

# All established connections
ss -tp state established

# Check for unexpected outbound connections
ss -tp state established | grep -v "127.0.0.1\|10.66.X"

# ARP table
arp -a
arp -n

# Routing table
ip route show

# Interface info
ip addr show

# Live packet capture
tcpdump -i eth0 -n

# Capture filtering (exclude known services)
tcpdump -i eth0 -n 'not port 22 and not port 80 and not port 443'

# Save capture for later analysis
tcpdump -i eth0 -w /tmp/capture.pcap

# Self-scan to see exposure
nmap -sV -p- localhost
nmap -F localhost
```

## iptables

```bash
# View all rules
iptables -L -v -n

# View with line numbers
iptables -L --line-numbers

# Flush all rules (careful!)
iptables -F

# Set default policies (NEVER set OUTPUT to DROP — TCDC rule)
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT     # ← REQUIRED by TCDC rules

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow specific port
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT

# Allow from specific subnet
iptables -A INPUT -p tcp -s 10.66.X.0/24 --dport 5432 -j ACCEPT

# Block specific outbound IP (TCDC-compliant — single IP + port)
iptables -A OUTPUT -d <malicious_ip> -p tcp --dport <port> -j DROP

# Log and drop
iptables -A INPUT -j LOG --log-prefix "IPT-DROP: "
iptables -A INPUT -j DROP

# Save rules (Debian/Ubuntu)
iptables-save > /etc/iptables/rules.v4

# Restore rules
iptables-restore < /etc/iptables/rules.v4
```

> ⚠️ **TCDC Rule:** No broad outgoing deny. Outgoing rules must be single IP + port only.

## ufw (Simpler Alternative)

```bash
# Enable ufw
ufw enable

# Set defaults
ufw default deny incoming
ufw default allow outgoing    # ← REQUIRED by TCDC rules

# Allow specific services
ufw allow ssh
ufw allow 80/tcp
ufw allow from 10.66.X.0/24 to any port 5432

# Check status
ufw status verbose

# Disable temporarily
ufw disable
```

## fail2ban

```bash
# Check all jail status
fail2ban-client status

# Check specific jail
fail2ban-client status sshd

# Manually ban an IP
fail2ban-client set sshd banip 10.66.2.99

# Unban an IP
fail2ban-client set sshd unbanip 10.66.2.99

# Reload config
fail2ban-client reload

# Watch fail2ban log live
tail -f /var/log/fail2ban.log

# Restart fail2ban
systemctl restart fail2ban
```

---

---

# 🛡️ Category 3: Service Hardening

## Apache / Nginx

```bash
# Test config before restarting (ALWAYS)
apache2ctl configtest
nginx -t

# Graceful reload (no dropped connections)
systemctl reload apache2
systemctl reload nginx

# Check loaded modules
apache2ctl -M

# Disable dangerous module
a2dismod autoindex status info userdir
systemctl reload apache2

# Enable a module
a2enmod headers ssl
systemctl reload apache2

# Find exposed .git or .env files in webroot
find /var/www -name ".git" -o -name ".env" 2>/dev/null

# Watch access log for attacks
tail -f /var/log/apache2/access.log | grep --color -E 'TRACE|PUT|DELETE|\.\.\/|\.git|\.env'

# Watch error log
tail -f /var/log/apache2/error.log

# Top requesting IPs
awk '{print $1}' /var/log/apache2/access.log | sort | uniq -c | sort -rn | head -10

# Scan for web attack patterns
grep -iE 'union.*select|<script|base64|etc/passwd|\.\.\/' /var/log/apache2/access.log | tail -10
```

**Key Apache hardening settings** (`/etc/apache2/conf-available/security.conf`):
```apache
ServerTokens Prod
ServerSignature Off
TraceEnable Off
Options -Indexes
```

## FTP (vsftpd)

```bash
# Check if anonymous FTP is on (bad)
grep "anonymous_enable" /etc/vsftpd.conf

# Disable anonymous login fast
sed -i 's/anonymous_enable=YES/anonymous_enable=NO/' /etc/vsftpd.conf

# Test config
vsftpd /etc/vsftpd.conf

# Restart vsftpd
systemctl restart vsftpd

# Check FTP connections
ss -tnp | grep ':21'

# Watch FTP log live
tail -f /var/log/vsftpd.log

# Check FTP ban list
cat /etc/ftpusers

# Add user to FTP ban list
echo "baduser" >> /etc/ftpusers
```

**Key vsftpd hardening settings** (`/etc/vsftpd.conf`):
```ini
anonymous_enable=NO
chroot_local_user=YES
xferlog_enable=YES
pasv_min_port=49152
pasv_max_port=49200
ssl_enable=YES
```

> ⚠️ **Passive mode:** Firewall must allow ports 49152-49200 or FTP transfers will fail the uptime check.

## SSH

```bash
# Test config (ALWAYS before restart)
sshd -t

# Reload without dropping connections
systemctl reload sshd

# View current config
cat /etc/ssh/sshd_config | grep -v '^#\|^$'

# Check what ciphers are offered
ssh -Q cipher
ssh -Q mac

# Watch auth log for brute force
tail -f /var/log/auth.log | grep sshd

# Count brute force attempts by IP
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn | head

# Check active SSH sessions
ss -tnp | grep ':22'
who | grep pts
```

**Key sshd_config hardening settings:**
```ini
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 30
Protocol 2
AllowUsers mike checker    # ← Always include checker!
```

> ⚠️ **reveille-remote:** SSH IS the scored service. Never block port 22. Always include `checker` in AllowUsers.

## PostgreSQL

```bash
# Connect as postgres superuser
sudo -u postgres psql

# List databases
sudo -u postgres psql -c "\l"

# List roles
sudo -u postgres psql -c "\du"

# Change postgres password (do immediately)
sudo -u postgres psql -c "ALTER USER postgres PASSWORD 'newpassword';"

# Check active connections
sudo -u postgres psql -c "SELECT usename,client_addr,state FROM pg_stat_activity;"

# Check what's listening on 5432
ss -tulnp | grep 5432

# Show config file locations
sudo -u postgres psql -c "SHOW hba_file;"
sudo -u postgres psql -c "SHOW config_file;"

# Reload config without restart
sudo -u postgres psql -c "SELECT pg_reload_conf();"

# Restart postgres
systemctl restart postgresql

# Watch postgres log
tail -f /var/log/postgresql/postgresql-*.log
```

**Key pg_hba.conf hardening** (`/etc/postgresql/*/main/pg_hba.conf`):
```
# Only allow your team subnet — no wildcards
local   all   postgres               peer
host    all   all   127.0.0.1/32     md5
host    all   all   10.66.X.0/24     md5
# No 0.0.0.0/0 entry!
```

## Node.js / React

```bash
# Find Node process and start command
ps aux | grep node

# Check what port it's on
ss -tulnp | grep node

# Check for debug/inspect flags (dangerous)
ps aux | grep node | grep -E '\-\-inspect|\-\-debug'

# Find .env files
find / -name ".env" -not -path "*/node_modules/*" 2>/dev/null

# Check environment variables
cat /proc/$(pgrep node)/environ | tr '\0' '\n'

# PM2 process manager
pm2 list
pm2 restart all
pm2 logs
```

---

---

# 📋 Category 4: Logging & Monitoring

## Key Log File Locations

| Log | Path | What it captures |
|---|---|---|
| Auth events | `/var/log/auth.log` | SSH, sudo, su, PAM, login |
| General system | `/var/log/syslog` | Everything |
| Kernel | `/var/log/kern.log` | Kernel messages |
| Packages | `/var/log/dpkg.log` | Installs/removals |
| Auditd | `/var/log/audit/audit.log` | Syscall-level events |
| fail2ban | `/var/log/fail2ban.log` | Bans and jail events |
| Apache access | `/var/log/apache2/access.log` | Every HTTP request |
| Apache error | `/var/log/apache2/error.log` | Apache errors |
| Nginx access | `/var/log/nginx/access.log` | Every HTTP request |
| FTP | `/var/log/vsftpd.log` | FTP auth and transfers |
| PostgreSQL | `/var/log/postgresql/postgresql-*.log` | DB activity |

## Live Log Watching

```bash
# Watch ALL critical logs at once
tail -f /var/log/auth.log /var/log/syslog /var/log/audit/audit.log

# Watch auth events only
tail -f /var/log/auth.log

# Watch systemd journal — all services
journalctl -f

# Watch journal — errors and above only
journalctl -f -p warning

# Watch a specific service
journalctl -f -u apache2
journalctl -f -u postgresql
journalctl -f -u sshd
```

## Auth Log Analysis

```bash
# Top IPs brute forcing SSH
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -20

# All successful logins
grep "Accepted" /var/log/auth.log | tail -20

# Root logins (should be none)
grep "Accepted.*root" /var/log/auth.log

# All sudo commands
grep "sudo.*COMMAND" /var/log/auth.log | tail -20

# Shell obtained via sudo (red flag)
grep "sudo.*COMMAND=/bin/bash\|sudo.*COMMAND=/bin/sh" /var/log/auth.log

# User/group management events
grep -E "useradd|userdel|usermod|new user" /var/log/auth.log | tail -10

# Root session opens
grep "session opened for user root" /var/log/auth.log | tail -10

# Password changes
grep "passwd\[" /var/log/auth.log | tail -10

# Recent events from journalctl
journalctl --since "1 hour ago"
journalctl -p err --since "1 hour ago"
```

## auditd

```bash
# Search by watch key
ausearch -k identity_change       # /etc/passwd, /etc/shadow
ausearch -k sudoers_change        # /etc/sudoers
ausearch -k ssh_keys              # authorized_keys
ausearch -k cron_change           # crontabs
ausearch -k tmp_execution         # exec from /tmp
ausearch -k priv_escalation       # sudo/su execution

# Recent events only
ausearch -k identity_change --start recent

# Login events
ausearch -m USER_LOGIN | tail -20

# Summary reports
aureport --summary
aureport --auth
aureport --failed
aureport --file

# List current audit rules
auditctl -l

# Check auditd status
systemctl status auditd
```

## Web Log Analysis

```bash
# Top IPs by request count
awk '{print $1}' /var/log/apache2/access.log | sort | uniq -c | sort -rn | head -10

# All 404 errors (scanning indicator)
awk '$9==404' /var/log/apache2/access.log | awk '{print $1}' | sort | uniq -c | sort -rn

# Directory traversal attempts
grep "\.\." /var/log/apache2/access.log | tail -10

# Scan for common web attacks
grep -iE 'union.*select|<script|base64|etc/passwd|cmd=|exec\(' /var/log/apache2/access.log | tail -10

# Requests for sensitive files
grep -E '\.git|\.env|\.bak|wp-config' /var/log/apache2/access.log | tail -10
```

---

---

# 🔍 Category 5: Vulnerability Management

## SUID / SGID Auditing

```bash
# Find all SUID binaries
find / -perm -4000 -type f 2>/dev/null | sort

# Find all SGID binaries
find / -perm -2000 -type f 2>/dev/null | sort

# Remove SUID from a binary
chmod u-s /path/to/binary

# Expected SUID on Ubuntu 24 (anything else is suspicious):
# /usr/bin/sudo, /usr/bin/su, /usr/bin/passwd, /usr/bin/newgrp
# /usr/bin/gpasswd, /usr/bin/chsh, /usr/bin/chfn
# /usr/bin/mount, /usr/bin/umount, /usr/bin/ping
# /usr/lib/openssh/ssh-keysign
```

## World-Writable Files

```bash
# World-writable files (high risk if root-owned)
find / -perm -o+w -type f \
    -not -path "/proc/*" -not -path "/sys/*" \
    -not -path "/dev/*" -not -path "/tmp/*" \
    2>/dev/null

# World-writable directories
find / -perm -o+w -type d \
    -not -path "/proc/*" -not -path "/sys/*" \
    2>/dev/null

# Fix world-writable file
chmod o-w /path/to/file

# Fix world-writable directory
chmod o-w /path/to/dir
```

## Kernel Parameters

```bash
# Check all at once
sysctl -a | grep -E 'randomize|ip_forward|syncookies|dmesg|suid_dump'

# Apply hardening
sysctl -w kernel.randomize_va_space=2     # Full ASLR
sysctl -w net.ipv4.ip_forward=0           # No IP forwarding
sysctl -w net.ipv4.tcp_syncookies=1       # SYN flood protection
sysctl -w fs.suid_dumpable=0              # No SUID core dumps
sysctl -w kernel.dmesg_restrict=1         # Restrict dmesg
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.all.accept_redirects=0

# Make persistent
echo "kernel.randomize_va_space=2" >> /etc/sysctl.conf
sysctl -p
```

## Package Management

```bash
# Check for available updates
apt list --upgradable 2>/dev/null

# Apply all updates
apt-get update && apt-get upgrade -y

# Check a specific package version
dpkg -l openssh-server
dpkg -l apache2

# Check recently installed packages (attacker tools)
grep " install " /var/log/dpkg.log | tail -20

# Remove a package completely
apt-get remove --purge packagename

# Verify package file integrity
debsums -s                      # Only show failures
debsums packagename             # Check specific package

# Check which package owns a binary
dpkg -S /usr/bin/sudo
```

## Lynis

```bash
# Install
apt install lynis -y

# Full system audit
lynis audit system

# Quick scan
lynis audit system --quick

# Quiet mode (only warnings)
lynis audit system --quiet

# Get details on a specific test
lynis show details AUTH-9328

# View full report
cat /var/log/lynis-report.dat | grep "warning\|suggestion"
```

## Rootkit Detection

```bash
# chkrootkit
apt install chkrootkit -y
chkrootkit

# rkhunter
apt install rkhunter -y
rkhunter --update
rkhunter --check --skip-keypress
rkhunter --check --report-warnings-only   # Show only warnings
```

## File Integrity

```bash
# Find recently modified files (last 60 min)
find / -mmin -60 -type f -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null

# Find recently modified files in sensitive paths
find /etc /home /root /bin /usr/bin -mmin -60 -type f 2>/dev/null

# Check if a binary was modified recently
stat /usr/bin/sudo
stat /usr/sbin/sshd

# AIDE file integrity monitor
apt install aide -y
aide --init             # Build baseline database
aide --check            # Check against baseline
```

## Suspicious Process Hunting

```bash
# Processes running from /tmp or /dev/shm (bad)
ps aux | grep -E '/tmp|/dev/shm|/var/tmp'

# Processes with network connections
lsof -i -P -n | grep LISTEN

# Find what opened a specific port
ss -tulnp | grep :<PORT>
lsof -i :<PORT>

# Processes with no associated binary (deleted executables = rootkit indicator)
ls -la /proc/*/exe 2>/dev/null | grep deleted

# Find hidden processes
ps aux | awk '{print $1}' | sort -u
ls /proc | grep -E '^[0-9]+$' | wc -l
```

---

---

# 🚨 Category 6: Incident Response

## Detect Active Intrusion

```bash
# Who is logged in right now?
who
w

# What are they doing?
ps aux | grep pts

# Active network connections
ss -tp state established

# Look for unexpected outbound connections
ss -tp state established | grep -v "10.66.X\|127.0.0.1"

# Processes listening on unusual ports
ss -tulnp | grep -vE ':22 |:80 |:443 |:21 |:5432 |:3000 '

# Recently modified files in last 30 minutes
find /etc /home /root /tmp -mmin -30 -type f 2>/dev/null

# Check cron for new entries
for user in $(cut -f1 -d: /etc/passwd); do
    echo "==$user=="; crontab -l -u "$user" 2>/dev/null | grep -v '^#'
done
```

## Kill / Remove the Threat

```bash
# Kick an active session by TTY
pkill -kill -t pts/1

# Kill a process by PID
kill -9 <PID>

# Kill all processes matching a name
pkill -f "suspicious_name"

# Find and kill a reverse shell (unexpected established connection)
ss -tp state established
# → get PID from output
kill -9 <PID>

# Block an attacking IP immediately
iptables -A INPUT -s <attacker_ip> -j DROP
iptables -A OUTPUT -d <attacker_ip> -j DROP    # Only single IP — TCDC compliant

# Manually ban with fail2ban
fail2ban-client set sshd banip <IP>

# Remove a backdoor user
userdel -r backdooruser

# Remove a planted SSH key
> /home/username/.ssh/authorized_keys
# OR edit and remove specific key:
vi /home/username/.ssh/authorized_keys

# Remove a malicious cron job
crontab -r -u username            # Removes ALL cron for user
crontab -e -u username            # Edit cron for user
rm /etc/cron.d/suspicious_file    # Remove specific cron file
```

## Preserve Evidence

```bash
# Capture current network state
ss -tulnp > /root/evidence/ports_$(date +%s).txt
ss -tp state established >> /root/evidence/ports_$(date +%s).txt

# Snapshot running processes
ps aux > /root/evidence/processes_$(date +%s).txt

# Save active connections
lsof -i -P -n > /root/evidence/lsof_$(date +%s).txt

# Capture relevant log entries
grep "$(date '+%b %e')" /var/log/auth.log > /root/evidence/auth_today.txt

# Record network capture
tcpdump -i eth0 -w /root/evidence/capture_$(date +%s).pcap &
# Stop with: kill %1
```

## Service Recovery

```bash
# Test config before any restart
apache2ctl configtest
nginx -t
sshd -t
vsftpd /etc/vsftpd.conf

# Graceful service reload (preferred — no dropped connections)
systemctl reload apache2
systemctl reload nginx
systemctl reload sshd

# Hard restart
systemctl restart apache2
systemctl restart nginx
systemctl restart sshd
systemctl restart vsftpd
systemctl restart postgresql

# Check service status
systemctl status apache2

# If a config is broken — restore backup
cp /root/tcdc_backups/apache2_backup/* /etc/apache2/
systemctl reload apache2
```

---

---

# 🔧 Category 7: System Utilities Reference

## File & Permission Commands

```bash
# View file permissions
ls -la /path/to/file
stat /path/to/file

# Change permissions
chmod 600 file           # rw------- (owner only)
chmod 644 file           # rw-r--r-- (world readable)
chmod 700 directory      # rwx------ (owner only)
chmod 755 directory      # rwxr-xr-x (world executable)

# Change ownership
chown user:group file
chown -R user:group directory

# Find files by permission
find / -perm -4000        # SUID
find / -perm -2000        # SGID
find / -perm -o+w         # World-writable

# Find files modified in last N minutes
find / -mmin -60 -type f 2>/dev/null
```

## Process Management

```bash
# List all processes
ps aux

# Process tree
ps auxf

# Real-time process monitor
top
htop

# Find process by name
pgrep -a apache
pgrep -a sshd

# Kill by PID
kill -9 <PID>

# Kill by name
pkill apache2
pkill -f "pattern"

# Open files by process
lsof -p <PID>

# What process is using a port
lsof -i :80
lsof -i :22
```

## Network Utilities

```bash
# All connections with process names
ss -tulnp
netstat -tulnp          # Legacy

# Established connections
ss -tp state established

# DNS lookup
dig domain.com
nslookup domain.com

# Check connectivity
ping -c 4 10.66.X.1
curl -I http://10.66.X.11

# Traceroute
traceroute 10.66.X.1

# Download a file
curl -O http://url/file
wget http://url/file
```

## System Information

```bash
# OS version
cat /etc/os-release
uname -a

# Disk usage
df -h
du -sh /var/log/*

# Memory usage
free -h

# System load
uptime
top

# Open file descriptors
lsof | wc -l

# Kernel version
uname -r

# Installed packages
dpkg -l | less
dpkg -l | grep apache
```

---

---

# 📝 TCDC-Specific Rules Summary

> Keep these in mind before making any firewall or hardening changes.

| Rule | Detail |
|---|---|
| **No broad outgoing firewall rules** | Outgoing rules must target single IP + port only |
| **Default deny incoming is OK** | Broad incoming blocks are allowed |
| **checker user is untouchable** | Do not change password, disable, or delete |
| **blackteam user is untouchable** | Do not change password, disable, or delete |
| **No DoS / ARP spoofing** | Network-level attacks are banned |
| **Purple team reversibly only** | Don't brick other teams' boxes |
| **All tools must be free** | Free tier of AI/red team tools only |
| **Custom tools must be on GitHub** | Submit tool links to Black Team via Google Form |
| **Service uptime = 80% of score** | Never break a scored service while hardening |
| **Ticks every 30 seconds** | Every 30s your service is down = lost points |

---

## 📡 TCDC Network Reference

```
centurytree     10.66.X.11    Ubuntu 24    HTTP Directory Search
aggiedrop        10.66.X.12    Ubuntu 24    FTP + Custom
bonfire          10.66.X.13    Ubuntu 24    React (HTTP)
reveille-remote  10.66.X.14    Ubuntu 24    SSH (scored service IS SSH)
excel            10.66.X.15    Ubuntu 24    PostgreSQL
```

> `X` = your team ID

---

*Last updated: TCDC 2026 | Texas Cyber Defense Challenge*
