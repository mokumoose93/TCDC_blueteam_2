#!/bin/bash
# =============================================================
# TCDC LOGGING QUICK REFERENCE / CHEATSHEET
# Run this to print all useful one-liners to the terminal.
# Usage: bash tcdc_log_cheatsheet.sh
# Or just read it as a reference.
# =============================================================

cat << 'CHEATSHEET'
╔══════════════════════════════════════════════════════════════╗
║           TCDC LOGGING & MONITORING CHEATSHEET               ║
╚══════════════════════════════════════════════════════════════╝

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 LIVE LOG WATCHING
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Watch ALL logs at once (auth + syslog + audit)
  tail -f /var/log/auth.log /var/log/syslog /var/log/audit/audit.log

# Watch only authentication events
  tail -f /var/log/auth.log

# Watch systemd journal (everything) with priority filter
  journalctl -f -p warning

# Watch only a specific service's logs
  journalctl -f -u apache2
  journalctl -f -u postgresql
  journalctl -f -u sshd

# Watch apache access log with highlighting
  tail -f /var/log/apache2/access.log | grep --color=auto -E '404|403|500|\.git|\.env|\.\.\/'

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 SSH / AUTH LOG ANALYSIS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Top IPs brute forcing SSH
  grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -20

# All successful logins
  grep "Accepted" /var/log/auth.log | tail -20

# All root logins (should be none)
  grep "Accepted.*root" /var/log/auth.log

# All sudo commands run
  grep "sudo.*COMMAND" /var/log/auth.log | tail -20

# Failed logins only (lastb reads /var/log/btmp)
  lastb | head -20

# Who is logged in right now
  who && w

# Full login history
  last | head -30

# Session opens for root (red flag)
  grep "session opened for user root" /var/log/auth.log | tail -10

# User/group changes
  grep -E "useradd|userdel|usermod|new user" /var/log/auth.log | tail -10

# Password changes
  grep "passwd\[" /var/log/auth.log | tail -10

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 AUDITD QUERIES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Search by key (set in rules)
  ausearch -k identity_change
  ausearch -k sudoers_change
  ausearch -k ssh_keys
  ausearch -k cron_change
  ausearch -k tmp_execution

# Recent events only
  ausearch -k identity_change --start recent

# Show all login events
  ausearch -m USER_LOGIN | tail -20

# Show privilege escalation
  ausearch -m USER_AUTH -m USER_CMD | tail -20

# Generate summary report
  aureport --summary
  aureport --auth
  aureport --failed
  aureport --file

# List current audit rules
  auditctl -l

# Check auditd status
  systemctl status auditd
  auditctl -s

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 FAIL2BAN
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Check all jail status
  fail2ban-client status

# Check specific jail
  fail2ban-client status sshd

# Manually ban an IP
  fail2ban-client set sshd banip 10.66.2.99

# Unban an IP (if you locked yourself out)
  fail2ban-client set sshd unbanip 10.66.X.1

# Watch fail2ban log live
  tail -f /var/log/fail2ban.log

# Reload fail2ban config
  fail2ban-client reload

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 WEB SERVER LOGS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Top IPs by request count
  awk '{print $1}' /var/log/apache2/access.log | sort | uniq -c | sort -rn | head -10

# All 404 errors (scanning indicator)
  awk '$9==404' /var/log/apache2/access.log | awk '{print $1}' | sort | uniq -c | sort -rn

# Directory traversal attempts
  grep "\.\." /var/log/apache2/access.log | tail -10

# Scan for web attacks
  grep -iE 'union.*select|<script|base64|etc/passwd|cmd=' /var/log/apache2/access.log | tail -10

# Requests for sensitive files
  grep -E '\.git|\.env|\.bak|wp-config' /var/log/apache2/access.log | tail -10

# Live watch with attack filter
  tail -f /var/log/apache2/access.log | grep --color -E '\.\./|\.git|\.env|TRACE|PUT|DELETE'

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 FTP LOGS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Failed FTP logins
  grep "FAIL LOGIN" /var/log/vsftpd.log | tail -10

# Successful logins
  grep "OK LOGIN" /var/log/vsftpd.log | tail -10

# File uploads
  grep "OK UPLOAD\|STOR" /var/log/vsftpd.log | tail -10

# Anonymous access attempts
  grep -i "anonymous" /var/log/vsftpd.log | tail -10

# Watch FTP live
  tail -f /var/log/vsftpd.log

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 POSTGRESQL LOGS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Find current log file
  ls -lt /var/log/postgresql/ | head -3

# Auth failures
  grep "FATAL.*password\|FATAL.*authentication" /var/log/postgresql/postgresql-*.log | tail -10

# Connections from unexpected hosts
  grep "connection received" /var/log/postgresql/postgresql-*.log | grep -v "127.0.0.1\|::1" | tail -10

# Watch postgres log live
  tail -f /var/log/postgresql/postgresql-*.log

# Active connections via psql
  sudo -u postgres psql -c "SELECT usename,client_addr,state,query FROM pg_stat_activity;"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 SYSTEM & PROCESS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Recently installed packages (attacker tools)
  grep " install " /var/log/dpkg.log | tail -20
  grep " install " /var/log/apt/history.log | tail -20

# Files modified in last 60 minutes
  find /etc /home /root /tmp /var/spool -mmin -60 -type f 2>/dev/null

# Processes running from suspicious locations
  ps aux | grep -E '/tmp|/dev/shm|/var/tmp'

# Open network connections with process names
  ss -tulnp
  lsof -i -P -n | grep LISTEN

# Check all cron jobs
  for u in $(cut -f1 -d: /etc/passwd); do echo "==$u=="; crontab -l -u $u 2>/dev/null | grep -v '^#'; done

# Kernel ring buffer (hardware/driver errors)
  dmesg | tail -20
  dmesg | grep -iE 'error|fail|attack'

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 JOURNALCTL POWER COMMANDS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Last hour of logs, all services
  journalctl --since "1 hour ago"

# Only errors and critical
  journalctl -p err --since "1 hour ago"

# Specific service since competition start
  journalctl -u sshd --since "09:00:00"

# Boot logs
  journalctl -b

# Disk usage of journal
  journalctl --disk-usage

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 INCIDENT RESPONSE QUICK ACTIONS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Kick an active session
  pkill -kill -t pts/1

# Kill a process by PID
  kill -9 <PID>

# Kill all processes by name
  pkill -f "suspicious_process"

# Ban an IP immediately
  iptables -A INPUT -s <attacker_ip> -j DROP

# Find what opened a port
  ss -tulnp | grep :<PORT>
  lsof -i :<PORT>

# Find and kill a reverse shell
  ss -tp state established | grep -v ":22\|:80\|:443\|:5432\|:21"
  # Then kill that PID

CHEATSHEET
