# TCDC 2026 — Competition Day Checklists

> **Scoring:** 80% Uptime / 20% Injects | Ticks every 30 seconds
> **Rule #1:** Never break a scored service. Test after every change.
> **Rule #2:** Never touch `checker` or `blackteam` users.

---

## ⚡ Checklist 1: Start of Competition (First 15–20 Minutes)

Work through this on **every box** as fast as possible. Assign boxes to teammates so you're all working in parallel.

### 🔴 Phase 1 — Do This Before Anything Else (First 2 Minutes)

- [ ] Note your team ID (`X`) and confirm box IPs match the packet
- [ ] Confirm you can reach all 5 boxes via SSH or Xen Orchestra console
- [ ] Verify `checker` and `blackteam` users exist — **do not touch them**
  ```bash
  id checker && id blackteam
  ```
- [ ] Run password reset immediately — all default passwords are public
  ```bash
  sudo bash tcdc_passwd_reset.sh
  ```
- [ ] Communicate new passwords to your **entire team right now** before anyone gets locked out

---

### 🟠 Phase 2 — IAM Lockdown (Minutes 2–7)

- [ ] Check for UID 0 backdoor accounts
  ```bash
  awk -F: '($3==0){print}' /etc/passwd
  ```
- [ ] List all users with login shells — compare to packet
  ```bash
  grep -v '/nologin\|/false' /etc/passwd
  ```
- [ ] Audit sudo group membership
  ```bash
  getent group sudo && getent group wheel && getent group admin
  ```
- [ ] Audit `/etc/sudoers` and `/etc/sudoers.d/` for NOPASSWD entries
  ```bash
  cat /etc/sudoers | grep -v '^#'
  ls /etc/sudoers.d/ && cat /etc/sudoers.d/*
  ```
- [ ] Find and clear all unauthorized SSH authorized_keys
  ```bash
  find / -name "authorized_keys" 2>/dev/null -exec cat {} \;
  ```
- [ ] Check shell config files for backdoors (.bashrc, .bash_profile, .profile)
  ```bash
  for u in alice bob craig chad trudy mallory mike yves judy sybil walter wendy root; do
      grep -Ei 'base64|/dev/tcp|curl|wget' /home/$u/.bashrc 2>/dev/null && echo "FLAG: $u"
  done
  ```
- [ ] Check PAM for `pam_permit.so` backdoors
  ```bash
  grep -r 'pam_permit.so' /etc/pam.d/ | grep 'sufficient'
  ```
- [ ] Lock or remove any unknown/suspicious user accounts
- [ ] Kick any active unauthorized sessions
  ```bash
  who
  pkill -kill -t pts/1   # replace pts/1 with offending TTY
  ```

---

### 🟡 Phase 3 — Service Verification & Hardening (Minutes 7–13)

- [ ] Confirm all scored services are running before touching anything
  ```bash
  systemctl status apache2 nginx vsftpd sshd postgresql
  ss -tulnp
  ```
- [ ] Run service audit to baseline current state
  ```bash
  sudo bash tcdc_service_audit.sh | tee /tmp/svc_$(hostname).txt
  ```
- [ ] Apply web hardening (centurytree, bonfire)
  ```bash
  sudo bash tcdc_harden_web.sh
  curl -I http://localhost   # verify service still up
  ```
- [ ] Apply FTP hardening (aggiedrop)
  ```bash
  sudo bash tcdc_harden_ftp.sh
  # Add passive port range to firewall after
  iptables -A INPUT -p tcp --dport 49152:49200 -j ACCEPT
  ```
- [ ] Apply PostgreSQL hardening (excel)
  ```bash
  sudo bash tcdc_harden_postgres.sh
  sudo -u postgres psql -c "SELECT 1;"   # verify still accessible
  ```
- [ ] Harden SSH config (ALL boxes, but extra care on reveille-remote)
  ```bash
  sshd -t   # test before every restart
  systemctl reload sshd
  ssh checker@localhost   # verify checker can still connect
  ```
- [ ] **Test every scored service after each change** — verify the checker can still reach it

---

### 🟢 Phase 4 — Firewall & Logging Setup (Minutes 13–20)

- [ ] Apply firewall rules per box (remember: no broad outgoing deny)
  ```bash
  # Set default INPUT DROP, allow only needed ports + established
  iptables -P INPUT DROP
  iptables -P OUTPUT ACCEPT        # REQUIRED — TCDC rule
  iptables -A INPUT -i lo -j ACCEPT
  iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
  iptables -A INPUT -p tcp --dport 22 -j ACCEPT    # adjust per box
  # Add box-specific service ports
  iptables-save > /etc/iptables/rules.v4
  ```
- [ ] Set up logging stack (auditd, fail2ban, rsyslog)
  ```bash
  sudo bash tcdc_logging_setup.sh
  ```
- [ ] Run vulnerability scan
  ```bash
  sudo bash tcdc_vuln_scan.sh | tee /tmp/vuln_$(hostname).txt
  ```
- [ ] Apply vulnerability fixes
  ```bash
  sudo bash tcdc_vuln_fix.sh
  ```
- [ ] Apply kernel hardening
  ```bash
  sysctl -w kernel.randomize_va_space=2
  sysctl -w net.ipv4.ip_forward=0
  sysctl -w fs.suid_dumpable=0
  ```
- [ ] Start all watchdog monitors
  ```bash
  sudo bash tcdc_iam_watchdog.sh &
  sudo bash tcdc_service_watchdog.sh &
  sudo bash tcdc_vuln_watchdog.sh &
  ```
- [ ] Open dedicated terminal for live log monitoring
  ```bash
  sudo bash tcdc_log_monitor.sh all
  ```
- [ ] Do a final scored service check — confirm everything is still up
  ```bash
  ss -tulnp
  systemctl status apache2 nginx vsftpd sshd postgresql
  curl -I http://localhost           # web boxes
  sudo -u postgres psql -c "\l"     # excel
  ```

---

### ✅ Phase 1–4 Sign-Off Per Box

| Box | Passwords | IAM Clean | Service Up | Firewall | Logging | Vuln Scan |
|---|---|---|---|---|---|---|
| centurytree (11) | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| aggiedrop (12) | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| bonfire (13) | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| reveille-remote (14) | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| excel (15) | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |

---
---

## 🔄 Checklist 2: Ongoing Monitoring (Every 15–30 Minutes)

Once initial hardening is done, rotate through these checks continuously. Divide these responsibilities between teammates so nothing falls through the cracks.

---

### 👤 IAM — Check Every 15–20 Minutes

- [ ] Check for new unexpected users
  ```bash
  awk -F: '($3==0){print}' /etc/passwd          # UID 0 check
  cut -d: -f1 /etc/passwd | sort                 # full user list
  ```
- [ ] Check for new sudo group members
  ```bash
  getent group sudo wheel admin
  ```
- [ ] Check for new or modified sudoers entries
  ```bash
  stat /etc/sudoers
  ls -la /etc/sudoers.d/
  ```
- [ ] Check for new authorized_keys entries
  ```bash
  find / -name "authorized_keys" -newer /tmp 2>/dev/null
  ```
- [ ] Check who is currently logged in
  ```bash
  who && w
  ```
- [ ] Check recent login history for unexpected sources
  ```bash
  last | head -10
  ```
- [ ] Review IAM watchdog terminal for any alerts

---

### 🛡️ Services — Check Every 15 Minutes (Every Tick = 30 Seconds Counts)

- [ ] Verify all scored services are running
  ```bash
  systemctl is-active apache2 nginx vsftpd sshd postgresql
  ss -tulnp
  ```
- [ ] Quick HTTP check on web boxes
  ```bash
  curl -sI http://10.66.X.11 | head -1    # centurytree
  curl -sI http://10.66.X.13 | head -1    # bonfire
  ```
- [ ] Quick PostgreSQL check
  ```bash
  sudo -u postgres psql -c "SELECT 1;" 2>/dev/null && echo "UP" || echo "DOWN"
  ```
- [ ] Check for new unexpected listening ports
  ```bash
  ss -tulnp | grep -vE ':22 |:80 |:443 |:21 |:5432 |:3000 '
  ```
- [ ] Check for unexpected established outbound connections
  ```bash
  ss -tp state established | grep -v "127.0.0.1\|10.66.X"
  ```
- [ ] Review service watchdog terminal for any alerts
- [ ] Check fail2ban for active bans (may indicate ongoing attack)
  ```bash
  fail2ban-client status sshd
  ```

---

### 📋 Logs — Check Every 20 Minutes

- [ ] Scan auth log for brute force or successful attacks
  ```bash
  tail -50 /var/log/auth.log | grep -E 'Failed|Accepted|useradd|sudo'
  ```
- [ ] Check for root logins
  ```bash
  grep "Accepted.*root" /var/log/auth.log | tail -5
  ```
- [ ] Check for suspicious sudo usage
  ```bash
  grep "sudo.*COMMAND" /var/log/auth.log | tail -10
  ```
- [ ] Check web access logs for scanning/attack patterns
  ```bash
  tail -100 /var/log/apache2/access.log | grep -iE '\.\./|\.git|\.env|TRACE|union'
  ```
- [ ] Check for new packages installed (attacker may install tools)
  ```bash
  tail -20 /var/log/dpkg.log | grep " install "
  ```
- [ ] Review live log monitor terminal for flagged events
- [ ] Check auditd for identity or sudoers changes
  ```bash
  ausearch -k identity_change --start recent 2>/dev/null | tail -10
  ausearch -k sudoers_change --start recent 2>/dev/null | tail -10
  ```

---

### 🔍 Vulnerabilities — Check Every 30 Minutes

- [ ] Check for new SUID binaries
  ```bash
  find / -perm -4000 -type f 2>/dev/null | sort
  ```
- [ ] Check for executables in /tmp or /dev/shm
  ```bash
  find /tmp /dev/shm /var/tmp -type f -executable 2>/dev/null
  ```
- [ ] Check for new world-writable root-owned files
  ```bash
  find /etc /usr /bin /sbin -perm -o+w -type f 2>/dev/null
  ```
- [ ] Check cron jobs for new or modified entries
  ```bash
  crontab -l -u root
  ls -la /etc/cron.d/
  ls -la /var/spool/cron/crontabs/
  ```
- [ ] Check for suspicious running processes
  ```bash
  ps aux | grep -E '/tmp|/dev/shm|base64|nc -e|bash -i'
  ```
- [ ] Check for new systemd services
  ```bash
  systemctl list-units --type=service --state=running | \
      grep -vE 'systemd|dbus|NetworkManager|cron|rsyslog|auditd|fail2ban|ssh|apache|nginx|vsftpd|postgresql'
  ```
- [ ] Review vuln watchdog terminal for any alerts

---

### 🌐 Network — Check Every 20 Minutes

- [ ] Scan for unexpected open ports
  ```bash
  ss -tulnp
  ```
- [ ] Check for new outbound connections (beaconing / reverse shells)
  ```bash
  ss -tp state established
  ```
- [ ] Verify firewall rules are still in place
  ```bash
  iptables -L -n --line-numbers | head -30
  ```
- [ ] Check ARP table for unusual entries (ARP spoofing)
  ```bash
  arp -n
  ```
- [ ] Check if any known attacker IPs need to be blocked
  ```bash
  grep "Failed password" /var/log/auth.log | \
      awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -5
  # Then ban: fail2ban-client set sshd banip <IP>
  ```

---

### 📝 Injects — Check Every 15 Minutes

- [ ] Check the inject dashboard for new tasks
  ```
  https://dash.playtcdc.org/team/injects
  ```
- [ ] Assign inject to a teammate so others stay on hardening
- [ ] Deliver inject before deadline — injects are 20% of your score
- [ ] Submit completed inject via the dashboard

---

### 🏪 Store — Check Periodically

- [ ] Review scoreboard to see how your uptime compares
  ```
  https://dash.playtcdc.org/scoreboard
  ```
- [ ] Consider using store currency defensively (box revert if badly compromised)
- [ ] Consider using store offensively only after all boxes are stable

---

## 🚨 Incident Response Quick Reference

If something goes wrong, stay calm and work through this:

```
1. IDENTIFY   → What service/box is affected? Check watchdog terminals.
2. CONTAIN    → Kill the process, kick the session, block the IP.
3. ERADICATE  → Remove backdoor, fix the vulnerability, change credentials.
4. RECOVER    → Restart the service, verify uptime check passes.
5. DOCUMENT   → Note what happened for inject reports if asked.
```

```bash
# Contain a live attacker session
who                          # identify TTY
pkill -kill -t pts/1         # kick them

# Block their IP
iptables -A INPUT -s <IP> -j DROP
fail2ban-client set sshd banip <IP>

# Find what they left behind
find / -mmin -30 -type f -not -path "/proc/*" 2>/dev/null
find / -perm -4000 -type f 2>/dev/null    # new SUID?
crontab -l -u root                         # new cron?
ss -tulnp                                  # new listener?

# Recover the service
systemctl status <service>
systemctl restart <service>
curl -I http://localhost                   # verify web
```

---

*TCDC 2026 | Texas Cyber Range | Good luck!*
