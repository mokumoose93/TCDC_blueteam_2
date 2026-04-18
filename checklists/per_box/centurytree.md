# centurytree (10.66.X.11) — Apache/Nginx HTTP

**Scored service:** HTTP on port 80 (Directory Search).
**Tick:** 30s. Every tick down = lost points.
**Verify alive:** `curl -sI http://localhost | head -1` → must return `HTTP/1.1 200`.

---

## T+0–5 min — Lock it down

```bash
# 1. Confirm scored service is up BEFORE touching anything
curl -sI http://localhost | head -1

# 2. Rotate all user passwords (mode 2 = unique per-user, logs to /root/)
sudo bash scripts/identity_access_management/tcdc_passwd_reset.sh

# 3. Snapshot current IAM state
sudo bash scripts/identity_access_management/tcdc_iam_audit.sh | tee /tmp/iam.txt

# 4. UID 0 check — anything other than `root` is a backdoor account
awk -F: '($3==0){print}' /etc/passwd
```
**Stop condition:** UID 0 line that is not `root` → open `playbooks/persist-backdoor-user.md`.

```bash
# 5. SSH key audit — red team plants authorized_keys first
find / -name "authorized_keys" 2>/dev/null -exec ls -la {} \; -exec cat {} \;
```
**Stop condition:** unexpected key in any `authorized_keys` → open `playbooks/persist-ssh-key.md`.

```bash
# 6. PAM backdoor check — a single `pam_permit.so sufficient` bypasses all auth
grep -r 'pam_permit.so' /etc/pam.d/ | grep 'sufficient'
```
**Stop condition:** ANY hit → open `playbooks/persist-pam-backdoor.md`. **Keep a second root session open before touching PAM.**

```bash
# 7. Sudoers NOPASSWD scan
grep -rE 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null
```
**Stop condition:** any NOPASSWD line → open `playbooks/persist-sudoers-nopasswd.md`.

## T+5–15 min — Harden

```bash
# Web server hardening (backs up to /root/tcdc_backups/, configtests, rolls back on fail)
sudo bash scripts/service_hardening/tcdc_harden_web.sh
curl -sI http://localhost | head -1                     # verify alive after

# Start watchdog in a dedicated terminal, leave running
sudo bash scripts/service_hardening/tcdc_service_watchdog.sh

# General hardening (fail2ban, auditd, Lynis)
sudo bash scripts/_installation/tcdc_install_tools.sh
curl -sI http://localhost | head -1                     # verify alive after
```

## Ongoing — every 15 min

- [ ] `curl -sI http://localhost | head -1` → `HTTP/1.1 200`
- [ ] `ss -tulnp | grep ':80 '` → apache2 or nginx is still the owner
- [ ] `ls /var/www/html/` → no new/unexpected files
- [ ] Glance at watchdog terminal — all services nominal?
- [ ] `last -n 20` → any unexpected logins?

## Do NOT touch on this box

- `checker` and `blackteam` users (never modify)
- Port 80 INPUT rule (scored service)
- `OUTPUT ACCEPT` firewall policy (TCDC rule — no broad egress deny)
- The default vhost serving the scored site (check `apachectl -S` or `nginx -T`)
- Suricata must stay in IDS-only mode (TCDC rule)

## If compromised

1. Run the verify-alive command first: `curl -sI http://localhost | head -1`.
2. Open the matching playbook:
   - Service down → `playbooks/uptime-service-down.md`
   - Defaced / wrong content → `playbooks/uptime-webroot-defaced.md`
   - `/server-status` / autoindex visible → `playbooks/uptime-web-module-reenabled.md`
   - Anything else → `playbooks/_decision_tree.md`
3. Notify team: "centurytree — <one-line symptom>".
