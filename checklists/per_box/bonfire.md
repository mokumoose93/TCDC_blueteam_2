# bonfire (10.66.X.13) — React + Node.js HTTP

**Scored service:** HTTP on port 80 (React frontend, Node backend usually on 3000, proxied).
**Tick:** 30s. Every tick down = lost points.
**Verify alive:** `curl -sI http://localhost | head -1` **and** `pgrep -x node` — both must succeed.

---

## T+0–5 min — Lock it down

```bash
# 1. Confirm scored service AND the Node process are up BEFORE touching anything
curl -sI http://localhost | head -1
pgrep -x node && echo "node OK" || echo "node DOWN"

# 2. Rotate all user passwords (mode 2 = unique per-user)
sudo bash scripts/identity_access_management/tcdc_passwd_reset.sh

# 3. Snapshot current IAM state
sudo bash scripts/identity_access_management/tcdc_iam_audit.sh | tee /tmp/iam.txt

# 4. UID 0 check
awk -F: '($3==0){print}' /etc/passwd
```
**Stop condition:** any UID 0 line other than `root` → `playbooks/persist-backdoor-user.md`.

```bash
# 5. SSH key audit
find / -name "authorized_keys" 2>/dev/null -exec ls -la {} \; -exec cat {} \;
```
**Stop condition:** unexpected key → `playbooks/persist-ssh-key.md`.

```bash
# 6. PAM backdoor check
grep -r 'pam_permit.so' /etc/pam.d/ | grep 'sufficient'
```
**Stop condition:** ANY hit → `playbooks/persist-pam-backdoor.md`. **Keep a second root session open.**

```bash
# 7. Sudoers scan
grep -rE 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null
```
**Stop condition:** any hit → `playbooks/persist-sudoers-nopasswd.md`.

```bash
# 8. Node debug-flag check — --inspect/--debug exposes a remote code-exec port
ps aux | grep '[n]ode' | grep -E '\-\-inspect|\-\-debug'
```
**Stop condition:** ANY match → restart Node without the flag (see T+5–15) AND open `playbooks/intrusion-new-listener.md` to check if the debug port was abused.

## T+5–15 min — Harden

```bash
# Apache/Nginx reverse proxy hardening (also detects Node)
sudo bash scripts/service_hardening/tcdc_harden_web.sh
curl -sI http://localhost | head -1                     # verify alive

# Lock down every .env file — Node secrets usually live here
find / -name ".env" -not -path "*/node_modules/*" 2>/dev/null -exec chmod 600 {} \;

# If PM2 is the process manager, audit it
command -v pm2 >/dev/null && pm2 list
command -v pm2 >/dev/null && pm2 logs --lines 20 --nostream

# Start watchdog
sudo bash scripts/service_hardening/tcdc_service_watchdog.sh

# General hardening
sudo bash scripts/_installation/tcdc_install_tools.sh
curl -sI http://localhost | head -1 && pgrep -x node    # verify alive
```

## Ongoing — every 15 min

- [ ] `curl -sI http://localhost | head -1` → `HTTP/1.1 200`
- [ ] `pgrep -x node` → Node PID still running
- [ ] `ss -tulnp | grep -E ':(80|3000) '` → no unexpected listeners
- [ ] Glance at watchdog terminal
- [ ] `ps aux | grep '[n]ode' | grep -vE '\-\-inspect|\-\-debug'` → clean (no debug flags)

## Do NOT touch on this box

- `checker` and `blackteam` users
- Port 80 INPUT rule (scored service)
- Port 3000 INPUT rule if Node binds it directly (check `ss -tulnp`)
- The Node PID and its pm2 ecosystem config
- `OUTPUT ACCEPT` firewall policy
- Suricata IDS-only mode

## If compromised

1. `curl -sI http://localhost | head -1 && pgrep -x node`.
2. Open the matching playbook:
   - Service down / Node dead → `playbooks/uptime-service-down.md`
   - Defaced content / unexpected file in webroot → `playbooks/uptime-webroot-defaced.md`
   - Unknown listener / debug port exposed → `playbooks/intrusion-new-listener.md`
   - Outbound connection from Node → `playbooks/intrusion-reverse-shell.md`
   - Anything else → `playbooks/_decision_tree.md`
3. Notify team: "bonfire — <one-line symptom>".
