# excel (10.66.X.15) — PostgreSQL

**Scored service:** PostgreSQL on port 5432.
**Tick:** 30s. Every tick down = lost points.
**Verify alive:** `sudo -u postgres psql -c "SELECT 1;"` — must return `1`.

---

## T+0–5 min — Lock it down

```bash
# 1. Confirm scored service is up
sudo -u postgres psql -c "SELECT 1;"
systemctl is-active postgresql

# 2. Rotate all user passwords
sudo bash scripts/identity_access_management/tcdc_passwd_reset.sh

# 3. ROTATE THE POSTGRES SUPERUSER IMMEDIATELY — default creds are public
NEW_PG_PASS='CHANGE-ME-LONG-RANDOM'
sudo -u postgres psql -c "ALTER USER postgres PASSWORD '$NEW_PG_PASS';"
echo "postgres : $NEW_PG_PASS" | sudo tee -a /root/tcdc_passwords_$(hostname).txt
sudo chmod 600 /root/tcdc_passwords_$(hostname).txt

# 4. List all DB roles — anything unexpected is a backdoor
sudo -u postgres psql -c "\du"
```
**Stop condition:** any unknown role, especially with `Superuser` → `playbooks/uptime-postgres-tampered.md`.

```bash
# 5. IAM snapshot
sudo bash scripts/identity_access_management/tcdc_iam_audit.sh | tee /tmp/iam.txt

# 6. UID 0 check
awk -F: '($3==0){print}' /etc/passwd
```
**Stop condition:** UID 0 ≠ `root` → `playbooks/persist-backdoor-user.md`.

```bash
# 7. SSH key audit
find / -name "authorized_keys" 2>/dev/null -exec ls -la {} \; -exec cat {} \;
```
**Stop condition:** unexpected key → `playbooks/persist-ssh-key.md`.

```bash
# 8. PAM backdoor check
grep -r 'pam_permit.so' /etc/pam.d/ | grep 'sufficient'
```
**Stop condition:** ANY hit → `playbooks/persist-pam-backdoor.md`. **Keep a second root session open.**

```bash
# 9. Sudoers scan
grep -rE 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null
```
**Stop condition:** any hit → `playbooks/persist-sudoers-nopasswd.md`.

```bash
# 10. Active DB sessions — unknown client IPs are the first sign of live access
sudo -u postgres psql -c "SELECT pid, usename, client_addr, state, query_start FROM pg_stat_activity WHERE client_addr IS NOT NULL;"
```
**Stop condition:** unknown IP → `playbooks/uptime-postgres-tampered.md`.

## T+5–15 min — Harden

```bash
# Postgres-specific hardening (pg_hba.conf tighten, log settings, SSL toggle)
sudo bash scripts/service_hardening/tcdc_harden_postgres.sh
sudo -u postgres psql -c "SELECT 1;"                    # verify alive

# Confirm pg_hba limits access to team subnet only (example — adjust to team network)
sudo grep -E '^(host|hostssl)' /etc/postgresql/*/main/pg_hba.conf

# Start watchdog
sudo bash scripts/service_hardening/tcdc_service_watchdog.sh

# General hardening
sudo bash scripts/_installation/tcdc_install_tools.sh
sudo -u postgres psql -c "SELECT 1;"                    # verify alive
```

## Ongoing — every 15 min

- [ ] `sudo -u postgres psql -c "SELECT 1;"` → `1`
- [ ] `ss -tulnp | grep ':5432 '` → postgres still listening
- [ ] `sudo -u postgres psql -c "\du"` → no new roles
- [ ] `sudo -u postgres psql -c "SELECT client_addr FROM pg_stat_activity WHERE client_addr IS NOT NULL;"` → only expected IPs
- [ ] Glance at watchdog terminal

## Do NOT touch on this box

- `checker` and `blackteam` users
- `postgres` OS user account (owns the data directory)
- Port 5432 INPUT rule (scored service)
- Team-subnet line in `pg_hba.conf` (closing it = score zero)
- `OUTPUT ACCEPT` firewall policy
- Suricata IDS-only mode

## If compromised

1. `sudo -u postgres psql -c "SELECT 1;"`.
2. Open the matching playbook:
   - `SELECT 1` fails / Postgres dead → `playbooks/uptime-service-down.md`
   - Unknown role, altered table, or unknown session → `playbooks/uptime-postgres-tampered.md`
   - Disk filling up (pg_wal) → run `_decision_tree.md` RECOVER step
   - Anything else → `playbooks/_decision_tree.md`
3. Notify team: "excel — <one-line symptom>".
