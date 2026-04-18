# PostgreSQL tampered (unknown role / altered data / unknown session)

## Trigger — how you notice

- `\du` shows an unknown role (especially with `Superuser`)
- `SELECT * FROM pg_stat_activity WHERE client_addr IS NOT NULL` lists an IP that is not a teammate
- `SELECT 1` fails or returns wrong
- Expected tables/rows look modified or missing

## Contain (≤60s)

```bash
BAD_ROLE=<name>     # or BAD_IP=<ip>
BAD_PID=<pg pid>    # from pg_stat_activity

# 1. Kick the active session immediately (terminate does not wait)
sudo -u postgres psql -c "SELECT pg_terminate_backend($BAD_PID);"

# 2. Rotate postgres superuser password (even if you already did)
NEW_PG_PASS='ROTATED-AGAIN-LONG-RANDOM'
sudo -u postgres psql -c "ALTER USER postgres PASSWORD '$NEW_PG_PASS';"
echo "postgres : $NEW_PG_PASS [rotated $(date)]" | sudo tee -a /root/tcdc_passwords_$(hostname).txt

# 3. Lock the bad role out (don't drop — preserve audit trail)
sudo -u postgres psql -c "ALTER USER \"$BAD_ROLE\" NOLOGIN;"
sudo -u postgres psql -c "ALTER USER \"$BAD_ROLE\" NOSUPERUSER NOCREATEDB NOCREATEROLE;"

# 4. Tighten pg_hba to team subnet only (backup first)
sudo cp /etc/postgresql/*/main/pg_hba.conf /root/tcdc_backups/pg_hba.conf.$(date +%s)
# Edit pg_hba.conf — remove any 0.0.0.0/0 host lines
sudo grep -vE '^\s*host.*(0\.0\.0\.0/0|::/0)' /etc/postgresql/*/main/pg_hba.conf | sudo tee /etc/postgresql/*/main/pg_hba.conf.new
sudo mv /etc/postgresql/*/main/pg_hba.conf.new /etc/postgresql/*/main/pg_hba.conf
sudo systemctl reload postgresql
```

## Eradicate

```bash
# Check for siblings — look for ALL unexpected roles, not just the one you saw
sudo -u postgres psql -c "\du"
sudo -u postgres psql -c "SELECT rolname FROM pg_roles WHERE rolsuper = true;"

# Check for backdoor functions / triggers (classic Postgres persistence)
sudo -u postgres psql -c "SELECT proname FROM pg_proc WHERE proowner != 10 AND prosrc LIKE '%COPY%';"
sudo -u postgres psql -c "SELECT tgname, tgrelid::regclass FROM pg_trigger WHERE tgname NOT LIKE 'RI_%' AND tgname NOT LIKE 'pg_%';"

# Check which databases/tables exist vs. baseline
sudo -u postgres psql -c "\l"
sudo -u postgres -d <scored_db> psql -c "\dt"

# Remove the bad role once you're sure it's not needed for forensics
sudo -u postgres psql -c "REASSIGN OWNED BY \"$BAD_ROLE\" TO postgres;"
sudo -u postgres psql -c "DROP OWNED BY \"$BAD_ROLE\";"
sudo -u postgres psql -c "DROP ROLE \"$BAD_ROLE\";"

# OS-level check — tampering usually comes with a pivot
grep -rE 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null
awk -F: '($3==0){print}' /etc/passwd
```

## Verify

```bash
# Scored service green
sudo -u postgres psql -c "SELECT 1;"

# Bad role gone
sudo -u postgres psql -c "SELECT rolname FROM pg_roles WHERE rolname = '$BAD_ROLE';"
# expected: (0 rows)

# No unexpected sessions
sudo -u postgres psql -c "SELECT pid, usename, client_addr FROM pg_stat_activity WHERE client_addr IS NOT NULL;"

# pg_hba.conf restricted
sudo grep -E '^(host|hostssl)' /etc/postgresql/*/main/pg_hba.conf
```

## Post-incident

- Tell team: "excel — kicked $BAD_ROLE/$BAD_IP, postgres password rotated, pg_hba tightened."
- If the role had `CREATEROLE` → every other role it touched is suspect. Re-audit all roles.
- Chain-check: if the OS-level pivot check flagged NOPASSWD → run `playbooks/persist-sudoers-nopasswd.md`.
