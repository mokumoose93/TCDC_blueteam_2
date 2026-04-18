# Cron job backdoor

## Trigger — how you notice

- `crontab -u <user> -l` shows an entry you didn't add
- New file in `/etc/cron.d/`, `/etc/cron.hourly/`, `/etc/cron.daily/`, `/etc/cron.weekly/`, `/etc/cron.monthly/`
- `ausearch -k cron_change` (if you have the audit rule) returns modifications
- A process spawns on a schedule and you can't find the parent

## Contain (≤60s)

```bash
BAD_USER=<name>            # user whose crontab is rogue
BAD_FILE=<path>            # or /etc/cron.d/<name>

# 1. Preserve evidence
sudo crontab -u $BAD_USER -l > /root/tcdc_evidence_$(date +%s)_${BAD_USER}_crontab 2>/dev/null
sudo cp -a $BAD_FILE /root/tcdc_evidence_$(date +%s)_$(basename $BAD_FILE) 2>/dev/null

# 2a. If rogue entry is in a user crontab
sudo crontab -r -u $BAD_USER          # clears entire user crontab
# or edit: sudo crontab -u $BAD_USER -e   # remove specific lines

# 2b. If rogue entry is a system cron file
sudo rm $BAD_FILE

# 3. Kill any running child the cron job spawned recently
ps -ef | grep $BAD_USER | grep -v grep
# sudo kill -9 <pid>   # if you see something active
```

## Eradicate

```bash
# Full cron audit — check EVERY source
# Per-user crontabs
for u in $(cut -d: -f1 /etc/passwd); do
    out=$(sudo crontab -u $u -l 2>/dev/null)
    [ -n "$out" ] && echo "=== $u ===" && echo "$out"
done

# System cron directories
ls -la /etc/cron.d/ /etc/cron.hourly/ /etc/cron.daily/ /etc/cron.weekly/ /etc/cron.monthly/
sudo cat /etc/cron.d/* 2>/dev/null

# Anacron
sudo cat /etc/anacrontab 2>/dev/null

# at jobs (often forgotten)
sudo atq
sudo ls /var/spool/cron/atjobs/ /var/spool/cron/atspool/ 2>/dev/null

# systemd timers (see persist-systemd-unit.md for depth — but at least grep)
systemctl list-timers --all | grep -v '^NEXT'

# What does the cron job CALL? Inspect the target script
# grep -r '<scriptname>' / 2>/dev/null
```

## Verify

```bash
# Bad entries gone
sudo crontab -u $BAD_USER -l 2>/dev/null
# expected: 'no crontab for $BAD_USER' or only legitimate entries

ls $BAD_FILE 2>&1 | grep "No such"
# expected: match

# No re-appearance in 2-3 minutes (attackers chain cron that recreates cron)
sleep 120
sudo crontab -u $BAD_USER -l 2>/dev/null
ls /etc/cron.d/ | grep -F $(basename $BAD_FILE) 2>/dev/null
# expected: still empty

# Scored service still up (box-specific)
```

## Post-incident

- Tell team: "<box> — removed rogue cron for $BAD_USER, <N> other entries audited."
- If the cron was recreating itself → the actual persistence lives elsewhere. Run `playbooks/persist-systemd-unit.md` and `playbooks/persist-bashrc-rc.md`.
- If the cron script lived in `/tmp` or a user home → remove those files and run `playbooks/intrusion-reverse-shell.md` (check for live session).
- Enable auditd rule if not already: `sudo auditctl -w /etc/crontab -p wa -k cron_change`.
