# Webroot defaced / unexpected content

## Trigger — how you notice

- Scored HTTP returns wrong content (`curl http://localhost | diff - /root/known_good.html`)
- New files in `/var/www/html` that shouldn't be there
- `index.*` modified timestamp is recent
- Red team inject says "we left you a present"

## Contain (≤60s)

```bash
BAD_FILE=/var/www/html/<file>              # or directory

# 1. Preserve evidence (copy, don't move — keep mtime/owner for analysis)
mkdir -p /root/tcdc_evidence_$(date +%s)
cp -a $BAD_FILE /root/tcdc_evidence_*/$(basename $BAD_FILE)

# 2. Move the bad file aside (don't delete — it may be needed for inject write-up)
mv $BAD_FILE $BAD_FILE.quarantined

# 3. Restore from backup or good content
LATEST=$(ls -td /root/tcdc_backups/*/ | head -1)
if [ -d "$LATEST/apache2_backup" ] && [ -d /var/www/html.baseline ]; then
    cp -a /var/www/html.baseline/. /var/www/html/
fi

# 4. Verify scored service still responds correctly
curl -sI http://localhost | head -1
```

## Eradicate

```bash
# Find siblings — web defacement almost always comes with persistence
find /var/www -newer /root/tcdc_backups -type f 2>/dev/null    # files changed since setup
find /var/www -name "*.php" -o -name "*.jsp" -o -name "*.cgi"  # web shells
grep -rE 'eval\(|base64_decode|system\(|passthru' /var/www 2>/dev/null | head -20
ls -la /var/www/html/.htaccess                                 # tampered?

# How did they get write access?
# Check Apache/Nginx logs for suspicious requests
tail -200 /var/log/apache2/access.log 2>/dev/null | grep -E 'POST|\.php'
tail -200 /var/log/nginx/access.log 2>/dev/null | grep -E 'POST|\.php'

# Cron / SSH-key check — usually the pivot
for u in $(cut -d: -f1 /etc/passwd); do crontab -u $u -l 2>/dev/null | grep -v '^#' | grep .; done
find / -name authorized_keys 2>/dev/null -exec ls -la {} \;

# Remove any web shells you identified
# rm -i /var/www/html/<shell.php>
```

## Verify

```bash
# Scored service green
curl -sI http://localhost | head -1

# Content matches baseline
diff -r /var/www/html /var/www/html.baseline 2>/dev/null | head -20

# No further modifications
find /var/www -newer /tmp -mmin -10 2>/dev/null
```

## Post-incident

- Tell team: "<box> — webroot defaced, restored from baseline, <N> shells found."
- If web shell found → also run `playbooks/persist-cron.md` and `playbooks/persist-ssh-key.md` — they often pivot.
- If the write access came through a reused login → also run `playbooks/persist-backdoor-user.md`.
