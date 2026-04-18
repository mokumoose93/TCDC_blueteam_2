# vsftpd anonymous login re-enabled

## Trigger — how you notice

- `grep anonymous_enable /etc/vsftpd.conf` → `YES`
- `ftp <host>` with username `anonymous` succeeds
- Watchdog NEW LISTENER notice on an unexpected port (rare — anon on 21)
- Inject / red team taunt mentions "welcome, anonymous"

## Contain (≤60s)

```bash
# 1. Backup current config
sudo cp /etc/vsftpd.conf /root/tcdc_backups/vsftpd.conf.$(date +%s)

# 2. Force anon-related settings OFF in one pass
sudo sed -i \
    -e 's/^anonymous_enable=.*/anonymous_enable=NO/' \
    -e 's/^anon_upload_enable=.*/anon_upload_enable=NO/' \
    -e 's/^anon_mkdir_write_enable=.*/anon_mkdir_write_enable=NO/' \
    /etc/vsftpd.conf

# 3. Reload (vsftpd has no configtest — restart carefully)
sudo systemctl restart vsftpd
sleep 2
systemctl is-active vsftpd && ss -tulnp | grep ':21 '
```

## Eradicate

```bash
# Check for siblings — a config rewrite came from somewhere
diff /etc/vsftpd.conf /root/tcdc_backups/vsftpd.conf.* 2>/dev/null | head -40

# Who edited it?
sudo stat /etc/vsftpd.conf
sudo ausearch -f /etc/vsftpd.conf 2>/dev/null | tail -20

# Cron / systemd unit that rewrites config? (classic persistence)
for u in $(cut -d: -f1 /etc/passwd); do crontab -u $u -l 2>/dev/null | grep -iE 'vsftpd|ftp'; done
grep -rE 'vsftpd|ftp' /etc/cron.* 2>/dev/null
systemctl list-unit-files --state=enabled | grep -iE 'vsftpd|ftp'

# Anon home writable? Uploads still there?
ls -la /srv/ftp /var/ftp 2>/dev/null
find /srv/ftp /var/ftp -type f 2>/dev/null

# Remove uploaded files (after preserving evidence)
mkdir -p /root/tcdc_evidence_$(date +%s)
find /srv/ftp /var/ftp -type f 2>/dev/null -exec cp -a {} /root/tcdc_evidence_*/ \;
# find /srv/ftp /var/ftp -type f -delete   # uncomment when ready
```

## Verify

```bash
# Scored service green
ss -tulnp | grep ':21 '
systemctl is-active vsftpd

# Anonymous rejected
grep -E '^(anonymous_enable|anon_upload_enable|anon_mkdir_write_enable)' /etc/vsftpd.conf
# expected: all = NO

# Quick negative test (may need `ftp` installed)
timeout 5 bash -c "echo -e 'user anonymous\nquit' | ftp -n localhost 21" 2>&1 | grep -i "530\|login incorrect" || echo "WARN: anonymous still possible?"
```

## Post-incident

- Tell team: "aggiedrop — anon re-enabled; flipped back off, evidence in /root/tcdc_evidence_*."
- Config rewrote itself? → almost certainly a cron or systemd unit → run `playbooks/persist-cron.md` then `playbooks/persist-systemd-unit.md`.
- Uploaded files found → run `playbooks/uptime-webroot-defaced.md` mindset (may be malware staged for pivot).
