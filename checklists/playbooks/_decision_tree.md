# Incident Decision Tree — when no playbook fits

Use this five-step flow when you saw something strange and don't know which playbook to open. **Keep it open alongside the master checklist.**

---

## 1. IDENTIFY

Answer these three questions in order:

1. **Which box?** `hostname`
2. **Is the scored service still up?** Run the box's verify-alive command:
   - centurytree / bonfire → `curl -sI http://localhost | head -1`
   - aggiedrop → `ss -tulnp | grep ':21 '`
   - excel → `sudo -u postgres psql -c "SELECT 1;"`
   - reveille-remote → `systemctl is-active sshd && ss -tulnp | grep ':22 '`
3. **What exactly did you see?** One sentence. Write it down.

If scored service is DOWN → go to step 2 immediately (containment can wait 30s; scoring cannot).
If scored service is UP → you have time. Breathe. Go to step 2.

## 2. CONTAIN

Kick / lock / block — do not delete yet. Preserve evidence.

| Symptom | Contain command |
|---|---|
| Unknown user logged in (`w` shows them) | `sudo pkill -KILL -u BAD_USER; sudo usermod -L BAD_USER` |
| Unknown process | `sudo kill -9 BAD_PID` (check parent first with `ps -o ppid= -p BAD_PID`) |
| Outbound connection | `sudo iptables -A OUTPUT -d BAD_IP -j DROP` (single IP only — never broad deny) |
| Unknown listener | `sudo fuser -k BAD_PORT/tcp` or `sudo kill -9 $(lsof -ti :BAD_PORT)` |
| Suspect file modified | `cp -a $BAD_FILE /root/tcdc_evidence_$(date +%s)_$(basename $BAD_FILE)` before any cleanup |

## 3. ERADICATE — find siblings first

Attackers rarely plant one artifact. Before declaring victory, check for the usual companions:

```bash
# All at once — one big sweep
awk -F: '($3==0){print}' /etc/passwd              # extra UID 0
find / -name authorized_keys 2>/dev/null          # SSH keys
grep -r 'pam_permit.so' /etc/pam.d/ | grep 'sufficient'
grep -rE 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null
for u in $(cut -d: -f1 /etc/passwd); do crontab -u $u -l 2>/dev/null | grep -v '^#' | grep .; done
ls /etc/cron.d/ /etc/cron.hourly/ /etc/cron.daily/
systemctl list-unit-files --state=enabled | tail -n +2
find / -perm -4000 -type f 2>/dev/null            # SUID binaries
ss -tulnp                                         # listeners
```

Any hit → match it to a `persist-*` playbook, run that playbook to completion, THEN come back here.

## 4. RECOVER

Bring the scored service back cleanly.

```bash
# If you changed config and the service is now broken
ls /root/tcdc_backups/                            # latest backup
# copy the relevant backup back, configtest, reload

# Service-specific reloads (always configtest first)
apache2ctl configtest && systemctl reload apache2
nginx -t && systemctl reload nginx
sshd -t && systemctl reload sshd
systemctl reload postgresql
systemctl restart vsftpd
```

If the service still won't come back, let the watchdog auto-restart catch it while you investigate. **Do not leave the service down while you dig.**

## 5. VERIFY

Both must be true before you declare the incident closed:

- [ ] **Threat is gone** — run the same detection command that flagged this incident; it returns nothing.
- [ ] **Scored service is UP** — the box's verify-alive command succeeds.

Leave a one-line note in `/root/tcdc_evidence_$(date +%s).txt` describing what you found. Tell the team: "box + symptom + resolution".

---

## Still stuck?

- Re-read the symptom table in `checklists/README.md` — you may have missed a match.
- Run the inject response in `checklists/TCDC_master_checklist.md` for strategic guidance.
- Ask a teammate for a second set of eyes — two people halve the miss rate.
