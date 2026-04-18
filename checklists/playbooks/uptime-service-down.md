# Scored service is DOWN

## Trigger — how you notice

- Watchdog `[ALERT] SERVICE DOWN: <svc>`
- Verify-alive command fails (curl timeout / `SELECT 1` errors / `systemctl is-active` returns `inactive`)
- `ss -tulnp | grep :<port>` returns nothing

## Contain (≤60s)

```bash
BAD_SVC=<apache2|nginx|vsftpd|sshd|postgresql|node>

# 1. Check if systemd thinks it's running
systemctl status $BAD_SVC --no-pager | head -20
journalctl -u $BAD_SVC --no-pager -n 40

# 2. Try config test FIRST (never restart a broken config)
case "$BAD_SVC" in
    apache2) apache2ctl configtest ;;
    nginx)   nginx -t ;;
    sshd)    sshd -t ;;
    vsftpd)  vsftpd /etc/vsftpd.conf ;;
esac

# 3. If config is OK, restart. If not, skip to Eradicate.
systemctl restart $BAD_SVC
sleep 2
systemctl is-active $BAD_SVC && echo "UP" || echo "STILL DOWN"
```

## Eradicate

```bash
# Check for siblings — an attacker may have broken the config deliberately,
# planted a backup service to take its place, or chewed up disk/memory.
diff /etc/$BAD_SVC /root/tcdc_backups/*/$BAD_SVC 2>/dev/null | head -40
df -h /                                            # disk full?
free -h                                            # memory exhausted?
ss -tulnp | grep :<port>                           # is another process squatting?
ausearch -k service_change 2>/dev/null | tail -20  # audit trail

# Restore from the latest backup if the config was tampered
LATEST_BACKUP=$(ls -td /root/tcdc_backups/*/ | head -1)
sudo cp -r $LATEST_BACKUP/$BAD_SVC/* /etc/$BAD_SVC/
case "$BAD_SVC" in
    apache2) apache2ctl configtest ;;
    nginx)   nginx -t ;;
    sshd)    sshd -t ;;
    vsftpd)  vsftpd /etc/vsftpd.conf ;;
esac
systemctl restart $BAD_SVC
```

## Verify

```bash
# Threat gone + service up
systemctl is-active $BAD_SVC
ss -tulnp | grep :<port>

# Box-specific verify-alive (pick the one for this box)
curl -sI http://localhost | head -1          # centurytree / bonfire
ss -tulnp | grep ':21 '                      # aggiedrop
sudo -u postgres psql -c "SELECT 1;"         # excel
systemctl is-active sshd && sshd -t          # reveille-remote
```

## Post-incident

- Tell team: "<box> — $BAD_SVC was down, restored from <backup|restart>."
- If config had been tampered → also run `playbooks/intrusion-new-listener.md` (attacker had write access; look for listener).
- If no backup helped and you had to rebuild → leave notes in `/root/tcdc_evidence_$(date +%s).txt`.
