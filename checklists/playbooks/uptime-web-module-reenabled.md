# Web server: dangerous module re-enabled (autoindex / status / info / userdir)

## Trigger — how you notice

- `curl http://localhost/server-status` returns 200 (Apache status info leak)
- `curl http://localhost/` shows a directory listing (autoindex re-enabled)
- `a2enmod status` / `a2enmod info` / `a2enmod userdir` in history
- New `*.conf` in `/etc/apache2/mods-enabled/` or `/etc/nginx/conf.d/`

## Contain (≤60s)

```bash
# Apache
sudo a2dismod autoindex 2>/dev/null
sudo a2dismod status 2>/dev/null
sudo a2dismod info 2>/dev/null
sudo a2dismod userdir 2>/dev/null

# Nginx — grep for autoindex on, flip off
sudo find /etc/nginx -name "*.conf" -exec sed -i 's/autoindex on/autoindex off/g' {} \;

# Configtest then reload (NOT restart — preserves connections)
apache2ctl configtest 2>/dev/null && sudo systemctl reload apache2
nginx -t 2>/dev/null && sudo systemctl reload nginx

# Verify scored service alive
curl -sI http://localhost | head -1
```

## Eradicate

```bash
# Check for siblings — if one module came back, others might too
ls /etc/apache2/mods-enabled/ 2>/dev/null
ls /etc/nginx/conf.d/ /etc/nginx/sites-enabled/ 2>/dev/null

# Diff config against last backup
LATEST=$(ls -td /root/tcdc_backups/*/ | head -1)
diff -r /etc/apache2 $LATEST/apache2_backup 2>/dev/null | head -60
diff -r /etc/nginx   $LATEST/nginx_backup   2>/dev/null | head -60

# How did the module get re-enabled? Check cron / systemd / history
for u in $(cut -d: -f1 /etc/passwd); do crontab -u $u -l 2>/dev/null | grep -iE 'a2enmod|autoindex|nginx'; done
grep -rE 'a2enmod|autoindex' /etc/cron.* 2>/dev/null
sudo cat /root/.bash_history 2>/dev/null | tail -30

# Remove any tampered .htaccess that enables Indexes
grep -rE '^\s*Options.*\+Indexes' /var/www 2>/dev/null
```

## Verify

```bash
# Scored service green
curl -sI http://localhost | head -1

# Dangerous endpoints NOT reachable
curl -s -o /dev/null -w "%{http_code}" http://localhost/server-status
# expected: 404 or 403 (not 200)
curl -s http://localhost/ | grep -i "index of" && echo "STILL DEFACED" || echo "OK"

# Modules stay off
apachectl -M 2>/dev/null | grep -E 'autoindex|status|info|userdir'
# expected: (empty)
```

## Post-incident

- Tell team: "<box> — re-disabled autoindex/status/info/userdir; config reloaded."
- If the re-enable came from a cron or shell rc → run `playbooks/persist-cron.md` then `playbooks/persist-bashrc-rc.md`.
- Config had unexpected diff → also run `playbooks/uptime-webroot-defaced.md` (they may have planted content too).
