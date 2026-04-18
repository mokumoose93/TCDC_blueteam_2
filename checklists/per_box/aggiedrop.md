# aggiedrop (10.66.X.12) — vsftpd FTP

**Scored service:** FTP (vsftpd) on port 21 with passive data ports 49152–49200.
**Tick:** 30s. Every tick down = lost points.
**Verify alive:** `ss -tulnp | grep -q ':21 '` — must succeed.

---

## T+0–5 min — Lock it down

```bash
# 1. Confirm scored service is up
ss -tulnp | grep ':21 '
systemctl is-active vsftpd

# 2. Rotate all user passwords
sudo bash scripts/identity_access_management/tcdc_passwd_reset.sh

# 3. Snapshot current IAM state
sudo bash scripts/identity_access_management/tcdc_iam_audit.sh | tee /tmp/iam.txt

# 4. UID 0 check
awk -F: '($3==0){print}' /etc/passwd
```
**Stop condition:** UID 0 ≠ `root` → `playbooks/persist-backdoor-user.md`.

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
# 8. Anonymous FTP check — should be OFF
grep -E '^(anonymous_enable|anon_upload_enable|anon_mkdir_write_enable)' /etc/vsftpd.conf
```
**Stop condition:** `anonymous_enable=YES` → `playbooks/uptime-ftp-anon-reenabled.md`.

## T+5–15 min — Harden

```bash
# FTP-specific hardening (disables anon, chroots locals, sets passive ports, writes ftpusers)
sudo bash scripts/service_hardening/tcdc_harden_ftp.sh
ss -tulnp | grep ':21 '                                 # verify alive

# Explicit firewall — allow 21 and the passive range
sudo iptables -A INPUT -p tcp --dport 21 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 49152:49200 -j ACCEPT

# Start watchdog
sudo bash scripts/service_hardening/tcdc_service_watchdog.sh

# General hardening
sudo bash scripts/_installation/tcdc_install_tools.sh
ss -tulnp | grep ':21 '                                 # verify alive
```

## Ongoing — every 15 min

- [ ] `ss -tulnp | grep ':21 '` → vsftpd still listening
- [ ] `grep '^anonymous_enable' /etc/vsftpd.conf` → `NO`
- [ ] `ls /etc/ftpusers` → present, contains root
- [ ] Glance at watchdog terminal
- [ ] `last -n 20` → no unexpected FTP logins

## Do NOT touch on this box

- `checker` and `blackteam` users
- Port 21 INPUT rule (scored service)
- **Passive port range 49152–49200 INPUT rule** — closing these breaks passive FTP mid-transfer
- `/etc/ftpusers` baseline content (don't remove `root`)
- `OUTPUT ACCEPT` firewall policy
- Suricata IDS-only mode

## If compromised

1. `ss -tulnp | grep ':21 '`.
2. Open the matching playbook:
   - vsftpd down / port 21 not listening → `playbooks/uptime-service-down.md`
   - `anonymous_enable=YES` reappeared → `playbooks/uptime-ftp-anon-reenabled.md`
   - Unknown upload in FTP home → `playbooks/uptime-webroot-defaced.md`
   - Anything else → `playbooks/_decision_tree.md`
3. Notify team: "aggiedrop — <one-line symptom>".
