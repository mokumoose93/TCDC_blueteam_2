# reveille-remote (10.66.X.14) — SSH (scored)

**Scored service:** SSH on port 22 — the authentication path itself is scored.
**Tick:** 30s. Every tick down = lost points.
**Verify alive:** all three must succeed:
```bash
systemctl is-active sshd && ss -tulnp | grep -q ':22 ' && sshd -t
```

---

## T+0–5 min — Lock it down

> **CRITICAL:** open a SECOND root session (tmux / second SSH) BEFORE editing anything sshd-related. A bad `sshd_config` plus a locked root account will permanently lock you out of this box.

```bash
# 1. Confirm scored service is up
systemctl is-active sshd
ss -tulnp | grep ':22 '
sshd -t && echo "sshd config OK"

# 2. Rotate all user passwords
sudo bash scripts/identity_access_management/tcdc_passwd_reset.sh

# 3. Snapshot current IAM state
sudo bash scripts/identity_access_management/tcdc_iam_audit.sh | tee /tmp/iam.txt

# 4. UID 0 check
awk -F: '($3==0){print}' /etc/passwd
```
**Stop condition:** UID 0 ≠ `root` → `playbooks/persist-backdoor-user.md`.

```bash
# 5. SSH key audit — THE PRIMARY RISK ON THIS BOX
find / -name "authorized_keys" 2>/dev/null -exec ls -la {} \; -exec cat {} \;
```
**Stop condition:** ANY unexpected key → `playbooks/persist-ssh-key.md`.

```bash
# 6. PAM backdoor check — double-critical here (SSH auth routes through PAM)
grep -r 'pam_permit.so' /etc/pam.d/ | grep 'sufficient'
```
**Stop condition:** ANY hit → `playbooks/persist-pam-backdoor.md`. **Second root session MUST be open.**

```bash
# 7. Sudoers scan
grep -rE 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null
```
**Stop condition:** any hit → `playbooks/persist-sudoers-nopasswd.md`.

```bash
# 8. Current sshd_config critical settings
grep -E '^(PermitRootLogin|PasswordAuthentication|AllowUsers|PermitEmptyPasswords|ChallengeResponseAuthentication)' /etc/ssh/sshd_config
```
**Stop condition:** `PermitRootLogin yes` or `PermitEmptyPasswords yes` → tighten in T+5–15 (see below); if you didn't set it, also open `playbooks/intrusion-new-listener.md` (red team tampered with config).

## T+5–15 min — Harden

```bash
# Backup sshd_config before edits
sudo cp /etc/ssh/sshd_config /root/tcdc_backups/sshd_config.$(date +%s)

# IAM hardening (runs iam_audit + tightens account policies)
sudo bash scripts/identity_access_management/tcdc_iam_harden.sh

# Tighten sshd_config carefully — YOUR second root session is insurance
sudo sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/^#\?PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
sudo sed -i 's/^#\?X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config

# Only test — DO NOT restart if test fails
sudo sshd -t && sudo systemctl reload sshd || {
    echo "sshd -t FAILED — restoring backup"
    sudo cp /root/tcdc_backups/sshd_config.* /etc/ssh/sshd_config
    sudo sshd -t && sudo systemctl reload sshd
}

# Verify scored service is still alive AFTER reload
systemctl is-active sshd && ss -tulnp | grep ':22 '

# Start watchdog
sudo bash scripts/service_hardening/tcdc_service_watchdog.sh

# General hardening
sudo bash scripts/_installation/tcdc_install_tools.sh
systemctl is-active sshd && ss -tulnp | grep ':22 '
```

## Ongoing — every 15 min

- [ ] `systemctl is-active sshd` → `active`
- [ ] `ss -tulnp | grep ':22 '` → sshd still listening
- [ ] `sshd -t` → no output (means config is valid)
- [ ] `last -n 20` → only expected logins
- [ ] `find /home /root -name "authorized_keys" -newer /tmp/iam.txt 2>/dev/null` → no new files
- [ ] Glance at watchdog terminal

## Do NOT touch on this box

- `checker` and `blackteam` users
- `checker`'s entry in `AllowUsers` if that directive is set (scoring bot needs SSH access)
- Port 22 INPUT rule (scored service)
- Root account password lockout — keep root usable for emergency console access
- `OUTPUT ACCEPT` firewall policy
- Suricata IDS-only mode

## If compromised

1. Run the verify-alive triple.
2. Open the matching playbook:
   - sshd dead / port 22 closed → `playbooks/uptime-service-down.md`
   - Unknown authorized_keys → `playbooks/persist-ssh-key.md`
   - PAM sufficient module → `playbooks/persist-pam-backdoor.md`
   - Unknown logged-in user / `w` shows surprise session → `playbooks/persist-backdoor-user.md`
   - New listener → `playbooks/intrusion-new-listener.md`
   - Anything else → `playbooks/_decision_tree.md`
3. Notify team: "reveille-remote — <one-line symptom>".
