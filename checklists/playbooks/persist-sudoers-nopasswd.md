# Sudoers NOPASSWD backdoor

## Trigger — how you notice

- `grep -rE 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null` returns hits you didn't add
- New file in `/etc/sudoers.d/` (e.g., `/etc/sudoers.d/zzz-dont-look`)
- User invokes `sudo -n true` and gets no password prompt

## Contain (≤60s)

```bash
BAD_FILE=<path>      # /etc/sudoers or /etc/sudoers.d/<name>
BAD_USER=<name>

# 1. Preserve evidence
sudo cp -a $BAD_FILE /root/tcdc_evidence_$(date +%s)_$(basename $BAD_FILE)

# 2. Validate CURRENT sudoers before editing — broken sudoers locks you out
sudo visudo -c

# 3a. If the line is in /etc/sudoers.d/<file>, just remove the file
if [[ "$BAD_FILE" == /etc/sudoers.d/* ]]; then
    sudo rm "$BAD_FILE"
fi

# 3b. If the line is in /etc/sudoers, edit with visudo (syntax-checked)
# sudo visudo   # remove the offending NOPASSWD line, save

# 4. Re-validate
sudo visudo -c

# 5. Kick any active sudo session from $BAD_USER
sudo pkill -KILL -u $BAD_USER
```

## Eradicate

```bash
# Full sudoers audit — not just the one line you saw
sudo grep -rE 'NOPASSWD|ALL=\(ALL\)' /etc/sudoers /etc/sudoers.d/ 2>/dev/null

# Files anyone (not root) can write to
sudo find /etc/sudoers.d -type f ! -user root 2>/dev/null
sudo find /etc/sudoers.d -type f -perm /022 2>/dev/null
sudo stat /etc/sudoers

# Is the user supposed to have sudo at all?
id $BAD_USER
getent group sudo wheel admin

# Check for siblings — NOPASSWD rarely stands alone
grep -r 'pam_permit.so' /etc/pam.d/ | grep 'sufficient'
find / -perm -4000 -type f 2>/dev/null
awk -F: '($3==0){print}' /etc/passwd

# Lock perms back down
sudo chmod 440 /etc/sudoers
sudo chmod 440 /etc/sudoers.d/*
sudo chown root:root /etc/sudoers /etc/sudoers.d/*
```

## Verify

```bash
# No more NOPASSWD
sudo grep -rE 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null
# expected: (empty)

# sudoers syntax is valid
sudo visudo -c

# Bad user can't sudo without password
sudo -u $BAD_USER sudo -n true 2>&1 | grep -q 'password is required' && echo "BLOCKED OK"

# Scored service still up
# (box-specific verify-alive goes here)
```

## Post-incident

- Tell team: "<box> — removed NOPASSWD entry for $BAD_USER, sudoers syntax verified."
- Who wrote it? → audit trail: `sudo ausearch -f /etc/sudoers.d/` and `sudo ausearch -f /etc/sudoers`.
- If $BAD_USER was unexpected → also run `playbooks/persist-backdoor-user.md`.
- If file ownership/perms were wrong → redo `sudo bash scripts/_installation/tcdc_install_tools.sh` to restore baseline.
