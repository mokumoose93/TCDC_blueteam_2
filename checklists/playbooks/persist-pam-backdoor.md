# PAM backdoor (pam_permit.so sufficient)

> **⚠️ WARNING — READ BEFORE PROCEEDING**
>
> PAM misconfiguration locks out **sudo AND SSH simultaneously**. Before touching any file in `/etc/pam.d/`:
>
> 1. Open a SECOND root session NOW (tmux split, second SSH, or console).
> 2. Keep it active until you're done. Do NOT close it even to reuse the terminal.
> 3. If you lock yourself out of the first session, the second session is your recovery path.

## Trigger — how you notice

- `grep -r 'pam_permit.so' /etc/pam.d/ | grep 'sufficient'` returns ANY hit
- `su - <any_user>` succeeds with no password
- Login with any password (even wrong) works for some service

## Contain (≤60s)

```bash
# Verify you have a second root session open RIGHT NOW
# (run this in the second session to confirm it works)
whoami
id

# Back in session 1:
BAD_FILE=<path from grep>   # e.g. /etc/pam.d/common-auth or /etc/pam.d/sshd

# 1. Preserve the current (broken) file
sudo cp -a $BAD_FILE /root/tcdc_evidence_$(date +%s)_$(basename $BAD_FILE)

# 2. Back up the whole /etc/pam.d/ directory (single tarball for rollback)
sudo tar -cf /root/tcdc_backups/pamd_$(date +%s).tar /etc/pam.d/

# 3. Remove the rogue line (sed filters it out of the file in place)
sudo grep -v 'pam_permit.so' $BAD_FILE | sudo tee ${BAD_FILE}.new
sudo mv ${BAD_FILE}.new $BAD_FILE
sudo chmod 644 $BAD_FILE
sudo chown root:root $BAD_FILE

# 4. TEST auth from the second session before closing ANYTHING
# In second session:  sudo -k; sudo true   # should prompt for password
```

## Eradicate

```bash
# Full PAM sweep — check EVERY file
sudo grep -rE 'pam_permit.so|pam_rootok\.so.*sufficient' /etc/pam.d/

# Reinstall libpam-modules if you want the full default set back
# (this is safer than hand-editing; it restores pristine defaults)
sudo apt-get install --reinstall -y libpam-modules libpam-runtime 2>/dev/null \
    || sudo dnf reinstall -y pam 2>/dev/null

# Run pam-auth-update to regenerate common-auth/common-account (Debian/Ubuntu)
sudo DEBIAN_FRONTEND=noninteractive pam-auth-update --force 2>/dev/null

# Sibling check — if PAM was subverted, look for what used it
awk -F: '($3==0){print}' /etc/passwd              # extra UID 0
find / -name authorized_keys 2>/dev/null          # SSH keys
grep -rE 'NOPASSWD' /etc/sudoers /etc/sudoers.d/  # sudoers
```

## Verify

```bash
# No pam_permit sufficient anywhere
sudo grep -r 'pam_permit.so' /etc/pam.d/ | grep 'sufficient'
# expected: (empty)

# Auth actually requires a password — test from the SECOND session
sudo -k
sudo true    # must prompt

# Scored service still up (especially reveille-remote!)
systemctl is-active sshd && ss -tulnp | grep ':22 '
sshd -t
```

## Post-incident

- Tell team: "<box> — removed pam_permit.so sufficient from <file>, auth re-verified."
- Only close the second root session AFTER you've confirmed password-based login works from a fresh session.
- PAM compromise = root compromise. Assume every credential on this box is burned. Rotate everything.
- Also run `playbooks/persist-ssh-key.md` — PAM subversion pairs with SSH keys as a fallback.
