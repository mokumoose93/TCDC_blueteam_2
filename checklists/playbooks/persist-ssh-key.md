# SSH key backdoor in authorized_keys

## Trigger — how you notice

- New/changed `authorized_keys` file under `/home/*/.ssh/` or `/root/.ssh/`
- Key comment you don't recognize (`ssh-ed25519 AAA... attacker@kali`)
- `find /home /root -name authorized_keys -newer /tmp/baseline 2>/dev/null` returns hits

## Contain (≤60s)

```bash
BAD_USER=<name>      # whose authorized_keys was modified

# 1. Preserve evidence
sudo cp -a /home/$BAD_USER/.ssh/authorized_keys /root/tcdc_evidence_$(date +%s)_${BAD_USER}_keys
# and for root if applicable:
sudo cp -a /root/.ssh/authorized_keys /root/tcdc_evidence_$(date +%s)_root_keys 2>/dev/null

# 2. Wipe the file (don't rm — preserve perms/owner so sshd doesn't error)
sudo bash -c "> /home/$BAD_USER/.ssh/authorized_keys"
sudo chown $BAD_USER:$BAD_USER /home/$BAD_USER/.ssh/authorized_keys
sudo chmod 600 /home/$BAD_USER/.ssh/authorized_keys

# 3. Kick any session that came in on that key
sudo pkill -KILL -u $BAD_USER
# confirm they're gone
who | grep $BAD_USER
```

## Eradicate

```bash
# Check for siblings — attackers plant multiple keys across multiple users
sudo find / -name "authorized_keys" 2>/dev/null -exec ls -la {} \; -exec cat {} \;

# authorized_keys2 is legal but less common — also check
sudo find / -name "authorized_keys2" 2>/dev/null

# Check for AuthorizedKeysFile override in sshd_config (could point elsewhere)
grep -iE '^(AuthorizedKeysFile|AuthorizedKeysCommand)' /etc/ssh/sshd_config

# Check each user's .ssh/config for ProxyJump / ForwardAgent shenanigans
sudo find /home -name "config" -path "*/.ssh/*" -exec cat {} \; 2>/dev/null

# Any fresh keypairs in /tmp, /dev/shm, /var/tmp (staging spots)?
sudo find /tmp /dev/shm /var/tmp -name "id_*" -o -name "*.pub" 2>/dev/null

# If YOU have a teammate SSH key you legitimately added, re-add it now
# cat <<'EOF' >> /home/$TEAMMATE/.ssh/authorized_keys
# ssh-ed25519 AAAA... teammate@laptop
# EOF
```

## Verify

```bash
# Bad key gone
sudo cat /home/$BAD_USER/.ssh/authorized_keys
# expected: empty, or only your team's key(s)

# No sessions from the bad key
who | grep $BAD_USER

# sshd still serving
systemctl is-active sshd
ss -tulnp | grep ':22 '
sshd -t

# (On reveille-remote specifically) scored service still scoreable
systemctl is-active sshd && ss -tulnp | grep ':22 '
```

## Post-incident

- Tell team: "<box> — wiped rogue key from $BAD_USER authorized_keys."
- If the key was in `/root/.ssh/` → urgent: all boxes may be exposed. Audit every box.
- Also run `playbooks/persist-pam-backdoor.md` — PAM `pam_permit.so sufficient` bypasses keys entirely.
- If $BAD_USER is an unexpected account → also run `playbooks/persist-backdoor-user.md`.
