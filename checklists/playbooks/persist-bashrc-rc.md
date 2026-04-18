# Shell rc / profile backdoor

## Trigger — how you notice

- `.bashrc` / `.profile` / `/etc/profile.d/*` / `/etc/bash.bashrc` contains:
  - `curl | bash`, `wget -O- | sh`
  - `/dev/tcp/<ip>/<port>` redirection
  - `base64 -d | bash`
  - Unknown alias that shadows `sudo`, `ls`, `cd`, etc.
- Login triggers an outbound connection (catch via watchdog NEW LISTENER or IDS)

## Contain (≤60s)

```bash
BAD_FILE=<path>            # e.g. /home/alice/.bashrc

# 1. Preserve evidence
sudo cp -a $BAD_FILE /root/tcdc_evidence_$(date +%s)_$(basename $BAD_FILE)

# 2. Strip the bad lines in place (edit in place; keep ownership/perms)
sudo cp -a $BAD_FILE ${BAD_FILE}.bak
sudo grep -vE '/dev/tcp|base64 -d|\| *(bash|sh)$|curl .* \| *(bash|sh)|wget .* \| *(bash|sh)' $BAD_FILE | sudo tee ${BAD_FILE}.clean >/dev/null
sudo cp ${BAD_FILE}.clean $BAD_FILE
sudo rm ${BAD_FILE}.clean

# 3. Kick any active shell that loaded the bad rc (new logins won't have it)
OWNER=$(stat -c %U $BAD_FILE)
sudo pkill -KILL -u $OWNER
```

## Eradicate

```bash
# Full shell-rc sweep — ALL the places an rc can hide
# User homes
sudo grep -lE '/dev/tcp|base64 -d|\| *(bash|sh)$|curl .*\|.*sh|wget .*\|.*sh' \
    /home/*/.bashrc /home/*/.profile /home/*/.bash_profile /home/*/.zshrc 2>/dev/null

# Root
sudo grep -E '/dev/tcp|base64 -d|\| *(bash|sh)$' /root/.bashrc /root/.profile 2>/dev/null

# System-wide rc files
sudo grep -rE '/dev/tcp|base64 -d|\| *(bash|sh)$' /etc/bash.bashrc /etc/profile /etc/profile.d/ /etc/skel/ 2>/dev/null

# Alias overrides (redefining sudo, ls, ssh, etc.)
sudo grep -rE '^\s*alias\s+(sudo|ls|cd|cat|ssh|su|vi|nano)=' /home /root /etc/bash.bashrc /etc/profile.d/ 2>/dev/null

# Less-obvious triggers
sudo ls -la /etc/profile.d/
sudo cat /etc/skel/.bashrc

# For each hit, repeat the sed-clean pattern above
```

## Verify

```bash
# Nothing matches the dangerous patterns anywhere
sudo grep -rE '/dev/tcp|base64 -d|\| *(bash|sh)$' \
    /home/*/.bashrc /home/*/.profile /root/.bashrc /root/.profile \
    /etc/bash.bashrc /etc/profile /etc/profile.d/ 2>/dev/null
# expected: (empty)

# No dangerous aliases
sudo grep -rE '^\s*alias\s+(sudo|ls)=' /home /root 2>/dev/null
# expected: (empty or only intended aliases)

# Scored service still up (box-specific)
```

## Post-incident

- Tell team: "<box> — cleaned rc backdoor from $BAD_FILE, <N> other rc files audited."
- The rc hook often calls a binary elsewhere → also run `playbooks/persist-suid-binary.md` and `playbooks/persist-cron.md`.
- If the backdoor was making outbound calls → also run `playbooks/intrusion-reverse-shell.md`.
- If the owner of $BAD_FILE is an unknown account → also run `playbooks/persist-backdoor-user.md`.
