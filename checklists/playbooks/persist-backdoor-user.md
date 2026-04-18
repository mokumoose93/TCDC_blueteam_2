# Backdoor user account

## Trigger — how you notice

- `awk -F: '($3==0){print}' /etc/passwd` returns a name that is not `root`
- `who` / `w` lists a user you don't recognize
- Watchdog `NEW LISTENER` from a non-root PID with unexpected UID
- `id <name>` returns groups including `sudo`/`wheel`/`admin` on a user that shouldn't have them

## Contain (≤60s)

```bash
BAD_USER=<name>

# 1. Kick every session owned by this user (SIGKILL, no negotiation)
sudo pkill -KILL -u $BAD_USER

# 2. Lock the account (password + shell off) — does NOT delete home dir or history
sudo usermod -L $BAD_USER
sudo usermod -s /usr/sbin/nologin $BAD_USER
sudo chage -E 0 $BAD_USER          # expire account

# 3. Snapshot what this user touched BEFORE cleanup
sudo cp -a /home/$BAD_USER /root/tcdc_evidence_$(date +%s)_$BAD_USER 2>/dev/null
sudo last -a | grep $BAD_USER > /root/tcdc_evidence_$(date +%s)_$BAD_USER_last.txt
```

## Eradicate

```bash
# Check for siblings — a backdoor user rarely exists in isolation
# SSH keys (their primary way back in)
sudo find / -name "authorized_keys" 2>/dev/null -exec grep -l "$BAD_USER" {} \;
sudo cat /home/$BAD_USER/.ssh/authorized_keys 2>/dev/null
sudo cat /root/.ssh/authorized_keys

# Sudoers entries
sudo grep -rE "$BAD_USER" /etc/sudoers /etc/sudoers.d/ 2>/dev/null

# Cron jobs owned by them
sudo crontab -u $BAD_USER -l 2>/dev/null
sudo ls /var/spool/cron/crontabs/$BAD_USER 2>/dev/null

# Shell rc files that run on login
sudo cat /home/$BAD_USER/.bashrc /home/$BAD_USER/.profile /home/$BAD_USER/.bash_profile 2>/dev/null

# Files owned by them outside their home
sudo find / -user $BAD_USER -not -path "/home/$BAD_USER*" 2>/dev/null

# Once siblings are neutralized, remove the user
sudo userdel -r $BAD_USER           # -r deletes home dir (after you took evidence)
sudo grep $BAD_USER /etc/passwd /etc/shadow /etc/group   # verify removed from all three
```

## Verify

```bash
# User gone
id $BAD_USER 2>&1 | grep "no such user"
sudo grep $BAD_USER /etc/passwd /etc/shadow /etc/group
# expected: (empty)

# No UID 0 besides root
awk -F: '($3==0){print}' /etc/passwd
# expected: root:x:0:0:root:/root:/bin/bash

# Scored service still up — pick your box
curl -sI http://localhost | head -1          # centurytree / bonfire
ss -tulnp | grep ':21 '                      # aggiedrop
sudo -u postgres psql -c "SELECT 1;"         # excel
systemctl is-active sshd && ss -tulnp | grep ':22 '   # reveille-remote
```

## Post-incident

- Tell team: "<box> — removed $BAD_USER, <N> siblings neutralized."
- If you found an authorized_keys entry → also run `playbooks/persist-ssh-key.md` for the key.
- If you found a sudoers line → also run `playbooks/persist-sudoers-nopasswd.md`.
- If you found a crontab → also run `playbooks/persist-cron.md`.
- If the user had been logged in → run `playbooks/intrusion-reverse-shell.md` to check for open shells.
