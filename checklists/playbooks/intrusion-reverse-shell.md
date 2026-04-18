# Active reverse shell / outbound C2

## Trigger — how you notice

- `ss -tp state established` shows a connection to an IP you don't recognize
- Process running from `/tmp`, `/dev/shm`, `/var/tmp`, or a user's home
- Watchdog: high load + strange process name
- IDS/Suricata alert (`ET MALWARE` / `ET POLICY`)
- `lsof -i` shows a shell (bash, sh, nc, python) with a socket

## Contain (≤60s)

```bash
BAD_PID=<pid>
BAD_IP=<remote ip>       # from ss -tp or lsof -i

# 1. Preserve evidence BEFORE killing — process info vanishes on kill
sudo ls -la /proc/$BAD_PID/ > /root/tcdc_evidence_$(date +%s)_pid_$BAD_PID.txt
sudo readlink /proc/$BAD_PID/exe >> /root/tcdc_evidence_$(date +%s)_pid_$BAD_PID.txt
sudo cat /proc/$BAD_PID/cmdline | tr '\0' ' '; echo >> /root/tcdc_evidence_$(date +%s)_pid_$BAD_PID.txt
sudo ls -la /proc/$BAD_PID/cwd >> /root/tcdc_evidence_$(date +%s)_pid_$BAD_PID.txt
PARENT=$(sudo ps -o ppid= -p $BAD_PID | tr -d ' ')
echo "parent_pid=$PARENT" >> /root/tcdc_evidence_$(date +%s)_pid_$BAD_PID.txt

# 2. Kill child AND parent (attacker shells usually have a watchdog parent)
sudo kill -9 $BAD_PID
sudo kill -9 $PARENT 2>/dev/null

# 3. Block the remote IP on OUTPUT only — SINGLE IP ONLY
#    Inbound source IP attribution is unreliable because ingress is NATed.
sudo iptables -A OUTPUT -d $BAD_IP -j DROP

# 4. Verify the shell is gone
ss -tp state established | grep $BAD_IP
# expected: (empty)
```

## Eradicate

```bash
# Check for siblings — a reverse shell rarely exists in isolation
# Other processes from the same spawn-spot
sudo ls -la /tmp /dev/shm /var/tmp 2>/dev/null
sudo find /tmp /dev/shm /var/tmp -type f -executable 2>/dev/null

# Persistence mechanisms that relaunch the shell
# - Cron
for u in $(cut -d: -f1 /etc/passwd); do sudo crontab -u $u -l 2>/dev/null | grep -v '^#' | grep .; done
sudo cat /etc/cron.d/* 2>/dev/null

# - systemd
systemctl list-unit-files --state=enabled | tail -n +2

# - Shell rc
sudo grep -rE '/dev/tcp|base64 -d|nc \-|\| *(bash|sh)$' /home /root /etc/bash.bashrc /etc/profile.d/ 2>/dev/null

# - SUID binary used as the shell
sudo find / -perm -4000 -type f -newer /tmp/baseline 2>/dev/null

# Other outbound connections from the same user / process tree
sudo ss -tp state established | grep $BAD_USER 2>/dev/null
sudo ss -tp state established | grep -v "127\." | grep -v "10\.66\."

# Remove the dropper binary / script you found
# sudo rm /tmp/<dropper>

# Wait 2-3 minutes, THEN re-check — did anything respawn?
sleep 180
ps -ef | grep -iE "nc |bash -i|python.*socket"
ss -tp state established | grep $BAD_IP
```

## Verify

```bash
# No connection to bad IP
ss -tp state established | grep $BAD_IP
# expected: (empty)

# iptables rule in place
sudo iptables -L OUTPUT -n | grep $BAD_IP

# OUTPUT policy is still ACCEPT (TCDC rule — critical)
sudo iptables -L OUTPUT -n | head -1
# expected: Chain OUTPUT (policy ACCEPT)

# Scored service still up (box-specific)
# And the box is still reachable from the team subnet
```

## Post-incident

- Tell team: "<box> — killed reverse shell pid=$BAD_PID, blocked $BAD_IP, found <N> siblings."
- If the shell was spawned from a cron/systemd → run `playbooks/persist-cron.md` / `playbooks/persist-systemd-unit.md`.
- If the dropper came from a web endpoint → run `playbooks/uptime-webroot-defaced.md`.
- If a new listener appeared related to this → run `playbooks/intrusion-new-listener.md`.
- **Do not** add a broad outbound deny. Only single-IP DROP rules. TCDC rules require OUTPUT ACCEPT.
