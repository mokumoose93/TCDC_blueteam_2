# New listener on unexpected port (or loaded kernel module / rootkit)

## Trigger — how you notice

- `ss -tulnp` port appears that wasn't in your baseline
- Watchdog `[WARN] NEW LISTENER DETECTED`
- `lsmod` shows a kernel module you didn't install
- `/proc/modules` has unexpected entries
- IDS alert about traffic to an unusual port on this box

## Contain (≤60s)

```bash
BAD_PORT=<port>

# 1. Identify what's listening
sudo ss -tulnp | grep ":$BAD_PORT "
BAD_PID=$(sudo lsof -ti :$BAD_PORT 2>/dev/null | head -1)
sudo lsof -i :$BAD_PORT                 # full detail
sudo readlink /proc/$BAD_PID/exe        # which binary
sudo cat /proc/$BAD_PID/cmdline | tr '\0' ' '; echo

# 2. Preserve evidence
sudo ls -la /proc/$BAD_PID/ > /root/tcdc_evidence_$(date +%s)_listener_$BAD_PORT.txt 2>/dev/null
sudo readlink /proc/$BAD_PID/exe >> /root/tcdc_evidence_$(date +%s)_listener_$BAD_PORT.txt

# 3. Kill the listener — and its parent
PARENT=$(sudo ps -o ppid= -p $BAD_PID | tr -d ' ')
sudo kill -9 $BAD_PID
sudo kill -9 $PARENT 2>/dev/null

# 4. Firewall-close the port (don't rely on the process staying dead)
sudo iptables -A INPUT -p tcp --dport $BAD_PORT -j DROP
sudo iptables -A INPUT -p udp --dport $BAD_PORT -j DROP

# 5. Confirm it's gone
sudo ss -tulnp | grep ":$BAD_PORT "
# expected: (empty)
```

## Kernel module variant — extra containment

```bash
# If lsmod shows an unexpected module:
BAD_MOD=<name>

# 1. Evidence
sudo modinfo $BAD_MOD > /root/tcdc_evidence_$(date +%s)_mod_$BAD_MOD.txt
sudo cp -a $(modinfo -n $BAD_MOD) /root/tcdc_evidence_$(date +%s)_mod_$BAD_MOD.ko 2>/dev/null

# 2. Try to unload — may be blocked if the module hides itself (rootkit)
sudo rmmod $BAD_MOD
lsmod | grep $BAD_MOD && echo "MODULE STILL LOADED — likely rootkit" || echo "UNLOADED OK"

# 3. If unload succeeded, prevent auto-load at boot
sudo grep -r $BAD_MOD /etc/modules-load.d/ /etc/modules /etc/modprobe.d/ 2>/dev/null
# remove entries you find
echo "blacklist $BAD_MOD" | sudo tee -a /etc/modprobe.d/tcdc-blacklist.conf

# 4. If unload FAILED — escalate. Rootkits require offline forensics.
#    At minimum: treat every credential on this box as burned.
```

## Eradicate

```bash
# Check for siblings — listeners often come with on-boot persistence
# What launched this binary?
# systemd:
sudo systemctl list-unit-files --state=enabled | tail -n +2

# cron:
for u in $(cut -d: -f1 /etc/passwd); do sudo crontab -u $u -l 2>/dev/null | grep -v '^#' | grep .; done
sudo cat /etc/cron.d/* 2>/dev/null

# /etc/rc.local or init scripts:
sudo cat /etc/rc.local 2>/dev/null

# The binary itself (remove it)
# sudo rm $(readlink /proc/$BAD_PID/exe)   # already saved as evidence

# Other unexpected listeners
sudo ss -tulnp | grep LISTEN

# Compare all loaded modules to a baseline
lsmod | sort > /tmp/modules_now.txt
diff /tmp/modules_now.txt /root/tcdc_backups/modules_baseline.txt 2>/dev/null
```

## Verify

```bash
# Port not listening
sudo ss -tulnp | grep ":$BAD_PORT "
# expected: (empty)

# Firewall rule in place
sudo iptables -L INPUT -n | grep $BAD_PORT

# Module not loaded (kernel-module variant)
lsmod | grep $BAD_MOD
# expected: (empty)

# No re-appearance after 2 minutes
sleep 120
sudo ss -tulnp | grep ":$BAD_PORT "
lsmod | grep $BAD_MOD 2>/dev/null

# OUTPUT policy still ACCEPT (TCDC rule)
sudo iptables -L OUTPUT -n | head -1

# Scored service still up (box-specific)
```

## Post-incident

- Tell team: "<box> — killed listener pid=$BAD_PID on port $BAD_PORT, firewalled port, <N> siblings."
- If a systemd unit launched it → run `playbooks/persist-systemd-unit.md`.
- If a cron launched it → run `playbooks/persist-cron.md`.
- If the listener had an active connection → run `playbooks/intrusion-reverse-shell.md`.
- If the kernel module didn't unload → this box is root-compromised at kernel level. Escalate to team lead.
- Create a module baseline NOW if you didn't have one: `lsmod | sort > /root/tcdc_backups/modules_baseline.txt`.
