# Rogue systemd unit or timer

## Trigger — how you notice

- `systemctl list-unit-files --state=enabled` shows a unit you didn't enable
- `systemctl list-timers` shows a timer firing an unknown target
- New file in `/etc/systemd/system/` or `/usr/lib/systemd/system/`
- Watchdog NEW LISTENER + the owning service is unfamiliar

## Contain (≤60s)

```bash
BAD_UNIT=<name>.service    # or <name>.timer

# 1. Preserve evidence
sudo systemctl cat $BAD_UNIT > /root/tcdc_evidence_$(date +%s)_${BAD_UNIT}.txt 2>/dev/null
UNIT_PATH=$(systemctl show -p FragmentPath $BAD_UNIT | cut -d= -f2-)
[ -n "$UNIT_PATH" ] && sudo cp -a "$UNIT_PATH" /root/tcdc_evidence_$(date +%s)_$(basename $UNIT_PATH)

# 2. Stop + disable + mask (mask prevents re-enable even by dependency)
sudo systemctl stop $BAD_UNIT
sudo systemctl disable $BAD_UNIT
sudo systemctl mask $BAD_UNIT

# 3. Kill remaining processes
sudo systemctl kill $BAD_UNIT 2>/dev/null
```

## Eradicate

```bash
# Check for siblings — units often come in pairs (.service + .timer)
systemctl list-unit-files --state=enabled | grep -iE "$(basename -s .service $BAD_UNIT)"

# Inspect ALL unit files installed outside package manager
sudo find /etc/systemd/system /usr/local/lib/systemd -type f | xargs ls -la 2>/dev/null

# Diff enabled units against a baseline if you have one
systemctl list-unit-files --state=enabled > /tmp/units_now.txt

# Remove the unit file and the target it was calling
sudo rm "$UNIT_PATH"
sudo rm /etc/systemd/system/$BAD_UNIT 2>/dev/null
sudo rm /usr/lib/systemd/system/$BAD_UNIT 2>/dev/null

# What binary/script did ExecStart point at? Remove that too.
# (you captured it in the evidence file — grep ExecStart)
grep ExecStart /root/tcdc_evidence_*_$BAD_UNIT.txt
# sudo rm /path/to/malicious/binary

# Reload systemd so it forgets the unit entirely
sudo systemctl daemon-reload
sudo systemctl reset-failed
```

## Verify

```bash
# Unit gone
systemctl status $BAD_UNIT 2>&1 | grep -E "could not be found|Unit.*not.*loaded"

# No listener on any port the unit may have opened
ss -tulnp | grep $BAD_UNIT
# expected: (empty)

# Still gone after a reboot of the unit's trigger window? (skip if short on time)
# systemctl list-timers | grep $BAD_UNIT

# Scored service still up (box-specific)
```

## Post-incident

- Tell team: "<box> — masked and removed $BAD_UNIT, killed its processes, deleted binary."
- If the unit was spawning a listener → also run `playbooks/intrusion-new-listener.md`.
- If a cron installed the unit → run `playbooks/persist-cron.md`.
- If a script in `/tmp` or `/dev/shm` was involved → also run `playbooks/intrusion-reverse-shell.md`.
