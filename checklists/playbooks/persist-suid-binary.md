# Rogue SUID/SGID binary

## Trigger — how you notice

- `find / -perm -4000 -type f 2>/dev/null` diff against baseline shows a new file
- A user runs an unfamiliar binary and becomes root
- File with `rws` permissions in `/tmp`, `/dev/shm`, `/var/tmp`, or a user's home

## Contain (≤60s)

```bash
BAD_FILE=<path>

# 1. Preserve evidence
sudo cp -a $BAD_FILE /root/tcdc_evidence_$(date +%s)_$(basename $BAD_FILE)
sudo ls -la $BAD_FILE >> /root/tcdc_evidence_$(date +%s)_$(basename $BAD_FILE).meta

# 2. Strip the SUID/SGID bits (does NOT break legitimate binaries you forgot about;
#    you can always put them back — but it immediately prevents privilege escalation)
sudo chmod u-s,g-s $BAD_FILE

# 3. Kill any running process using this binary
for pid in $(pgrep -f "$BAD_FILE"); do sudo kill -9 $pid; done
```

## Eradicate

```bash
# Full SUID/SGID sweep — compare against a known-good baseline
sudo find / -perm -4000 -type f 2>/dev/null | sort > /tmp/suid_now.txt
diff /tmp/suid_now.txt /root/tcdc_backups/suid_baseline.txt 2>/dev/null
# (if no baseline exists, at least eyeball the list for anything in /tmp,
#  /dev/shm, /var/tmp, a user home, or /opt that you didn't install)

# Same for SGID
sudo find / -perm -2000 -type f 2>/dev/null | sort

# Find world-writable files with SUID (yikes)
sudo find / -perm -4002 -type f 2>/dev/null

# Check the file's owner and call-tree
file $BAD_FILE
sudo stat $BAD_FILE
strings $BAD_FILE 2>/dev/null | head -40   # look for hardcoded IPs / paths

# Remove the file (after evidence is saved)
sudo rm $BAD_FILE

# If it's a copy of a legitimate binary with SUID added (e.g. cp /bin/bash /tmp/x; chmod u+s /tmp/x),
# check for other copies
file $BAD_FILE | grep -i elf
# sudo find / -name "$(basename $BAD_FILE)" 2>/dev/null
```

## Verify

```bash
# Bit stripped or file gone
ls -la $BAD_FILE 2>/dev/null
# expected: no 's' in permission bits, OR "No such file or directory"

# SUID list matches baseline
sudo find / -perm -4000 -type f 2>/dev/null | sort > /tmp/suid_after.txt
diff /tmp/suid_after.txt /root/tcdc_backups/suid_baseline.txt 2>/dev/null
# expected: no diff (or only expected differences)

# Scored service still up (box-specific)
```

## Post-incident

- Tell team: "<box> — stripped SUID from $BAD_FILE, <N> other SUID files verified."
- The SUID binary was likely placed by someone with write access → also run `playbooks/persist-backdoor-user.md`.
- If the binary was in `/tmp` or `/dev/shm` → also run `playbooks/intrusion-reverse-shell.md`.
- Create a SUID baseline NOW if you didn't have one: `sudo find / -perm -4000 -type f 2>/dev/null | sort > /root/tcdc_backups/suid_baseline.txt`.
