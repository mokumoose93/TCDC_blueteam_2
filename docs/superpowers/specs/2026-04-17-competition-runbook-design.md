# TCDC Competition Runbook — Design

**Date:** 2026-04-17
**Status:** Design approved, pending implementation plan
**Owner:** Blue Team 2

## Context

Blue Team 2 fields 3 people for a 5-box TCDC competition. Scoring is 80% uptime (30-second ticks) / 20% injects. Box ownership splits by service type:

- **Web person** — centurytree (Apache/Nginx) + bonfire (React/Node)
- **Data person** — aggiedrop (vsftpd) + excel (PostgreSQL)
- **SSH/IAM person** — reveille-remote (SSH is the scored service)

The repo already has `checklists/TCDC_master_checklist.md` (strategic reference, 392 lines) and `cheatsheets/TCDC_master_cheatsheet.md` (command reference by category). Both are thorough but too long to operate from under pressure — a teammate mid-incident needs one short file scoped to exactly what they're doing or what they just saw, not a table of contents.

This design adds two families of short, scoped files on top of the existing references:

1. **Per-box setup checklists** — one per box, tells the owner exactly what to run for that box and nothing else.
2. **Incident response playbooks** — one per scenario, scoped to a single type of attack (15 scenarios), optimized for ≤60s containment then eradicate/verify.

## Goals

- A teammate assigned to 2 boxes can run both boxes' setup in parallel using two files, without cross-referencing the master checklist.
- A teammate who sees something suspicious finds the matching playbook in ≤5 seconds.
- Every playbook's Contain step is ≤60 seconds of commands; anything longer is flagged explicitly.
- Every playbook's Verify step includes the scored-service check for that box (fixing an intrusion while breaking uptime is still a loss).
- Zero duplication of hardening script invocations — files reference `scripts/<path>/<name>.sh`, they don't inline.

## Non-goals

- Not replacing `TCDC_master_checklist.md` or the cheatsheet — those remain the strategic reference and the command reference.
- Not building interactive tooling (no `tcdc_runbook.sh <scenario>` state machine; see rejected approach 3 below).
- Not consolidating content into two mega-files (see rejected approach 2). One file per artifact.
- Not introducing new hardening scripts. Existing `tcdc_*.sh` are the execution units; runbook files route to them.

## Rejected alternatives

- **Consolidated two-file approach** — `per_box_checklists.md` + `incident_playbooks.md` with anchors, plus a helper script to print sections in-terminal. Rejected because scrolling past 14 irrelevant playbooks during a live incident is exactly the cognitive tax this project is meant to remove.
- **Interactive runbook state machine** — `scripts/tcdc_runbook.sh` walks the user through prompts and can offer to run scripts. Rejected because the implementation cost is weeks for real quality and the partial version is worse than nothing. Reconsider post-competition.

## File layout

```
checklists/
  TCDC_master_checklist.md          # unchanged — strategic reference
  README.md                          # NEW — index: role table + symptom→playbook lookup
  per_box/
    centurytree.md                   # Apache/Nginx, web person
    bonfire.md                       # React+Node, web person
    aggiedrop.md                     # vsftpd, data person
    excel.md                         # PostgreSQL, data person
    reveille-remote.md               # SSH-scored, SSH/IAM person
  playbooks/
    _decision_tree.md                # fallback when no playbook matches
    uptime-service-down.md
    uptime-webroot-defaced.md
    uptime-postgres-tampered.md
    uptime-ftp-anon-reenabled.md
    uptime-web-module-reenabled.md
    persist-backdoor-user.md
    persist-ssh-key.md
    persist-sudoers-nopasswd.md
    persist-pam-backdoor.md
    persist-cron.md
    persist-systemd-unit.md
    persist-bashrc-rc.md
    persist-suid-binary.md
    intrusion-reverse-shell.md
    intrusion-new-listener.md
```

**Naming rules:**

- Per-box filenames equal the hostname exactly (no prefix, no version suffix). Anyone assigned `centurytree` opens `centurytree.md`.
- Playbook filenames are `<category>-<what>.md`. Categories are `uptime`, `persist`, `intrusion` — matching how a teammate triages what they see (*"service looks down"* / *"they planted something"* / *"they're actively inside"*).
- `_decision_tree.md` is underscore-prefixed so it sorts to the top of `ls playbooks/`.

Total new artifacts: **22 files** (1 README + 5 per-box + 15 playbooks + 1 decision tree).

## Per-box checklist template

Every file in `per_box/` follows this skeleton. Fixed structure removes format-learning cost mid-competition. Target length: 80–100 lines.

```markdown
# <hostname> (10.66.X.NN) — <service stack>

**Scored service:** <service> on port <port>.
**Tick:** 30s. Every tick down = lost points.
**Verify alive:** <one-line command that returns success iff scored service works>

---

## T+0–5 min — Lock it down
<5–7 exact commands, each with stop conditions inline>

**Stop condition:** <X detected> → open `playbooks/<matching>.md`.

## T+5–15 min — Harden
<3–6 exact script invocations, each followed by the verify-alive command>

## Ongoing — every 15 min
- [ ] <check 1 — command → expected output>
- [ ] <check 2>
- [ ] <check 3>
- [ ] <check 4 — glance at watchdog terminal>

## Do NOT touch on this box
- `checker`, `blackteam` users
- <scored port INPUT rule>
- <box-specific untouchables>
- `OUTPUT ACCEPT` firewall policy

## If compromised
1. Run the verify-alive command first.
2. Open matching `playbooks/<category>-<what>.md`.
3. Notify team: box name + one-line symptom.
```

### Design decisions

- **Stop conditions inline with commands.** When the checklist says `awk -F: '($3==0){print}'`, the very next line says *"if you see anything but root → `playbooks/persist-backdoor-user.md`"*. No hunting across files to know what to do with what was just found.
- **Verify-alive sits on line 4.** If a teammate worries they broke something mid-hardening, the answer is always the same one-liner at the top of the file.
- **"Do NOT touch" near the bottom**, immediately before "If compromised". Placed where it's most relevant — right before destructive action.

## Playbook template

Every file in `playbooks/` follows this skeleton. Target length: 50–80 lines (half the per-box length, because read under stress).

```markdown
# <Scenario name>

## Trigger — how you notice
- <watchdog alert text, exact>
- <command output pattern>
- <visible symptom>

## Contain (≤60s)
```bash
BAD_USER=<name>     # or BAD_IP, BAD_PID, BAD_FILE — whichever fits
<2–4 commands to stop the bleeding:
  kick session / lock account / block IP / kill PID>
```

## Eradicate
```bash
# Check for siblings — attackers plant multiples
<commands to find related artifacts>

# Remove
<exact removal commands>
```

## Verify
```bash
<command 1 — threat is gone>
<command 2 — scored service still up, box-specific verify-alive>
```

## Post-incident
- Tell team: box + one-line what you found.
- If you also saw X → run `playbooks/<related>.md`.
- Leave a note in `/root/tcdc_evidence_<timestamp>.txt` if anything weird.
```

### Design decisions

- **Top-of-file shell variable.** `BAD_USER=<name>` (or `BAD_IP`, `BAD_PID`, `BAD_FILE`) declared once at the top of Contain, reused throughout. Teammate edits one line; every subsequent command just works. No copy-paste-and-patch in 8 places.
- **Contain ≤60s is a hard promise.** If a scenario can't honor it (e.g. PostgreSQL role compromise requires SQL before the bleeding stops), the playbook flags that explicitly at the top — no buried multi-minute preambles.
- **Lock before delete.** Contain locks/kicks/blocks; Eradicate destroys. This sequencing preserves evidence (`userdel -r` wipes `.bash_history`; locking first keeps it).
- **"Check for siblings" is mandatory in Eradicate.** Red team rarely plants one artifact — backdoor user usually comes with SSH key + cron + sudoers edit. Forces the lateral check before declaring victory.
- **Verify always includes scored-service check.** Non-negotiable in every playbook — fixing the intrusion while breaking uptime is still a loss.
- **Post-incident links related playbooks.** Prevents tunnel vision when attackers chain persistence.

## Index & discovery — three layers

**Layer 1 — `checklists/README.md`** is a single-page index with two tables:

```markdown
# TCDC Competition Runbook — Index

## Who are you?
| Role | Files to keep open |
|---|---|
| Web person     | per_box/centurytree.md, per_box/bonfire.md |
| Data person    | per_box/aggiedrop.md, per_box/excel.md |
| SSH/IAM person | per_box/reveille-remote.md |

## I saw something. Which playbook?
| Symptom (what you observe) | Playbook |
| ... (15 rows, one per playbook) ... | ... |

## Not sure what you're looking at?
→ `playbooks/_decision_tree.md`
```

**Layer 2 — per-box stop conditions link inline** to playbooks (already in the per-box template). Teammates executing T+0–5 never return to the index to know what to do with what they just found.

**Layer 3 — playbooks cross-link** via the Post-incident section (already in the playbook template). Finding a NOPASSWD entry nudges the teammate toward `persist-backdoor-user.md` automatically.

### Design decisions

- **One flat table for symptoms, not a decision tree.** Grep-friendly; 15 rows scan faster than a tree walks under stress.
- **Symptoms phrased as what you observe**, not what the attack is named. Teammate searches `"autoindex"`, not `"module reenable via a2enmod"`.
- **Filename-prefix grouping doubles as discovery.** `ls playbooks/` already groups `uptime-* / persist-* / intrusion-*`.
- **No priority column.** In-game priority is always the same: scored service down first, otherwise contain what you see.

## Content scope per file

### Per-box files

| File | Verify-alive (top-of-file) | Key T+5–15 scripts | Box-specific "Do NOT touch" |
|---|---|---|---|
| `centurytree.md` | `curl -sI http://localhost \| head -1` → 200 | `tcdc_harden_web.sh` | default vhost, port 80 INPUT |
| `bonfire.md` | `curl -sI http://localhost \| head -1` → 200 **and** `pgrep -x node` | `tcdc_harden_web.sh`; Node `.env` chmod 600; confirm no `--inspect`/`--debug` flag | Node PID, pm2 config, port 3000/80 INPUT |
| `aggiedrop.md` | `ss -tulnp \| grep -q ':21 '` | `tcdc_harden_ftp.sh`; firewall open **49152–49200** | passive port range INPUT, `/etc/ftpusers` baseline |
| `excel.md` | `sudo -u postgres psql -c "SELECT 1;"` | `tcdc_harden_postgres.sh`; **immediate** `ALTER USER postgres PASSWORD '...'` as T+0–5 step | postgres superuser, team-subnet `pg_hba.conf` line, port 5432 INPUT |
| `reveille-remote.md` | `systemctl is-active sshd` + `ss -tulnp \| grep -q ':22 '` + `sshd -t` | `tcdc_iam_harden.sh`; sshd_config harden with rollback-on-fail; `AllowUsers checker <team>` | `checker` in `AllowUsers`, port 22 INPUT, root-password lockout |

All five also share the universal T+0–5 IAM phase:

```bash
sudo bash scripts/identity_access_management/tcdc_passwd_reset.sh   # mode 2
sudo bash scripts/identity_access_management/tcdc_iam_audit.sh | tee /tmp/iam.txt
awk -F: '($3==0){print}' /etc/passwd                                # UID 0 check
find / -name "authorized_keys" 2>/dev/null -exec cat {} \;          # SSH key audit
grep -r 'pam_permit.so' /etc/pam.d/ | grep 'sufficient'             # PAM backdoor check
```

### Playbooks

| File | Trigger signal | Contain focus | Primary related |
|---|---|---|---|
| `uptime-service-down.md` | watchdog ALERT / verify-alive fails | configtest → reload; if broken, restore `/root/tcdc_backups/<svc>_<ts>/` | intrusion-new-listener |
| `uptime-webroot-defaced.md` | curl returns wrong content / new files in `/var/www` | move files aside (preserve evidence), restore from backup | persist-cron, persist-ssh-key |
| `uptime-postgres-tampered.md` | `psql SELECT 1` fails / `pg_stat_activity` unknown client / expected tables altered | rotate postgres password, disconnect unknown sessions, tighten `pg_hba` | persist-sudoers-nopasswd |
| `uptime-ftp-anon-reenabled.md` | `grep anonymous_enable /etc/vsftpd.conf` = YES / anon login works | `sed -i 's/YES/NO/'` + restart vsftpd | persist-cron, persist-sudoers-nopasswd |
| `uptime-web-module-reenabled.md` | `/server-status` 200 / autoindex visible / unexpected `a2enmod` | `a2dismod autoindex status info userdir` | uptime-webroot-defaced |
| `persist-backdoor-user.md` | UID 0 ≠ root / watchdog NEW USER / unknown in `who` | `pkill -KILL -u`, `usermod -L`, `usermod -s nologin` | persist-ssh-key, persist-sudoers-nopasswd, persist-cron |
| `persist-ssh-key.md` | `authorized_keys` new/changed | `> /home/$BAD_USER/.ssh/authorized_keys` | persist-pam-backdoor, persist-backdoor-user |
| `persist-sudoers-nopasswd.md` | `NOPASSWD` line / new `/etc/sudoers.d/*` | `visudo -c` then remove NOPASSWD / rm file | persist-backdoor-user |
| `persist-pam-backdoor.md` | `pam_permit.so sufficient` in `/etc/pam.d/*` | **WARNING BANNER**: keep second root session open; reinstall libpam-* or restore from backup | persist-ssh-key |
| `persist-cron.md` | unknown crontab / new `/etc/cron.*` file / `ausearch -k cron_change` | `crontab -r -u $BAD_USER` or `rm /etc/cron.d/$BAD_FILE` | persist-systemd-unit, persist-bashrc-rc |
| `persist-systemd-unit.md` | `systemctl list-unit-files \| grep enabled` unknown / new unit in `/etc/systemd/system/` | `systemctl stop && disable && rm unit && daemon-reload` | persist-cron |
| `persist-bashrc-rc.md` | `grep -Ei 'base64\|/dev/tcp\|curl\|wget'` in shell rc files | back up, remove lines (check `/etc/profile*`, `/etc/bash.bashrc`, `/etc/profile.d/*` too) | persist-backdoor-user |
| `persist-suid-binary.md` | `find / -perm -4000` diff from baseline | `chmod u-s <path>` | persist-backdoor-user |
| `intrusion-reverse-shell.md` | `ss -tp state established` unknown peer / process from `/tmp` or `/dev/shm` | `kill -9 $BAD_PID`; single-IP OUTPUT drop; kill parent if respawning | persist-cron, persist-bashrc-rc, uptime-webroot-defaced |
| `intrusion-new-listener.md` | `ss -tulnp` port not in baseline / loaded kernel module | `lsof -i :$PORT` → kill; `rmmod` + check `/etc/modules*` | intrusion-reverse-shell, persist-systemd-unit |

### Support files

- **`_decision_tree.md`** — five-step incident flow: IDENTIFY (which box, is scored service still up?) → CONTAIN (kick/lock/block) → ERADICATE (find siblings and remove) → RECOVER (restart cleanly; restore from `/root/tcdc_backups/` if config broken) → VERIFY (threat gone + scored service green). One page. Used when no playbook matches or symptom is unclear.
- **`README.md`** — the index described in "Index & discovery" above: role table, 15-row symptom-lookup table, decision-tree link.

## Key decisions called out

- **PostgreSQL password rotation is T+0–5, not T+5–15.** Default `postgres` superuser credentials are public; delay costs the whole DB. `excel.md` calls this out as the first action after `tcdc_passwd_reset.sh`.
- **FTP passive port range 49152–49200 is T+5–15 hardening**, but `aggiedrop.md`'s "Do NOT touch" list calls it out explicitly so the data person doesn't close those ports while tightening the firewall.
- **`persist-pam-backdoor.md` gets a loud warning callout.** PAM misconfiguration locks out sudo *and* ssh simultaneously. Template gains a *"Keep a second root session open while editing"* banner for this single file.
- **Rootkit / loaded kernel module folds into `intrusion-new-listener.md`.** Response shape matches (identify → unload → find persistence). If this assumption breaks during implementation, split into a separate `intrusion-kernel-module.md` file — template still applies.
- **No shared "common setup" file.** The universal T+0–5 IAM phase is duplicated into all five per-box files intentionally. Two-box owners running in parallel don't have to context-switch to a shared file. Cost: ~5 lines duplicated × 5 files = acceptable.

## Out of scope for this design

- Interactive runbook tooling (post-competition, if ever).
- Printable/PDF export workflow (any markdown file prints; not a design concern).
- New hardening scripts. Existing `tcdc_*.sh` are the execution units.
- Modifying `TCDC_master_checklist.md` or the cheatsheet.

## Success criteria

- All 22 files exist and follow the templates verbatim.
- Per-box file: teammate can execute T+0–5 without opening any other file.
- Playbook file: teammate can execute Contain in ≤60s from open-file to command-run.
- README.md symptom-lookup table covers every playbook, each row pointing to exactly one file.
- Every "If compromised" link in per-box files resolves to an existing playbook.
- Every "Primary related" link in playbooks resolves to another existing playbook or a per-box file.
