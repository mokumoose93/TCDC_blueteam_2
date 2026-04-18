# TCDC Competition Runbook — Index

Short, scoped files for the 3-person Blue Team 2 fielding a 5-box TCDC competition. This index has two tables: (1) which files each role keeps open, and (2) which playbook matches what you just saw.

For strategic guidance during injects or unusual situations, see the longer reference at [`TCDC_master_checklist.md`](./TCDC_master_checklist.md).

---

## Who are you?

| Role | Box(es) | Files to keep open |
|---|---|---|
| Web person     | centurytree (10.66.X.11), bonfire (10.66.X.12) | [`per_box/centurytree.md`](./per_box/centurytree.md), [`per_box/bonfire.md`](./per_box/bonfire.md) |
| Data person    | aggiedrop (10.66.X.13), excel (10.66.X.14)     | [`per_box/aggiedrop.md`](./per_box/aggiedrop.md), [`per_box/excel.md`](./per_box/excel.md) |
| SSH/IAM person | reveille-remote (10.66.X.15)                    | [`per_box/reveille-remote.md`](./per_box/reveille-remote.md) |

Each per-box file is self-contained — T+0–5 lock-down, T+5–15 hardening, ongoing checks, and an "If compromised" section that routes to playbooks.

---

## I saw something. Which playbook?

Find your row; open the file. Rows sorted by category (uptime → persistence → intrusion) so `ls playbooks/` groups in the same order.

| Symptom (what you observe) | Playbook |
|---|---|
| Scored service won't respond / `systemctl` inactive / verify-alive fails | [`uptime-service-down.md`](./playbooks/uptime-service-down.md) |
| Webroot has new files / `curl` returns wrong HTML | [`uptime-webroot-defaced.md`](./playbooks/uptime-webroot-defaced.md) |
| `psql \du` shows unknown role / `pg_stat_activity` unknown client IP | [`uptime-postgres-tampered.md`](./playbooks/uptime-postgres-tampered.md) |
| `grep anonymous_enable /etc/vsftpd.conf` = YES / anon FTP login works | [`uptime-ftp-anon-reenabled.md`](./playbooks/uptime-ftp-anon-reenabled.md) |
| `/server-status` 200 / autoindex directory listing / unexpected `a2enmod` | [`uptime-web-module-reenabled.md`](./playbooks/uptime-web-module-reenabled.md) |
| UID 0 != root / `who` shows unknown user / unrecognized account in `/etc/passwd` | [`persist-backdoor-user.md`](./playbooks/persist-backdoor-user.md) |
| New/changed `authorized_keys` / unrecognized key comment | [`persist-ssh-key.md`](./playbooks/persist-ssh-key.md) |
| `NOPASSWD` in sudoers / new file in `/etc/sudoers.d/` | [`persist-sudoers-nopasswd.md`](./playbooks/persist-sudoers-nopasswd.md) |
| `pam_permit.so sufficient` anywhere in `/etc/pam.d/` | [`persist-pam-backdoor.md`](./playbooks/persist-pam-backdoor.md) ⚠️ |
| Unknown crontab / new file in `/etc/cron.d/` / scheduled process you can't trace | [`persist-cron.md`](./playbooks/persist-cron.md) |
| `systemctl list-unit-files` shows unknown enabled unit / new `.service` in `/etc/systemd/system/` | [`persist-systemd-unit.md`](./playbooks/persist-systemd-unit.md) |
| `.bashrc` / `.profile` contains `/dev/tcp`, `base64 -d`, `curl \| bash`, or aliased `sudo` | [`persist-bashrc-rc.md`](./playbooks/persist-bashrc-rc.md) |
| `find / -perm -4000` diff from baseline / SUID file in `/tmp` or `/dev/shm` | [`persist-suid-binary.md`](./playbooks/persist-suid-binary.md) |
| `ss -tp state established` unknown peer / process from `/tmp` with a socket | [`intrusion-reverse-shell.md`](./playbooks/intrusion-reverse-shell.md) |
| `ss -tulnp` port not in baseline / `lsmod` shows unfamiliar module | [`intrusion-new-listener.md`](./playbooks/intrusion-new-listener.md) |

⚠️ `persist-pam-backdoor.md` requires a second root session open **before** editing. Read the WARNING banner first.

---

## Not sure what you're looking at?

→ [`playbooks/_decision_tree.md`](./playbooks/_decision_tree.md) — five-step flow: IDENTIFY → CONTAIN → ERADICATE → RECOVER → VERIFY.

---

## Reference files (not for mid-incident use)

- [`TCDC_master_checklist.md`](./TCDC_master_checklist.md) — full 392-line strategic reference, inject response guidance.
- [`../cheatsheets/TCDC_master_cheatsheet.md`](../cheatsheets/TCDC_master_cheatsheet.md) — command reference by category.
