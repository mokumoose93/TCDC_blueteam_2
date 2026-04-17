#!/bin/bash
# =============================================================
# TCDC IAM HARDENING SCRIPT
# Applies hardening to users, sudo, SSH keys, PAM, and shells.
# Run AFTER tcdc_iam_audit.sh so you know what you're changing.
# Usage: sudo bash tcdc_iam_harden.sh
# =============================================================

RED='\033[0;31m'
YLW='\033[0;33m'
GRN='\033[0;32m'
BLU='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

flag() { echo -e "  ${RED}[!] $1${NC}"; }
warn() { echo -e "  ${YLW}[~] $1${NC}"; }
ok()   { echo -e "  ${GRN}[+] $1${NC}"; }
info() { echo -e "  ${BLU}[*] $1${NC}"; }

banner() {
    echo -e "\n${BOLD}${BLU}========================================${NC}"
    echo -e "${BOLD}${BLU}  $1${NC}"
    echo -e "${BOLD}${BLU}========================================${NC}"
}

# -------------------------------------------------------------
# SAFETY CHECKS
# -------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    echo "Must be run as root. Exiting."
    exit 1
fi

echo -e "${BOLD}TCDC IAM HARDENING SCRIPT${NC}"
echo -e "Host: $(hostname) | Time: $(date)"
echo ""
warn "This script will change passwords, modify sudoers, and remove SSH keys."
warn "Make sure your TEAM knows the new passwords before running."
echo ""
read -rp "Continue? (yes/no): " confirm
[ "$confirm" != "yes" ] && echo "Aborted." && exit 0

# -------------------------------------------------------------
# CONFIGURATION — edit these before running
# -------------------------------------------------------------

# New password for all regular users — CHANGE THIS before competition
# Format: use something your team agrees on
BASE_PASSWORD="TCDC2026-Secure-$(hostname)-01"

# Users that should have their passwords changed
CHANGE_PASS_USERS="alice bob craig chad trudy mallory mike yves judy sybil walter wendy"

# Users that should be locked (no interactive login needed)
# Adjust based on which box you're on
LOCK_USERS=""   # e.g., "alice trudy yves wendy" on a box they don't administer

# Users that should have sudo access — adjust per box
# centurytree: bob (dir search admin)
# bonfire/reveille: craig, sybil (react admin), mike (ssh admin)
# aggiedrop: mike (ftp admin)
# excel: nobody needs sudo except root
SUDO_USERS="root"   # REPLACE with actual needed sudo users per box

# Users who legitimately need SSH key auth (usually just checker)
KEEP_KEYS_FOR="checker blackteam"

# -------------------------------------------------------------
banner "1. PASSWORD CHANGES"
# -------------------------------------------------------------
info "Changing passwords for all known users..."
for user in $CHANGE_PASS_USERS; do
    if id "$user" &>/dev/null; then
        # Generate a unique password per user
        new_pass="${BASE_PASSWORD}-${user}"
        echo "$user:$new_pass" | chpasswd
        ok "Password changed for $user → ${new_pass}"
    else
        warn "User $user not found on this box — skipping"
    fi
done

echo ""
info "IMPORTANT: New passwords follow the pattern:"
info "  ${BASE_PASSWORD}-<username>"
info "Write these down now!"

# -------------------------------------------------------------
banner "2. REMOVE UNKNOWN/BACKDOOR USERS"
# -------------------------------------------------------------
KNOWN_USERS="root alice bob craig chad trudy mallory mike yves judy sybil walter wendy checker blackteam daemon bin sys sync games man lp mail news uucp proxy www-data backup list irc gnats nobody systemd-network systemd-resolve systemd-timesync messagebus syslog _apt tss uuidd tcpdump sshd pollinate usbmux landscape fwupd-refresh"

info "Checking for unknown users..."
while IFS=: read -r user pass uid gid gecos home shell; do
    [ "$uid" -lt 1000 ] && continue   # skip system accounts
    [ "$uid" -eq 65534 ] && continue  # skip nobody
    known=0
    for k in $KNOWN_USERS; do
        [ "$user" = "$k" ] && known=1 && break
    done
    if [ "$known" -eq 0 ]; then
        flag "Unknown user found: $user (UID=$uid)"
        read -rp "    Delete $user? (yes/no): " del_confirm
        if [ "$del_confirm" = "yes" ]; then
            userdel -r "$user" 2>/dev/null && ok "Deleted $user" || warn "Could not fully delete $user"
        else
            warn "Skipped deletion of $user — review manually"
        fi
    fi
done < /etc/passwd

# -------------------------------------------------------------
banner "3. SUDO HARDENING"
# -------------------------------------------------------------
info "Removing all non-root users from sudo group..."
for user in $(getent group sudo | cut -d: -f4 | tr ',' ' '); do
    if [ "$user" != "root" ] && [[ ! " $SUDO_USERS " =~ " $user " ]]; then
        gpasswd -d "$user" sudo 2>/dev/null && ok "Removed $user from sudo group" || warn "Could not remove $user from sudo"
    fi
done

for user in $(getent group wheel | cut -d: -f4 | tr ',' ' '); do
    if [ "$user" != "root" ] && [[ ! " $SUDO_USERS " =~ " $user " ]]; then
        gpasswd -d "$user" wheel 2>/dev/null && ok "Removed $user from wheel group" || true
    fi
done

echo ""
info "Backing up and scanning /etc/sudoers.d/..."
mkdir -p /root/tcdc_backups
cp /etc/sudoers /root/tcdc_backups/sudoers.bak
ok "Backed up /etc/sudoers to /root/tcdc_backups/sudoers.bak"

if [ -d /etc/sudoers.d ]; then
    for f in /etc/sudoers.d/*; do
        [ -f "$f" ] || continue
        if grep -Eq 'NOPASSWD' "$f" 2>/dev/null; then
            flag "NOPASSWD found in $f"
            cp "$f" /root/tcdc_backups/
            read -rp "    Remove $f? (yes/no): " rm_confirm
            if [ "$rm_confirm" = "yes" ]; then
                rm "$f" && ok "Removed $f"
            fi
        fi
    done
fi

# Ensure /etc/sudoers doesn't have dangerous entries
if grep -Eq 'NOPASSWD.*ALL' /etc/sudoers | grep -v '^#'; then
    flag "NOPASSWD ALL found in /etc/sudoers — review and edit with visudo"
fi

# -------------------------------------------------------------
banner "4. SSH AUTHORIZED KEYS CLEANUP"
# -------------------------------------------------------------
info "Removing unauthorized SSH keys..."
find / -name "authorized_keys" 2>/dev/null | while read -r keyfile; do
    owner=$(stat -c '%U' "$keyfile" 2>/dev/null)

    # Check if this owner should keep their keys
    keep=0
    for k in $KEEP_KEYS_FOR; do
        [ "$owner" = "$k" ] && keep=1 && break
    done

    if [ "$keep" -eq 1 ]; then
        ok "Keeping keys for $owner (protected user): $keyfile"
    else
        if [ -s "$keyfile" ]; then
            warn "Clearing authorized_keys for $owner: $keyfile"
            cp "$keyfile" "${keyfile}.bak.$(date +%s)"
            > "$keyfile"
            chmod 600 "$keyfile"
            ok "Cleared $keyfile (backup saved)"
        fi
    fi
done

# -------------------------------------------------------------
banner "5. FIX SERVICE ACCOUNT SHELLS"
# -------------------------------------------------------------
info "Setting nologin shell for service accounts..."
for svc in www-data apache nginx ftp vsftpd mysql postgres daemon; do
    if id "$svc" &>/dev/null; then
        current_shell=$(getent passwd "$svc" | cut -d: -f7)
        if echo "$current_shell" | grep -qE '/bash|/sh$|/zsh|/fish'; then
            usermod -s /usr/sbin/nologin "$svc"
            ok "Changed $svc shell from $current_shell to /usr/sbin/nologin"
        else
            ok "$svc already has non-login shell: $current_shell"
        fi
    fi
done

# -------------------------------------------------------------
banner "6. LOCK SPECIFIED ACCOUNTS"
# -------------------------------------------------------------
if [ -n "$LOCK_USERS" ]; then
    for user in $LOCK_USERS; do
        if id "$user" &>/dev/null; then
            usermod -L "$user"
            ok "Locked account: $user"
        fi
    done
else
    info "No users configured for locking (edit LOCK_USERS in script)"
fi

# -------------------------------------------------------------
banner "7. SSH CONFIG HARDENING"
# -------------------------------------------------------------
SSHD_CONFIG="/etc/ssh/sshd_config"
info "Backing up sshd_config..."
cp "$SSHD_CONFIG" /root/tcdc_backups/sshd_config.bak
ok "Backed up to /root/tcdc_backups/sshd_config.bak"

info "Applying SSH hardening settings..."

set_ssh_option() {
    local key="$1"
    local value="$2"
    if grep -qE "^#?${key}" "$SSHD_CONFIG"; then
        sed -i "s|^#\?${key}.*|${key} ${value}|" "$SSHD_CONFIG"
    else
        echo "${key} ${value}" >> "$SSHD_CONFIG"
    fi
    ok "Set $key = $value"
}

set_ssh_option "PermitRootLogin" "no"
set_ssh_option "PermitEmptyPasswords" "no"
set_ssh_option "X11Forwarding" "no"
set_ssh_option "MaxAuthTries" "3"
set_ssh_option "LoginGraceTime" "30"
set_ssh_option "Protocol" "2"

# Validate and restart
if sshd -t 2>/dev/null; then
    systemctl restart sshd
    ok "SSH restarted successfully"
else
    flag "sshd config has errors! Restoring backup..."
    cp /root/tcdc_backups/sshd_config.bak "$SSHD_CONFIG"
    systemctl restart sshd
    flag "Backup restored — review SSH config manually"
fi

# -------------------------------------------------------------
banner "8. PAM PASSWORD POLICY"
# -------------------------------------------------------------
info "Installing libpam-pwquality if not present..."
apt-get install -y libpam-pwquality -qq 2>/dev/null && ok "libpam-pwquality ready"

PAM_PWQUALITY="/etc/security/pwquality.conf"
if [ -f "$PAM_PWQUALITY" ]; then
    cp "$PAM_PWQUALITY" /root/tcdc_backups/pwquality.conf.bak
    cat > "$PAM_PWQUALITY" << EOF
minlen = 12
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
maxrepeat = 3
EOF
    ok "Password quality policy applied"
fi

# -------------------------------------------------------------
banner "9. FIX HOME DIRECTORY PERMISSIONS"
# -------------------------------------------------------------
info "Fixing home directory permissions..."
for user in alice bob craig chad trudy mallory mike yves judy sybil walter wendy; do
    homedir=$(getent passwd "$user" | cut -d: -f6)
    [ -z "$homedir" ] || [ ! -d "$homedir" ] && continue
    chmod 750 "$homedir"
    chown "$user:$user" "$homedir"
    ok "Fixed permissions on $homedir"
    # Fix .ssh directory if exists
    if [ -d "$homedir/.ssh" ]; then
        chmod 700 "$homedir/.ssh"
        [ -f "$homedir/.ssh/authorized_keys" ] && chmod 600 "$homedir/.ssh/authorized_keys"
        ok "Fixed .ssh permissions for $user"
    fi
done

# -------------------------------------------------------------
banner "10. KICK ACTIVE UNAUTHORIZED SESSIONS"
# -------------------------------------------------------------
info "Current active sessions:"
who
echo ""
read -rp "Kick any active session? Enter TTY (e.g. pts/1) or 'skip': " tty_input
if [ "$tty_input" != "skip" ] && [ -n "$tty_input" ]; then
    pkill -kill -t "$tty_input" && ok "Kicked session on $tty_input" || warn "Could not kick $tty_input"
fi

# -------------------------------------------------------------
banner "HARDENING COMPLETE"
# -------------------------------------------------------------
echo ""
ok "All steps complete on $(hostname)"
info "Backups saved to /root/tcdc_backups/"
info "Run tcdc_iam_audit.sh again to verify changes."
echo ""
warn "REMEMBER: New password pattern is: ${BASE_PASSWORD}-<username>"
warn "Tell your team NOW before they get locked out."
echo ""
