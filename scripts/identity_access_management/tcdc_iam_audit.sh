#!/bin/bash
# =============================================================
# TCDC IAM AUDIT SCRIPT
# Run this first on every box to get a full picture before
# making any changes. Read-only — nothing is modified.
# Usage: sudo bash tcdc_iam_audit.sh | tee /tmp/iam_audit.txt
# =============================================================

RED='\033[0;31m'
YLW='\033[0;33m'
GRN='\033[0;32m'
BLU='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

HOSTNAME=$(hostname)
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

banner() {
    echo -e "\n${BOLD}${BLU}========================================${NC}"
    echo -e "${BOLD}${BLU}  $1${NC}"
    echo -e "${BOLD}${BLU}========================================${NC}"
}

flag() { echo -e "  ${RED}[!] FLAG: $1${NC}"; }
warn() { echo -e "  ${YLW}[~] WARN: $1${NC}"; }
ok()   { echo -e "  ${GRN}[+] OK:   $1${NC}"; }
info() { echo -e "  ${BLU}[*] INFO: $1${NC}"; }

# Known TCDC users from the competition packet
KNOWN_USERS="root alice bob craig chad trudy mallory mike yves judy sybil walter wendy checker blackteam"

echo -e "${BOLD}TCDC IAM AUDIT REPORT${NC}"
echo -e "Host:      $HOSTNAME"
echo -e "Time:      $TIMESTAMP"
echo -e "Run as:    $(whoami)"

# -------------------------------------------------------------
banner "1. UID 0 ACCOUNTS (Should only be root)"
# -------------------------------------------------------------
uid0=$(awk -F: '($3 == 0) {print $1}' /etc/passwd)
for u in $uid0; do
    if [ "$u" = "root" ]; then
        ok "root has UID 0 (expected)"
    else
        flag "$u has UID 0 — BACKDOOR ACCOUNT"
    fi
done

# -------------------------------------------------------------
banner "2. ALL USERS WITH LOGIN SHELLS"
# -------------------------------------------------------------
info "Users with interactive login shells:"
grep -v '/nologin\|/false\|/sync\|/halt\|/shutdown' /etc/passwd | while IFS=: read -r user pass uid gid gecos home shell; do
    if [ "$uid" -ge 1000 ] || [ "$user" = "root" ]; then
        echo "    $user (UID=$uid, shell=$shell, home=$home)"
    fi
done

# -------------------------------------------------------------
banner "3. UNKNOWN USERS (Not in TCDC packet)"
# -------------------------------------------------------------
info "Checking for users not listed in competition packet..."
found_unknown=0
while IFS=: read -r user pass uid gid gecos home shell; do
    if [ "$uid" -ge 1000 ] && [ "$uid" -lt 65534 ]; then
        known=0
        for k in $KNOWN_USERS; do
            [ "$user" = "$k" ] && known=1 && break
        done
        if [ "$known" -eq 0 ]; then
            flag "UNKNOWN USER: $user (UID=$uid, shell=$shell)"
            found_unknown=1
        fi
    fi
done < /etc/passwd
[ "$found_unknown" -eq 0 ] && ok "No unknown users found"

# -------------------------------------------------------------
banner "4. SUDO & PRIVILEGE AUDIT"
# -------------------------------------------------------------
info "Sudo group members:"
getent group sudo 2>/dev/null | awk -F: '{print "    "$4}' | tr ',' '\n'
getent group wheel 2>/dev/null | awk -F: '{print "    "$4}' | tr ',' '\n'
getent group admin 2>/dev/null | awk -F: '{print "    "$4}' | tr ',' '\n'

echo ""
info "Scanning /etc/sudoers for dangerous entries..."
if grep -E 'NOPASSWD|ALL.*ALL' /etc/sudoers 2>/dev/null | grep -v '^#'; then
    flag "Dangerous sudoers entries found above"
else
    ok "No obvious dangerous entries in /etc/sudoers"
fi

echo ""
info "Scanning /etc/sudoers.d/ for dangerous entries..."
if [ -d /etc/sudoers.d ]; then
    for f in /etc/sudoers.d/*; do
        [ -f "$f" ] || continue
        echo "    File: $f"
        if grep -E 'NOPASSWD|ALL.*ALL' "$f" 2>/dev/null | grep -v '^#'; then
            flag "Dangerous entry in $f"
        else
            ok "  $f looks clean"
        fi
    done
else
    info "/etc/sudoers.d not found"
fi

# -------------------------------------------------------------
banner "5. SSH AUTHORIZED KEYS"
# -------------------------------------------------------------
info "Searching for authorized_keys files..."
found_keys=0
find / -name "authorized_keys" 2>/dev/null | while read -r keyfile; do
    if [ -s "$keyfile" ]; then
        warn "Keys found in: $keyfile"
        count=$(wc -l < "$keyfile")
        echo "    $count key(s):"
        while read -r line; do
            [ -z "$line" ] && continue
            keytype=$(echo "$line" | awk '{print $1}')
            keycomment=$(echo "$line" | awk '{print $3}')
            echo "      - Type: $keytype | Comment: $keycomment"
        done < "$keyfile"
        found_keys=1
    fi
done
[ "$found_keys" -eq 0 ] && ok "No authorized_keys files with content found"

# -------------------------------------------------------------
banner "6. PASSWORD & ACCOUNT STATUS"
# -------------------------------------------------------------
info "Checking account lock status (! = locked, * = no password):"
for user in alice bob craig chad trudy mallory mike yves judy sybil walter wendy; do
    shadow_entry=$(grep "^$user:" /etc/shadow 2>/dev/null)
    if [ -z "$shadow_entry" ]; then
        warn "$user — not found in /etc/shadow"
        continue
    fi
    pw_hash=$(echo "$shadow_entry" | cut -d: -f2)
    last_change=$(echo "$shadow_entry" | cut -d: -f3)
    if echo "$pw_hash" | grep -q '^!'; then
        warn "$user — LOCKED"
    elif echo "$pw_hash" | grep -q '^\*'; then
        warn "$user — NO PASSWORD SET"
    elif [ -z "$pw_hash" ]; then
        flag "$user — EMPTY PASSWORD"
    else
        ok "$user — password set (last changed: day $last_change)"
    fi
done

# -------------------------------------------------------------
banner "7. SHELL CONFIG BACKDOOR CHECK"
# -------------------------------------------------------------
info "Checking .bashrc, .bash_profile, .profile for suspicious content..."
SUSPICIOUS_PATTERNS='base64|/dev/tcp|/dev/udp|curl|wget|nc |ncat|python.*socket|perl.*socket|ruby.*socket|bash -i'

for user in alice bob craig chad trudy mallory mike yves judy sybil walter wendy root; do
    homedir=$(eval echo "~$user" 2>/dev/null)
    [ -z "$homedir" ] && continue
    for rcfile in .bashrc .bash_profile .profile .zshrc; do
        fullpath="$homedir/$rcfile"
        if [ -f "$fullpath" ]; then
            if grep -Ei "$SUSPICIOUS_PATTERNS" "$fullpath" 2>/dev/null | grep -v '^#' > /dev/null; then
                flag "SUSPICIOUS content in $fullpath:"
                grep -Ei "$SUSPICIOUS_PATTERNS" "$fullpath" | grep -v '^#' | while read -r line; do
                    echo "      >> $line"
                done
            fi
        fi
    done
done
ok "Shell config check complete"

# -------------------------------------------------------------
banner "8. PAM BACKDOOR CHECK"
# -------------------------------------------------------------
info "Checking PAM configs for pam_permit.so (allows any password)..."
if grep -r 'pam_permit.so' /etc/pam.d/ 2>/dev/null | grep -v '^#' | grep -v 'requisite\|required.*pam_permit' | grep 'sufficient\|optional'; then
    flag "pam_permit.so found in a dangerous context — check above"
else
    ok "No obvious pam_permit.so backdoors found"
fi

# -------------------------------------------------------------
banner "9. CURRENTLY LOGGED IN SESSIONS"
# -------------------------------------------------------------
info "Active sessions:"
who
echo ""
info "Recent login history (last 15):"
last | head -15

# -------------------------------------------------------------
banner "10. RECENTLY MODIFIED AUTH FILES"
# -------------------------------------------------------------
info "Files modified in last 2 hours in sensitive locations:"
find /etc/passwd /etc/shadow /etc/sudoers /etc/ssh /etc/pam.d /home /root \
    -newer /tmp -maxdepth 3 2>/dev/null | while read -r f; do
    warn "Recently modified: $f"
done

# -------------------------------------------------------------
banner "11. SERVICE ACCOUNT SHELL CHECK"
# -------------------------------------------------------------
info "Service accounts that should NOT have a login shell:"
BAD_SERVICE_ACCOUNTS=""
for svc in www-data apache nginx ftp vsftpd mysql postgres postgresql daemon bin sys games man lp mail news uucp proxy backup list irc gnats nobody; do
    entry=$(grep "^$svc:" /etc/passwd 2>/dev/null)
    [ -z "$entry" ] && continue
    shell=$(echo "$entry" | cut -d: -f7)
    if echo "$shell" | grep -qE '/bash|/sh|/zsh|/fish|/ksh|/csh'; then
        flag "$svc has login shell: $shell"
        BAD_SERVICE_ACCOUNTS="$BAD_SERVICE_ACCOUNTS $svc"
    else
        ok "$svc shell is $shell (no login)"
    fi
done

# -------------------------------------------------------------
echo ""
echo -e "${BOLD}========================================${NC}"
echo -e "${BOLD}AUDIT COMPLETE — $HOSTNAME${NC}"
echo -e "${BOLD}========================================${NC}"
echo ""
echo "Review all [!] FLAG and [~] WARN items above."
echo "Run tcdc_iam_harden.sh to apply fixes."
echo ""
