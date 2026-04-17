#!/bin/bash
# =============================================================
# TCDC BULK PASSWORD CHANGER
# Fastest possible password reset for all known TCDC users.
# Run this FIRST on every box at competition start.
# Usage: sudo bash tcdc_passwd_reset.sh
# =============================================================

RED='\033[0;31m'
YLW='\033[0;33m'
GRN='\033[0;32m'
BLU='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

if [ "$(id -u)" -ne 0 ]; then
    echo "Must be run as root."
    exit 1
fi

echo -e "${BOLD}TCDC BULK PASSWORD RESET — $(hostname)${NC}"
echo ""

# -------------------------------------------------------------
# PASSWORD STRATEGY
# Choose ONE of these modes:
#
# MODE 1 — Same password for all users (fast, simple)
# MODE 2 — Unique password per user (more secure)
# MODE 3 — Interactive (you type each password)
# -------------------------------------------------------------

echo "Select password mode:"
echo "  1) Same password for all users"
echo "  2) Unique password per user (pattern: BASE-username)"
echo "  3) Interactive — enter each manually"
echo ""
read -rp "Mode (1/2/3): " MODE

USERS="alice bob craig chad trudy mallory mike yves judy sybil walter wendy"

# -------------------- MODE 1 --------------------
if [ "$MODE" = "1" ]; then
    read -rsp "Enter new password for ALL users: " PASS1
    echo ""
    read -rsp "Confirm password: " PASS2
    echo ""
    if [ "$PASS1" != "$PASS2" ]; then
        echo -e "${RED}Passwords do not match. Exiting.${NC}"
        exit 1
    fi
    if [ ${#PASS1} -lt 8 ]; then
        echo -e "${YLW}Warning: Password is less than 8 characters.${NC}"
        read -rp "Continue anyway? (yes/no): " weak_confirm
        [ "$weak_confirm" != "yes" ] && exit 1
    fi

    echo ""
    for user in $USERS; do
        if id "$user" &>/dev/null; then
            echo "$user:$PASS1" | chpasswd 2>/dev/null \
                && echo -e "  ${GRN}[+] $user — password changed${NC}" \
                || echo -e "  ${RED}[!] $user — FAILED${NC}"
        else
            echo -e "  ${YLW}[~] $user — not found on this box, skipping${NC}"
        fi
    done
    echo ""
    echo -e "${BOLD}All passwords set to the same value.${NC}"

# -------------------- MODE 2 --------------------
elif [ "$MODE" = "2" ]; then
    read -rsp "Enter base password (will append -username): " BASE
    echo ""
    if [ ${#BASE} -lt 6 ]; then
        echo -e "${RED}Base password too short. Exiting.${NC}"
        exit 1
    fi

    echo ""
    echo -e "${BOLD}Passwords will be: ${BASE}-<username>${NC}"
    echo ""
    PASS_LOG="/root/tcdc_passwords_$(hostname).txt"
    echo "TCDC Password Log — $(hostname) — $(date)" > "$PASS_LOG"
    echo "======================================" >> "$PASS_LOG"

    for user in $USERS; do
        new_pass="${BASE}-${user}"
        if id "$user" &>/dev/null; then
            echo "$user:$new_pass" | chpasswd 2>/dev/null \
                && echo -e "  ${GRN}[+] $user → $new_pass${NC}" \
                || echo -e "  ${RED}[!] $user — FAILED${NC}"
            echo "$user : $new_pass" >> "$PASS_LOG"
        else
            echo -e "  ${YLW}[~] $user — not found on this box, skipping${NC}"
        fi
    done

    chmod 600 "$PASS_LOG"
    echo ""
    echo -e "${GRN}Password log saved to: $PASS_LOG (chmod 600)${NC}"
    echo -e "${YLW}Share this with your team securely!${NC}"

# -------------------- MODE 3 --------------------
elif [ "$MODE" = "3" ]; then
    echo ""
    for user in $USERS; do
        if ! id "$user" &>/dev/null; then
            echo -e "  ${YLW}[~] $user — not on this box, skipping${NC}"
            continue
        fi
        read -rsp "  Password for $user (leave blank to skip): " user_pass
        echo ""
        if [ -z "$user_pass" ]; then
            echo -e "  ${YLW}[~] Skipped $user${NC}"
        else
            echo "$user:$user_pass" | chpasswd 2>/dev/null \
                && echo -e "  ${GRN}[+] $user — changed${NC}" \
                || echo -e "  ${RED}[!] $user — FAILED${NC}"
        fi
    done

else
    echo "Invalid mode. Exiting."
    exit 1
fi

# -------------------------------------------------------------
# Also change root password
# -------------------------------------------------------------
echo ""
read -rp "Change root password too? (yes/no): " change_root
if [ "$change_root" = "yes" ]; then
    read -rsp "New root password: " root_pass1
    echo ""
    read -rsp "Confirm root password: " root_pass2
    echo ""
    if [ "$root_pass1" = "$root_pass2" ]; then
        echo "root:$root_pass1" | chpasswd \
            && echo -e "${GRN}[+] root password changed${NC}" \
            || echo -e "${RED}[!] root password change FAILED${NC}"
    else
        echo -e "${RED}Root passwords do not match — root NOT changed${NC}"
    fi
fi

# -------------------------------------------------------------
# Verify checker and blackteam are untouched
# -------------------------------------------------------------
echo ""
echo -e "${BLU}[*] Verifying protected accounts are intact...${NC}"
for protected in checker blackteam; do
    if id "$protected" &>/dev/null; then
        echo -e "  ${GRN}[+] $protected exists — DO NOT MODIFY${NC}"
    else
        echo -e "  ${YLW}[~] $protected not found on this box${NC}"
    fi
done

echo ""
echo -e "${BOLD}Password reset complete on $(hostname).${NC}"
echo -e "${YLW}Communicate new passwords to your team NOW.${NC}"
