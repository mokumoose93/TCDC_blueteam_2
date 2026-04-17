#!/bin/bash
# =============================================================
# TCDC POSTGRESQL HARDENING SCRIPT
# For: excel (PostgreSQL scored service)
# Usage: sudo bash tcdc_harden_postgres.sh
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

[ "$(id -u)" -ne 0 ] && echo "Must be run as root." && exit 1

echo -e "${BOLD}TCDC POSTGRESQL HARDENING — $(hostname)${NC}"
echo -e "Time: $(date)"

# Find PostgreSQL version and config paths
PG_VERSION=$(sudo -u postgres psql -tAc "SHOW server_version_num;" 2>/dev/null | cut -c1-2)
if [ -z "$PG_VERSION" ]; then
    PG_VERSION=$(ls /etc/postgresql/ 2>/dev/null | sort -V | tail -1)
fi

PG_CONF="/etc/postgresql/${PG_VERSION}/main/postgresql.conf"
HBA_CONF="/etc/postgresql/${PG_VERSION}/main/pg_hba.conf"

# Try to find them if standard paths fail
[ -f "$PG_CONF" ] || PG_CONF=$(find /etc/postgresql -name "postgresql.conf" 2>/dev/null | head -1)
[ -f "$HBA_CONF" ] || HBA_CONF=$(find /etc/postgresql -name "pg_hba.conf" 2>/dev/null | head -1)

if [ -z "$PG_CONF" ] || [ ! -f "$PG_CONF" ]; then
    flag "postgresql.conf not found — is PostgreSQL installed?"
    exit 1
fi

info "postgresql.conf: $PG_CONF"
info "pg_hba.conf:     $HBA_CONF"

BACKUP_DIR="/root/tcdc_backups/postgres_$(date +%s)"
mkdir -p "$BACKUP_DIR"
cp "$PG_CONF" "$BACKUP_DIR/postgresql.conf.bak"
cp "$HBA_CONF" "$BACKUP_DIR/pg_hba.conf.bak"
ok "Configs backed up to $BACKUP_DIR"

MY_IP=$(hostname -I | awk '{print $1}')
MY_SUBNET=$(echo "$MY_IP" | cut -d. -f1-3).0/24

# Helper to set postgresql.conf value
set_pg_conf() {
    local key="$1"
    local value="$2"
    if grep -qE "^#?${key}\s*=" "$PG_CONF"; then
        sed -i "s|^#\?${key}\s*=.*|${key} = ${value}|" "$PG_CONF"
    else
        echo "${key} = ${value}" >> "$PG_CONF"
    fi
    ok "Set ${key} = ${value}"
}

# -------------------------------------------------------------
banner "1. NETWORK BINDING"
# -------------------------------------------------------------
info "Restricting listen_addresses to localhost and this box only..."
set_pg_conf "listen_addresses" "'localhost,${MY_IP}'"
warn "If the scored checker connects from a different host, you may need to add its IP"

# -------------------------------------------------------------
banner "2. LOGGING"
# -------------------------------------------------------------
info "Enabling connection logging..."
set_pg_conf "log_connections" "on"
set_pg_conf "log_disconnections" "on"
set_pg_conf "log_failed_authentications" "on"
set_pg_conf "log_hostname" "off"
set_pg_conf "log_line_prefix" "'%t [%p]: [%l-1] user=%u,db=%d,app=%a,client=%h '"
ok "Logging configured"

# -------------------------------------------------------------
banner "3. CONNECTION LIMITS"
# -------------------------------------------------------------
set_pg_conf "max_connections" "50"
ok "max_connections = 50"

# -------------------------------------------------------------
banner "4. pg_hba.conf — ACCESS CONTROL"
# -------------------------------------------------------------
info "Rewriting pg_hba.conf to restrict access..."

# Backup is already done above
cat > "$HBA_CONF" << EOF
# TCDC pg_hba.conf — hardened
# TYPE  DATABASE  USER      ADDRESS           METHOD

# Local socket connections (required for postgres user admin)
local   all       postgres                    peer
local   all       all                         md5

# Localhost connections
host    all       all       127.0.0.1/32      md5
host    all       all       ::1/128           md5

# Team subnet connections (for scored checker and internal access)
host    all       all       ${MY_SUBNET}      md5

# All other connections denied by default (no wildcard entry)
EOF

ok "pg_hba.conf rewritten — only localhost and $MY_SUBNET allowed"
warn "If checker connects from outside your subnet, add its IP above"

# -------------------------------------------------------------
banner "5. POSTGRES USER PASSWORD"
# -------------------------------------------------------------
info "Changing postgres superuser password..."
read -rsp "Enter new password for postgres DB user: " PG_PASS
echo ""
if [ -n "$PG_PASS" ]; then
    sudo -u postgres psql -c "ALTER USER postgres PASSWORD '$PG_PASS';" 2>/dev/null \
        && ok "postgres password changed" \
        || flag "Failed to change postgres password"
    echo "postgres DB password: $PG_PASS" > "$BACKUP_DIR/pg_credentials.txt"
    chmod 600 "$BACKUP_DIR/pg_credentials.txt"
    ok "Credentials saved to $BACKUP_DIR/pg_credentials.txt"
else
    warn "No password entered — postgres password unchanged"
fi

# -------------------------------------------------------------
banner "6. AUDIT EXISTING ROLES"
# -------------------------------------------------------------
info "Current PostgreSQL roles:"
sudo -u postgres psql -c "\du" 2>/dev/null

echo ""
info "Checking for roles with dangerous privileges..."
sudo -u postgres psql -tAc "
    SELECT rolname, rolsuper, rolcreaterole, rolcreatedb
    FROM pg_roles
    WHERE rolsuper = true OR rolcreaterole = true
    ORDER BY rolname;
" 2>/dev/null | while IFS='|' read -r name super createrole createdb; do
    name=$(echo "$name" | xargs)
    super=$(echo "$super" | xargs)
    if [ "$name" != "postgres" ] && [ "$super" = "t" ]; then
        flag "Non-postgres superuser found: $name — review and revoke if unnecessary"
        echo "    To revoke: sudo -u postgres psql -c \"ALTER USER $name NOSUPERUSER;\""
    fi
done

# -------------------------------------------------------------
banner "7. REVOKE PUBLIC SCHEMA PERMISSIONS"
# -------------------------------------------------------------
info "Revoking public schema CREATE from PUBLIC role..."
sudo -u postgres psql -c "REVOKE CREATE ON SCHEMA public FROM PUBLIC;" 2>/dev/null \
    && ok "Revoked CREATE on public schema from PUBLIC" \
    || warn "Could not revoke — check manually"

# -------------------------------------------------------------
banner "8. RELOAD & VERIFY"
# -------------------------------------------------------------
info "Reloading PostgreSQL config..."
sudo -u postgres psql -c "SELECT pg_reload_conf();" 2>/dev/null

systemctl restart postgresql
sleep 3

if systemctl is-active --quiet postgresql; then
    ok "PostgreSQL is running after hardening"
    info "Testing connection on $MY_IP:5432..."
    sudo -u postgres psql -c "SELECT version();" 2>/dev/null | head -3
else
    flag "PostgreSQL is DOWN after hardening"
    warn "Restoring backups..."
    cp "$BACKUP_DIR/postgresql.conf.bak" "$PG_CONF"
    cp "$BACKUP_DIR/pg_hba.conf.bak" "$HBA_CONF"
    systemctl restart postgresql
    flag "Backup restored — review manually"
fi

echo ""
echo -e "${BOLD}========================================${NC}"
echo -e "${BOLD}POSTGRESQL HARDENING COMPLETE — $(hostname)${NC}"
echo -e "${BOLD}========================================${NC}"
echo "Backup: $BACKUP_DIR"
echo ""
warn "Remember: The scored checker must be able to connect to PostgreSQL."
warn "If uptime drops after this, check pg_hba.conf and listen_addresses."
