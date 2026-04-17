#!/bin/bash
# =============================================================
# TCDC SURICATA IDS CONFIGURATION SCRIPT
# Configures Suricata in IDS (detection-only) mode for TCDC.
#
# CRITICAL TCDC RULES THIS SCRIPT RESPECTS:
#   - IDS mode ONLY (af-packet, NOT nfqueue/IPS)
#   - Checker IP is whitelisted — never triggers alerts
#   - No traffic is blocked — only logged and alerted
#   - All rules tuned for TCDC's 5-service environment
#
# Usage: sudo bash tcdc_suricata_config.sh
# Run AFTER: sudo apt install suricata suricata-update
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
    echo -e "\n${BOLD}${BLU}============================================${NC}"
    echo -e "${BOLD}${BLU}  $1${NC}"
    echo -e "${BOLD}${BLU}============================================${NC}"
}

[ "$(id -u)" -ne 0 ] && echo "Must be run as root." && exit 1

echo -e "${BOLD}TCDC SURICATA IDS CONFIGURATION — $(hostname)${NC}"
echo -e "Time: $(date)"
echo ""

# Verify Suricata is installed
if ! command -v suricata &>/dev/null; then
    flag "Suricata is not installed."
    info "Install with: apt install suricata suricata-update"
    exit 1
fi

SURICATA_VERSION=$(suricata --build-info 2>/dev/null | grep "Version" | head -1 | awk '{print $2}')
ok "Suricata version: $SURICATA_VERSION"

BACKUP_DIR="/root/tcdc_backups/suricata_$(date +%s)"
mkdir -p "$BACKUP_DIR"

# Backup existing config
cp /etc/suricata/suricata.yaml "$BACKUP_DIR/suricata.yaml.bak" 2>/dev/null
ok "Backed up suricata.yaml to $BACKUP_DIR"

# =============================================================
banner "1. NETWORK DETECTION"
# =============================================================

# Auto-detect primary interface
PRIMARY_IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
MY_IP=$(hostname -I | awk '{print $1}')
MY_SUBNET=$(echo "$MY_IP" | cut -d. -f1-3).0/24

info "Detected interface: $PRIMARY_IFACE"
info "Detected IP:        $MY_IP"
info "Detected subnet:    $MY_SUBNET"

# Ask for confirmation / override
echo ""
read -rp "Use interface [$PRIMARY_IFACE]? (Enter to confirm or type override): " IFACE_INPUT
[ -n "$IFACE_INPUT" ] && PRIMARY_IFACE="$IFACE_INPUT"

read -rp "Enter checker IP to whitelist (or Enter to skip): " CHECKER_IP
read -rp "Enter your team's subnet [$MY_SUBNET]: " SUBNET_INPUT
[ -n "$SUBNET_INPUT" ] && MY_SUBNET="$SUBNET_INPUT"

# Determine this box's scored service for tuned rules
echo ""
info "Which scored service is on this box?"
echo "  1) centurytree  — HTTP Directory Search"
echo "  2) aggiedrop    — FTP + Custom"
echo "  3) bonfire      — React (HTTP)"
echo "  4) reveille     — SSH"
echo "  5) excel        — PostgreSQL"
echo "  6) All / Unknown"
read -rp "Box type (1-6): " BOX_TYPE

# =============================================================
banner "2. WRITE MAIN SURICATA CONFIG"
# =============================================================
info "Writing /etc/suricata/suricata.yaml..."

# Build HOME_NET value
HOME_NET="[$MY_SUBNET"
[ -n "$CHECKER_IP" ] && HOME_NET="$HOME_NET,$CHECKER_IP"
HOME_NET="$HOME_NET]"

cat > /etc/suricata/suricata.yaml << EOF
%YAML 1.1
---
# =============================================================
# TCDC Suricata IDS Configuration
# Mode: IDS only (af-packet) — NO traffic blocking
# Generated: $(date)
# =============================================================

vars:
  address-groups:
    HOME_NET: "$HOME_NET"
    EXTERNAL_NET: "!\$HOME_NET"

    # Scored service definitions
    HTTP_SERVERS: "\$HOME_NET"
    SMTP_SERVERS: "\$HOME_NET"
    SQL_SERVERS: "\$HOME_NET"
    DNS_SERVERS: "\$HOME_NET"
    TELNET_SERVERS: "\$HOME_NET"
    AIM_SERVERS: "\$EXTERNAL_NET"
    DC_SERVERS: "\$HOME_NET"
    DNP3_SERVER: "\$HOME_NET"
    DNP3_CLIENT: "\$HOME_NET"
    MODBUS_CLIENT: "\$HOME_NET"
    MODBUS_SERVER: "\$HOME_NET"
    ENIP_CLIENT: "\$HOME_NET"
    ENIP_SERVER: "\$HOME_NET"

  port-groups:
    HTTP_PORTS: "80,443,3000,8080,8443"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: 1521
    SSH_PORTS: 22
    DNP3_PORTS: 20000
    MODBUS_PORTS: 502
    FILE_DATA_PORTS: "[\$HTTP_PORTS,110,143]"
    FTP_PORTS: 21
    VXLAN_PORTS: 4789
    TEREDO_PORTS: 3544

# =============================================================
# DETECTION ENGINE
# =============================================================
default-log-dir: /var/log/suricata/

stats:
  enabled: yes
  interval: 8

# =============================================================
# OUTPUT CONFIGURATION
# IDS mode: all outputs are logs — nothing is dropped
# =============================================================
outputs:
  # Fast alerts log (one line per alert — easiest to watch live)
  - fast:
      enabled: yes
      filename: fast.log
      append: yes

  # EVE JSON unified log (best for analysis and parsing)
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      community-id: true
      types:
        - alert:
            payload: yes
            payload-printable: yes
            packet: yes
            metadata: yes
            http-body: yes
            http-body-printable: yes
        - anomaly:
            enabled: yes
        - http:
            extended: yes
        - dns:
            query: yes
            answer: yes
        - tls:
            extended: yes
        - files:
            force-magic: yes
        - smtp: {}
        - ftp: {}
        - ssh: {}
        - flow: {}
        - netflow: {}

  # Stats log
  - stats:
      enabled: yes
      filename: stats.log
      totals: yes
      threads: no

  # Syslog integration
  - syslog:
      enabled: yes
      facility: local5
      format: "[%i] <%d> -- "

# =============================================================
# AF-PACKET CAPTURE (IDS mode — read-only, no blocking)
# =============================================================
af-packet:
  - interface: $PRIMARY_IFACE
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes
    ring-size: 2048
    block-size: 32768
    threads: auto
    copy-mode: none       # IDS ONLY — never set to ips/tap

# IMPORTANT: nfqueue section intentionally omitted
# nfqueue = IPS mode = can block checker = competition loss

# =============================================================
# APP LAYER PROTOCOLS
# =============================================================
app-layer:
  protocols:
    tls:
      enabled: yes
      detection-ports:
        dp: 443
    dcerpc:
      enabled: yes
    ftp:
      enabled: yes
      memcap: 64mb
    ssh:
      enabled: yes
    smtp:
      enabled: yes
    imap:
      enabled: detection-only
    http:
      enabled: yes
      libhtp:
        default-config:
          personality: IDS
          request-body-limit: 100kb
          response-body-limit: 100kb
          request-body-minimal-inspect-size: 32kb
          request-body-inspect-window: 4kb
          response-body-minimal-inspect-size: 40kb
          response-body-inspect-window: 16kb
          response-body-decompress-layer-limit: 2
          http-body-inline: auto
          swf-decompression:
            enabled: yes
    dnp3:
      enabled: no
    modbus:
      enabled: no
    enip:
      enabled: no
    nfs:
      enabled: yes
    ikev2:
      enabled: yes
    krb5:
      enabled: yes
    dhcp:
      enabled: yes
    snmp:
      enabled: yes
    rdp:
      enabled: yes
    http2:
      enabled: yes
    tftp:
      enabled: yes
    postgresql:
      enabled: yes

# =============================================================
# DETECTION ENGINE SETTINGS
# =============================================================
detect:
  profile: medium
  custom-values:
    toclient-groups: 3
    toserver-groups: 25
  sgh-mpm-context: auto
  inspection-recursion-limit: 3000

# Stream settings
stream:
  memcap: 64mb
  checksum-validation: yes
  inline: no           # IDS mode — no inline processing
  reassembly:
    memcap: 256mb
    depth: 1mb
    toserver-chunk-size: 2560
    toclient-chunk-size: 2560
    randomize-chunk-size: yes

# Defrag
defrag:
  memcap: 32mb
  hash-size: 65536
  trackers: 65535
  max-frags: 65535
  prealloc: yes
  timeout: 60

# Flow settings
flow:
  memcap: 128mb
  hash-size: 65536
  prealloc: 10000
  emergency-recovery: 30

flow-timeouts:
  default:
    new: 30
    established: 300
    closed: 0
    bypassed: 100
    emergency-new: 10
    emergency-established: 100
    emergency-closed: 0
    emergency-bypassed: 50
  tcp:
    new: 60
    established: 600
    closed: 60
    bypassed: 100
    emergency-new: 5
    emergency-established: 100
    emergency-closed: 10
    emergency-bypassed: 50
  udp:
    new: 30
    established: 300
    bypassed: 100
    emergency-new: 10
    emergency-established: 100
    emergency-bypassed: 50

# =============================================================
# RULE FILES
# =============================================================
default-rule-path: /etc/suricata/rules

rule-files:
  - suricata.rules
  - tcdc-local.rules

# Suppress noisy/irrelevant rules
suppress-file: /etc/suricata/suppress.conf

# =============================================================
# LOGGING
# =============================================================
logging:
  default-log-level: notice
  outputs:
    - console:
        enabled: no
    - file:
        enabled: yes
        level: info
        filename: /var/log/suricata/suricata.log
    - syslog:
        enabled: yes
        facility: local5
        format: "[%i] <%d> -- "

# Host table
host-mode: auto
max-pending-packets: 1024
runmode: autofp
default-packet-size: 1514
unix-command:
  enabled: auto
legacy:
  uricontent: enabled

# =============================================================
# PERFORMANCE (conservative for competition boxes)
# =============================================================
threading:
  set-cpu-affinity: no
  detect-thread-ratio: 1.0

luajit:
  states: 128

profiling:
  rules:
    enabled: yes
    filename: rule_perf.log
    append: yes
    limit: 10
    json: yes
EOF

ok "suricata.yaml written"

# =============================================================
banner "3. WRITE LOCAL TCDC RULES"
# =============================================================
info "Writing TCDC-specific detection rules..."

mkdir -p /etc/suricata/rules
LOCAL_RULES="/etc/suricata/rules/tcdc-local.rules"

cat > "$LOCAL_RULES" << EOF
# =============================================================
# TCDC Local Suricata Rules
# Generated: $(date)
# IDS mode only — these generate ALERTS, not blocks
# SID range: 9000001-9099999
# =============================================================

# -------------------------------------------------------------
# WHITELIST — Checker and team subnet (suppress all alerts)
# These pass silently — never alert on checker activity
# -------------------------------------------------------------
EOF

if [ -n "$CHECKER_IP" ]; then
    cat >> "$LOCAL_RULES" << EOF
pass ip $CHECKER_IP any -> any any (msg:"TCDC Checker whitelist"; sid:9000001; rev:1;)
pass ip any any -> $CHECKER_IP any (msg:"TCDC Checker whitelist return"; sid:9000002; rev:1;)
EOF
    ok "Checker IP $CHECKER_IP whitelisted in rules"
fi

cat >> "$LOCAL_RULES" << 'EOF'

# -------------------------------------------------------------
# REVERSE SHELL DETECTION
# Common reverse shell patterns used in competitions
# -------------------------------------------------------------

# Bash reverse shell over /dev/tcp
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"TCDC REVSHELL bash /dev/tcp outbound"; flow:to_server,established; content:"/dev/tcp/"; nocase; classtype:trojan-activity; sid:9001001; rev:1;)

# Netcat reverse shell
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"TCDC REVSHELL netcat connect-back"; flow:to_server,established; content:"nc "; content:"-e"; distance:0; within:20; nocase; classtype:trojan-activity; sid:9001002; rev:1;)

# Python reverse shell
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"TCDC REVSHELL python socket"; flow:to_server,established; content:"import socket"; nocase; classtype:trojan-activity; sid:9001003; rev:1;)

# Perl reverse shell
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"TCDC REVSHELL perl socket"; flow:to_server,established; content:"use Socket"; nocase; classtype:trojan-activity; sid:9001004; rev:1;)

# Base64 encoded command execution (common C2 technique)
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"TCDC C2 base64 encoded payload in HTTP"; flow:to_server,established; content:"base64"; http_client_body; nocase; classtype:trojan-activity; sid:9001005; rev:1;)

# -------------------------------------------------------------
# CREDENTIAL THEFT
# -------------------------------------------------------------

# /etc/passwd access over HTTP (LFI attempt)
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"TCDC LFI /etc/passwd attempt"; flow:to_server,established; content:"/etc/passwd"; http_uri; nocase; classtype:attempted-recon; sid:9002001; rev:1;)

# /etc/shadow access over HTTP
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"TCDC LFI /etc/shadow attempt"; flow:to_server,established; content:"/etc/shadow"; http_uri; nocase; classtype:attempted-recon; sid:9002002; rev:1;)

# Directory traversal
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"TCDC Directory traversal attempt"; flow:to_server,established; content:"../"; http_uri; classtype:web-application-attack; sid:9002003; rev:1;)
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"TCDC Directory traversal encoded"; flow:to_server,established; content:"%2e%2e%2f"; http_uri; nocase; classtype:web-application-attack; sid:9002004; rev:1;)

# .git exposure attempt
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"TCDC Exposed .git directory access"; flow:to_server,established; content:"/.git/"; http_uri; classtype:attempted-recon; sid:9002005; rev:1;)

# .env file access
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"TCDC Exposed .env file access"; flow:to_server,established; content:"/.env"; http_uri; classtype:attempted-recon; sid:9002006; rev:1;)

# -------------------------------------------------------------
# WEB ATTACKS (centurytree, bonfire)
# -------------------------------------------------------------

# SQL Injection
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"TCDC SQLi UNION SELECT"; flow:to_server,established; content:"UNION"; http_uri; content:"SELECT"; http_uri; nocase; classtype:web-application-attack; sid:9003001; rev:1;)

alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"TCDC SQLi boolean 1=1"; flow:to_server,established; content:"1=1"; http_uri; classtype:web-application-attack; sid:9003002; rev:1;)

# XSS attempts
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"TCDC XSS script tag in URI"; flow:to_server,established; content:"<script"; http_uri; nocase; classtype:web-application-attack; sid:9003003; rev:1;)

# HTTP TRACE method (recon)
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"TCDC HTTP TRACE method"; flow:to_server,established; content:"TRACE"; http_method; classtype:attempted-recon; sid:9003004; rev:1;)

# Command injection via HTTP
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"TCDC Command injection attempt"; flow:to_server,established; pcre:"/[;&|`]\s*(ls|cat|id|whoami|wget|curl|bash|sh|nc)\s/Ui"; http_uri; classtype:web-application-attack; sid:9003005; rev:1;)

# Web shell upload indicators
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"TCDC PHP webshell upload attempt"; flow:to_server,established; content:"<?php"; http_client_body; nocase; classtype:web-application-attack; sid:9003006; rev:1;)

# Nikto/scanner user agent
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"TCDC Nikto scanner detected"; flow:to_server,established; content:"Nikto"; http_user_agent; nocase; classtype:attempted-recon; sid:9003007; rev:1;)

# curl/wget tool detected making requests
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"TCDC Automated tool curl/wget request"; flow:to_server,established; pcre:"/^(curl|wget)\//i"; http_user_agent; classtype:attempted-recon; sid:9003008; rev:1;)

# -------------------------------------------------------------
# SSH ATTACKS (reveille-remote — scored service)
# -------------------------------------------------------------

# SSH brute force — high volume connection attempts
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"TCDC SSH brute force attempt"; flow:to_server; flags:S; threshold:type threshold,track by_src,count 5,seconds 30; classtype:attempted-admin; sid:9004001; rev:1;)

# SSH version scanner
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"TCDC SSH version scan"; flow:to_server,established; content:"SSH-"; depth:4; threshold:type threshold,track by_src,count 3,seconds 10; classtype:attempted-recon; sid:9004002; rev:1;)

# -------------------------------------------------------------
# FTP ATTACKS (aggiedrop)
# -------------------------------------------------------------

# FTP brute force
alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"TCDC FTP brute force"; flow:to_server,established; content:"PASS"; threshold:type threshold,track by_src,count 5,seconds 60; classtype:attempted-admin; sid:9005001; rev:1;)

# FTP anonymous login attempt
alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"TCDC FTP anonymous login attempt"; flow:to_server,established; content:"USER anonymous"; nocase; classtype:attempted-user; sid:9005002; rev:1;)

alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"TCDC FTP anonymous login attempt v2"; flow:to_server,established; content:"USER ftp"; nocase; classtype:attempted-user; sid:9005003; rev:1;)

# FTP path traversal
alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"TCDC FTP path traversal attempt"; flow:to_server,established; content:"../"; classtype:web-application-attack; sid:9005004; rev:1;)

# -------------------------------------------------------------
# POSTGRESQL ATTACKS (excel)
# -------------------------------------------------------------

# PostgreSQL brute force
alert tcp $EXTERNAL_NET any -> $HOME_NET 5432 (msg:"TCDC PostgreSQL brute force"; flow:to_server,established; threshold:type threshold,track by_src,count 5,seconds 30; classtype:attempted-admin; sid:9006001; rev:1;)

# PostgreSQL connection from unexpected source
alert tcp $EXTERNAL_NET any -> $HOME_NET 5432 (msg:"TCDC PostgreSQL external connection attempt"; flow:to_server,new; classtype:attempted-admin; sid:9006002; rev:1;)

# -------------------------------------------------------------
# PORT SCANNING & RECONNAISSANCE
# -------------------------------------------------------------

# Nmap SYN scan
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"TCDC Nmap SYN scan"; flow:to_server; flags:S; threshold:type threshold,track by_src,count 20,seconds 5; classtype:attempted-recon; sid:9007001; rev:1;)

# Nmap NULL scan
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"TCDC Nmap NULL scan"; flow:to_server; flags:0; classtype:attempted-recon; sid:9007002; rev:1;)

# Nmap XMAS scan
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"TCDC Nmap XMAS scan"; flow:to_server; flags:FPU; classtype:attempted-recon; sid:9007003; rev:1;)

# Mass port sweep (many ports, one source)
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"TCDC Port sweep detected"; flags:S; threshold:type threshold,track by_src,count 50,seconds 10; classtype:attempted-recon; sid:9007004; rev:1;)

# -------------------------------------------------------------
# BACKDOOR / C2 INDICATORS
# -------------------------------------------------------------

# Known backdoor ports
alert tcp $HOME_NET any -> $EXTERNAL_NET 4444 (msg:"TCDC Metasploit default port outbound"; flow:to_server; classtype:trojan-activity; sid:9008001; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET 1234 (msg:"TCDC Common backdoor port 1234 outbound"; flow:to_server; classtype:trojan-activity; sid:9008002; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET 9001 (msg:"TCDC Tor/backdoor port 9001 outbound"; flow:to_server; classtype:trojan-activity; sid:9008003; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET 31337 (msg:"TCDC Elite backdoor port 31337 outbound"; flow:to_server; classtype:trojan-activity; sid:9008004; rev:1;)

# Outbound connection on unusual ports (potential beacon)
alert tcp $HOME_NET any -> $EXTERNAL_NET ![80,443,22,21,25,53,123,5432,3000] (msg:"TCDC Unusual outbound TCP connection"; flow:to_server,established; threshold:type threshold,track by_src,count 1,seconds 60; classtype:trojan-activity; sid:9008005; rev:1;)

# ICMP tunneling (data exfil over ping)
alert icmp $HOME_NET any -> $EXTERNAL_NET any (msg:"TCDC ICMP large packet potential tunnel"; itype:8; dsize:>100; threshold:type threshold,track by_src,count 5,seconds 10; classtype:policy-violation; sid:9008006; rev:1;)

# DNS tunneling
alert dns $HOME_NET any -> any 53 (msg:"TCDC DNS query length suspicious"; dns.query; content:"."; pcre:"/[a-z0-9]{30,}/i"; classtype:policy-violation; sid:9008007; rev:1;)

# -------------------------------------------------------------
# PRIVILEGE ESCALATION INDICATORS
# -------------------------------------------------------------

# SUID shell execution pattern
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"TCDC SUID shell command injection"; flow:to_server,established; pcre:"/chmod\s+[0-9]*s|chown\s+root/i"; http_client_body; classtype:attempted-admin; sid:9009001; rev:1;)

EOF

ok "Local TCDC rules written to $LOCAL_RULES"

# Count rules
RULE_COUNT=$(grep -c "^alert\|^pass\|^drop" "$LOCAL_RULES" 2>/dev/null || echo 0)
info "  $RULE_COUNT custom TCDC rules loaded"

# =============================================================
banner "4. WRITE SUPPRESS CONFIG"
# =============================================================
info "Writing suppress list to reduce noise..."

cat > /etc/suricata/suppress.conf << EOF
# TCDC Suricata suppress list
# Suppresses noisy/irrelevant alerts that aren't actionable
# Generated: $(date)

EOF

if [ -n "$CHECKER_IP" ]; then
    cat >> /etc/suricata/suppress.conf << EOF
# Suppress ALL alerts from checker IP
suppress gen_id 1, sig_id 0, track by_src, ip $CHECKER_IP
suppress gen_id 1, sig_id 0, track by_dst, ip $CHECKER_IP
EOF
    ok "All alerts from checker $CHECKER_IP suppressed"
fi

cat >> /etc/suricata/suppress.conf << EOF

# Suppress noisy internal traffic
suppress gen_id 1, sig_id 2010935, track by_src, ip $MY_SUBNET
suppress gen_id 1, sig_id 2013028, track by_src, ip $MY_SUBNET

# Suppress ET SCAN rules on team subnet (internal scans are expected)
suppress gen_id 1, sig_id 9007001, track by_src, ip $MY_SUBNET
suppress gen_id 1, sig_id 9007004, track by_src, ip $MY_SUBNET
EOF

ok "Suppress list configured"

# =============================================================
banner "5. UPDATE SURICATA RULES"
# =============================================================
info "Updating Suricata community rules..."

if command -v suricata-update &>/dev/null; then
    suricata-update 2>/dev/null | tail -10 | while read -r line; do
        info "  $line"
    done
    ok "Rules updated"
else
    warn "suricata-update not found — rules may be outdated"
fi

# =============================================================
banner "6. CREATE SYSTEMD SERVICE (IDS MODE)"
# =============================================================
info "Creating Suricata systemd service in IDS mode..."

cat > /etc/systemd/system/suricata-tcdc.service << EOF
[Unit]
Description=TCDC Suricata IDS (af-packet, detection-only)
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStartPre=/bin/bash -c 'suricata -T -c /etc/suricata/suricata.yaml 2>/dev/null || exit 1'
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml --af-packet=$PRIMARY_IFACE --pidfile /run/suricata.pid
ExecReload=/bin/kill -USR2 \$MAINPID
PIDFile=/run/suricata.pid
Restart=on-failure
RestartSec=5
User=root
LimitNOFILE=131072

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
ok "Suricata systemd service created: suricata-tcdc"
warn "Start with: systemctl start suricata-tcdc"
warn "Enable at boot: systemctl enable suricata-tcdc"

# =============================================================
banner "7. VALIDATE CONFIG"
# =============================================================
info "Validating Suricata configuration..."

if suricata -T -c /etc/suricata/suricata.yaml 2>&1; then
    ok "Suricata config validation PASSED"
    VALID=true
else
    flag "Suricata config validation FAILED"
    warn "Check /var/log/suricata/suricata.log for details"
    VALID=false
fi

# =============================================================
banner "8. START SURICATA"
# =============================================================
if [ "$VALID" = true ]; then
    info "Starting Suricata IDS..."
    systemctl start suricata-tcdc
    sleep 3

    if systemctl is-active --quiet suricata-tcdc; then
        ok "Suricata IDS is running"
        ok "Interface: $PRIMARY_IFACE"
        ok "Mode: af-packet (IDS only — no traffic blocking)"
    else
        flag "Suricata failed to start"
        warn "Check: journalctl -u suricata-tcdc -n 30"
        warn "Check: cat /var/log/suricata/suricata.log"
    fi
else
    warn "Suricata not started due to config validation failure"
    warn "Fix the config then run: systemctl start suricata-tcdc"
fi

# =============================================================
banner "9. LOG MONITORING SETUP"
# =============================================================
info "Setting up log monitoring helpers..."

# Create alert monitor script
cat > /usr/local/bin/tcdc-suricata-watch << 'WATCH_SCRIPT'
#!/bin/bash
# Live Suricata alert monitor
# Usage: tcdc-suricata-watch [severity]
# Severity: all (default), high, critical

RED='\033[0;31m'
YLW='\033[0;33m'
GRN='\033[0;32m'
BLU='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

FAST_LOG="/var/log/suricata/fast.log"
EVE_LOG="/var/log/suricata/eve.json"

echo -e "${BOLD}TCDC Suricata Alert Monitor${NC}"
echo -e "Watching: $FAST_LOG"
echo -e "Press Ctrl+C to stop"
echo ""

tail -f "$FAST_LOG" 2>/dev/null | while read -r line; do
    # Color by severity/category
    if echo "$line" | grep -q "REVSHELL\|C2\|WEBSHELL\|backdoor\|trojan"; then
        echo -e "${BOLD}${RED}[CRITICAL] $line${NC}"
    elif echo "$line" | grep -q "SQLi\|SQLI\|LFI\|UNION\|webshell\|injection"; then
        echo -e "${RED}[HIGH] $line${NC}"
    elif echo "$line" | grep -q "brute.force\|BRUTE\|scan\|SCAN\|traversal"; then
        echo -e "${YLW}[MED] $line${NC}"
    elif echo "$line" | grep -q "recon\|RECON\|probe\|PROBE"; then
        echo -e "${BLU}[LOW] $line${NC}"
    else
        echo -e "[ALERT] $line"
    fi
done
WATCH_SCRIPT

chmod +x /usr/local/bin/tcdc-suricata-watch
ok "Alert monitor created: tcdc-suricata-watch"

# Create quick stats script
cat > /usr/local/bin/tcdc-suricata-stats << 'STATS_SCRIPT'
#!/bin/bash
# Show Suricata alert statistics
EVE_LOG="/var/log/suricata/eve.json"
FAST_LOG="/var/log/suricata/fast.log"

echo "=== SURICATA ALERT STATS ==="
echo ""
echo "Total alerts:"
grep -c '"event_type":"alert"' "$EVE_LOG" 2>/dev/null || wc -l < "$FAST_LOG"

echo ""
echo "Top alert types:"
grep '"signature"' "$EVE_LOG" 2>/dev/null | \
    grep -oP '"signature":"\K[^"]+' | \
    sort | uniq -c | sort -rn | head -10

echo ""
echo "Top source IPs:"
grep '"event_type":"alert"' "$EVE_LOG" 2>/dev/null | \
    grep -oP '"src_ip":"\K[^"]+' | \
    sort | uniq -c | sort -rn | head -10

echo ""
echo "Recent alerts (last 10):"
tail -10 "$FAST_LOG" 2>/dev/null
STATS_SCRIPT

chmod +x /usr/local/bin/tcdc-suricata-stats
ok "Stats script created: tcdc-suricata-stats"

# =============================================================
banner "CONFIGURATION SUMMARY"
# =============================================================
echo ""
echo -e "${BOLD}Suricata IDS Configuration Complete — $(hostname)${NC}"
echo ""
ok "Mode:       IDS only (af-packet) — NO traffic blocking"
ok "Interface:  $PRIMARY_IFACE"
ok "Rules:      Suricata community + $RULE_COUNT TCDC custom rules"
[ -n "$CHECKER_IP" ] && ok "Checker:    $CHECKER_IP whitelisted"
ok "Fast log:   /var/log/suricata/fast.log"
ok "EVE JSON:   /var/log/suricata/eve.json"
echo ""
echo -e "${BOLD}Useful commands:${NC}"
info "  Start:         systemctl start suricata-tcdc"
info "  Stop:          systemctl stop suricata-tcdc"
info "  Live alerts:   tcdc-suricata-watch"
info "  Stats:         tcdc-suricata-stats"
info "  Fast log:      tail -f /var/log/suricata/fast.log"
info "  EVE JSON:      tail -f /var/log/suricata/eve.json | python3 -m json.tool"
info "  Reload rules:  kill -USR2 \$(cat /run/suricata.pid)"
info "  Test config:   suricata -T -c /etc/suricata/suricata.yaml"
echo ""
warn "REMEMBER: Suricata is in IDS mode — it DETECTS but does NOT block."
warn "To act on an alert: iptables -A INPUT -s <attacker_ip> -j DROP"
warn "Or: fail2ban-client set sshd banip <attacker_ip>"
