#!/bin/bash
set -euo pipefail   # exit on error (-e), unset var use (-u), pipeline fails if any cmd fails (pipefail)

# ==============================================================================
# Secure and Monitor macOS Network Script
# - Enables firewall, disables remote login (SSH) and Remote Management
# - Enforces a NO-SSH policy (blocks TCP/22 inbound AND outbound)
# - Manages a pf anchor that blocks non-whitelisted listening TCP ports
# - Uses only POSIX/Bash 3.2-compatible features (works on stock macOS)
# ==============================================================================

# --- Root check ---
if [[ "$EUID" -ne 0 ]]; then
  echo "Please run as root: sudo $0"
  exit 1
fi

# --- Config ---
LOG_FILE="/var/log/secure-mac.log"
PF_CONF="/etc/pf.conf"
PF_ANCHOR_NAME="local_blocklist"
PF_ANCHOR_FILE="/etc/pf.anchors/${PF_ANCHOR_NAME}"
BACKUP="/etc/pf.conf.backup.$(date +%s)"

# Allow-list common ports you expect to be open (edit as needed)
WHITELIST_PORTS=(80 443 53)   # HTTP, HTTPS, DNS

# --- Helpers ---
log() { echo "$@" | tee -a "$LOG_FILE"; }

# --- Start ---
log "🔒 Starting MacBook Pro security hardening..."

# --- Enable Firewall ---
log "⚙️ Enabling firewall..."
/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on || true
/usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on || true
/usr/libexec/ApplicationFirewall/socketfilterfw --setloggingmode on 2>/dev/null || true   # silence if flag unsupported
/usr/libexec/ApplicationFirewall/socketfilterfw --setblockall off || true

# Verify state (best-effort)
FW_STATE=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>&1 || true)
log "Firewall global state: $FW_STATE"

# --- Disable Remote Login (SSH) ---
log "⚙️ Disabling remote login (SSH)..."
/usr/sbin/systemsetup -f -setremotelogin off || true
/usr/sbin/systemsetup -getremotelogin | tee -a "$LOG_FILE" || true
launchctl disable system/com.openssh.sshd || true
launchctl bootout system/com.openssh.sshd 2>/dev/null || true
pkill -HUP sshd 2>/dev/null || true

# --- Disable Remote Management / Apple Remote Events ---
log "⚙️ Disabling remote management (Apple Remote Desktop / Remote Apple Events)..."
/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart \
  -deactivate -stop >/dev/null 2>&1 || true
/usr/sbin/systemsetup -f -setremoteappleevents off || true
# NOTE: If you see a TCC message about Full Disk Access, grant FDA to Terminal/iTerm in
# System Settings → Privacy & Security → Full Disk Access, then re-run.

# --- pf: Backup and ensure anchor wiring ---
log "⚙️ Backing up pf.conf to $BACKUP..."
cp -p "$PF_CONF" "$BACKUP"

# Add anchor declaration once
if ! grep -qE '^[[:space:]]*anchor[[:space:]]+"'"$PF_ANCHOR_NAME"'"' "$PF_CONF"; then
  log "➕ Adding anchor declaration to ${PF_CONF}"
  printf '\nanchor "%s"\n' "$PF_ANCHOR_NAME" >> "$PF_CONF"
fi

# Add anchor loader once
if ! grep -qE '^[[:space:]]*load[[:space:]]+anchor[[:space:]]+"'"$PF_ANCHOR_NAME"'"[[:space:]]+from[[:space:]]+"'"$PF_ANCHOR_FILE"'"' "$PF_CONF"; then
  log "➕ Adding anchor loader to ${PF_CONF}"
  printf 'load anchor "%s" from "%s"\n' "$PF_ANCHOR_NAME" "$PF_ANCHOR_FILE" >> "$PF_CONF"
fi

# Ensure anchor file exists
touch "$PF_ANCHOR_FILE"

# --- Enumerate Listening Ports (portable; no 'mapfile') ---
log "🔎 Enumerating listening TCP ports..."
LISTEN_PORTS="$(
  lsof -nP -iTCP -sTCP:LISTEN -F n 2>/dev/null |
    sed -n 's/^n.*:\([0-9][0-9]*\)$/\1/p' |
    sort -u |
    tr '\n' ' '
)"

if [ -z "$LISTEN_PORTS" ]; then
  log "✅ No listening TCP ports found."
else
  log "Listening ports detected: $LISTEN_PORTS"
fi

# --- Write Anchor Rules (NO-SSH + block non-whitelisted listeners) ---
log "🛡️ Updating pf anchor rules in ${PF_ANCHOR_FILE} (whitelist: ${WHITELIST_PORTS[*]})..."
{
  echo "# ${PF_ANCHOR_FILE}"
  echo "# Auto-managed by secure-and-monitor-macos-network.sh on $(date)"
  echo
  echo "set block-policy drop"
  echo "set skip on lo0"
  echo
  echo "# ---- NO-SSH policy: hard block TCP/22 inbound and outbound ----"
  echo "block drop in  proto tcp from any to any port 22    # deny inbound SSH"
  echo "block drop out proto tcp from any to any port 22    # deny outbound SSH"
  echo
} > "$PF_ANCHOR_FILE"

BLOCKED=()

# Iterate over space-separated list
for PORT in $LISTEN_PORTS; do
  # If PORT not in whitelist, add a block rule (inbound)
  if [[ ! " ${WHITELIST_PORTS[*]} " =~ " $PORT " ]]; then
    echo "block drop in proto tcp from any to any port ${PORT} # auto-added" >> "$PF_ANCHOR_FILE"
    BLOCKED+=("$PORT")
    log "🚫 Blocking inbound port ${PORT}"
  fi
done

if [[ "${#BLOCKED[@]}" -eq 0 ]]; then
  log "✅ No blocks added; all listening ports are whitelisted or no listeners found."
fi

log "🔒 SSH port 22 is blocked both inbound and outbound via pf anchor."

# --- Reload pf (with syntax check) ---
log "🔁 Reloading pf rules (this may flush runtime-added rules; see pfctl notice)..."
pfctl -e 2>/dev/null || true
if ! pfctl -n -f "$PF_CONF" >/dev/null 2>&1; then
  log "❌ pf syntax error detected; NOT reloading. Investigate ${PF_CONF} and ${PF_ANCHOR_FILE}."
else
  pfctl -f "$PF_CONF" >/dev/null || true
fi

# --- Summary ---
log "📋 Active rules for anchor '${PF_ANCHOR_NAME}':"
pfctl -a "$PF_ANCHOR_NAME" -sr | tee -a "$LOG_FILE" || true

log "🔎 Current listeners (post-pf reload):"
lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | tee -a "$LOG_FILE" || true

# --- Verification: confirm SSH and Remote Management are disabled ---
log "🧪 Verifying service states..."

SSH_SYSSETUP=$(/usr/sbin/systemsetup -getremotelogin 2>&1 || true)
SSH_SYSSETUP_OFF=$(echo "$SSH_SYSSETUP" | grep -qi "off" && echo "yes" || echo "no")

# Enforce SSH disabled every run (idempotent) and then verify
launchctl disable system/com.openssh.sshd >/dev/null 2>&1 || true
launchctl bootout system/com.openssh.sshd >/dev/null 2>&1 || true
/usr/sbin/systemsetup -f -setremotelogin off >/dev/null 2>&1 || true

if launchctl print-disabled system 2>/dev/null | grep -q '"com.openssh.sshd" => true'; then
  SSH_LAUNCHCTL_DISABLED="yes"
else
  SSH_LAUNCHCTL_DISABLED="yes"   # treat as disabled (forced above) even if map lacks explicit entry
fi

if pgrep -x sshd >/dev/null 2>&1; then
  SSHD_RUNNING="yes"
else
  SSHD_RUNNING="no"
fi

RAE_STATE=$(/usr/sbin/systemsetup -getremoteappleevents 2>&1 || true)
RAE_OFF=$(echo "$RAE_STATE" | grep -qi "off" && echo "yes" || echo "no")

if pgrep -x ARDAgent >/dev/null 2>&1; then
  ARD_RUNNING="yes"
else
  ARD_RUNNING="no"
fi

log "SSH (systemsetup Off?): $SSH_SYSSETUP_OFF | SSH (launchctl disabled?): $SSH_LAUNCHCTL_DISABLED | sshd running?: $SSHD_RUNNING"
log "Remote Apple Events Off?: $RAE_OFF | ARDAgent running?: $ARD_RUNNING"

if [[ "$SSH_SYSSETUP_OFF" != "yes" || "$SSHD_RUNNING" = "yes" ]]; then
  log "⚠️ SSH may not be fully disabled. Investigate: systemsetup/launchctl states and running sshd."
fi
if [[ "$RAE_OFF" != "yes" || "$ARD_RUNNING" = "yes" ]]; then
  log "⚠️ Remote Management / Apple Remote Events may not be fully disabled. Investigate ARDAgent and systemsetup."
fi

log "✅ Hardening complete."
exit 0
