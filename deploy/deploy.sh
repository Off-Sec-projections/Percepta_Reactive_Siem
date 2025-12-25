#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
#  Percepta SIEM — Server Deploy Script
#  Run as root on Ubuntu 22.04/24.04 (on the VPS itself)
#
#  Handles both fresh installs and upgrades.  When the service is
#  already installed it backs up the running binary, copies new files,
#  and restarts — preserving .env, certs, and ClickHouse data.
#
#  Usage:
#    Fresh cloud install : bash deploy.sh cloud <domain> <admin-email>
#    Fresh local lab     : bash deploy.sh local
#    Upgrade             : bash deploy.sh update          (auto-detected)
#
#  Normally you deploy FROM your dev machine with:
#    make push           — builds + pushes only what changed (uses push.sh)
#    make deploy-pack    — creates percepta-siem.tar.gz for a fresh server
#
#  This script is what runs ON the server (inside the extracted tarball
#  or if you SSH in and run it manually).
# ─────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

health_status_from_json() {
  local raw="${1:-}"

  if [[ -z "${raw}" ]]; then
    return 0
  fi

  if command -v python3 >/dev/null 2>&1; then
    HEALTH_RAW="${raw}" python3 - <<'PY' 2>/dev/null || true
import json
import os

raw = os.environ.get("HEALTH_RAW", "")
try:
    data = json.loads(raw)
except Exception:
    print("")
else:
    status = data.get("status", "")
    print(status if isinstance(status, str) else "")
PY
    return 0
  fi

  if echo "${raw}" | grep -q '"status":"ok"'; then
    echo "ok"
  elif echo "${raw}" | grep -q '"status":"degraded"'; then
    echo "degraded"
  fi
}

# ── Resolve paths ────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUNDLE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
INSTALL_DIR="/opt/percepta-siem"
SERVICE_USER="percepta"

# ── Parse arguments ──────────────────────────────────────────────────
MODE=""
DOMAIN=""
EMAIL=""

case "${1:-}" in
  local)   MODE="local"  ;;
  cloud)   MODE="cloud"; DOMAIN="${2:-}"; EMAIL="${3:-}" ;;
  update)  MODE="update" ;;
  *)
    # Auto-detect: if systemd service exists → update; else legacy cloud args
    if systemctl list-unit-files percepta-server.service &>/dev/null \
       && systemctl cat percepta-server.service &>/dev/null 2>&1; then
      MODE="update"
      info "Existing installation detected — running in update mode"
    elif [[ -n "${1:-}" && -n "${2:-}" ]]; then
      MODE="cloud"; DOMAIN="${1}"; EMAIL="${2}"
    else
      echo "Usage:"
      echo "  Fresh cloud install : bash deploy.sh cloud <domain> <admin-email>"
      echo "  Fresh local lab     : bash deploy.sh local"
      echo "  Upgrade existing    : bash deploy.sh update"
      exit 1
    fi
    ;;
esac

# ─────────────────────────────────────────────────────────────────────
#  PRE-FLIGHT CHECKS
# ─────────────────────────────────────────────────────────────────────
info "Running pre-flight checks..."

# Root check
[[ "$EUID" -eq 0 ]] || fail "This script must be run as root.  Use: sudo bash deploy.sh ..."
ok "Running as root"

# OS check
if command -v lsb_release &>/dev/null; then
  UBUNTU_VERSION=$(lsb_release -rs | cut -d. -f1)
  if [[ "$UBUNTU_VERSION" != "22" && "$UBUNTU_VERSION" != "24" ]]; then
    warn "Ubuntu ${UBUNTU_VERSION} detected — only 22.04/24.04 are tested."
  else
    ok "Ubuntu ${UBUNTU_VERSION}.04"
  fi
fi

# Required commands
for cmd in curl systemctl; do
  command -v "$cmd" &>/dev/null || fail "'${cmd}' not found."
done
ok "Required commands available"

# Disk space
AVAIL_GB=$(($(df "${INSTALL_DIR}" 2>/dev/null || df /opt | tail -1 | awk '{print $4}') / 1024 / 1024)) 2>/dev/null || AVAIL_GB=999
if [[ $AVAIL_GB -lt 10 ]]; then
  fail "Only ${AVAIL_GB}GB free — minimum 10GB required."
fi
ok "Disk: ${AVAIL_GB}GB free"

# Validate domain/email for cloud mode
if [[ "$MODE" == "cloud" ]]; then
  [[ -n "$DOMAIN" && -n "$EMAIL" ]] || fail "Usage: bash deploy.sh cloud <domain> <admin-email>"
  [[ "$DOMAIN" =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$ ]] || fail "Invalid domain: $DOMAIN"
  [[ "$EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] || fail "Invalid email: $EMAIL"
  ok "Domain: $DOMAIN  Email: $EMAIL"
fi

if [[ "$MODE" == "local" ]]; then
  DOMAIN="localhost"
fi

# ─────────────────────────────────────────────────────────────────────
#  UPDATE MODE — fast path: just copy files, backup, restart
# ─────────────────────────────────────────────────────────────────────
if [[ "$MODE" == "update" ]]; then
  echo ""
  echo "╔══════════════════════════════════════════════╗"
  echo "║   Percepta SIEM — Update                     ║"
  echo "╚══════════════════════════════════════════════╝"
  echo ""

  # Detect in-place (bundle already at /opt/percepta-siem)
  REAL_INSTALL="$(cd "$INSTALL_DIR" 2>/dev/null && pwd)"
  if [[ "$BUNDLE_DIR" == "$REAL_INSTALL" ]]; then
    IN_PLACE=true
  else
    IN_PLACE=false
  fi

  # ── 1. Stop service ─────────────────────────────────────────────────
  info "Stopping percepta-server..."
  systemctl stop percepta-server 2>/dev/null || true
  ok "Service stopped"

  # ── 2. Backup current binary ────────────────────────────────────────
  if [[ -f "$INSTALL_DIR/percepta-server" ]]; then
    cp "$INSTALL_DIR/percepta-server" "$INSTALL_DIR/percepta-server.bak"
    ok "Binary backed up → percepta-server.bak"
  fi

  # ── 3. Copy new files ──────────────────────────────────────────────
  if [[ "$IN_PLACE" == false ]]; then
    # Find binary
    BINARY_PATH="${BUNDLE_DIR}/percepta-server"
    [[ -f "$BINARY_PATH" ]] || BINARY_PATH="${BUNDLE_DIR}/target/release/percepta-server"
    [[ -f "$BINARY_PATH" ]] || fail "percepta-server binary not found in bundle"

    info "Copying binary..."
    cp -f "$BINARY_PATH" "$INSTALL_DIR/percepta-server"

    info "Copying assets..."
    for asset in dashboard rules.yaml parsers.yaml event_knowledge.json \
                 compliance_mappings config Logo static; do
      if [[ -e "${BUNDLE_DIR}/${asset}" ]]; then
        cp -rf "${BUNDLE_DIR}/${asset}" "$INSTALL_DIR/"
      elif [[ -e "${BUNDLE_DIR}/server/${asset}" ]]; then
        cp -rf "${BUNDLE_DIR}/server/${asset}" "$INSTALL_DIR/"
      fi
    done

    # Agent builds — only overwrite if bundle has them
    if ls "${BUNDLE_DIR}/agent_builds/"* &>/dev/null 2>&1; then
      mkdir -p "$INSTALL_DIR/agent_builds"
      cp -f "${BUNDLE_DIR}/agent_builds/"* "$INSTALL_DIR/agent_builds/"
      ok "Agent builds updated"
    fi

    # GeoIP — only copy if missing on server (it's large, don't overwrite needlessly)
    if [[ ! -f "$INSTALL_DIR/geoip/GeoLite2-City.mmdb" ]]; then
      for gdir in "${BUNDLE_DIR}/geoip" "${BUNDLE_DIR}/server/geoip"; do
        if [[ -d "$gdir" ]]; then
          mkdir -p "$INSTALL_DIR/geoip"
          cp -rn "${gdir}/"* "$INSTALL_DIR/geoip/" 2>/dev/null || true
          break
        fi
      done
    fi
  fi

  chmod +x "$INSTALL_DIR/percepta-server"
  chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
  ok "Files updated"

  # ── 4. Reload and restart ──────────────────────────────────────────
  # Re-install service file in case it changed
  if [[ -f "${SCRIPT_DIR}/percepta-server.service" ]]; then
    cp -f "${SCRIPT_DIR}/percepta-server.service" /etc/systemd/system/percepta-server.service
    systemctl daemon-reload
  fi

  info "Starting percepta-server..."
  systemctl start percepta-server
  sleep 2

  if systemctl is-active percepta-server | grep -q "^active$"; then
    ok "Service is active"
  else
    fail "Service failed to start!  Check: journalctl -u percepta-server -n 40"
  fi

  # ── 5. Health check ────────────────────────────────────────────────
  HEALTH_URL="http://127.0.0.1:8080/healthz"

  info "Waiting for health check (${HEALTH_URL})..."
  HEALTHY=false
  for i in $(seq 1 10); do
    RAW=$(curl -s --max-time 5 "$HEALTH_URL" 2>/dev/null || true)
    STATUS="$(health_status_from_json "${RAW}")"
    if [[ "$STATUS" == "ok" || "$STATUS" == "degraded" ]]; then
      HEALTHY=true
      [[ "$STATUS" == "degraded" ]] && warn "Health check returned degraded — dependencies are still settling"
      break
    fi
    sleep 2
  done

  if [[ "$HEALTHY" == true ]]; then
    ok "Health check passed"
  else
    warn "Health check didn't return OK within 20s"
    warn "The service IS running — it may still be initializing."
    warn "Check manually: curl -s $HEALTH_URL"
  fi

  echo ""
  echo "╔══════════════════════════════════════════════╗"
  echo "║   Update Complete!                            ║"
  echo "╚══════════════════════════════════════════════╝"
  echo "  Status : systemctl status percepta-server"
  echo "  Logs   : journalctl -u percepta-server -f"
  echo "  Rollback: cp percepta-server.bak percepta-server && systemctl restart percepta-server"
  echo ""
  exit 0
fi

# ─────────────────────────────────────────────────────────────────────
#  FRESH INSTALL (cloud / local)
# ─────────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════╗"
if [[ "$MODE" == "cloud" ]]; then
  echo "║   Percepta SIEM — Fresh Cloud Install         ║"
else
  echo "║   Percepta SIEM — Fresh Local Install          ║"
fi
echo "╚══════════════════════════════════════════════╝"
echo ""

# ── 1. Install ClickHouse ──────────────────────────────────────────────
echo "[1/8] Installing ClickHouse database..."
if command -v clickhouse-server &>/dev/null; then
  ok "ClickHouse already installed"
else
  apt-get install -y apt-transport-https ca-certificates curl gnupg
  curl -fsSL 'https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key' \
    | gpg --dearmor -o /usr/share/keyrings/clickhouse-keyring.gpg
  echo "deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg] https://packages.clickhouse.com/deb stable main" \
    > /etc/apt/sources.list.d/clickhouse.list
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y clickhouse-server clickhouse-client
  ok "ClickHouse installed"
fi
systemctl enable clickhouse-server
systemctl start clickhouse-server || true
info "Waiting for ClickHouse to be ready..."
for i in $(seq 1 30); do
  clickhouse-client --query "SELECT 1" &>/dev/null && break
  sleep 1
done
ok "ClickHouse ready"

# ── 2. Create service user ────────────────────────────────────────────
echo "[2/8] Creating service user '${SERVICE_USER}'..."
id "$SERVICE_USER" &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
mkdir -p "$INSTALL_DIR"
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
ok "User '$SERVICE_USER' ready"

# ── 3. Copy binary + assets ────────────────────────────────────────────
echo "[3/8] Installing Percepta server..."

# Detect in-place deploy
REAL_INSTALL="$(mkdir -p "$INSTALL_DIR" && cd "$INSTALL_DIR" && pwd)"
IN_PLACE=false
[[ "$BUNDLE_DIR" == "$REAL_INSTALL" ]] && IN_PLACE=true

# Find binary
BINARY_PATH="${BUNDLE_DIR}/percepta-server"
[[ -f "$BINARY_PATH" ]] || BINARY_PATH="${BUNDLE_DIR}/target/release/percepta-server"
[[ -f "$BINARY_PATH" ]] || fail "percepta-server binary not found at ${BUNDLE_DIR}/"

if [[ "$IN_PLACE" == false ]]; then
  cp -f "$BINARY_PATH" "$INSTALL_DIR/percepta-server"
fi
chmod +x "$INSTALL_DIR/percepta-server"
chown "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR/percepta-server"
ok "Binary installed ($(du -h "$INSTALL_DIR/percepta-server" | cut -f1))"

# ── 4. Copy agent builds ───────────────────────────────────────────────
echo "[4/8] Copying agent builds..."
if [[ "$IN_PLACE" == false ]]; then
  mkdir -p "$INSTALL_DIR/agent_builds"
  AGENT_DIR="${BUNDLE_DIR}/agent_builds"
  [[ -d "$AGENT_DIR" ]] || AGENT_DIR="${BUNDLE_DIR}/server/agent_builds"
  if [[ -d "$AGENT_DIR" ]]; then
    for f in "${AGENT_DIR}/"*; do
      [[ -f "$f" ]] && cp -f "$f" "$INSTALL_DIR/agent_builds/"
    done
    ok "Agent builds copied"
  else
    warn "No agent builds found — agents can be added later with: make push-agents"
  fi
fi

# ── 5. Copy GeoIP + dashboard + config assets ─────────────────────────
echo "[5/8] Copying GeoIP, dashboard & config assets..."
if [[ "$IN_PLACE" == false ]]; then
  # GeoIP
  for gdir in "${BUNDLE_DIR}/geoip" "${BUNDLE_DIR}/server/geoip"; do
    if [[ -d "$gdir" ]]; then
      mkdir -p "$INSTALL_DIR/geoip"
      cp -rn "${gdir}/"* "$INSTALL_DIR/geoip/" 2>/dev/null || true
      ok "GeoIP database"
      break
    fi
  done

  # Dashboard + config assets
  for asset in dashboard rules.yaml parsers.yaml event_knowledge.json \
               compliance_mappings config Logo static; do
    if [[ -e "${BUNDLE_DIR}/${asset}" ]]; then
      cp -r "${BUNDLE_DIR}/${asset}" "$INSTALL_DIR/"
      ok "${asset}"
    elif [[ -e "${BUNDLE_DIR}/server/${asset}" ]]; then
      cp -r "${BUNDLE_DIR}/server/${asset}" "$INSTALL_DIR/"
      ok "${asset}"
    fi
  done
fi
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"

# ── 6. Generate env file ───────────────────────────────────────────────
echo "[6/8] Creating environment file..."
mkdir -p "$INSTALL_DIR/certs"
chown "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR/certs"

if [[ ! -f "$INSTALL_DIR/.env" ]]; then
  ADMIN_PASS="$(openssl rand -base64 18 | tr -dc 'A-Za-z0-9!@#' | head -c 20)"
  ANALYST_PASS="$(openssl rand -base64 18 | tr -dc 'A-Za-z0-9!@#' | head -c 20)"

  cat > "$INSTALL_DIR/.env" << ENV
# Percepta SIEM Environment — generated $(date -u)
PERCEPTA_BASE_DIR=${INSTALL_DIR}
PERCEPTA_BEHIND_PROXY=$([[ "$MODE" == "cloud" ]] && echo 1 || echo 0)
PERCEPTA_WEB_BIND=$([[ "$MODE" == "cloud" ]] && echo "127.0.0.1:8080" || echo "0.0.0.0:8080")
PERCEPTA_PUBLIC_HOST=${DOMAIN}

PERCEPTA_ADMIN_PASS=${ADMIN_PASS}
PERCEPTA_ANALYST_PASS=${ANALYST_PASS}

PERCEPTA_GEOIP_DB=${INSTALL_DIR}/geoip/GeoLite2-City.mmdb
PERCEPTA_CA_DIR=${INSTALL_DIR}/certs
PERCEPTA_CH_SYSTEMD_FALLBACK=1
ENV
  chmod 640 "$INSTALL_DIR/.env"
  chown "root:${SERVICE_USER}" "$INSTALL_DIR/.env"
  echo ""
  echo "  ┌──────────────────────────────────────────┐"
  echo "  │  Credentials saved to: $INSTALL_DIR/.env │"
  echo "  │  View with: sudo cat $INSTALL_DIR/.env   │"
  echo "  │  (passwords are NOT printed to terminal) │"
  echo "  └──────────────────────────────────────────┘"
  echo ""
else
  ok ".env already exists — keeping existing credentials"
fi

# ── 7. Install systemd service ─────────────────────────────────────────
echo "[7/8] Installing systemd service..."
cp -f "${SCRIPT_DIR}/percepta-server.service" /etc/systemd/system/percepta-server.service
systemctl daemon-reload
systemctl enable percepta-server
ok "Systemd service installed"

# ── 8. Setup Nginx + SSL ───────────────────────────────────────────────
if [[ "$MODE" == "cloud" ]]; then
  echo "[8/8] Setting up Nginx + Let's Encrypt..."
  bash "${SCRIPT_DIR}/setup-nginx.sh" "$DOMAIN" "$EMAIL" 8080
  ok "Nginx + SSL configured"
else
  echo "[8/8] Local mode — skipping Nginx + SSL"
fi

# ── 9. Open firewall for gRPC agent port ─────────────────────────────
if command -v ufw &>/dev/null; then
  ufw allow 50051/tcp 2>/dev/null || true
  ufw allow 22/tcp 2>/dev/null || true
  ufw allow 80/tcp 2>/dev/null || true
  ufw allow 443/tcp 2>/dev/null || true
  ok "Firewall rules added (22, 80, 443, 50051)"
fi

# ── Start the service ────────────────────────────────────────────────
systemctl start percepta-server
sleep 2

if systemctl is-active percepta-server | grep -q "^active$"; then
  ok "Service is active"
else
  warn "Service may still be starting — check: journalctl -u percepta-server -f"
fi

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║   Deployment Complete!                       ║"
echo "╚══════════════════════════════════════════════╝"
if [[ "$MODE" == "cloud" ]]; then
  echo "  URL      : https://${DOMAIN}/"
else
  echo "  URL      : http://$(hostname -I | awk '{print $1}'):8080/"
fi
echo "  Status   : systemctl status percepta-server"
echo "  Logs     : journalctl -u percepta-server -f"
echo ""
echo "  For future updates from your dev machine:"
echo "    make push              # full update (binary + dashboard + config)"
echo "    make push-dashboard    # dashboard-only (fast)"
echo "    make push-binary       # server binary only"
echo "    make push-rollback     # roll back to previous version"
echo ""
