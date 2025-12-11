#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
#  Percepta SIEM — Incremental Push Deploy
#
#  Fast, safe deployment of code changes to the remote VPS.
#  Handles: binary, dashboard, config, agents, rules, parsers
#  — with backup and automatic rollback if the health check fails.
#
#  Usage:
#    ./deploy/push.sh                    # Deploy everything that changed
#    ./deploy/push.sh --binary-only      # Only deploy the server binary
#    ./deploy/push.sh --dashboard-only   # Only deploy dashboard JS/CSS/HTML
#    ./deploy/push.sh --config-only      # Only deploy rules/parsers/config
#    ./deploy/push.sh --agents-only      # Only deploy agent builds
#    ./deploy/push.sh --rollback         # Roll back to previous binary
#    ./deploy/push.sh --status           # Show service status + logs
#    ./deploy/push.sh --logs [N]         # Tail last N (default 50) log lines
#    ./deploy/push.sh --setup-ssh-key    # Copy your SSH key to VPS (first time)
#    ./deploy/push.sh --ssh              # Interactive SSH into VPS
#
#  Configure via:
#    PERCEPTA_SSH_KEY     — path to SSH private key   (default: ~/digitalocean)
#    PERCEPTA_SSH_USER    — remote user                (default: root)
#    PERCEPTA_HOST        — remote hostname/IP         (default: off-sec-projections.me)
#    PERCEPTA_REMOTE_DIR  — install directory on VPS   (default: /opt/percepta-siem)
#
#  Or place overrides in deploy/.env.deploy (sourced automatically).
# ─────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Resolve paths ────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ── Load optional config ─────────────────────────────────────────────
if [[ -f "${SCRIPT_DIR}/.env.deploy" ]]; then
  # shellcheck disable=SC1091
  source "${SCRIPT_DIR}/.env.deploy"
fi

# ── Defaults (override via env vars or .env.deploy) ──────────────────
SSH_KEY="${PERCEPTA_SSH_KEY:-${HOME}/digitalocean}"
SSH_USER="${PERCEPTA_SSH_USER:-root}"
REMOTE_HOST="${PERCEPTA_HOST:-off-sec-projections.me}"
REMOTE_DIR="${PERCEPTA_REMOTE_DIR:-/opt/percepta-siem}"
HEALTH_URL="https://${REMOTE_HOST}/healthz"
HEALTH_TIMEOUT=45
SCP_OPTS="-C"  # compress transfer

# ── SSH helper ────────────────────────────────────────────────────────
SSH_CMD="ssh -i ${SSH_KEY} -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10"
SCP_CMD="scp -i ${SSH_KEY} ${SCP_OPTS}"

remote() {
  ${SSH_CMD} "${SSH_USER}@${REMOTE_HOST}" "$@"
}

# ── Colors ────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; }

health_status_from_json() {
  local raw="${1:-}"

  if [[ -z "${raw}" ]]; then
    return 0
  fi

  if command -v python3 >/dev/null 2>&1; then
    HEALTH_RAW="${raw}" python3 - <<'PY'  || true
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

# ── Pre-flight ────────────────────────────────────────────────────────
preflight() {
  if [[ ! -f "${SSH_KEY}" ]]; then
    fail "SSH key not found: ${SSH_KEY}"
    echo ""
    echo "  Your SSH key must be at: ${SSH_KEY}"
    echo "  If your key is somewhere else, set in deploy/.env.deploy:"
    echo "    PERCEPTA_SSH_KEY=\"/path/to/your/key\""
    echo ""
    echo "  If the key has a passphrase, load it first:"
    echo "    eval \"\$(ssh-agent -s)\" && ssh-add ${SSH_KEY}"
    exit 1
  fi

  info "Testing SSH connection to ${SSH_USER}@${REMOTE_HOST}..."
  if ! remote 'echo ok' &>/dev/null; then
    fail "Cannot connect via SSH."
    echo ""
    echo "  Troubleshooting:"
    echo "    1. Load key passphrase : eval \"\$(ssh-agent -s)\" && ssh-add ${SSH_KEY}"
    echo "    2. Check VPS is up     : ping ${REMOTE_HOST}"
    echo "    3. Test manually       : ssh -i ${SSH_KEY} ${SSH_USER}@${REMOTE_HOST}"
    echo "    4. Setup key on new VPS: ./deploy/push.sh --setup-ssh-key"
    echo ""
    exit 1
  fi
  ok "SSH connection OK"
}

# ── Build binary (if needed) ─────────────────────────────────────────
build_binary() {
  local binary="${PROJECT_ROOT}/target/release/percepta-server"

  local needs_build=false
  if [[ ! -f "${binary}" ]]; then
    needs_build=true
  else
    local newer_count
    newer_count=$(find "${PROJECT_ROOT}/server/src" -name '*.rs' -newer "${binary}"  | wc -l)
    if [[ "${newer_count}" -gt 0 ]]; then
      needs_build=true
    fi
  fi

  if [[ "${needs_build}" == true ]]; then
    info "Building release binary (incremental)..."
    cd "${PROJECT_ROOT}"
    cargo build --release -p percepta-server
    ok "Binary built"
  else
    ok "Binary is up-to-date (skipping build)"
  fi
}

# ── Backup on remote ─────────────────────────────────────────────────
backup_remote() {
  info "Creating backup on remote..."
  remote "
    cd ${REMOTE_DIR}
    if [[ -f percepta-server ]]; then
      cp percepta-server percepta-server.bak
    fi
  "
  ok "Backup created (percepta-server.bak)"
}

# ── Deploy binary ─────────────────────────────────────────────────────
deploy_binary() {
  local binary="${PROJECT_ROOT}/target/release/percepta-server"
  if [[ ! -f "${binary}" ]]; then
    fail "Binary not found at ${binary}. Run 'make build-release' first."
    exit 1
  fi

  local size
  size=$(du -h "${binary}" | cut -f1)
  info "Uploading binary (${size})..."
  ${SCP_CMD} "${binary}" "${SSH_USER}@${REMOTE_HOST}:${REMOTE_DIR}/percepta-server.new"
  ok "Binary uploaded"

  info "Swapping binary..."
  remote "
    cd ${REMOTE_DIR}
    mv percepta-server.new percepta-server
    chmod +x percepta-server
    chown percepta:percepta percepta-server
  "
  ok "Binary swapped"
}

# ── Deploy dashboard ─────────────────────────────────────────────────
deploy_dashboard() {
  local dash_dir="${PROJECT_ROOT}/server/dashboard"
  if [[ ! -d "${dash_dir}" ]]; then
    fail "Dashboard directory not found: ${dash_dir}"
    exit 1
  fi

  info "Syncing dashboard files..."
  if command -v rsync &>/dev/null; then
    rsync -avz --delete \
      -e "ssh -i ${SSH_KEY} -o StrictHostKeyChecking=accept-new" \
      "${dash_dir}/" \
      "${SSH_USER}@${REMOTE_HOST}:${REMOTE_DIR}/dashboard/"
  else
    ${SCP_CMD} -r "${dash_dir}"/* "${SSH_USER}@${REMOTE_HOST}:${REMOTE_DIR}/dashboard/"
  fi

  remote "chown -R percepta:percepta ${REMOTE_DIR}/dashboard"
  ok "Dashboard deployed"
}

# ── Deploy config (rules, parsers, event_knowledge, compliance) ──────
deploy_config() {
  info "Syncing configuration files..."
  local server_dir="${PROJECT_ROOT}/server"
  local changed=0

  for f in rules.yaml parsers.yaml event_knowledge.json; do
    if [[ -f "${server_dir}/${f}" ]]; then
      ${SCP_CMD} "${server_dir}/${f}" "${SSH_USER}@${REMOTE_HOST}:${REMOTE_DIR}/${f}"
      ((changed++)) || true
    fi
  done

  for d in compliance_mappings config Logo static; do
    if [[ -d "${server_dir}/${d}" ]]; then
      if command -v rsync &>/dev/null; then
        rsync -avz \
          -e "ssh -i ${SSH_KEY} -o StrictHostKeyChecking=accept-new" \
          "${server_dir}/${d}/" \
          "${SSH_USER}@${REMOTE_HOST}:${REMOTE_DIR}/${d}/"
      else
        ${SCP_CMD} -r "${server_dir}/${d}" "${SSH_USER}@${REMOTE_HOST}:${REMOTE_DIR}/"
      fi
      ((changed++)) || true
    fi
  done

  remote "chown -R percepta:percepta ${REMOTE_DIR}"
  ok "Config deployed (${changed} items)"
}

# ── Deploy agents ─────────────────────────────────────────────────────
deploy_agents() {
  info "Syncing agent and installer builds..."

  # Prefer native glibc binary (can dlopen GUI libs) over musl-static
  local linux_agent="${PROJECT_ROOT}/target/release/percepta-agent"
  if [[ ! -f "${linux_agent}" ]]; then
    linux_agent="${PROJECT_ROOT}/target/x86_64-unknown-linux-musl/release/percepta-agent"
  fi
  local win_agent="${PROJECT_ROOT}/target/x86_64-pc-windows-msvc/release/percepta-agent.exe"
  if [[ ! -f "${win_agent}" ]]; then
    win_agent="${PROJECT_ROOT}/target/x86_64-pc-windows-gnu/release/percepta-agent.exe"
  fi
  local linux_installer="${PROJECT_ROOT}/target/release/percepta-installer"
  if [[ ! -f "${linux_installer}" ]]; then
    linux_installer="${PROJECT_ROOT}/target/x86_64-unknown-linux-musl/release/percepta-installer"
  fi
  local win_installer="${PROJECT_ROOT}/target/x86_64-pc-windows-msvc/release/percepta-installer.exe"
  if [[ ! -f "${win_installer}" ]]; then
    win_installer="${PROJECT_ROOT}/target/x86_64-pc-windows-gnu/release/percepta-installer.exe"
  fi
  local uploaded=0

  remote "mkdir -p ${REMOTE_DIR}/agent_builds"

  if [[ -f "${linux_agent}" ]]; then
    ${SCP_CMD} "${linux_agent}" "${SSH_USER}@${REMOTE_HOST}:${REMOTE_DIR}/agent_builds/percepta-agent-linux"
    remote "cp ${REMOTE_DIR}/agent_builds/percepta-agent-linux ${REMOTE_DIR}/agent_builds/percepta-agent"
    ((uploaded++)) || true
    ok "Linux agent uploaded ($(basename $(dirname $(dirname ${linux_agent}))))"
  fi

  if [[ -f "${win_agent}" ]]; then
    ${SCP_CMD} "${win_agent}" "${SSH_USER}@${REMOTE_HOST}:${REMOTE_DIR}/agent_builds/percepta-agent-windows.exe"
    remote "cp ${REMOTE_DIR}/agent_builds/percepta-agent-windows.exe ${REMOTE_DIR}/agent_builds/percepta-agent.exe"
    ((uploaded++)) || true
    ok "Windows agent uploaded"
  fi

  if [[ -f "${linux_installer}" ]]; then
    ${SCP_CMD} "${linux_installer}" "${SSH_USER}@${REMOTE_HOST}:${REMOTE_DIR}/agent_builds/percepta-installer"
    remote "cp ${REMOTE_DIR}/agent_builds/percepta-installer ${REMOTE_DIR}/agent_builds/percepta-agent-installer"
    ((uploaded++)) || true
    ok "Linux installer uploaded"
  fi

  if [[ -f "${win_installer}" ]]; then
    ${SCP_CMD} "${win_installer}" "${SSH_USER}@${REMOTE_HOST}:${REMOTE_DIR}/agent_builds/percepta-installer.exe"
    remote "cp ${REMOTE_DIR}/agent_builds/percepta-installer.exe ${REMOTE_DIR}/agent_builds/percepta-agent-installer.exe"
    ((uploaded++)) || true
    ok "Windows installer uploaded"
  fi

  if [[ ${uploaded} -eq 0 ]]; then
    warn "No agent or installer builds found in target/. Build first:"
    warn "  make build-agent-linux      (Linux musl static)"
    warn "  make build-agent-windows-msvc  (preferred Windows build)"
    warn "  make build-agent-windows       (Windows GNU fallback)"
    return 1
  fi

  remote "chown -R percepta:percepta ${REMOTE_DIR}/agent_builds"
  ok "Agent and installer builds deployed (${uploaded} artifacts)"
}

# ── Restart service ───────────────────────────────────────────────────
restart_service() {
  info "Restarting percepta-server service..."
  remote "systemctl restart percepta-server"
  sleep 5

  if remote "systemctl is-active percepta-server" | grep -q "^active$"; then
    ok "Service is active"
  else
    fail "Service failed to start!"
    remote "journalctl -u percepta-server --no-pager -n 20" || true
    return 1
  fi
}

# ── Health check ──────────────────────────────────────────────────────
health_check() {
  info "Running health check..."
  local elapsed=0
  local interval=3

  while [[ ${elapsed} -lt ${HEALTH_TIMEOUT} ]]; do
    local raw
    local status
    raw=$(remote "curl -s --max-time 3 http://127.0.0.1:8080/healthz " || true)
    status="$(health_status_from_json "${raw}")"

    case "${status}" in
      ok)
        ok "Health check passed — server is healthy"
        return 0
        ;;
      degraded)
        warn "Health check returned degraded — service is up but dependencies are still settling"
        return 0
        ;;
    esac

    sleep ${interval}
    elapsed=$((elapsed + interval))
  done

  fail "Health check failed after ${HEALTH_TIMEOUT}s"
  return 1
}

# ── Rollback ──────────────────────────────────────────────────────────
rollback() {
  warn "Rolling back to previous binary..."
  remote "
    cd ${REMOTE_DIR}
    if [[ -f percepta-server.bak ]]; then
      systemctl stop percepta-server  || true
      cp percepta-server.bak percepta-server
      chmod +x percepta-server
      chown percepta:percepta percepta-server
      systemctl start percepta-server
      echo 'Rollback complete'
    else
      echo 'ERROR: No backup found (percepta-server.bak)'
      exit 1
    fi
  "

  sleep 2
  if health_check; then
    ok "Rollback successful — previous version restored"
  else
    fail "Rollback failed — manual intervention required!"
    fail "SSH in: ssh -i ${SSH_KEY} ${SSH_USER}@${REMOTE_HOST}"
    exit 1
  fi
}

# ── Show status ───────────────────────────────────────────────────────
show_status() {
  echo ""
  echo "═══════════════════════════════════════════════"
  echo "  Percepta SIEM — Remote Status"
  echo "═══════════════════════════════════════════════"
  remote "
    echo ''
    echo 'Service:'
    systemctl is-active percepta-server
    echo ''
    echo 'Binary:'
    ls -lh ${REMOTE_DIR}/percepta-server
    echo ''
    echo 'Uptime:'
    systemctl show percepta-server --property=ActiveEnterTimestamp | cut -d= -f2
    echo ''
    echo 'Memory:'
    ps -o rss=,vsz= -p \$(pgrep -f percepta-server  || echo 0)  | \
      awk '{printf \"  RSS: %.0f MB  VSZ: %.0f MB\\n\", \$1/1024, \$2/1024}' || echo '  (not running)'
    echo ''
    echo 'Agent builds:'
    ls -lh ${REMOTE_DIR}/agent_builds/  || echo '  (none)'
    echo ''
    echo 'Disk:'
    du -sh ${REMOTE_DIR}/  || true
    echo ''
    echo 'Last 5 log lines:'
    journalctl -u percepta-server --no-pager -n 5  || true
  "
  echo ""
}

# ── Show logs ─────────────────────────────────────────────────────────
show_logs() {
  local lines="${1:-50}"
  remote "journalctl -u percepta-server --no-pager -n ${lines}"
}

# ── Setup SSH key on a new VPS ────────────────────────────────────────
setup_ssh_key() {
  echo ""
  echo "═══════════════════════════════════════════════"
  echo "  Percepta SIEM — SSH Key Setup"
  echo "═══════════════════════════════════════════════"
  echo ""
  echo "  This copies your SSH public key to the VPS so"
  echo "  passwordless login works for future deploys."
  echo ""

  local pub_key="${SSH_KEY}.pub"
  if [[ ! -f "${pub_key}" ]]; then
    fail "Public key not found: ${pub_key}"
    echo "  Generate one with: ssh-keygen -t ed25519 -f ${SSH_KEY}"
    exit 1
  fi

  echo "  Key   : ${pub_key}"
  echo "  Target: ${SSH_USER}@${REMOTE_HOST}"
  echo ""
  read -rp "  Proceed? (y/N) " answer
  if [[ ! "$answer" =~ ^[Yy]$ ]]; then
    echo "  Aborted."
    exit 0
  fi

  echo ""
  info "Copying public key (you may be prompted for the VPS password)..."
  ssh-copy-id -i "${pub_key}" "${SSH_USER}@${REMOTE_HOST}"
  echo ""
  ok "SSH key installed! Test with: ssh -i ${SSH_KEY} ${SSH_USER}@${REMOTE_HOST}"
}

# ── Full deploy ───────────────────────────────────────────────────────
deploy_all() {
  echo ""
  echo "╔══════════════════════════════════════════════╗"
  echo "║   Percepta SIEM — Push Deploy                ║"
  echo "╚══════════════════════════════════════════════╝"
  echo ""

  preflight
  build_binary
  backup_remote

  deploy_binary
  deploy_dashboard
  deploy_config
  if ! deploy_agents; then
    warn "Agent or installer builds were not updated during full push. Build them first or run 'make push-agents'."
  fi

  restart_service

  if health_check; then
    echo ""
    ok "Deployment complete!"
    echo "  URL: https://${REMOTE_HOST}/"
    echo ""
  else
    warn "Health check failed — initiating rollback..."
    rollback
    exit 1
  fi
}

# ── Main ──────────────────────────────────────────────────────────────
case "${1:-}" in
  --binary-only)
    preflight
    build_binary
    backup_remote
    deploy_binary
    restart_service
    health_check || { rollback; exit 1; }
    ok "Binary deploy complete!"
    ;;
  --dashboard-only)
    preflight
    deploy_dashboard
    # Percepta inlines JS at startup via <!-- @include --> so restart is needed
    restart_service
    health_check || { rollback; exit 1; }
    ok "Dashboard deploy complete!"
    ;;
  --config-only)
    preflight
    deploy_config
    restart_service
    health_check || { rollback; exit 1; }
    ok "Config deploy complete!"
    ;;
  --agents-only)
    preflight
    deploy_agents
    ok "Agent deploy complete! (no restart needed)"
    ;;
  --rollback)
    preflight
    rollback
    ;;
  --status)
    preflight
    show_status
    ;;
  --logs)
    preflight
    show_logs "${2:-50}"
    ;;
  --setup-ssh-key)
    setup_ssh_key
    ;;
  --ssh)
    exec ${SSH_CMD} "${SSH_USER}@${REMOTE_HOST}"
    ;;
  --help|-h)
    echo "Usage: $0 [option]"
    echo ""
    echo "Deploy options:"
    echo "  (none)              Deploy everything (binary + dashboard + config)"
    echo "  --binary-only       Only deploy the server binary"
    echo "  --dashboard-only    Only deploy dashboard JS/CSS/HTML"
    echo "  --config-only       Only deploy rules, parsers, config"
    echo "  --agents-only       Only deploy agent builds from target/"
    echo "  --rollback          Roll back to previous binary"
    echo ""
    echo "Info options:"
    echo "  --status            Show remote service status"
    echo "  --logs [N]          Show last N log lines (default: 50)"
    echo "  --ssh               SSH into the VPS interactively"
    echo "  --help              Show this help"
    echo ""
    echo "Setup options:"
    echo "  --setup-ssh-key     Copy your SSH public key to the VPS"
    echo ""
    echo "Environment variables (or set in deploy/.env.deploy):"
    echo "  PERCEPTA_SSH_KEY     Path to SSH key (default: ~/digitalocean)"
    echo "  PERCEPTA_SSH_USER    SSH user (default: root)"
    echo "  PERCEPTA_HOST        Remote host (default: off-sec-projections.me)"
    echo "  PERCEPTA_REMOTE_DIR  Install dir (default: /opt/percepta-siem)"
    echo ""
    echo "Makefile shortcuts:"
    echo "  make push              build + deploy everything"
    echo "  make push-dashboard    deploy dashboard only"
    echo "  make push-binary       build + deploy binary only"
    echo "  make push-config       deploy rules/parsers/config"
    echo "  make push-rollback     roll back to previous binary"
    echo "  make remote-status     show VPS status"
    echo "  make remote-logs       show last 50 log lines"
    echo "  make deploy-pack       create full tar.gz for fresh server"
    echo "  make deploy-pack-fast  create tar.gz without agent cross-compile"
    ;;
  *)
    deploy_all
    ;;
esac
