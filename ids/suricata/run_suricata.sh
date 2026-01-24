#!/usr/bin/env bash
set -euo pipefail

SURICATA_BIN="${SURICATA_BIN:-suricata}"
CONFIG_PATH="${PERCEPTA_SURICATA_CONFIG_PATH:-/etc/suricata/suricata.yaml}"
LOG_DIR="${PERCEPTA_SURICATA_LOG_DIR:-/var/log/suricata}"
RULES_PATH="${PERCEPTA_SURICATA_RULES_PATH:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/rules/percepta.rules}"
IFACE="${PERCEPTA_SURICATA_IFACE:-}"

if [[ -z "$IFACE" ]]; then
  IFACE=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++){if($i=="dev"){print $(i+1); exit}}}')
fi
if [[ -z "$IFACE" ]]; then
  IFACE=$(ip route show default 2>/dev/null | awk '{print $5}' | head -n1)
fi
if [[ -z "$IFACE" ]]; then
  echo "[percepta-ids] Could not determine default interface. Set PERCEPTA_SURICATA_IFACE." >&2
  exit 1
fi

mkdir -p "$LOG_DIR"
mkdir -p "$(dirname "$RULES_PATH")"
if [[ ! -f "$RULES_PATH" ]]; then
  echo "# Percepta managed rules" > "$RULES_PATH"
fi

exec "$SURICATA_BIN" -c "$CONFIG_PATH" -i "$IFACE" -l "$LOG_DIR" \
  -S "$RULES_PATH" \
  --set outputs.eve-log.enabled=yes \
  --set outputs.eve-log.filename=eve.json \
  --set outputs.eve-log.types=[alert] \
  --set default-log-dir="$LOG_DIR" \
  -D
