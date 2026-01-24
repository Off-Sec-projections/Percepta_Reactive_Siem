#!/usr/bin/env bash
set -euo pipefail

if [[ "$EUID" -ne 0 ]]; then
  echo "[percepta-ids] Please run as root (sudo)." >&2
  exit 1
fi

install_with() {
  local pm="$1"; shift
  echo "[percepta-ids] Installing Suricata via $pm" >&2
  "$pm" "$@"
}

if command -v apt-get >/dev/null 2>&1; then
  install_with apt-get update
  install_with apt-get install -y suricata
elif command -v dnf >/dev/null 2>&1; then
  install_with dnf install -y suricata
elif command -v yum >/dev/null 2>&1; then
  install_with yum install -y suricata
elif command -v pacman >/dev/null 2>&1; then
  install_with pacman -Sy --noconfirm suricata
elif command -v zypper >/dev/null 2>&1; then
  install_with zypper install -y suricata
else
  echo "[percepta-ids] No supported package manager found (apt/dnf/yum/pacman/zypper)." >&2
  exit 1
fi

suricata --build-info | head -n 5 || true
