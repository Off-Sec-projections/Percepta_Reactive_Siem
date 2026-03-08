#!/usr/bin/env bash
set -euo pipefail

if command -v apt-get >/dev/null 2>&1; then
  echo "[percepta] Installing Postgres via apt-get"
  sudo apt-get update
  sudo apt-get install -y postgresql postgresql-client
  exit 0
fi

if command -v dnf >/dev/null 2>&1; then
  echo "[percepta] Installing Postgres via dnf"
  sudo dnf install -y postgresql-server postgresql
  exit 0
fi

if command -v pacman >/dev/null 2>&1; then
  echo "[percepta] Installing Postgres via pacman"
  sudo pacman -S --noconfirm postgresql
  exit 0
fi

cat >&2 <<'EOF'
[percepta] ERROR: Unsupported package manager.
Install PostgreSQL locally and ensure pg_ctl/initdb/psql are on PATH.
EOF
exit 1
