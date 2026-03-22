#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$ROOT_DIR/server/geoip"
OUT_FILE="$OUT_DIR/GeoLite2-City.mmdb"
TMP_DIR="${TMPDIR:-/tmp}/percepta-geoip.$$"

if [[ -z "${MAXMIND_LICENSE_KEY:-}" ]]; then
  echo "MAXMIND_LICENSE_KEY is required." >&2
  echo "Create a MaxMind GeoLite2 license key, then run:" >&2
  echo "  MAXMIND_LICENSE_KEY=YOUR_KEY tools/install_geolite2_city_mmdb.sh" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
mkdir -p "$TMP_DIR"
trap 'rm -rf "$TMP_DIR"' EXIT

URL="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz"

echo "Downloading GeoLite2 City tarball..."
# MaxMind sometimes rate-limits; retry a bit.
curl -fsSL --retry 3 --retry-delay 2 "$URL" -o "$TMP_DIR/GeoLite2-City.tar.gz"

echo "Extracting .mmdb..."
tar -xzf "$TMP_DIR/GeoLite2-City.tar.gz" -C "$TMP_DIR"

MMDB_PATH="$(find "$TMP_DIR" -type f -name 'GeoLite2-City.mmdb' | head -n 1)"
if [[ -z "$MMDB_PATH" ]]; then
  echo "Could not find GeoLite2-City.mmdb in downloaded archive." >&2
  exit 2
fi

cp -f "$MMDB_PATH" "$OUT_FILE"

echo "Installed: $OUT_FILE"
echo "Tip: server will auto-detect it at server/geoip/GeoLite2-City.mmdb"
