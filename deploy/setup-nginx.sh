#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
#  Percepta SIEM — Nginx + Let's Encrypt setup for DigitalOcean
#  Run this ONCE on your droplet after pointing your DNS A record.
#
#  Usage: sudo bash setup-nginx.sh <domain> <email> [app-port]
#  Example: sudo bash setup-nginx.sh off-sec-projections.me admin@off-sec-projections.me
#
#  BEFORE RUNNING:
#    1. In Namecheap Advanced DNS: add A record  @  →  YOUR_DROPLET_IP
#    2. Wait ~5 min for DNS to propagate
#    3. Run this script
# ─────────────────────────────────────────────────────────────────────
set -euo pipefail

DOMAIN="${1:-}"
EMAIL="${2:-}"
APP_PORT="${3:-8080}"

if [[ -z "$DOMAIN" || -z "$EMAIL" ]]; then
  echo "Usage: sudo bash setup-nginx.sh <domain> <email> [app-port]"
  echo "Example: sudo bash setup-nginx.sh off-sec-projections.me admin@off-sec-projections.me"
  exit 1
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root: sudo bash $0 $*"
  exit 1
fi

echo "──────────────────────────────────────────────"
echo " Percepta SIEM — SSL Setup"
echo " Domain : $DOMAIN"
echo " Email  : $EMAIL"
echo " App    : http://127.0.0.1:$APP_PORT"
echo "──────────────────────────────────────────────"

echo "[1/4] Installing Nginx..."
BUNDLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/bundle"
if ls "${BUNDLE_DIR}"/nginx*.deb "${BUNDLE_DIR}"/nginx-common*.deb >/dev/null 2>&1; then
  echo "  Using bundled .deb packages (offline install)..."
  dpkg -i "${BUNDLE_DIR}"/nginx-common*.deb "${BUNDLE_DIR}"/nginx*.deb 2>/dev/null || \
  apt-get install -f -y --quiet  # satisfy any missing deps
else
  echo "  Downloading from apt..."
  apt-get update -qq
  apt-get install -y nginx
fi

echo "[2/4] Configuring Nginx for $DOMAIN..."
mkdir -p /var/www/certbot

# ── Phase 1: HTTP-only config (so we can get certs) ──────────────────
cat > /etc/nginx/sites-available/percepta << NGINXCONF
# Percepta SIEM — HTTP only (temporary, until SSL cert is obtained)
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN} www.${DOMAIN};

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }
    location / {
        proxy_pass http://127.0.0.1:${APP_PORT};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
NGINXCONF

ln -sf /etc/nginx/sites-available/percepta /etc/nginx/sites-enabled/percepta
rm -f /etc/nginx/sites-enabled/default

nginx -t
systemctl enable --now nginx
systemctl reload nginx

echo "[3/4] Obtaining Let's Encrypt certificate for $DOMAIN..."
# NOTE: cert issuance always requires port 80/443 reachable from the internet
#       and Let's Encrypt to reach your server (DNS must resolve to this IP).
BUNDLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/bundle"
ACME_SH="${BUNDLE_DIR}/acme.sh"

if command -v certbot >/dev/null 2>&1; then
  # Prefer certbot if installed
  certbot --nginx -d "$DOMAIN" -d "www.$DOMAIN" \
      --email "$EMAIL" --agree-tos --non-interactive --redirect \
      2>/dev/null \
  || certbot --nginx -d "$DOMAIN" \
      --email "$EMAIL" --agree-tos --non-interactive --redirect
  nginx -t && systemctl reload nginx
  echo "[4/4] Auto-renewal configured."
  systemctl enable certbot.timer 2>/dev/null || true
  (crontab -l 2>/dev/null; echo "0 3 * * * certbot renew --quiet && systemctl reload nginx") | crontab - 2>/dev/null || true

elif [[ -f "$ACME_SH" ]]; then
  # Use bundled acme.sh — pure-shell, no apt dependencies
  echo "  Using bundled acme.sh (certbot not installed)..."

  # Paths for acme.sh
  ACME_HOME="/root/.acme.sh"
  CERT_DIR="/etc/letsencrypt/live/${DOMAIN}"
  mkdir -p "$CERT_DIR"

  # Issue cert via HTTP-01 challenge (nginx must be running on port 80)
  "$ACME_SH" --register-account -m "$EMAIL" --server letsencrypt 2>/dev/null || true
  "$ACME_SH" --issue -d "$DOMAIN" -d "www.$DOMAIN" \
      --webroot /var/www/certbot \
      --server letsencrypt \
      --fullchain-file "${CERT_DIR}/fullchain.pem" \
      --key-file "${CERT_DIR}/privkey.pem" \
  || "$ACME_SH" --issue -d "$DOMAIN" \
      --webroot /var/www/certbot \
      --server letsencrypt \
      --fullchain-file "${CERT_DIR}/fullchain.pem" \
      --key-file "${CERT_DIR}/privkey.pem"

  nginx -t && systemctl reload nginx
  echo "[4/4] Auto-renewal configured (via acme.sh cron)."
  "$ACME_SH" --install-cronjob 2>/dev/null || true

else
  # No certbot or acme.sh — install certbot from apt as last resort
  echo "  Neither certbot nor bundled acme.sh found — trying apt-get..."
  apt-get install -y certbot python3-certbot-nginx
  certbot --nginx -d "$DOMAIN" \
      --email "$EMAIL" --agree-tos --non-interactive --redirect
  nginx -t && systemctl reload nginx
  echo "[4/4] Auto-renewal configured."
  (crontab -l 2>/dev/null; echo "0 3 * * * certbot renew --quiet && systemctl reload nginx") | crontab - 2>/dev/null || true
fi

# ── Phase 2: Upgrade to full HTTPS config now that certs exist ────────
if [[ -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" ]]; then
  echo "  Upgrading Nginx to HTTPS..."
  cat > /etc/nginx/sites-available/percepta << NGINXCONF
# Percepta SIEM — HTTP → HTTPS redirect + ACME challenge
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN} www.${DOMAIN};

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }
    location / {
        return 301 https://\$host\$request_uri;
    }
}

# Percepta SIEM — HTTPS reverse proxy
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${DOMAIN} www.${DOMAIN};

    ssl_certificate     /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
    ssl_stapling on;
    ssl_stapling_verify on;

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy "same-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;

    location / {
        proxy_pass http://127.0.0.1:${APP_PORT};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
        proxy_buffering off;
    }
}
NGINXCONF
  nginx -t && systemctl reload nginx
  echo "  ✓ HTTPS active"
else
  echo "  ⚠ SSL cert not obtained — running HTTP only. Re-run this script after DNS propagates."
fi

echo ""
echo "✅ Setup complete!"
echo "   Dashboard: https://${DOMAIN}/"
echo ""
echo "Now start Percepta SIEM with proxy mode:"
echo "   PERCEPTA_BEHIND_PROXY=1 PERCEPTA_WEB_BIND=127.0.0.1:${APP_PORT} ./percepta-server"
echo ""
echo "Or update /opt/percepta-siem/.env:"
echo "   PERCEPTA_BEHIND_PROXY=1"
echo "   PERCEPTA_WEB_BIND=127.0.0.1:${APP_PORT}"
echo "   PERCEPTA_ADMIN_PASS=YourStrongPasswordHere"
echo "   PERCEPTA_ANALYST_PASS=AnotherStrongPassword"
echo ""
echo "Then: sudo systemctl restart percepta-server"
