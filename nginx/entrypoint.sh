#!/bin/sh
set -e

PRIMARY_DOMAIN="${CERTBOT_PRIMARY_DOMAIN:-}"
CERTBOT_EMAIL="${CERTBOT_EMAIL:-}"
CERTBOT_STAGING="${CERTBOT_STAGING:-0}"
WEBROOT="/var/www/certbot"
CONF_DIR="/etc/nginx/conf.d"
TEMPLATES="/etc/nginx/templates"

mkdir -p "$CONF_DIR/snippets" /var/www/certbot
rm -f "$CONF_DIR/default.conf"
cp "$TEMPLATES/snippets/proxy.inc" "$CONF_DIR/snippets/proxy.inc"

render_ssl_config() {
  sed "s/\${CERTBOT_PRIMARY_DOMAIN}/${PRIMARY_DOMAIN}/g" \
    "$TEMPLATES/10-ssl.conf.template" > "$CONF_DIR/10-ssl.conf"
}

use_ssl=0
if [ -n "$PRIMARY_DOMAIN" ]; then
  if [ -f "/etc/letsencrypt/live/${PRIMARY_DOMAIN}/fullchain.pem" ]; then
    use_ssl=1
  fi
fi

should_request_cert=0
if command -v certbot >/dev/null 2>&1 \
  && [ "$use_ssl" -eq 0 ] \
  && [ -n "$PRIMARY_DOMAIN" ] \
  && [ -n "$CERTBOT_EMAIL" ]; then
  case "$PRIMARY_DOMAIN" in
    localhost|127.0.0.1) ;;
    *)
      should_request_cert=1
      ;;
  esac
fi

if [ "$should_request_cert" -eq 1 ]; then
  echo "[nginx] Obtaining certificate for ${PRIMARY_DOMAIN}"
  cp "$TEMPLATES/00-http-proxy.conf" "$CONF_DIR/00-http.conf"
  rm -f "$CONF_DIR/10-ssl.conf"
  nginx
  STAGING_ARG=""
  if [ "$CERTBOT_STAGING" = "1" ] || [ "$CERTBOT_STAGING" = "true" ]; then
    STAGING_ARG="--staging"
  fi
  certbot certonly --webroot -w "$WEBROOT" \
    $STAGING_ARG \
    --email "$CERTBOT_EMAIL" \
    --agree-tos \
    --non-interactive \
    --keep-until-expiring \
    -d "$PRIMARY_DOMAIN" || echo "[nginx] certbot failed — continuing with HTTP"
  nginx -s quit
  sleep 1
  if [ -f "/etc/letsencrypt/live/${PRIMARY_DOMAIN}/fullchain.pem" ]; then
    use_ssl=1
  fi
fi

rm -f "$CONF_DIR/00-http.conf" "$CONF_DIR/10-ssl.conf"

if [ "$use_ssl" -eq 1 ]; then
  render_ssl_config
  cp "$TEMPLATES/00-http-redirect.conf" "$CONF_DIR/00-http.conf"
  echo "[nginx] HTTPS enabled for ${PRIMARY_DOMAIN}"
else
  cp "$TEMPLATES/00-http-proxy.conf" "$CONF_DIR/00-http.conf"
  echo "[nginx] HTTP only. SSL: mount certs to /etc/letsencrypt or compose --profile ssl"
fi

exec nginx -g "daemon off;"
