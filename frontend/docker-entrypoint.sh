#!/bin/sh
set -e

CONFIG="/usr/share/nginx/html/env-config.js"
API_URL="${API_URL:-http://localhost:8080}"
escaped=$(printf '%s' "$API_URL" | sed 's/\\/\\\\/g; s/"/\\"/g')

printf 'window.__APP_CONFIG__ = { API_URL: "%s" };\n' "$escaped" > "$CONFIG"
exec nginx -g 'daemon off;'
