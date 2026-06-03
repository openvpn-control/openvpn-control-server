#!/bin/sh
set -e

INDEX="/usr/share/nginx/html/index.html"
# Пустой data-api-url → браузер использует тот же origin (/api на edge nginx)
API_URL="${API_URL:-}"
html_esc=$(printf '%s' "$API_URL" | sed 's/&/\&amp;/g; s/"/\&quot;/g')

if [ -n "$API_URL" ]; then
  sed -i "s|data-api-url=\"\"|data-api-url=\"${html_esc}\"|" "$INDEX"
fi
rm -f /usr/share/nginx/html/env-config.js
exec nginx -g 'daemon off;'
