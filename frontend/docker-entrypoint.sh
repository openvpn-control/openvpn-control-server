#!/bin/sh
set -e

INDEX="/usr/share/nginx/html/index.html"
API_URL="${API_URL:-http://localhost:8080}"
# HTML attribute value: escape & and " for index.html
escaped=$(printf '%s' "$API_URL" | sed 's/&/\&amp;/g; s/"/\&quot;/g')

sed -i "s|data-api-url=\"\"|data-api-url=\"${escaped}\"|" "$INDEX"
exec nginx -g 'daemon off;'
