#!/bin/sh
set -e

# Пересборка зависимостей: docker compose build backend
#   или: DEPS_REFRESH=1 docker compose up -d backend
if [ "${DEPS_REFRESH:-0}" = "1" ]; then
  echo "[backend] Refreshing node_modules..."
  npm ci
  npx prisma generate
fi

npx prisma migrate deploy
node prisma/seed.js
exec npm run dev
