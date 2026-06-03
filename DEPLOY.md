# Развёртывание OpenVPN Control

## Docker Compose (разработка)

```bash
cp .env.example .env
docker compose up --build
```

- Панель: **http://localhost:8080/**
- API: **http://localhost:8080/api/...** (прокси frontend nginx → Go backend)

Миграции БД выполняются при старте **Go backend** (`internal/migrate`). Отдельного контейнера migrate нет.

## Docker Compose (продакшен, образы GHCR)

```bash
cp .env.example .env
# IMAGE_TAG, секреты, CORS_ORIGIN=http://your-host:8080
docker compose -f docker-compose.prod.yml up -d
```

## Kubernetes (Helm)

```bash
helm upgrade --install openvpn-control ./helm/openvpn-control \
  -n openvpn-control --create-namespace \
  -f my-values.yaml
```

В `values.yaml` задайте образы, секреты, `frontend.service.port: 8080`, `backendLegacy.enabled: true`.

## CI

GitHub Actions **Docker publish** собирает образы `backend` (Go) и `frontend` → GHCR.
