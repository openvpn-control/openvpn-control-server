# Backend на Go

Единственный API-сервер панели — **Go** (`cmd/server`), порт **8080**. Схема БД в `prisma/`; миграции при старте (`internal/migrate`).

## Архитектура

| Компонент | Роль |
|-----------|------|
| `backend/` (Go) | Весь `/api/*`, фоновые циклы, audit log |
| `frontend/` | Статика + nginx proxy `/api` → backend:8080 |

## Локально

```bash
cd backend
go mod tidy
go run ./cmd/server
```

## Docker

```bash
docker compose up --build
```

Панель: http://localhost:8080/

## API

- **auth**: login, login/mfa, refresh
- **agent**: nodes CRUD, sync
- **clients**: list, history, source-history, disconnect
- **organizations**: CRUD + firewall
- **monitoring**: overview, admin-actions
- **tasks**: list, retry
- **admins**: CRUD, TOTP, `/me`, change-password
- **admin-invite**, **admin-password-reset**: публичные маршруты
- **certificates**, **vpn-users**: полные модули
- **panel/nodes**: OpenVPN-панель узла
- **panel/app-backups**: резервные копии панели

## Фоновые процессы

- `worker`: метрики агентов, panel tasks, клиенты, OpenVPN info
- `panelbackup`: планировщик ZIP-бэкапов

## Audit

Мутации API под auth пишутся в `AdminActionLog` (`internal/audit`). Отключить: `AUDIT_ADMIN_ACTIONS_DISABLED=1`.
