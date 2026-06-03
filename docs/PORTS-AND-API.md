# Порты и API

## Docker Compose

| Сервис | Порт (контейнер) | С хоста | Назначение |
|--------|------------------|---------|------------|
| **frontend** | 8080 | **8080** (`HTTP_PORT`) | Панель + прокси `/api` → backend |
| **backend** (Go) | 8080 | — | Весь API + фоновые циклы |
| **postgres** | 5432 | — | БД |

## URL

- Панель: `http://localhost:8080/`
- API: `http://localhost:8080/api/...`
- Health: `http://localhost:8080/health`

Миграции БД — при старте Go backend, отдельного контейнера `migrate` нет.
