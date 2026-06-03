# Порты и URL: без путаницы

## Сервисы (Docker Compose по умолчанию)

| Сервис | Порт в контейнере | Порт на хосте | Назначение |
|--------|-------------------|---------------|------------|
| **nginx** (edge) | 80, 443 | **80**, **443** | Публичный вход, SSL, маршрутизация |
| **frontend** | 80 | — (только сеть compose) | Статика + SPA |
| **backend** | 8080 | — (только сеть compose) | API |
| **postgres** | 5432 | 5432 (если не переопределён) | БД |

## Куда ходит браузер (edge nginx)

```
Браузер → http://localhost/              (прокси → frontend:80)
Браузер → http://localhost/api/...       (прокси → backend:8080)
```

С HTTPS (certbot или свой сертификат):

```
Браузер → https://hostname/
Браузер → https://hostname/api/...
```

`API_URL` / `PUBLIC_BASE_URL` в `.env` задают `data-api-url` только если нужен явный origin. **По умолчанию пусто** — фронт использует тот же origin, что и страница (`/api` на edge).

## Режим :5173 (без edge)

```bash
docker compose -f docker-compose.yml -f docker-compose.direct.yml up --build
```

- Панель: `http://localhost:5173/`
- API: `http://localhost:5173/api/...` (внутренний nginx frontend → backend)

## Прямой доступ к API (отладка)

- `docker compose exec backend wget -qO- http://127.0.0.1:8080/health`
- С edge: `curl http://localhost/health` или `https://домен/health`

## SSL

См. [nginx/README.md](../nginx/README.md): `CERTBOT_PRIMARY_DOMAIN`, `CERTBOT_EMAIL`, volume `letsencrypt`.
