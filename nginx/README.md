# Edge Nginx

Публичный вход **80/443** → `/` frontend, `/api` backend.

## Образы

| Dockerfile | Размер (порядок) | Назначение |
|------------|------------------|------------|
| `Dockerfile` | ~45 MB | Локальная разработка, HTTP, свой сертификат в volume |
| `Dockerfile.certbot` | ~120 MB | Прод + автоматический Let's Encrypt |

По умолчанию в `docker compose up` — **лёгкий** образ без certbot.

С certbot:

```bash
docker compose -f docker-compose.yml -f docker-compose.ssl.yml up --build
```

## Переменные

| Переменная | Описание |
|------------|----------|
| `CERTBOT_PRIMARY_DOMAIN` | FQDN |
| `CERTBOT_EMAIL` | Email LE (только в образе с certbot) |
| `CERTBOT_STAGING` | `1` — тестовые сертификаты |

## Продление (образ с certbot)

```bash
docker compose -f docker-compose.yml -f docker-compose.ssl.yml exec nginx certbot renew --webroot -w /var/www/certbot
docker compose -f docker-compose.yml -f docker-compose.ssl.yml exec nginx nginx -s reload
```
