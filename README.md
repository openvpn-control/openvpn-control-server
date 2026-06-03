# OpenVPN Control Server

Веб-панель управления OpenVPN.

**Лицензия:** [MIT](LICENSE) · **Безопасность:** [SECURITY.md](SECURITY.md) · **Вклад:** [CONTRIBUTING.md](CONTRIBUTING.md)

## Быстрый старт

```bash
cp .env.example .env
docker compose up --build
```

- Панель: **http://localhost:8080/**
- Проверка: **http://localhost:8080/health**

Переменные окружения — в `.env.example`. Подробнее о развёртывании: [DEPLOY.md](DEPLOY.md).

## Продакшен

```bash
cp .env.example .env
# задайте IMAGE_TAG, секреты, CORS_ORIGIN и остальное по .env.example
docker compose -f docker-compose.prod.yml up -d
```

## Kubernetes

```bash
helm upgrade --install openvpn-control ./helm/openvpn-control -n openvpn-control --create-namespace
```

Значения по умолчанию и секреты — в `helm/openvpn-control/values.yaml`.

## Агент на VPN-серверах

На каждом узле OpenVPN установите **openvpn-control-agent** (отдельный репозиторий) и добавьте узел в панели (хост, порт, токен из `/var/lib/openvpn-control-agent/token`).
