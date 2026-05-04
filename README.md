# OpenVPN Control Server

Веб-панель (React), API (Node.js) и PostgreSQL для управления узлами OpenVPN. Рядом на узле VPN обычно ставят отдельный репозиторий **openvpn-control-agent** (Linux).

**Лицензия:** [MIT](LICENSE) · **Безопасность:** [SECURITY.md](SECURITY.md) · **Вклад:** [CONTRIBUTING.md](CONTRIBUTING.md)

## Состав

- `frontend` — панель (React + Vite)
- `backend` — API (Express + Prisma)
- `postgres` — база (в Docker Compose / Helm)

## Быстрый старт (локально)

```bash
docker compose up --build
```

- Frontend: `http://localhost:5173`
- Backend: `http://localhost:8080`
- PostgreSQL: `localhost:5432`

### Учётные данные по умолчанию в Compose

В `docker-compose.yml` заданы **демонстрационные** `INIT_ADMIN_*`. Для сети смените их, `JWT_SECRET` и пароль БД — см. [backend/.env.example](backend/.env.example).

## Развёртывание у себя (self-host)

1. **Секреты:** `JWT_SECRET`, пароль PostgreSQL, начальный админ — без демо-значений в проде.
2. **URL:** `CORS_ORIGIN`, `CSRF_TRUSTED_ORIGINS`, `ALLOWED_HOSTS` строго под ваш HTTPS-хост (учёт reverse proxy / `X-Forwarded-Host`).
3. **HTTPS** end-to-end для доступа из недоверенных сетей.
4. **Сеть:** по возможности ограничьте доступ к панели; порты агента на узлах — не в открытый интернет без необходимости.
5. **Бэкапы:** PostgreSQL и каталог резервных копий панели (`docker-compose` / PVC в Helm).
6. **Обновления:** образы и зависимости.

### Kubernetes (Helm)

[helm/openvpn-control/README.md](helm/openvpn-control/README.md) — пример `values-prod`, миграции, bootstrap администратора.

### Где хранятся резервные копии панели

- В контейнере backend: `/app/data/panel-backups`
- В Compose: том `panel_backups_data`

## Релизы: образы Docker (GitHub Actions)

При **push тега** `v*` воркфлоу **Docker publish** пушит в **ghcr.io** (имена в нижнем регистре):

- `ghcr.io/<владелец>/<репозиторий>-backend:<тег>` (+ `latest` для тегов вида `v…`)
- `ghcr.io/<владелец>/<репозиторий>-frontend:<тег>`

Ручной запуск: **Actions → Docker publish → Run workflow**.

**Settings → Actions → General:** для публикации в GHCR обычно нужны **Read and write** для `GITHUB_TOKEN`. Пакеты сделайте Public или используйте `docker login ghcr.io`.

Закомментированный пример входа в Docker Hub: [.github/workflows/docker-publish.yml](.github/workflows/docker-publish.yml).

**Бинарники агента** собираются в отдельном репозитории **openvpn-control-agent** (релизы с приложенными файлами).

## Функции (обзор)

- Вход администратора, 2FA (TOTP), администраторы, аудит.
- Узлы OpenVPN через агент (адрес, порт, токен).
- Метрики, сессии, сертификаты, организации, пользователи VPN, бэкапы панели.

## Документация

- Тесты: [TESTING.md](TESTING.md)

## Отказ от гарантий

ПО поставляется «как есть» ([LICENSE](LICENSE)). Эксплуатация и соответствие требованиям — зона ответственности оператора.
