# OpenVPN Control Server

Веб-панель (React), API (Node.js) и PostgreSQL для управления узлами OpenVPN. Рядом на узле VPN обычно ставят отдельный репозиторий **openvpn-control-agent** (Linux).

**Лицензия:** [MIT](LICENSE) · **Безопасность:** [SECURITY.md](SECURITY.md) · **Вклад:** [CONTRIBUTING.md](CONTRIBUTING.md)

## Состав

- `frontend` — панель (React + TypeScript, сборка Vite → nginx)
- `backend` — API (Express + Prisma)

## Быстрый старт (локально)

### Backend и frontend отдельно

```bash
# backend
cd backend && npm install && npm run dev

# frontend (сборка + любой статический сервер, либо Docker ниже)
cd frontend && npm install && npm run build
# затем отдайте dist/ через nginx или docker compose
```

- Панель: `http://localhost/` (через edge nginx) или `:5173` с override `docker-compose.direct.yml`
- Backend: `http://localhost/api/...` (через edge) или `:8080` (curl напрямую)

### Docker Compose (режим разработки)

Из каталога `openvpn-control-server`:

```bash
docker compose up --build
```

Поднимаются PostgreSQL, backend, frontend (внутренняя сеть) и **edge nginx** (порты 80/443). Зависимости backend ставятся **при сборке образа**, не при каждом `up`. SSL: лёгкий nginx по умолчанию; certbot — `docker compose -f docker-compose.yml -f docker-compose.ssl.yml up`. См. [nginx/README.md](nginx/README.md).

После смены `package.json` / `package-lock.json`: `docker compose build backend`. С принудительным `npm ci` в контейнере: `DEPS_REFRESH=1 docker compose up -d backend`.

- Панель: **`http://localhost/`**
- API с браузера: **`http://localhost/api/...`**
- HTTPS (прод): задайте `CERTBOT_PRIMARY_DOMAIN` и `CERTBOT_EMAIL` в `.env` → **`https://домен/`** и **`https://домен/api/...`**

Прямой доступ к панели на `:5173` (как раньше):

```bash
docker compose -f docker-compose.yml -f docker-compose.direct.yml up --build
```
- Переменные: [.env.example](.env.example) → `.env`
- Схема портов: [docs/PORTS-AND-API.md](docs/PORTS-AND-API.md)
- Остановка: `docker compose down` (данные БД в томе `postgres_data_dev`)

**Firefox: пустая страница, в HAR скрипты `status: 0`** — не баг сборки. Подробно: [docs/FIREFOX-LOCALHOST.md](docs/FIREFOX-LOCALHOST.md).

Кратко:

1. Замок → **Разрешения** → **Выполнять JavaScript** = **Разрешить** для localhost.
2. В Network Firefox — только `GET /` (скрипт встроен в HTML). Диагностика: `http://localhost:5173/firefox-check.html`.
3. Тот же URL в Chrome / Cursor — если там работает, правите Firefox / антивирус.

Продакшен-образы из GHCR — в каталоге **openvpn-control** (`docker-compose.yml`, Helm).

### Docker / Kubernetes

Развёртывание через образы GHCR и переменные окружения — в каталоге **openvpn-control** (`docker-compose.yml`, `.env.example`, Helm chart). Там же задаётся `API_URL` для панели.

Адрес API для панели:

- **Docker / Kubernetes**: `API_URL` при старте контейнера frontend → атрибут `data-api-url` в `index.html` (см. `docker-entrypoint.sh`).

## Развёртывание у себя (self-host)

1. **Секреты:** `JWT_SECRET`, пароль PostgreSQL, начальный админ — без демо-значений в проде.
2. **URL:** `CORS_ORIGIN`, `CSRF_TRUSTED_ORIGINS`, `ALLOWED_HOSTS`, `API_URL` строго под ваш HTTPS-хост (учёт reverse proxy / `X-Forwarded-Host`).
3. **HTTPS** end-to-end для доступа из недоверенных сетей.
4. **Сеть:** по возможности ограничьте доступ к панели; порты агента на узлах — не в открытый интернет без необходимости.
5. **Бэкапы:** PostgreSQL и каталог резервных копий панели (PVC в Kubernetes или том в `openvpn-control/docker-compose.yml`).
6. **Обновления:** образы и зависимости.

### Kubernetes

Helm-чарт в этом репозитории не поставляется. Пример Compose и Helm с образами GHCR — в соседнем каталоге `openvpn-control/` (bundled deployment), если он есть в вашей копии дерева исходников.

### Где хранятся резервные копии панели

- В контейнере backend: `/app/data/panel-backups`
- В `openvpn-control/docker-compose.yml`: том `panel_backups_data`

## Релизы: образы Docker (GitHub Actions)

Воркфлоу **Docker publish** пушит в **ghcr.io** (имена в нижнем регистре):

- **push в любую ветку** — тег = короткий SHA коммита (7 символов), например `a1b2c3d`:
  - `ghcr.io/<владелец>/<репозиторий>-backend:a1b2c3d`
  - `ghcr.io/<владелец>/<репозиторий>-frontend:a1b2c3d`
- **push git-тега** `v*` — тег релиза (`v1.2.3`) и дополнительно `latest` для тегов вида `v…`

Ручной запуск: **Actions → Docker publish → Run workflow** (произвольный тег в input).

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
