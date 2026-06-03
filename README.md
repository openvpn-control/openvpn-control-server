# OpenVPN Control Server

Веб-панель (React), API (Node.js) и PostgreSQL для управления узлами OpenVPN. Рядом на узле VPN обычно ставят отдельный репозиторий **openvpn-control-agent** (Linux).

**Лицензия:** [MIT](LICENSE) · **Безопасность:** [SECURITY.md](SECURITY.md) · **Вклад:** [CONTRIBUTING.md](CONTRIBUTING.md)

## Состав

- `frontend` — панель (React + Vite)
- `backend` — API (Express + Prisma)

## Быстрый старт (локально)

### Backend и frontend отдельно

```bash
# backend
cd backend && npm install && npm run dev

# frontend (в другом терминале)
cd frontend && npm install
VITE_API_URL=http://localhost:8080 npm run dev
```

- Frontend: `http://localhost:5173`
- Backend: `http://localhost:8080`

### Docker / Kubernetes

Развёртывание через образы GHCR и переменные окружения — в каталоге **openvpn-control** (`docker-compose.yml`, `.env.example`, Helm chart). Там же задаётся `API_URL` для панели.

Адрес API для панели:

- **Локальная разработка** (`npm run dev`): переменная `VITE_API_URL` в окружении (см. пример выше).
- **Docker / Kubernetes**: `API_URL` при старте контейнера frontend (в `.env` каталога `openvpn-control` или в Helm values).

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
