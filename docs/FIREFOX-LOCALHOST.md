# Firefox: пустая страница на localhost:5173

## Симптом (ваш HAR)

- `GET /` → **200**
- `GET /static/*.js` или старый `/assets/*.js` → **`status: 0`** (Firefox / блокировщик **не отправляет** запрос)
- В **Cursor / Chrome** всё работает → nginx в порядке, режет **Firefox**

**Обход в сборке:** бандл встраивается в `index.html` при `npm run build` — отдельного `.js` в Network быть не должно.

## 1. Быстрая диагностика

Откройте: **http://localhost/firefox-check.html** (или `:5173` в режиме direct)

| Строка | Значение | Вывод |
|--------|----------|--------|
| inline | OK | JavaScript для localhost **разрешён** |
| inline | pending | JS **выключен** для сайта |
| external | OK | Бандл грузится, смотрите консоль панели |
| external | bundle did not run | Внешний `.js` **блокируется** (расширение / фильтр) |

Проверка с хоста (PowerShell):

```powershell
curl.exe -s http://localhost:5173/ | Select-String "OpenVpnControl"
```

В HTML: `<script src="/static/index-....js">`, без `/assets/` и без `env-config.js`.

## 2. Частые причины в Firefox

### Расширения (самое частое)

uBlock Origin, AdGuard, NoScript, Privacy Badger, «защита» Kaspersky/Dr.Web часто режут пути вроде `app.js` / большие скрипты на localhost.

1. **Окно приватности** без расширений: Ctrl+Shift+P → `http://localhost:5173`
2. Или **Справка → Устранение неполадок** (отключить расширения) и перезагрузить страницу
3. В uBlock: **выключить для localhost** или добавить в белый список

### Cookies Метрики на localhost

В HAR на `/` есть cookies `_ym_uid`, `_ym_d` (Яндекс.Метрика). Усиленная защита Firefox иногда ужесточает поведение для таких сайтов.

1. F12 → **Хранилище** → удалить данные для `http://localhost:5173`
2. Либо `about:preferences#privacy` → **Стандартная** защита (временно для проверки)

### Разрешение «Выполнять JavaScript»

Замок слева от URL → **Разрешения** → **Выполнять JavaScript** → **Разрешить**.

### localhost vs 127.0.0.1

Иногда помогает открыть панель как **http://127.0.0.1:5173** (в `.env` задать `API_URL=http://127.0.0.1:5173` и `docker compose up --build`).

## 3. Логи Docker

```powershell
docker logs ovc-server-frontend
```

После F5 в логах достаточно `GET /` с **200**. Отдельного `GET /assets/openvpn-control.js` быть не должно (бандл в HTML).

## 4. Пересборка после обновления кода

```powershell
cd openvpn-control-server
docker compose down
docker compose up --build
```

В Network: `GET /`, `GET /static/index-*.js`, `GET /static/index-*.css` со статусом **200**.
