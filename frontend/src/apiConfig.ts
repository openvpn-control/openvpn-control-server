/** Прямой доступ к backend без прокси панели (локальный `npm run` backend отдельно). */
const FALLBACK_DIRECT_BACKEND = "http://localhost:8080";

function normalizeApiUrl(url: string | undefined | null): string {
  if (!url || typeof url !== "string") return "";
  return url.trim().replace(/\/+$/, "");
}

/**
 * Базовый URL API для fetch().
 * Источники: ENV контейнера `API_URL` → data-api-url на <html> (docker-entrypoint).
 * Пустое значение в браузере → тот же origin, что и панель (нужен прокси /api на nginx или Vite).
 */
export function resolveApiUrl(): string {
  if (typeof window !== "undefined") {
    const fromHtml = normalizeApiUrl(document.documentElement?.dataset?.apiUrl);
    if (fromHtml) return fromHtml;

    const legacy = normalizeApiUrl(window.__APP_CONFIG__?.API_URL);
    if (legacy) return legacy;

    if (window.location?.origin) return window.location.origin;
  }

  return FALLBACK_DIRECT_BACKEND;
}

export const API_URL = resolveApiUrl();
