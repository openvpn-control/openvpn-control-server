const DEV_DEFAULT_API_URL = "http://localhost:8080";

function normalizeApiUrl(url) {
  if (!url || typeof url !== "string") return "";
  return url.trim().replace(/\/+$/, "");
}

export function resolveApiUrl() {
  if (typeof window !== "undefined") {
    const runtime = normalizeApiUrl(window.__APP_CONFIG__?.API_URL);
    if (runtime) return runtime;

    const fromHtml = normalizeApiUrl(document.documentElement?.dataset?.apiUrl);
    if (fromHtml) return fromHtml;
  }

  const vite = normalizeApiUrl(import.meta.env.VITE_API_URL);
  if (vite) return vite;

  return DEV_DEFAULT_API_URL;
}

export const API_URL = resolveApiUrl();
