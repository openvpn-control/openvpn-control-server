// @ts-nocheck — постепенная типизация; сборка Vite не зависит от tsc.
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { parseAppRoute, paths } from "./appRoutes";
import {
  applyPanelDataPatch,
  fetchPanelDataKeys,
  panelDataFetchContext,
  panelDataKeysForRoute,
  panelDataPollIntervalMs,
  panelDataRouteKey,
  ALL_PANEL_DATA_KEYS,
  PANEL_DATA_REFRESH,
} from "./panelData";
import { DocumentationPage } from "./DocumentationPage";
import { OPENVPN_SERVER_SETTINGS_FIELDS } from "./openvpnServerSettingsMeta";
import { OPENVPN_CLIENT_SETTINGS_FIELDS } from "./openvpnClientSettingsMeta";
import MonitoringCharts from "./MonitoringCharts";
import { parseUtcMs } from "./monitoringTime";

const PANEL_ONLY_OPENVPN_KEYS = new Set([
  "panelRootCaId",
  "panelServerCertId",
  "panelDhMaterialId",
  "panelTlsAuthMaterialId",
  "remote",
  "resolv-retry",
  "nobind",
  "key-direction",
  "client-verb",
  "remote-cert-tls",
]);

const PANEL_SAVE_EXTRA_KEYS = [
  "panelRootCaId",
  "panelServerCertId",
  "panelDhMaterialId",
  "panelTlsAuthMaterialId",
];

const OPENVPN_SERVER_FORM_CLIENT_DIRECTIVES = new Set([
  "remote",
  "resolv-retry",
  "nobind",
  "key-direction",
  "remote-cert-tls",
  "client-verb",
]);
const OPENVPN_SERVER_FORM_SHARED_DIRECTIVES = new Set([
  "proto",
  "persist-key",
  "persist-tun",
  "data-ciphers-fallback",
  "comp-lzo",
  "mute",
]);
const PANEL_CLIENT_PROFILE_KEYS = [
  "remote",
  "resolv-retry",
  "nobind",
  "key-direction",
  "client-verb",
  "remote-cert-tls",
];

/** Default server.conf paths when linking panel root CA / server cert (sync tasks write these files). */
function openvpnCertPathsPartial(settings, { panelRootCaId, panelServerCertId } = {}) {
  const partial = {};
  if (panelRootCaId !== undefined) {
    partial.panelRootCaId = panelRootCaId;
    if (panelRootCaId) {
      if (!String(settings?.ca ?? "").trim()) partial.ca = "/etc/openvpn/ca.crt";
      if (!String(settings?.["crl-verify"] ?? "").trim()) partial["crl-verify"] = "/etc/openvpn/crl.pem";
    }
  }
  if (panelServerCertId !== undefined) {
    partial.panelServerCertId = panelServerCertId;
    if (panelServerCertId) {
      if (!String(settings?.cert ?? "").trim()) partial.cert = "/etc/openvpn/server.crt";
      if (!String(settings?.key ?? "").trim()) partial.key = "/etc/openvpn/server.key";
    }
  }
  return partial;
}

function buildOpenVpnPayloadForAgent(stateObj) {
  const out = { ...stateObj };
  for (const f of OPENVPN_SERVER_SETTINGS_FIELDS) {
    const k = f.key;
    if (f.type === "number") {
      const raw = out[k];
      if (raw === "" || raw === undefined || raw === null) {
        delete out[k];
        continue;
      }
      const n = Number(raw);
      if (Number.isFinite(n)) out[k] = n;
      else delete out[k];
      continue;
    }
    if (f.type === "textarea") {
      const raw = out[k];
      if (Array.isArray(raw)) {
        out[k] = raw.map((x) => String(x).trim()).filter(Boolean);
      } else {
        const s = String(raw || "");
        out[k] = s
          .split("\n")
          .map((x) => x.trim())
          .filter(Boolean);
      }
      continue;
    }
    if (f.type === "select" && (out[k] === "" || out[k] === undefined)) {
      delete out[k];
    }
  }
  for (const pk of PANEL_ONLY_OPENVPN_KEYS) {
    delete out[pk];
  }
  return out;
}

/** Сохранение на панели: директивы для агента + служебные поля панели. */
function buildOpenVpnSettingsForPanelSave(stateObj) {
  const base = buildOpenVpnPayloadForAgent(stateObj);
  for (const f of OPENVPN_SERVER_SETTINGS_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(stateObj, f.key)) continue;
    if (f.type === "number") {
      const raw = stateObj[f.key];
      if (raw === "" || raw === undefined || raw === null) {
        base[f.key] = "";
        continue;
      }
      const n = Number(raw);
      base[f.key] = Number.isFinite(n) ? n : "";
      continue;
    }
    if (f.type === "select") {
      const raw = stateObj[f.key];
      base[f.key] =
        raw === undefined || raw === null || raw === "" ? "" : String(raw).trim();
      continue;
    }
    if (f.type === "text") {
      const raw = stateObj[f.key];
      base[f.key] = raw === undefined || raw === null ? "" : String(raw).trim();
    }
  }
  for (const pk of PANEL_SAVE_EXTRA_KEYS) {
    if (Object.prototype.hasOwnProperty.call(stateObj, pk)) {
      const v = stateObj[pk];
      base[pk] = v === undefined || v === null ? "" : String(v);
    }
  }
  for (const k of PANEL_CLIENT_PROFILE_KEYS) {
    if (!Object.prototype.hasOwnProperty.call(stateObj, k)) continue;
    const v = stateObj[k];
    if (typeof v === "boolean") base[k] = v;
    else base[k] = v === undefined || v === null ? "" : String(v);
  }
  return base;
}

/** Построчное сравнение (как в Git): удаления — относительно файла на сервере, добавления — из черновика. */
function lineDiffLcs(oldStr, newStr) {
  const toLines = (v) => {
    const lines = String(v ?? "").replace(/\r\n/g, "\n").split("\n");
    while (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
    return lines;
  };
  const a = toLines(oldStr);
  const b = toLines(newStr);
  const m = a.length;
  const n = b.length;
  const dp = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (a[i - 1] === b[j - 1]) dp[i][j] = dp[i - 1][j - 1] + 1;
      else dp[i][j] = Math.max(dp[i - 1][j], dp[i][j - 1]);
    }
  }
  const out = [];
  let i = m;
  let j = n;
  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && a[i - 1] === b[j - 1]) {
      out.push({ type: "same", line: a[i - 1] });
      i--;
      j--;
    } else if (j > 0 && (i === 0 || dp[i][j - 1] >= dp[i - 1][j])) {
      out.push({ type: "add", line: b[j - 1] });
      j--;
    } else {
      out.push({ type: "del", line: a[i - 1] });
      i--;
    }
  }
  return out.reverse();
}

/** Текст нового server.conf из блока diff (строки «+» и без изменений, без «-»). */
function rawConfigFromServerSettingsDiff(diff) {
  if (!Array.isArray(diff) || diff.length === 0) return "";
  return diff
    .filter((d) => d && d.type !== "del")
    .map((d) => String(d.line ?? ""))
    .join("\n");
}

function fallbackRawFromSettings(settings) {
  const stripped = buildOpenVpnPayloadForAgent(settings || {});
  const payload = { ...stripped };
  for (const k of Object.keys(payload)) {
    if (String(k).startsWith("panel")) delete payload[k];
  }
  const lines = [];
  const preferredKeys = OPENVPN_SERVER_SETTINGS_FIELDS.map((f) => f.key);
  const payloadKeys = Object.keys(payload);
  const restKeys = payloadKeys
    .filter((k) => !preferredKeys.includes(k))
    .sort((a, b) => a.localeCompare(b, "ru"));
  const keys = [...preferredKeys.filter((k) => payloadKeys.includes(k)), ...restKeys];
  for (const key of keys) {
    const v = payload[key];
    if (v === undefined || v === null || v === "") continue;
    if (typeof v === "boolean") {
      if (v) lines.push(key);
      continue;
    }
    if (Array.isArray(v)) {
      for (const item of v) {
        const s = String(item || "").trim();
        if (!s) continue;
        if (key === "push" || key === "route") lines.push(`${key} "${s}"`);
        else lines.push(`${key} ${s}`);
      }
      continue;
    }
    lines.push(`${key} ${String(v).trim()}`);
  }
  return lines.join("\n");
}

function buildOpenVpnClientConfigPayload(stateObj) {
  const out = { ...stateObj };
  for (const f of OPENVPN_CLIENT_SETTINGS_FIELDS) {
    const k = f.key;
    if (f.type === "number") {
      const raw = out[k];
      if (raw === "" || raw === undefined || raw === null) {
        delete out[k];
        continue;
      }
      const n = Number(raw);
      if (Number.isFinite(n)) out[k] = String(Math.trunc(n));
      else delete out[k];
      continue;
    }
    if (f.type === "checkbox") {
      out[k] = Boolean(out[k]);
      continue;
    }
    const text = String(out[k] ?? "").trim();
    if (!text) delete out[k];
    else out[k] = text;
  }
  return out;
}

function fallbackRawFromClientSettings(settings, serverSettings) {
  const payload = buildOpenVpnClientConfigPayload(settings || {});
  const lines = [];
  lines.push(...fallbackServerDerivedClientLines(serverSettings));
  const serverDerivedKeys = new Set(["dev", "proto", "remote", "resolv-retry", "nobind", "key-direction"]);
  for (const f of OPENVPN_CLIENT_SETTINGS_FIELDS) {
    const key = f.key;
    if (serverDerivedKeys.has(key)) continue;
    if (!Object.prototype.hasOwnProperty.call(payload, key)) continue;
    const v = payload[key];
    if (typeof v === "boolean") {
      if (v) lines.push(key);
      continue;
    }
    lines.push(`${key} ${String(v)}`);
  }
  const s = serverSettings && typeof serverSettings === "object" && !Array.isArray(serverSettings) ? serverSettings : {};
  for (const key of ["data-ciphers", "data-ciphers-fallback", "auth", "remote-cert-tls"]) {
    if (serverDerivedKeys.has(key) || Object.prototype.hasOwnProperty.call(payload, key)) continue;
    const v = String(s[key] ?? "").trim();
    if (!v) continue;
    if (key === "remote-cert-tls") {
      lines.push(`${key} ${v === "client" ? "server" : v === "server" ? "client" : v || "server"}`);
      continue;
    }
    lines.push(`${key} ${v}`);
  }
  lines.push("", "<ca>", "{{ca}}", "</ca>", "");
  lines.push("<cert>", "{{cert}}", "</cert>", "");
  lines.push("<key>", "{{key}}", "</key>", "");
  lines.push("<tls-auth>", "{{tls_auth}}", "</tls-auth>", "");
  return lines.join("\n");
}

function normalizeClientDevFromServer(devRaw) {
  const v = String(devRaw || "").trim().toLowerCase();
  if (!v) return "tun";
  if (v.startsWith("tap")) return "tap";
  return "tun";
}

function fallbackServerDerivedClientLines(serverSettings) {
  const s = serverSettings && typeof serverSettings === "object" && !Array.isArray(serverSettings) ? serverSettings : {};
  const proto = String(s.proto || "").trim() || "{{proto}}";
  const remote = String(s.remote || "").trim() || "{{host}} {{port}}";
  const resolvRetry = String(s["resolv-retry"] || "").trim() || "infinite";
  const dev = normalizeClientDevFromServer(s.dev);
  const keyDirection = String(s["key-direction"] || "").trim() || "{{key_direction}}";
  const out = [];
  out.push(`dev ${dev}`);
  out.push(`proto ${proto}`);
  out.push(`remote ${remote}`);
  out.push(`resolv-retry ${resolvRetry}`);
  if (Boolean(s.nobind ?? true)) out.push("nobind");
  out.push(`key-direction ${keyDirection}`);
  return out;
}

import { API_URL } from "./apiConfig";
const TOKEN_STORAGE_KEY = "ovpn_control_admin_token";
const SESSION_INVALID_EVENT = "ovpn:session-invalid";

/** OpenVPN работает: management или служба systemd active/running. */
function isOpenvpnUp(server) {
  if (!server || typeof server !== "object") return false;
  if (server.openvpnRunning) return true;
  const active = String(server.openvpnServiceActiveState || "").trim().toLowerCase();
  const sub = String(server.openvpnServiceSubState || "").trim().toLowerCase();
  const pid = Number(server.openvpnServiceMainPid) || 0;
  return active === "active" && (sub === "running" || sub === "started" || pid > 0);
}

function openvpnStatusLabel(server) {
  if (!isOpenvpnUp(server)) return "Не работает";
  if (!server.openvpnRunning) {
    return "Работает (служба systemd, management недоступен)";
  }
  return "Работает";
}
const DISCONNECTING_SESSIONS_STORAGE_KEY = "ovpn:disconnecting-sessions";

function parseJwtPayload(token) {
  if (!token || typeof token !== "string") return null;
  try {
    const part = token.split(".")[1];
    if (!part) return null;
    const base64 = part.replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64 + "==".slice(0, (4 - (base64.length % 4)) % 4);
    return JSON.parse(atob(padded));
  } catch {
    return null;
  }
}

function readStoredTokenIfValid() {
  try {
    const t = localStorage.getItem(TOKEN_STORAGE_KEY);
    if (!t) return "";
    const payload = parseJwtPayload(t);
    const expSec = payload?.exp;
    if (!expSec || Date.now() >= expSec * 1000) {
      localStorage.removeItem(TOKEN_STORAGE_KEY);
      return "";
    }
    return t;
  } catch {
    return "";
  }
}

function normalizeAdminBlockConfirmInput(s) {
  return String(s ?? "").trim().replace(/\s+/g, " ");
}

function formatSessionCountdown(totalSeconds) {
  const s = Math.max(0, Math.floor(totalSeconds));
  const m = Math.floor(s / 60);
  const r = s % 60;
  return `${String(m).padStart(2, "0")}:${String(r).padStart(2, "0")}`;
}

function avatarInitials(name) {
  const trimmed = String(name || "").trim();
  if (!trimmed) return "?";
  const parts = trimmed.split(/\s+/);
  if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
  return trimmed.slice(0, 2).toUpperCase();
}

function normalizeIfaceLikeOpenvpnDev(raw) {
  const s = String(raw || "").trim();
  if (!s) return "";
  const l = s.toLowerCase();
  if (l === "tun") return "tun0";
  if (l === "tap") return "tap0";
  return s;
}

function parseHostFromAddr(raw) {
  const s = String(raw || "").trim();
  if (!s) return "";
  // host:port | http(s)://host:port | [ipv6]:port
  if (s.startsWith("http://") || s.startsWith("https://")) {
    try {
      return new URL(s).hostname || "";
    } catch {
      return "";
    }
  }
  const m = s.match(/^\[([^\]]+)\](?::\d+)?$/);
  if (m) return m[1];
  const parts = s.split(":");
  if (parts.length === 2 && /^\d+$/.test(parts[1])) return parts[0];
  return s;
}

function IconServers() {
  return (
    <svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" aria-hidden>
      <rect x="3" y="4" width="18" height="6" rx="1.5" />
      <rect x="3" y="14" width="18" height="6" rx="1.5" />
    </svg>
  );
}

function IconUsers() {
  return (
    <svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" aria-hidden>
      <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
      <circle cx="9" cy="7" r="4" />
      <path d="M23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75" />
    </svg>
  );
}

function IconSettings() {
  return (
    <svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" aria-hidden>
      <circle cx="12" cy="12" r="3" />
      <path d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72 1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42" />
    </svg>
  );
}

function IconDocumentation() {
  return (
    <svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" aria-hidden>
      <path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20" />
      <path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z" />
      <path d="M8 7h8M8 11h8" />
    </svg>
  );
}

function IconLogs() {
  return (
    <svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" aria-hidden>
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
      <path d="M14 2v6h6M16 13H8M16 17H8M10 9H8" />
    </svg>
  );
}

function IconTasks() {
  return (
    <svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" aria-hidden>
      <path d="M9 11l3 3L22 4" />
      <path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11" />
    </svg>
  );
}

function IconBackup() {
  return (
    <svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" aria-hidden>
      <ellipse cx="12" cy="5" rx="9" ry="3" />
      <path d="M3 5v14c0 1.7 4 3 9 3s9-1.3 9-3V5" />
      <path d="M3 12c0 1.7 4 3 9 3s9-1.3 9-3" />
    </svg>
  );
}

function IconRestore() {
  return (
    <svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" aria-hidden>
      <path d="M3 12a9 9 0 1 0 3-7.1" />
      <path d="M3 4v4h4" />
    </svg>
  );
}

function IconCa() {
  return (
    <svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" aria-hidden>
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <path d="M9 12l2 2 4-4" />
    </svg>
  );
}

function IconOrganizations() {
  return (
    <svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" aria-hidden>
      <path d="M3 21h18M5 21V7l8-4v18M19 21V11l-6-4M9 9v0M9 12v0M9 15v0M9 18v0" />
    </svg>
  );
}

function IconNavOrganizations() {
  return (
    <svg className="resource-nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" aria-hidden>
      <path d="M3 21h18M5 21V7l8-4v18M19 21V11l-6-4M9 9v0M9 12v0M9 15v0M9 18v0" />
    </svg>
  );
}

function IconNavOverview() {
  return (
    <svg className="resource-nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" aria-hidden>
      <rect x="3" y="3" width="7" height="9" rx="1.25" />
      <rect x="14" y="3" width="7" height="5" rx="1.25" />
      <rect x="14" y="11" width="7" height="10" rx="1.25" />
      <rect x="3" y="15" width="7" height="6" rx="1.25" />
    </svg>
  );
}

function IconNavMonitoring() {
  return (
    <svg className="resource-nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" aria-hidden>
      <path d="M3 3v18h18" />
      <path d="M7 16l4-4 3 3 5-6" />
    </svg>
  );
}

function IconNavSessions() {
  return (
    <svg className="resource-nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" aria-hidden>
      <circle cx="9" cy="7" r="4" />
      <path d="M17 11v6M14 14h6" />
      <path d="M3 21v-2a4 4 0 0 1 4-4h4" />
    </svg>
  );
}

function IconNavCertificate() {
  return (
    <svg className="resource-nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" aria-hidden>
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
      <path d="M14 2v6h6" />
      <path d="M12 18v-5M9 15h6" />
    </svg>
  );
}

function IconNavOperations() {
  return (
    <svg className="resource-nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" aria-hidden>
      <path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01" />
    </svg>
  );
}

function IconNavVpn() {
  return (
    <svg className="resource-nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" aria-hidden>
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  );
}

async function request(path, method = "GET", token, body) {
  let res;
  try {
    res = await fetch(`${API_URL}${path}`, {
      method,
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new Error("Ошибка сети: сервер недоступен или заблокирован браузером.");
  }

  if (res.status === 401 && token) {
    window.dispatchEvent(new Event(SESSION_INVALID_EVENT));
  }

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: "Ошибка запроса" }));
    const e = new Error(err.error || "Ошибка запроса");
    if (typeof err.retryAfterSeconds === "number") e.retryAfterSeconds = err.retryAfterSeconds;
    if (Array.isArray(err.hints)) e.hints = err.hints;
    if (typeof err.output === "string" && err.output) e.output = err.output;
    if (typeof err.command === "string" && err.command) e.command = err.command;
    if (typeof err.configPath === "string" && err.configPath) e.configPath = err.configPath;
    if (typeof err.serviceLog === "string" && err.serviceLog) e.serviceLog = err.serviceLog;
    if (typeof err.backupPath === "string" && err.backupPath) e.backupPath = err.backupPath;
    if (typeof err.rolledBack === "boolean") e.rolledBack = err.rolledBack;
    throw e;
  }
  if (res.status === 204) return null;
  return res.json();
}

async function downloadBackupArchive(apiUrl, token, backupId, fileName) {
  let res;
  try {
    res = await fetch(`${apiUrl}/api/panel/app-backups/archives/${encodeURIComponent(backupId)}/download`, {
      method: "GET",
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
  } catch {
    throw new Error("Ошибка сети: не удалось скачать архив (сервер недоступен или блокируется запрос).");
  }
  if (res.status === 401 && token) {
    window.dispatchEvent(new Event(SESSION_INVALID_EVENT));
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: "Ошибка скачивания" }));
    throw new Error(err.error || "Ошибка скачивания");
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  try {
    const a = document.createElement("a");
    a.href = url;
    a.download = fileName || `backup-${backupId}.zip`;
    a.rel = "noopener";
    document.body.appendChild(a);
    a.click();
    a.remove();
  } finally {
    URL.revokeObjectURL(url);
  }
}

function formatBytes(n) {
  const v = Number(n) || 0;
  if (v < 1024) return `${v} Б`;
  if (v < 1024 * 1024) return `${(v / 1024).toFixed(1)} КиБ`;
  return `${(v / (1024 * 1024)).toFixed(2)} МиБ`;
}

function formatBps(value) {
  const numeric = Number(value || 0);
  if (numeric < 1024) return `${numeric.toFixed(0)} B/s`;
  return `${(numeric / 1024).toFixed(1)} KB/s`;
}

function formatRateForChart(value) {
  const numeric = Math.max(Number(value || 0), 0);
  if (numeric < 1000) return `${numeric.toFixed(0)} Bps`;
  if (numeric < 1000 * 1000) return `${(numeric / 1000).toFixed(0)} kbps`;
  if (numeric < 1000 * 1000 * 1000) return `${(numeric / (1000 * 1000)).toFixed(1)} Mbps`;
  return `${(numeric / (1000 * 1000 * 1000)).toFixed(1)} Gbps`;
}

function emptyTableDrag() {
  return { scope: "", dragId: "", overId: "", placeAfter: false };
}

function reorderRowInList(list, dragId, targetId, placeAfter) {
  const dragIdStr = String(dragId ?? "");
  const targetIdStr = String(targetId ?? "");
  if (!dragIdStr || !targetIdStr) return Array.isArray(list) ? [...list] : [];

  if (dragIdStr === targetIdStr) {
    if (!placeAfter) return Array.isArray(list) ? [...list] : [];
    const arr = Array.isArray(list) ? [...list] : [];
    const origIdx = arr.findIndex((x) => String(x?.id ?? "") === dragIdStr);
    if (origIdx < 0) return arr;
    const item = arr[origIdx];
    const rest = arr.filter((x) => String(x?.id ?? "") !== dragIdStr);
    const insertAt = Math.min(origIdx + 1, rest.length);
    rest.splice(insertAt, 0, item);
    return rest;
  }

  const arr = Array.isArray(list) ? [...list] : [];
  const from = arr.findIndex((x) => String(x?.id ?? "") === dragIdStr);
  const targetIdx = arr.findIndex((x) => String(x?.id ?? "") === targetIdStr);
  if (from < 0 || targetIdx < 0) return Array.isArray(list) ? [...list] : [];

  const [item] = arr.splice(from, 1);
  let insertAt = targetIdx + (placeAfter ? 1 : 0);
  if (from < insertAt) insertAt -= 1;
  arr.splice(insertAt, 0, item);
  return arr;
}

let tableDragPreviewTeardown = null;

function endTableRowDragPreview() {
  if (typeof tableDragPreviewTeardown === "function") {
    try {
      tableDragPreviewTeardown();
    } catch (_) {
      /* ignore */
    }
    tableDragPreviewTeardown = null;
  }
}

function beginTableRowDragPreview(tr, e, dragIdForPayload) {
  endTableRowDragPreview();
  try {
    const dt = e?.dataTransfer;
    if (!tr || !dt || typeof tr.getBoundingClientRect !== "function") return;
    dt.effectAllowed = "move";
    try {
      dt.setData("text/plain", `row-reorder:${String(dragIdForPayload ?? "")}`);
    } catch (_) {
      /* ignore */
    }

    const rect = tr.getBoundingClientRect();
    if (rect.width < 2 || rect.height < 2) return;

    const w = Math.max(2, Math.round(rect.width));
    const rowH = Math.round(Math.max(rect.height, 28));

    const rowEl = tr.cloneNode(true);
    rowEl.removeAttribute("draggable");
    rowEl.classList.remove("app-table-row--drag-source", "app-table-row--drop-before", "app-table-row--drop-after");
    rowEl.querySelectorAll("[draggable]").forEach((el) => {
      el.removeAttribute("draggable");
    });

    const srcCells = tr.querySelectorAll(":scope > td, :scope > th");
    const dstCells = rowEl.querySelectorAll(":scope > td, :scope > th");
    const n = srcCells.length;
    if (n > 0 && dstCells.length === n) {
      const raw = [...srcCells].map((c) => Math.max(0, c.getBoundingClientRect().width));
      const sum = raw.reduce((a, b) => a + b, 0) || 1;
      const ideal = raw.map((rw) => (rw / sum) * w);
      let acc = 0;
      for (let i = 0; i < n - 1; i += 1) {
        const cw = Math.max(1, Math.floor(ideal[i]));
        dstCells[i].style.width = `${cw}px`;
        dstCells[i].style.maxWidth = `${cw}px`;
        dstCells[i].style.boxSizing = "border-box";
        acc += cw;
      }
      const lastW = Math.max(1, w - acc);
      dstCells[n - 1].style.width = `${lastW}px`;
      dstCells[n - 1].style.maxWidth = `${lastW}px`;
      dstCells[n - 1].style.boxSizing = "border-box";
    }

    const table = document.createElement("table");
    table.className = "app-table app-table--compact app-table-drag-float-table";
    table.style.width = `${w}px`;
    table.style.maxWidth = `${w}px`;
    table.style.tableLayout = "fixed";
    table.style.borderCollapse = "collapse";
    table.style.boxSizing = "border-box";

    const tbody = document.createElement("tbody");
    tbody.appendChild(rowEl);
    table.appendChild(tbody);

    const wrap = document.createElement("div");
    wrap.className = "app-table-drag-float";
    wrap.style.width = `${w}px`;
    wrap.style.maxWidth = `${w}px`;
    wrap.style.boxSizing = "border-box";
    wrap.style.overflow = "hidden";
    wrap.appendChild(table);
    document.body.appendChild(wrap);

    const pointer =
      e?.nativeEvent && typeof e.nativeEvent.clientX === "number" && typeof e.nativeEvent.clientY === "number"
        ? e.nativeEvent
        : e;
    const ox = Math.round(Math.max(0, Math.min(w, pointer.clientX - rect.left)));
    const oy = Math.round(Math.max(0, Math.min(rowH, pointer.clientY - rect.top)));

    const positionPreview = (ev) => {
      if (!ev || typeof ev.clientX !== "number" || typeof ev.clientY !== "number") return;
      wrap.style.transform = `translate(${Math.round(ev.clientX - ox)}px, ${Math.round(ev.clientY - oy)}px)`;
    };
    positionPreview(pointer);

    const onDragOverGlobal = (ev) => {
      ev.preventDefault();
      try {
        if (ev.dataTransfer) ev.dataTransfer.dropEffect = "move";
      } catch (_) {
        /* ignore */
      }
      positionPreview(ev);
    };
    document.addEventListener("dragover", onDragOverGlobal, true);

    const blank = document.createElement("canvas");
    blank.width = 1;
    blank.height = 1;
    try {
      dt.setDragImage(blank, 0, 0);
    } catch (_) {
      /* ignore */
    }

    tableDragPreviewTeardown = () => {
      document.removeEventListener("dragover", onDragOverGlobal, true);
      wrap.remove();
    };

    window.addEventListener(
      "dragend",
      () => {
        endTableRowDragPreview();
      },
      { once: true },
    );
  } catch (_) {
    /* ignore */
  }
}

function tableRowDragOverHandler(e, scope, ruleId, setTableDrag) {
  e.preventDefault();
  try {
    if (e.dataTransfer) e.dataTransfer.dropEffect = "move";
  } catch (_) {
    /* ignore */
  }
  let rowEl = e.currentTarget;
  if (!rowEl || typeof rowEl.getBoundingClientRect !== "function") {
    const t = e.target;
    if (t && typeof t.closest === "function") rowEl = t.closest("tr");
  }
  if (!rowEl || typeof rowEl.getBoundingClientRect !== "function") return;

  const rect = rowEl.getBoundingClientRect();
  const placeAfter = e.clientY > rect.top + rect.height / 2;
  const rid = ruleId;

  setTableDrag((prev) => {
    if (prev.scope !== scope || !prev.dragId) return prev;
    if (String(prev.overId) === String(rid) && prev.placeAfter === placeAfter) return prev;
    return { ...prev, overId: rid, placeAfter };
  });
}

function rowReorderClass(scope, ruleId, tableDrag) {
  if (tableDrag.scope !== scope || !tableDrag.dragId) return "";
  const idStr = String(ruleId ?? "");
  const cls = [];
  if (String(tableDrag.dragId) === idStr) cls.push("app-table-row--drag-source");
  if (String(tableDrag.overId) === idStr) {
    cls.push(tableDrag.placeAfter ? "app-table-row--drop-after" : "app-table-row--drop-before");
  }
  return cls.filter(Boolean).join(" ");
}

function dnsTypeLabel(type) {
  const t = String(type || "");
  if (t === "domain-resolver") return "Домен -> DNS";
  if (t === "cache") return "Кэширование";
  if (t === "ip-override") return "Подмена IP";
  if (t === "arbitrary-address") return "Произвольный адрес";
  if (t === "forward") return "Форвард";
  if (t === "hosts-file") return "Файл hosts";
  if (t === "listen-interface") return "Интерфейс";
  return t;
}

function parseDnsmasqConfigToDraft(raw) {
  const out = [];
  const lines = String(raw || "")
    .split(/\r?\n/)
    .map((x) => x.trim())
    .filter(Boolean);
  let seq = 1;
  for (const line of lines) {
    let m = line.match(/^server=\/([^/]+)\/(.+)$/);
    if (m) {
      out.push({ id: `dns-${seq++}`, type: "domain-resolver", domain: m[1], targetDns: m[2] });
      continue;
    }
    m = line.match(/^cache-size=(.+)$/);
    if (m) {
      out.push({ id: `dns-${seq++}`, type: "cache", cacheSize: m[1] });
      continue;
    }
    m = line.match(/^address=\/([^/]+)\/(.+)$/);
    if (m) {
      if (m[1] === "#") out.push({ id: `dns-${seq++}`, type: "arbitrary-address", ip: m[2] });
      else out.push({ id: `dns-${seq++}`, type: "ip-override", domain: m[1], ip: m[2] });
      continue;
    }
    m = line.match(/^server=(.+)$/);
    if (m) {
      out.push({ id: `dns-${seq++}`, type: "forward", targetDns: m[1] });
      continue;
    }
    m = line.match(/^(?:addn-hosts|hosts-file)=(.+)$/);
    if (m) {
      out.push({ id: `dns-${seq++}`, type: "hosts-file", path: m[1] });
      continue;
    }
    m = line.match(/^interface=(.+)$/);
    if (m) {
      out.push({ id: `dns-${seq++}`, type: "listen-interface", iface: m[1] });
      continue;
    }
  }
  return out;
}

function buildDnsmasqTextFromDraft(draft) {
  const rows = Array.isArray(draft) ? draft : [];
  const lines = [];
  for (const row of rows) {
    const type = String(row?.type || "");
    if (type === "domain-resolver") {
      const domain = String(row?.domain || "").trim();
      const target = String(row?.targetDns || "").trim();
      if (domain && target) lines.push(`server=/${domain}/${target}`);
    } else if (type === "cache") {
      const size = String(row?.cacheSize || "").trim();
      if (size) lines.push(`cache-size=${size}`);
    } else if (type === "ip-override") {
      const domain = String(row?.domain || "").trim();
      const ip = String(row?.ip || "").trim();
      if (domain && ip) lines.push(`address=/${domain}/${ip}`);
    } else if (type === "arbitrary-address") {
      const ip = String(row?.ip || "").trim();
      if (ip) lines.push(`address=/#/${ip}`);
    } else if (type === "forward") {
      const target = String(row?.targetDns || "").trim();
      if (target) lines.push(`server=${target}`);
    } else if (type === "hosts-file") {
      const path = String(row?.path || "").trim();
      if (path) lines.push(`addn-hosts=${path}`);
    } else if (type === "listen-interface") {
      const iface = String(row?.iface || "").trim();
      if (iface) lines.push(`interface=${iface}`);
    }
  }
  return lines.join("\n");
}

function mergeLiveMetricSamples(recentMetrics, live) {
  const sorted = [...(recentMetrics || [])].sort(
    (a, b) => parseUtcMs(a.createdAt) - parseUtcMs(b.createdAt),
  );
  const liveT = Date.now();
  const last = sorted[sorted.length - 1];
  if (last && Math.abs(parseUtcMs(last.createdAt) - liveT) < 800) {
    const copy = [...sorted];
    copy[copy.length - 1] = {
      ...last,
      createdAt: new Date(liveT).toISOString(),
      cpuPercent: live.cpuPercent,
      memoryPercent: live.memoryPercent,
      diskPercent: live.diskPercent,
      diskReadBps: live.diskReadBps,
      diskWriteBps: live.diskWriteBps,
      networkInBps: live.networkInBps,
      networkOutBps: live.networkOutBps,
    };
    return copy;
  }
  return [
    ...sorted,
    {
      createdAt: new Date(liveT).toISOString(),
      cpuPercent: live.cpuPercent,
      memoryPercent: live.memoryPercent,
      diskPercent: live.diskPercent,
      diskReadBps: live.diskReadBps,
      diskWriteBps: live.diskWriteBps,
      networkInBps: live.networkInBps,
      networkOutBps: live.networkOutBps,
    },
  ];
}

const RU_DATE_TITLE_OPTS = { dateStyle: "short", timeStyle: "medium" };

function formatMaybeDate(value) {
  if (!value) return "n/a";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString();
}

function formatDurationSeconds(totalSec) {
  if (totalSec == null || totalSec === undefined || !Number.isFinite(Number(totalSec))) return "—";
  const s = Math.max(0, Math.floor(Number(totalSec)));
  if (s < 60) return `${s} с`;
  const m = Math.floor(s / 60);
  const rs = s % 60;
  if (m < 60) return rs ? `${m} мин ${rs} с` : `${m} мин`;
  const h = Math.floor(m / 60);
  const rm = m % 60;
  return rm ? `${h} ч ${rm} мин` : `${h} ч`;
}

function dateMsOrZero(value) {
  if (!value) return 0;
  const t = new Date(value).getTime();
  return Number.isFinite(t) ? t : 0;
}

/** IPv4:порт или [IPv6]:порт → только IP (для отображения и поиска). */
function remoteAddrHostOnlyDisplay(addr) {
  const s = String(addr ?? "").trim();
  if (!s) return "";
  if (s.startsWith("[")) {
    const end = s.indexOf("]");
    if (end > 1) return s.slice(1, end);
  }
  const lastColon = s.lastIndexOf(":");
  if (lastColon > 0) {
    const tail = s.slice(lastColon + 1);
    if (/^\d{1,5}$/.test(tail)) {
      const host = s.slice(0, lastColon);
      if (host.includes(".")) return host;
    }
  }
  return s;
}

function clientIpAssignmentDurationSeconds(item) {
  const start = dateMsOrZero(item.firstSeenAt);
  if (!start) return null;
  if (item.endedAt) {
    return Math.max(0, Math.floor((dateMsOrZero(item.endedAt) - start) / 1000));
  }
  return Math.max(0, Math.floor((Date.now() - start) / 1000));
}

function clientSourceHistoryDurationSeconds(item) {
  if (item.endedAt != null && item.durationSeconds != null && Number.isFinite(Number(item.durationSeconds))) {
    return Math.max(0, Math.floor(Number(item.durationSeconds)));
  }
  const start = dateMsOrZero(item.firstSeenAt);
  if (!start) return null;
  if (item.endedAt) {
    return Math.max(0, Math.floor((dateMsOrZero(item.endedAt) - start) / 1000));
  }
  return Math.max(0, Math.floor((Date.now() - start) / 1000));
}

function sortRowsByLastSeenDesc(rows) {
  return [...rows].sort((a, b) => {
    const d = dateMsOrZero(b.lastSeenAt) - dateMsOrZero(a.lastSeenAt);
    if (d !== 0) return d;
    const d2 = dateMsOrZero(b.firstSeenAt) - dateMsOrZero(a.firstSeenAt);
    if (d2 !== 0) return d2;
    return String(a.id || "").localeCompare(String(b.id || ""), undefined, { sensitivity: "base" });
  });
}

function sortRowsByCreatedDesc(rows) {
  return [...rows].sort((a, b) => {
    const d = dateMsOrZero(b.createdAt) - dateMsOrZero(a.createdAt);
    if (d !== 0) return d;
    return String(a.id || "").localeCompare(String(b.id || ""), undefined, { sensitivity: "base" });
  });
}

function adminLogMethodClass(method) {
  const m = String(method || "").toUpperCase();
  if (m === "GET") return "admin-log-method admin-log-method--get";
  if (m === "POST") return "admin-log-method admin-log-method--post";
  if (m === "PUT" || m === "PATCH") return "admin-log-method admin-log-method--put";
  if (m === "DELETE") return "admin-log-method admin-log-method--delete";
  if (m === "HEAD" || m === "OPTIONS") return "admin-log-method admin-log-method--head";
  return "admin-log-method admin-log-method--other";
}

function adminLogStatusClass(statusCode) {
  const n = Number(statusCode);
  if (!Number.isFinite(n)) return "admin-log-status admin-log-status--other";
  if (n >= 200 && n < 300) return "admin-log-status admin-log-status--2xx";
  if (n >= 300 && n < 400) return "admin-log-status admin-log-status--3xx";
  if (n >= 400 && n < 500) return "admin-log-status admin-log-status--4xx";
  if (n >= 500) return "admin-log-status admin-log-status--5xx";
  return "admin-log-status admin-log-status--other";
}

/** RFC 5280 / PKIX extended key usage: человекочитаемое имя и OID в одной строке. */
const EKU_OID_LABEL = [
  ["1.3.6.1.5.5.7.3.1", "serverAuth"],
  ["1.3.6.1.5.5.7.3.2", "clientAuth"],
  ["1.3.6.1.5.5.7.3.3", "codeSigning"],
  ["1.3.6.1.5.5.7.3.4", "emailProtection"],
  ["1.3.6.1.5.5.7.3.8", "timeStamping"],
  ["1.3.6.1.5.5.7.3.9", "ocspSigning"],
];

const EKU_OID_BY_NAME_LOWER = Object.fromEntries(
  EKU_OID_LABEL.map(([oid, label]) => [label.toLowerCase(), oid]),
);

function formatEkuValue(value) {
  const raw = String(value || "").trim();
  if (!raw) return "";
  const lower = raw.toLowerCase();
  const byOid = EKU_OID_LABEL.find(([oid]) => oid.toLowerCase() === lower);
  if (byOid) {
    return `${byOid[1]} (${byOid[0]})`;
  }
  const oidFromName = EKU_OID_BY_NAME_LOWER[lower];
  if (oidFromName) {
    const label = EKU_OID_LABEL.find(([oid]) => oid === oidFromName)[1];
    return `${label} (${oidFromName})`;
  }
  return raw;
}

/** Оставшиеся полные сутки до даты (для лимита срока выпуска сертификата). */
function daysRemainingUntil(iso) {
  if (!iso) return 0;
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return 0;
  return Math.max(0, Math.ceil((t - Date.now()) / 86400000));
}

function formatExactRuDateTime(value) {
  if (value == null || value === "") return "";
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return date.toLocaleString("ru-RU", RU_DATE_TITLE_OPTS);
}

/** @returns {number|null} */
function parseSessionInstantMs(raw) {
  if (raw == null || raw === "") return null;
  if (typeof raw === "number" && Number.isFinite(raw)) {
    return raw > 1e12 ? raw : raw * 1000;
  }
  const s = String(raw).trim();
  if (!s) return null;
  if (/^\d+$/.test(s)) {
    const n = Number(s);
    if (!Number.isFinite(n)) return null;
    return n > 1e12 ? n : n * 1000;
  }
  const t = Date.parse(s);
  return Number.isNaN(t) ? null : t;
}

/** Длительность от 0 до ms (секунды … годы, до двух крупных единиц). */
function formatDurationRuFromMs(ms) {
  if (!Number.isFinite(ms) || ms < 0) return "—";
  let sec = Math.floor(ms / 1000);
  const Y = 31536000;
  const MO = 2592000;
  const D = 86400;
  const H = 3600;
  const M = 60;
  if (sec >= Y) {
    const y = Math.floor(sec / Y);
    sec %= Y;
    const mo = Math.floor(sec / MO);
    return mo ? `${y} г. ${mo} мес.` : `${y} г.`;
  }
  if (sec >= MO) {
    const mo = Math.floor(sec / MO);
    sec %= MO;
    const d = Math.floor(sec / D);
    return d ? `${mo} мес. ${d} дн.` : `${mo} мес.`;
  }
  if (sec >= D) {
    const d = Math.floor(sec / D);
    sec %= D;
    const h = Math.floor(sec / H);
    return h ? `${d} дн. ${h} ч.` : `${d} дн.`;
  }
  if (sec >= H) {
    const h = Math.floor(sec / H);
    sec %= H;
    const m = Math.floor(sec / M);
    return m ? `${h} ч. ${m} мин.` : `${h} ч.`;
  }
  if (sec >= M) {
    const m = Math.floor(sec / M);
    sec %= M;
    return sec ? `${m} мин. ${sec} с` : `${m} мин.`;
  }
  return `${sec} с`;
}

function formatSessionConnectedLabel(raw, nowMs) {
  const start = parseSessionInstantMs(raw);
  if (start == null) return "—";
  return formatDurationRuFromMs(Math.max(0, nowMs - start));
}

function formatSessionConnectedTitle(raw) {
  const start = parseSessionInstantMs(raw);
  if (start == null) return undefined;
  const t = formatExactRuDateTime(start);
  return t || undefined;
}

function uint8ArrayToBase64(bytes) {
  let binary = "";
  const chunk = 8192;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

function readFileAsArrayBufferWithProgress(file, onProgress) {
  return new Promise((resolve, reject) => {
    const fr = new FileReader();
    fr.onprogress = (e) => {
      if (e.lengthComputable && e.total > 0) {
        onProgress(Math.min(0.98, e.loaded / e.total));
      }
    };
    fr.onload = () => {
      onProgress(1);
      resolve(fr.result);
    };
    fr.onerror = () => reject(fr.error || new Error("Ошибка чтения файла"));
    fr.readAsArrayBuffer(file);
  });
}

async function fileToBase64AndSha256(file, onProgress) {
  const buf = onProgress
    ? await readFileAsArrayBufferWithProgress(file, (p) => onProgress(p * 0.88))
    : await file.arrayBuffer();
  const bytes = new Uint8Array(buf);
  onProgress?.(0.92);
  const hashBuf = await crypto.subtle.digest("SHA-256", bytes);
  const hashHex = [...new Uint8Array(hashBuf)].map((b) => b.toString(16).padStart(2, "0")).join("");
  onProgress?.(0.97);
  const base64 = uint8ArrayToBase64(bytes);
  onProgress?.(1);
  return { base64, sha256: hashHex };
}

function postJsonWithUploadProgress(path, token, body, onUploadProgress) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const xhr = new XMLHttpRequest();
    /** 0–1; не отражает только сокет до панели — тело часто буферизуется и «100% upload» приходит мгновенно, пока панель ещё шлёт на агента. */
    const bump = (x) => {
      if (typeof onUploadProgress === "function") {
        onUploadProgress(Math.max(0, Math.min(1, x)));
      }
    };

    xhr.upload.onloadstart = () => bump(0.04);

    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable && e.total > 0) {
        const raw = e.loaded / e.total;
        bump(Math.min(0.68, raw * 0.68));
      }
    };

    xhr.upload.onloadend = () => {
      if (xhr.readyState !== XMLHttpRequest.DONE) {
        bump(0.76);
      }
    };

    xhr.onreadystatechange = () => {
      if (xhr.readyState === XMLHttpRequest.HEADERS_RECEIVED) bump(0.84);
      else if (xhr.readyState === XMLHttpRequest.LOADING) bump(0.91);
    };

    xhr.open("POST", `${API_URL}${path}`);
    xhr.setRequestHeader("Content-Type", "application/json");
    if (token) xhr.setRequestHeader("Authorization", `Bearer ${token}`);

    xhr.onload = () => {
      let parsed = {};
      try {
        parsed = xhr.responseText ? JSON.parse(xhr.responseText) : {};
      } catch {
        parsed = { error: xhr.responseText || "Некорректный ответ сервера" };
      }
      if (xhr.status === 401 && token) {
        window.dispatchEvent(new Event(SESSION_INVALID_EVENT));
      }
      if (xhr.status >= 400) {
        const err = new Error(parsed.error || xhr.statusText || "Ошибка запроса");
        if (typeof parsed.output === "string") err.output = parsed.output;
        reject(err);
        return;
      }
      bump(1);
      resolve(parsed);
    };
    xhr.onerror = () => reject(new Error("Сеть: запрос не выполнен"));
    xhr.send(payload);
  });
}

function formatUserSessionEndedLabel(row) {
  const start = parseSessionInstantMs(row.connectedAt);
  const endRaw = row.endedAt || row.lastSeenAt;
  const endMs = endRaw ? new Date(endRaw).getTime() : NaN;
  if (start == null || Number.isNaN(endMs)) return "—";
  return `завершена · ${formatDurationRuFromMs(Math.max(0, endMs - start))}`;
}

function formatUserSessionEndedTitle(row) {
  const start = parseSessionInstantMs(row.connectedAt);
  const endRaw = row.endedAt || row.lastSeenAt;
  const parts = [];
  const startLabel = start != null ? formatExactRuDateTime(start) : "";
  if (startLabel) parts.push(`Начало: ${startLabel}`);
  const endLabel = endRaw ? formatExactRuDateTime(endRaw) : "";
  if (endLabel) parts.push(`Окончание: ${endLabel}`);
  return parts.length ? parts.join(" · ") : undefined;
}

/** Как у агента: id = CommonName|ConnectedSince(time_t). */
function openvpnSessionIdParts(sessionId) {
  const raw = String(sessionId || "").trim();
  if (!raw) return { commonName: "—", sessionNumber: "—" };
  const i = raw.indexOf("|");
  if (i === -1) return { commonName: raw, sessionNumber: raw };
  const cn = raw.slice(0, i).trim() || "—";
  const num = raw.slice(i + 1).trim() || "—";
  return { commonName: cn, sessionNumber: num };
}

function formatUserLastActivityCell(user, nowMs) {
  if (user.activeSessions > 0) {
    return { label: "онлайн", title: "Есть активные VPN-сессии" };
  }
  const raw = user.lastVpnActivityAt;
  if (!raw) {
    return { label: "—", title: undefined };
  }
  const end = new Date(raw).getTime();
  if (Number.isNaN(end)) {
    return { label: "—", title: undefined };
  }
  return {
    label: `${formatDurationRuFromMs(Math.max(0, nowMs - end))} назад`,
    title: formatExactRuDateTime(raw) || undefined,
  };
}

const TABLE_PAGE_SIZE = 25;

function sliceTablePage(items, page) {
  const list = Array.isArray(items) ? items : [];
  const total = list.length;
  const totalPages = Math.max(1, Math.ceil(total / TABLE_PAGE_SIZE));
  const p = Math.min(Math.max(1, page), totalPages);
  const start = (p - 1) * TABLE_PAGE_SIZE;
  return { slice: list.slice(start, start + TABLE_PAGE_SIZE), total, totalPages, page: p };
}

function TablePagination({ page, totalPages, total, onPageChange }) {
  if (total <= 0) return null;
  const from = (page - 1) * TABLE_PAGE_SIZE + 1;
  const to = Math.min(page * TABLE_PAGE_SIZE, total);
  return (
    <div className="app-table-pagination" role="navigation" aria-label="Страницы таблицы">
      <span className="muted">
        {from}–{to} из {total} · по {TABLE_PAGE_SIZE} на странице
      </span>
      <div className="app-table-pagination-actions">
        <button type="button" className="btn-pagination" disabled={page <= 1} onClick={() => onPageChange(page - 1)}>
          Назад
        </button>
        <span className="muted">
          {page} / {totalPages}
        </span>
        <button type="button" className="btn-pagination" disabled={page >= totalPages} onClick={() => onPageChange(page + 1)}>
          Вперёд
        </button>
      </div>
    </div>
  );
}

function sidebarRailClass(active) {
  return active ? "sidebar-rail-btn is-active" : "sidebar-rail-btn";
}

/** Подпись и значение отпечатка по полю certificateSignatureHash из material-summary. */
function panelCertFingerprintRow(data) {
  if (!data) return { label: "Отпечаток (SHA-256)", value: "—" };
  const h = String(data.certificateSignatureHash || "sha256").toLowerCase();
  if (h === "sha512") {
    return {
      label: "Отпечаток (SHA-512)",
      value: data.fingerprintSha512 || data.fingerprintSha256 || "—",
    };
  }
  if (h === "sha384") {
    return {
      label: "Отпечаток (SHA-384)",
      value: data.fingerprintSha384 || data.fingerprintSha256 || "—",
    };
  }
  if (h === "sha1") {
    return { label: "Отпечаток (SHA-1)", value: data.fingerprintSha1 || "—" };
  }
  return { label: "Отпечаток (SHA-256)", value: data.fingerprintSha256 || "—" };
}

/** Текст и признак «ещё действует» по ISO-дате окончания (validTo / expiresAt). */
function panelCertValidityPresentation(validToIso) {
  if (!validToIso) return { active: false, text: "Просрочен" };
  const t = new Date(validToIso).getTime();
  if (Number.isNaN(t)) return { active: false, text: "Просрочен" };
  if (t > Date.now()) return { active: true, text: "Действующий" };
  return { active: false, text: "Просрочен" };
}

/** Статус строки в таблице сертификатов пользователя: отзыв, затем срок. */
function userCertRowStatusPresentation(cert) {
  if (cert.revokedAt) return { text: "Отозван", statusClass: "app-status app-status--off" };
  const v = panelCertValidityPresentation(cert.expiresAt);
  return {
    text: v.text,
    statusClass: v.active ? "app-status app-status--ok" : "app-status app-status--bad",
  };
}

/** Ссылка «Скачать» конфиг: пара PEM в БД, срок не истёк, не отозван, есть узел для профиля. */
function userCertCanShowConfigDownload(cert) {
  if (cert.revokedAt) return false;
  const v = panelCertValidityPresentation(cert.expiresAt);
  if (!v.active) return false;
  const hasPair = Boolean(
    cert.hasKeyMaterial ?? (cert.hasCertPem && cert.hasKeyPem),
  );
  if (!hasPair) return false;
  if (!String(cert.agentNodeId || "").trim()) return false;
  return true;
}

function ServerPanelCertificateSummaryTable({ cert, summary }) {
  const fp = panelCertFingerprintRow(summary);
  const mat = summary || {};
  const validToIso = mat.validTo || cert.expiresAt;
  const validity = panelCertValidityPresentation(validToIso);
  return (
    <div style={{ marginTop: 16 }}>
      <div className="app-table-scroll">
        <table className="app-table app-table--compact server-root-ca-summary">
          <tbody>
            <tr>
              <th scope="row" className="app-table-nowrap">
                Common Name
              </th>
              <td className="app-table-mono">{cert.commonName || "—"}</td>
            </tr>
            <tr>
              <th scope="row" className="app-table-nowrap">
                {fp.label}
              </th>
              <td className="app-table-mono">{fp.value}</td>
            </tr>
            <tr>
              <th scope="row" className="app-table-nowrap">
                Серийный номер
              </th>
              <td className="app-table-mono">{mat.serialNumber || "—"}</td>
            </tr>
            <tr>
              <th scope="row" className="app-table-nowrap">
                Алгоритм ключа
              </th>
              <td>
                {mat.algorithm || "—"}
                {mat.keySize ? ` · ${mat.keySize} бит` : ""}
              </td>
            </tr>
            <tr>
              <th scope="row" className="app-table-nowrap">
                Действителен до
              </th>
              <td className="app-table-nowrap">{formatMaybeDate(validToIso)}</td>
            </tr>
            <tr>
              <th scope="row" className="app-table-nowrap">
                Состояние
              </th>
              <td>
                <span
                  style={{
                    fontWeight: 600,
                    color: validity.active ? "#1a7f37" : "#c62828",
                  }}
                >
                  {validity.text}
                </span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  );
}

function OpenvpnPanelMaterialSummaryTable({ material }) {
  const kindRu =
    material.kind === "tls_auth"
      ? "Статический ключ TLS-auth (OpenVPN)"
      : material.kind === "dh"
        ? "Параметры DH (Diffie–Hellman)"
        : String(material.kind || "—");
  const fp = material.fingerprintSha256 || "—";
  const size =
    typeof material.sizeBytes === "number" && Number.isFinite(material.sizeBytes)
      ? String(material.sizeBytes)
      : "—";
  return (
    <div style={{ marginTop: 16 }}>
      <div className="app-table-scroll">
        <table className="app-table app-table--compact server-root-ca-summary">
          <tbody>
            <tr>
              <th scope="row" className="app-table-nowrap">
                Тип
              </th>
              <td>{kindRu}</td>
            </tr>
            <tr>
              <th scope="row" className="app-table-nowrap">
                Создан в панели
              </th>
              <td className="app-table-nowrap">{formatMaybeDate(material.createdAt)}</td>
            </tr>
            <tr>
              <th scope="row" className="app-table-nowrap">
                Отпечаток SHA-256 (PEM)
              </th>
              <td className="app-table-mono">{fp}</td>
            </tr>
            <tr>
              <th scope="row" className="app-table-nowrap">
                Размер, байт
              </th>
              <td className="app-table-mono">{size}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  );
}

function AdminPasswordResetAccept({ apiUrl, token }) {
  const navigate = useNavigate();
  const [preview, setPreview] = useState(null);
  const [loadError, setLoadError] = useState("");
  const [password, setPassword] = useState("");
  const [password2, setPassword2] = useState("");
  const [submitError, setSubmitError] = useState("");
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const t = String(token || "").trim();
    if (!t) {
      setLoadError("Ссылка недействительна (нет токена).");
      return undefined;
    }
    void (async () => {
      try {
        const res = await fetch(`${apiUrl}/api/admin-password-reset?token=${encodeURIComponent(t)}`);
        const body = await res.json().catch(() => ({}));
        if (cancelled) return;
        if (!res.ok) {
          setLoadError(typeof body.error === "string" ? body.error : "Не удалось загрузить форму сброса пароля");
          return;
        }
        setPreview(body);
      } catch (e) {
        if (!cancelled) setLoadError(e instanceof Error ? e.message : "Ошибка сети");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [apiUrl, token]);

  const submit = async (e) => {
    e.preventDefault();
    setSubmitError("");
    if (password.length < 8) {
      setSubmitError("Пароль не короче 8 символов");
      return;
    }
    if (password !== password2) {
      setSubmitError("Пароли не совпадают");
      return;
    }
    setBusy(true);
    try {
      const res = await fetch(`${apiUrl}/api/admin-password-reset/complete`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: String(token || "").trim(), password }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        setSubmitError(typeof body.error === "string" ? body.error : "Не удалось сохранить пароль");
        return;
      }
      setDone(true);
    } catch (err) {
      setSubmitError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="auth-shell">
      <div className="auth-inner">
        {done ? (
          <div className="auth-card auth-card--center">
            <div className="auth-success-icon" aria-hidden="true">
              ✓
            </div>
            <h2 className="auth-card-title">Пароль обновлён</h2>
            <p className="auth-success-text">Теперь можно войти в панель с новым паролем.</p>
            <button type="button" className="auth-submit btn-app-primary" onClick={() => navigate(paths.home(), { replace: true })}>
              На страницу входа
            </button>
          </div>
        ) : loadError ? (
          <div className="auth-card">
            <h2 className="auth-card-title">Ссылка недействительна</h2>
            <p className="auth-card-subtitle" style={{ marginBottom: 0 }}>
              Запросите у администратора панели новую ссылку для сброса пароля.
            </p>
            <div className="auth-alert auth-alert--error" style={{ marginTop: 20 }} role="alert">
              {loadError}
            </div>
            <button type="button" className="auth-btn-secondary" style={{ marginTop: 20 }} onClick={() => navigate(paths.home(), { replace: true })}>
              На страницу входа
            </button>
          </div>
        ) : !preview ? (
          <div className="auth-card auth-card--center">
            <div className="auth-loading-panel">
              <div className="auth-spinner" role="status" aria-label="Загрузка" />
              <p className="auth-loading-text">Загрузка…</p>
            </div>
          </div>
        ) : (
          <div className="auth-card">
            <h2 className="auth-card-title">Сброс пароля администратора</h2>
            <p className="auth-card-subtitle">Учётная запись: {preview.username || "—"}. Задайте новый пароль для входа в панель.</p>
            <form className="auth-form" onSubmit={submit}>
              <p className="auth-section-label">Данные учётной записи</p>
              <div className="auth-readonly-block">
                <div className="auth-readonly-heading">ФИО</div>
                <div className="auth-readonly-value">{preview.fullName || "—"}</div>
              </div>
              <div className="auth-readonly-block">
                <div className="auth-readonly-heading">Аккаунт</div>
                <div className="auth-readonly-value app-table-mono">{preview.username || "—"}</div>
              </div>
              <div className="auth-readonly-block">
                <div className="auth-readonly-heading">Электронная почта</div>
                <div className="auth-readonly-value">{preview.email || "—"}</div>
              </div>
              <p className="auth-section-label">Новый пароль</p>
              <div className="auth-field">
                <label className="auth-label" htmlFor="reset-admin-password">
                  Пароль
                </label>
                <input
                  id="reset-admin-password"
                  className="auth-input"
                  type="password"
                  autoComplete="new-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  disabled={busy}
                  placeholder="Не менее 8 символов"
                />
              </div>
              <div className="auth-field">
                <label className="auth-label" htmlFor="reset-admin-password2">
                  Пароль ещё раз
                </label>
                <input
                  id="reset-admin-password2"
                  className="auth-input"
                  type="password"
                  autoComplete="new-password"
                  value={password2}
                  onChange={(e) => setPassword2(e.target.value)}
                  disabled={busy}
                  placeholder="Повторите пароль"
                />
              </div>
              {submitError ? (
                <div className="auth-alert auth-alert--error" role="alert">
                  {submitError}
                </div>
              ) : null}
              <button type="submit" className="auth-submit btn-app-primary" disabled={busy}>
                {busy ? "Сохранение…" : "Сохранить пароль"}
              </button>
            </form>
          </div>
        )}
        <p className="auth-footer-note">Если вы не запрашивали сброс пароля, закройте страницу.</p>
      </div>
    </main>
  );
}

function AdminInviteAccept({ apiUrl, token }) {
  const navigate = useNavigate();
  const [preview, setPreview] = useState(null);
  const [loadError, setLoadError] = useState("");
  const [password, setPassword] = useState("");
  const [password2, setPassword2] = useState("");
  const [submitError, setSubmitError] = useState("");
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const t = String(token || "").trim();
    if (!t) {
      setLoadError("Ссылка приглашения недействительна (нет токена).");
      return undefined;
    }
    void (async () => {
      try {
        const res = await fetch(`${apiUrl}/api/admin-invite?token=${encodeURIComponent(t)}`);
        const body = await res.json().catch(() => ({}));
        if (cancelled) return;
        if (!res.ok) {
          setLoadError(typeof body.error === "string" ? body.error : "Не удалось загрузить приглашение");
          return;
        }
        setPreview(body);
      } catch (e) {
        if (!cancelled) setLoadError(e instanceof Error ? e.message : "Ошибка сети");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [apiUrl, token]);

  const submit = async (e) => {
    e.preventDefault();
    setSubmitError("");
    if (password.length < 8) {
      setSubmitError("Пароль не короче 8 символов");
      return;
    }
    if (password !== password2) {
      setSubmitError("Пароли не совпадают");
      return;
    }
    setBusy(true);
    try {
      const res = await fetch(`${apiUrl}/api/admin-invite/complete`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: String(token || "").trim(), password }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        setSubmitError(typeof body.error === "string" ? body.error : "Не удалось сохранить пароль");
        return;
      }
      setDone(true);
    } catch (err) {
      setSubmitError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="auth-shell">
      <div className="auth-inner">
        {done ? (
          <div className="auth-card auth-card--center">
            <div className="auth-success-icon" aria-hidden="true">
              ✓
            </div>
            <h2 className="auth-card-title">Регистрация завершена</h2>
            <p className="auth-success-text">Пароль установлен. Теперь можно войти в панель управления.</p>
            <button type="button" className="auth-submit btn-app-primary" onClick={() => navigate(paths.home(), { replace: true })}>
              На страницу входа
            </button>
          </div>
        ) : loadError ? (
          <div className="auth-card">
            <h2 className="auth-card-title">Приглашение недоступно</h2>
            <p className="auth-card-subtitle" style={{ marginBottom: 0 }}>
              Ссылка могла устареть или уже была использована. Попросите администратора отправить новое приглашение.
            </p>
            <div className="auth-alert auth-alert--error" style={{ marginTop: 20 }} role="alert">
              {loadError}
            </div>
            <button type="button" className="auth-btn-secondary" style={{ marginTop: 20 }} onClick={() => navigate(paths.home(), { replace: true })}>
              На страницу входа
            </button>
          </div>
        ) : !preview ? (
          <div className="auth-card auth-card--center">
            <div className="auth-loading-panel">
              <div className="auth-spinner" role="status" aria-label="Загрузка приглашения" />
              <p className="auth-loading-text">Загрузка приглашения…</p>
            </div>
          </div>
        ) : (
          <div className="auth-card">
            <h2 className="auth-card-title">Регистрация администратора</h2>
            <p className="auth-card-subtitle">Проверьте данные учётной записи и задайте пароль для входа в панель.</p>
            <form className="auth-form" onSubmit={submit}>
              <p className="auth-section-label">Данные учётной записи</p>
              <div className="auth-readonly-block">
                <div className="auth-readonly-heading">ФИО</div>
                <div className="auth-readonly-value">{preview.fullName || "—"}</div>
              </div>
              <div className="auth-readonly-block">
                <div className="auth-readonly-heading">Аккаунт</div>
                <div className="auth-readonly-value app-table-mono">{preview.username || "—"}</div>
              </div>
              <div className="auth-readonly-block">
                <div className="auth-readonly-heading">Электронная почта</div>
                <div className="auth-readonly-value">{preview.email || "—"}</div>
              </div>
              <p className="auth-section-label">Пароль для входа</p>
              <div className="auth-field">
                <label className="auth-label" htmlFor="invite-password">
                  Пароль
                </label>
                <input
                  id="invite-password"
                  className="auth-input"
                  type="password"
                  autoComplete="new-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  disabled={busy}
                  placeholder="Не менее 8 символов"
                />
              </div>
              <div className="auth-field">
                <label className="auth-label" htmlFor="invite-password2">
                  Пароль ещё раз
                </label>
                <input
                  id="invite-password2"
                  className="auth-input"
                  type="password"
                  autoComplete="new-password"
                  value={password2}
                  onChange={(e) => setPassword2(e.target.value)}
                  disabled={busy}
                  placeholder="Повторите пароль"
                />
              </div>
              {submitError ? (
                <div className="auth-alert auth-alert--error" role="alert">
                  {submitError}
                </div>
              ) : null}
              <button type="submit" className="auth-submit btn-app-primary" disabled={busy}>
                {busy ? "Сохранение…" : "Установить пароль и завершить"}
              </button>
            </form>
          </div>
        )}
        <p className="auth-footer-note">Приглашение действует ограниченное время. Не пересылайте ссылку посторонним.</p>
      </div>
    </main>
  );
}

export default function App() {
  const [token, setToken] = useState(() => readStoredTokenIfValid());
  const [sessionNow, setSessionNow] = useState(() => Date.now());
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("admin123");
  const [error, setError] = useState("");
  const [mfaModalOpen, setMfaModalOpen] = useState(false);
  const [mfaPendingToken, setMfaPendingToken] = useState("");
  const [mfaTotpCode, setMfaTotpCode] = useState("");
  const [mfaRecoveryCode, setMfaRecoveryCode] = useState("");
  const [mfaError, setMfaError] = useState("");
  const [mfaBusy, setMfaBusy] = useState(false);
  const [myAdminProfile, setMyAdminProfile] = useState(null);
  const [myAdminProfileLoading, setMyAdminProfileLoading] = useState(false);
  const [myAdminPasswordDraft, setMyAdminPasswordDraft] = useState({ currentPassword: "", newPassword: "", confirmPassword: "" });
  const [myAdminPasswordBusy, setMyAdminPasswordBusy] = useState(false);
  const [myAdminPasswordError, setMyAdminPasswordError] = useState("");
  const [myAdminTotpSetup, setMyAdminTotpSetup] = useState({
    loading: false,
    qrDataUrl: "",
    manualSecret: "",
    expiresAt: "",
    code: "",
    error: "",
    busy: false,
  });
  const [myAdminTotpDisableCode, setMyAdminTotpDisableCode] = useState("");
  const [myAdminTotpDisableBusy, setMyAdminTotpDisableBusy] = useState(false);
  const [myAdminTotpDisableError, setMyAdminTotpDisableError] = useState("");
  const [myAdminRecoveryCodesDisplay, setMyAdminRecoveryCodesDisplay] = useState(null);
  const [myAdminRecoveryRegenerateCode, setMyAdminRecoveryRegenerateCode] = useState("");
  const [myAdminRecoveryRegenerateBusy, setMyAdminRecoveryRegenerateBusy] = useState(false);
  const [myAdminRecoveryRegenerateError, setMyAdminRecoveryRegenerateError] = useState("");
  const [myAdminPasswordModalOpen, setMyAdminPasswordModalOpen] = useState(false);
  const [myAdminTotpSetupModalOpen, setMyAdminTotpSetupModalOpen] = useState(false);
  const [myAdminTotpDisableModalOpen, setMyAdminTotpDisableModalOpen] = useState(false);
  const [myAdminRecoveryModalOpen, setMyAdminRecoveryModalOpen] = useState(false);
  const [overview, setOverview] = useState(null);
  const [admins, setAdmins] = useState([]);
  const [nodes, setNodes] = useState([]);
  const [certificates, setCertificates] = useState([]);
  const [rootCAs, setRootCAs] = useState([]);
  const [clients, setClients] = useState([]);
  const [ipHistory, setIpHistory] = useState([]);
  const [sourceIpHistory, setSourceIpHistory] = useState([]);
  const [newAdmin, setNewAdmin] = useState({ fullName: "", username: "", email: "" });
  const [addAdminModalOpen, setAddAdminModalOpen] = useState(false);
  const [addAdminBusy, setAddAdminBusy] = useState(false);
  const [addAdminError, setAddAdminError] = useState("");
  const [addAdminInviteResult, setAddAdminInviteResult] = useState(null);
  const [adminDetailStatusBusy, setAdminDetailStatusBusy] = useState(false);
  const [adminDetailStatusError, setAdminDetailStatusError] = useState("");
  const [adminBlockModal, setAdminBlockModal] = useState({
    open: false,
    adminId: "",
    expectedNormalized: "",
    confirmByFullName: true,
    confirmInput: "",
    busy: false,
    validationError: "",
    error: "",
  });
  const [adminProfileDraft, setAdminProfileDraft] = useState({ fullName: "", username: "", email: "" });
  const [adminProfileSaving, setAdminProfileSaving] = useState(false);
  const [adminProfileFieldError, setAdminProfileFieldError] = useState("");
  const [adminPasswordResetModal, setAdminPasswordResetModal] = useState({
    open: false,
    resetUrl: "",
    busy: false,
    error: "",
  });
  const [panelBackupsData, setPanelBackupsData] = useState({ settings: null, backups: [] });
  const [panelBackupsLoading, setPanelBackupsLoading] = useState(false);
  const [panelBackupsSaving, setPanelBackupsSaving] = useState(false);
  const [panelBackupsRunBusy, setPanelBackupsRunBusy] = useState(false);
  const [panelBackupDeleteModal, setPanelBackupDeleteModal] = useState({
    open: false,
    backupId: "",
    fileName: "",
    busy: false,
    error: "",
  });
  const [backupFormInterval, setBackupFormInterval] = useState(0);
  const [backupFormRetain, setBackupFormRetain] = useState(10);
  const [restoreFile, setRestoreFile] = useState(null);
  const [restoreConfirm, setRestoreConfirm] = useState(false);
  const [restoreBusy, setRestoreBusy] = useState(false);
  const [restoreMessage, setRestoreMessage] = useState("");
  const [newNode, setNewNode] = useState({ name: "", protocol: "http", host: "", port: "9443", authToken: "" });
  const [serverAgentDraft, setServerAgentDraft] = useState({
    name: "",
    protocol: "http",
    host: "",
    port: "",
    authToken: "",
  });
  const [newRootCA, setNewRootCA] = useState({
    name: "",
    commonName: "",
    days: "3650",
    keySize: "4096",
    signatureAlgorithm: "sha256",
  });
  const [importRootCA, setImportRootCA] = useState({
    name: "",
    commonName: "",
    certPem: "",
    keyPem: "",
    issuedListText: "",
    revokedListText: "",
  });
  const [caImportMessage, setCaImportMessage] = useState("");
  const [newUserCert, setNewUserCert] = useState({ vpnUserId: "", commonName: "", rootCaId: "", validityDays: "365" });
  const [vpnUsers, setVpnUsers] = useState([]);
  const [newVpnUser, setNewVpnUser] = useState({
    fullName: "",
    position: "",
    email: "",
    phone: "",
    organizationId: "",
    notes: "",
  });
  const [newUserIssueServers, setNewUserIssueServers] = useState([]);
  const [newUserCertServerId, setNewUserCertServerId] = useState("");
  const [newUserCertChoice, setNewUserCertChoice] = useState("");
  const [newUserCertNewCn, setNewUserCertNewCn] = useState("");
  const [newUserCertValidityDays, setNewUserCertValidityDays] = useState("1825");
  const [certKeyUploadDraft, setCertKeyUploadDraft] = useState({ certPem: "", keyPem: "" });
  const [certKeyUploadBusy, setCertKeyUploadBusy] = useState(false);
  const [certKeyImportModalOpen, setCertKeyImportModalOpen] = useState(false);
  const [certMaterialViewModal, setCertMaterialViewModal] = useState({
    open: false,
    title: "",
    pem: "",
    busy: false,
  });
  const [certMaterialSummary, setCertMaterialSummary] = useState({
    loading: false,
    data: null,
  });
  const [certMaterialUploadModal, setCertMaterialUploadModal] = useState({
    open: false,
    certId: "",
    kind: "cert",
    pem: "",
    busy: false,
    error: "",
  });
  const [userProfileDraft, setUserProfileDraft] = useState({
    fullName: "",
    position: "",
    email: "",
    phone: "",
    organizationId: "",
    notes: "",
  });
  const [profileIssueCert, setProfileIssueCert] = useState({ commonName: "", serverId: "", validityDays: "1825" });
  const [userCertBindModalOpen, setUserCertBindModalOpen] = useState(false);
  const [userCertBindSelectedCertId, setUserCertBindSelectedCertId] = useState("");
  const [userCertBindBusy, setUserCertBindBusy] = useState(false);
  const [userCertIssueModalOpen, setUserCertIssueModalOpen] = useState(false);
  const [userCertRevokeModal, setUserCertRevokeModal] = useState({
    open: false,
    certId: null,
    commonName: "",
    busy: false,
    error: "",
  });
  const [userCertUnlinkModal, setUserCertUnlinkModal] = useState({
    open: false,
    certId: null,
    commonName: "",
    busy: false,
    error: "",
  });
  const [adminActionLogs, setAdminActionLogs] = useState([]);
  const [serviceActionModal, setServiceActionModal] = useState({ open: false, action: "", busy: false, error: "" });
  const [agentUpdateFileName, setAgentUpdateFileName] = useState("");
  const [agentUpdateSha256, setAgentUpdateSha256] = useState("");
  const [agentUpdateBinaryBase64, setAgentUpdateBinaryBase64] = useState("");
  const [agentUpdateBusy, setAgentUpdateBusy] = useState(false);
  const [agentUpdateResult, setAgentUpdateResult] = useState("");
  const [agentUpdateError, setAgentUpdateError] = useState("");
  const [agentUpdateModalOpen, setAgentUpdateModalOpen] = useState(false);
  const [agentUpdateUploadPct, setAgentUpdateUploadPct] = useState(0);
  const [agentUpdateJournalTail, setAgentUpdateJournalTail] = useState("");
  const [userProfileSessions, setUserProfileSessions] = useState([]);
  const [userConnectionProfileOptions, setUserConnectionProfileOptions] = useState({
    certificates: [],
    servers: [],
    defaultEmail: "",
  });
  const [userConnectionProfileDraft, setUserConnectionProfileDraft] = useState({
    certificateId: "",
    serverId: "",
    email: "",
  });
  const [serverSessionsSearch, setServerSessionsSearch] = useState("");
  const [userConnectionProfileBusy, setUserConnectionProfileBusy] = useState(false);
  const [userCertBindServerId, setUserCertBindServerId] = useState("");
  const [userCcdDraft, setUserCcdDraft] = useState({
    ifconfigPushLocal: "",
    ifconfigPushRemote: "",
    pushRoutes: "",
    iroutes: "",
    dnsServers: "",
    customDirectives: "",
  });
  const [serverFirewallTunnelDefaultPolicy, setServerFirewallTunnelDefaultPolicy] = useState("deny");
  const [serverFirewallTunnelRules, setServerFirewallTunnelRules] = useState([]);
  const [serverFirewallTunnelNatRules, setServerFirewallTunnelNatRules] = useState([]);
  const [serverFirewallLoading, setServerFirewallLoading] = useState(false);
  const [serverFirewallBusy, setServerFirewallBusy] = useState(false);
  const [userFirewallOverrideRules, setUserFirewallOverrideRules] = useState([]);
  const [userFirewallOverrideNatRules, setUserFirewallOverrideNatRules] = useState([]);
  const [userFirewallMode, setUserFirewallMode] = useState("merge");
  const [userFirewallBusy, setUserFirewallBusy] = useState(false);
  /** Не перетирать черновик правил при каждом poll refreshPanelData — только при смене выбранного пользователя. */
  const userFirewallHydratedForUserIdRef = useRef(null);
  const userCcdHydratedForUserIdRef = useRef(null);
  const [userCcdBusy, setUserCcdBusy] = useState(false);
  const [userCcdResult, setUserCcdResult] = useState("");
  const [firewallRuleModal, setFirewallRuleModal] = useState({
    open: false,
    scope: "server",
    section: "tunnel",
    kind: "filter",
    editId: "",
    draft: { action: "allow", proto: "tcp", destination: "", ports: "", note: "", type: "masquerade", src: "", dst: "", outInterface: "", toAddress: "" },
    error: "",
  });
  const [serverFirewallEffectiveModal, setServerFirewallEffectiveModal] = useState({ open: false, title: "", content: "" });
  const [userFirewallEffectiveModal, setUserFirewallEffectiveModal] = useState({ open: false, title: "", content: "" });
  const [natOutInterfaceInputMode, setNatOutInterfaceInputMode] = useState("manual");
  const [natToAddressInputMode, setNatToAddressInputMode] = useState("manual");
  const [natDetectedInterfaces, setNatDetectedInterfaces] = useState([]);
  const [natDetectedAddresses, setNatDetectedAddresses] = useState([]);
  const [disconnectingSessionKeys, setDisconnectingSessionKeys] = useState(() => {
    try {
      const raw = localStorage.getItem(DISCONNECTING_SESSIONS_STORAGE_KEY);
      const arr = JSON.parse(raw || "[]");
      return Array.isArray(arr) ? arr.map((x) => String(x || "")).filter(Boolean) : [];
    } catch {
      return [];
    }
  });
  const [userSessionDisconnectModal, setUserSessionDisconnectModal] = useState({
    open: false,
    nodeName: "",
    sessionNumber: "",
    profileName: "",
    busy: false,
    error: "",
  });
  const userSessionDisconnectTargetRef = useRef({ nodeId: "", sessionId: "" });
  const [serviceActionResult, setServiceActionResult] = useState("");
  const [serviceCheckBusy, setServiceCheckBusy] = useState(false);
  const [serviceCheckResult, setServiceCheckResult] = useState("");
  const [serviceCheckHints, setServiceCheckHints] = useState([]);
  const [systemServicesRows, setSystemServicesRows] = useState([]);
  const [systemServicesLoading, setSystemServicesLoading] = useState(false);
  const [systemServicesError, setSystemServicesError] = useState("");
  const [systemServicesQuery, setSystemServicesQuery] = useState("");
  const [dnsmasqState, setDnsmasqState] = useState({
    loading: false,
    error: "",
    applyBusy: false,
    queueMessage: "",
  });
  const [dnsmasqDraft, setDnsmasqDraft] = useState([]);
  const [dnsRuleModal, setDnsRuleModal] = useState({
    open: false,
    editId: "",
    type: "domain-resolver",
    draft: {},
    error: "",
  });
  const [tableDrag, setTableDrag] = useState(() => emptyTableDrag());
  const [journalQuery, setJournalQuery] = useState("");
  const [logsVpnSearch, setLogsVpnSearch] = useState("");
  const [logsSrcSearch, setLogsSrcSearch] = useState("");
  const [logsAdminSearch, setLogsAdminSearch] = useState("");

  useEffect(() => {
    if (!tableDrag.dragId) return undefined;
    const onWindowDragOver = (ev) => {
      ev.preventDefault();
      try {
        if (ev.dataTransfer) ev.dataTransfer.dropEffect = "move";
      } catch (_) {
        /* ignore */
      }
    };
    const onWindowDrop = (ev) => {
      ev.preventDefault();
    };
    window.addEventListener("dragover", onWindowDragOver);
    window.addEventListener("drop", onWindowDrop);
    return () => {
      window.removeEventListener("dragover", onWindowDragOver);
      window.removeEventListener("drop", onWindowDrop);
    };
  }, [tableDrag.dragId]);
  const [journalLogsPage, setJournalLogsPage] = useState(1);
  const [journalLogsPageSize] = useState(50);
  const [journalLogsTotal, setJournalLogsTotal] = useState(0);
  const [journalLogsTotalPages, setJournalLogsTotalPages] = useState(1);
  const [journalLogsRows, setJournalLogsRows] = useState([]);
  const [journalLogsLoading, setJournalLogsLoading] = useState(false);
  const [serverNameFilter, setServerNameFilter] = useState("");
  const [userListFilter, setUserListFilter] = useState("");
  const [caSignedListFilter, setCaSignedListFilter] = useState("");
  const [serverOpenVpnSettings, setServerOpenVpnSettings] = useState({});
  const [serverOpenVpnClientSettings, setServerOpenVpnClientSettings] = useState({});
  const [serverOpenVpnClientVersions, setServerOpenVpnClientVersions] = useState([]);
  const [serverOpenVpnClientActiveVersionId, setServerOpenVpnClientActiveVersionId] = useState("");
  const [serverOpenVpnClientSelectedVersionId, setServerOpenVpnClientSelectedVersionId] = useState("");
  const [serverOpenVpnClientLoading, setServerOpenVpnClientLoading] = useState(false);
  const [serverOpenVpnClientError, setServerOpenVpnClientError] = useState("");
  const [serverOpenVpnClientSaving, setServerOpenVpnClientSaving] = useState(false);
  const [serverOpenVpnConfigPath, setServerOpenVpnConfigPath] = useState("");
  const [serverOpenVpnLoading, setServerOpenVpnLoading] = useState(false);
  const [serverOpenVpnError, setServerOpenVpnError] = useState("");
  const [serverOpenVpnHints, setServerOpenVpnHints] = useState([]);
  const [serverOpenVpnApplying, setServerOpenVpnApplying] = useState(false);
  const [serverOpenVpnApplyConfirmModal, setServerOpenVpnApplyConfirmModal] = useState({
    open: false,
    done: false,
  });
  const [serverOpenVpnApplyLogVisible, setServerOpenVpnApplyLogVisible] = useState(false);
  const [serverOpenVpnApplyLog, setServerOpenVpnApplyLog] = useState("");
  const [serverOpenVpnApplyResult, setServerOpenVpnApplyResult] = useState({
    status: "idle",
    message: "",
  });
  const [serverOpenVpnSaveModal, setServerOpenVpnSaveModal] = useState({ open: false, text: "" });
  const [serverOpenVpnClientDeleteVersionModal, setServerOpenVpnClientDeleteVersionModal] = useState({
    open: false,
    versionId: "",
    versionLabel: "",
    busy: false,
    error: "",
  });
  const [serverOpenVpnClientApplyConfirmModal, setServerOpenVpnClientApplyConfirmModal] = useState({
    open: false,
    busy: false,
    error: "",
  });
  const [serverAgentRawConfig, setServerAgentRawConfig] = useState("");
  const [serverAgentRawLoading, setServerAgentRawLoading] = useState(false);
  const [openvpnMaterialsDh, setOpenvpnMaterialsDh] = useState([]);
  const [openvpnMaterialsTls, setOpenvpnMaterialsTls] = useState([]);
  const [openvpnCheckModal, setOpenvpnCheckModal] = useState({
    open: false,
    title: "",
    message: "",
    details: "",
    hints: [],
    success: true,
  });
  const [serverKeyMaterialModal, setServerKeyMaterialModal] = useState({
    mode: null,
    kind: null,
    busy: false,
    error: "",
    importPem: "",
  });
  const serverKeyImportFileRef = useRef(null);
  const [openvpnMaterialDeleteModal, setOpenvpnMaterialDeleteModal] = useState({
    open: false,
    id: null,
    kindLabel: "",
    busy: false,
    error: "",
  });
  const [srvCertCreateModal, setSrvCertCreateModal] = useState({
    open: false,
    cn: "",
    validityDays: 825,
    keySize: "2048",
    signatureAlgorithm: "sha256",
    busy: false,
    error: "",
  });
  const [serverServerCertDeleteModal, setServerServerCertDeleteModal] = useState({
    open: false,
    busy: false,
    error: "",
  });
  const [srvCertImportModal, setSrvCertImportModal] = useState({
    open: false,
    certPem: "",
    keyPem: "",
    busy: false,
    error: "",
  });
  const [serverRootCaCreateModalOpen, setServerRootCaCreateModalOpen] = useState(false);
  const [serverRootCaImportModalOpen, setServerRootCaImportModalOpen] = useState(false);
  const [serverRootCaSummary, setServerRootCaSummary] = useState({ loading: false, data: null });
  const [serverPanelServerCertMaterials, setServerPanelServerCertMaterials] = useState({});
  const [serverPanelRootCaImport, setServerPanelRootCaImport] = useState({ certPem: "", keyPem: "" });
  const [serverCaSignedFilter, setServerCaSignedFilter] = useState("");
  const [serverCaIssueModal, setServerCaIssueModal] = useState({
    open: false,
    commonName: "",
    validityDays: "365",
    busy: false,
    error: "",
  });
  const [serverCaImportModal, setServerCaImportModal] = useState({
    open: false,
    certPem: "",
    keyPem: "",
    busy: false,
    error: "",
  });
  const [serverCaIndexImportModal, setServerCaIndexImportModal] = useState({
    open: false,
    indexText: "",
    busy: false,
    error: "",
  });
  const [serverBindRootCaPick, setServerBindRootCaPick] = useState("");
  const [serverBindRootCaBusy, setServerBindRootCaBusy] = useState(false);
  const serverCaIndexFileRef = useRef(null);
  const [serverRootCaDeleteModal, setServerRootCaDeleteModal] = useState({
    open: false,
    step: 1,
    confirmCommonName: "",
    busy: false,
    error: "",
  });
  const srvCertImportCertFileRef = useRef(null);
  const srvCertImportKeyFileRef = useRef(null);
  const [panelAsyncTasks, setPanelAsyncTasks] = useState([]);
  const [taskRetryModal, setTaskRetryModal] = useState({
    open: false,
    taskId: "",
    taskType: "",
    busy: false,
    error: "",
  });
  const [systemUnitActionModal, setSystemUnitActionModal] = useState({
    open: false,
    unit: "",
    action: "",
    busy: false,
    error: "",
  });
  const [organizations, setOrganizations] = useState([]);
  const [newOrganization, setNewOrganization] = useState({
    name: "",
    inn: "",
    legalAddress: "",
    generalDirector: "",
    phone: "",
    email: "",
  });
  const [editOrganization, setEditOrganization] = useState({
    id: "",
    name: "",
    inn: "",
    legalAddress: "",
    generalDirector: "",
    phone: "",
    email: "",
  });
  const [organizationFirewallMode, setOrganizationFirewallMode] = useState("merge");
  const [organizationFirewallRules, setOrganizationFirewallRules] = useState([]);
  const [organizationFirewallNatRules, setOrganizationFirewallNatRules] = useState([]);
  const [organizationFirewallBusy, setOrganizationFirewallBusy] = useState(false);
  const [organizationFirewallEffectiveModal, setOrganizationFirewallEffectiveModal] = useState({ open: false, title: "", content: "" });
  const organizationFirewallHydratedForIdRef = useRef(null);
  const [tablePages, setTablePages] = useState({
    servers: 1,
    tasks: 1,
    organizations: 1,
    users: 1,
    admins: 1,
    caRoots: 1,
    caSigned: 1,
    serverSessions: 1,
    serverCaSigned: 1,
    serverCerts: 1,
    userConnections: 1,
    userCerts: 1,
    logsVpn: 1,
    logsSrc: 1,
    logsAdmin: 1,
    certSessions: 1,
    certIp: 1,
    certSrc: 1,
  });

  const location = useLocation();
  const navigate = useNavigate();
  const route = useMemo(() => parseAppRoute(location.pathname, location.search), [location.pathname, location.search]);
  const {
    primaryNav,
    serversView,
    selectedServerId,
    serverDetailTab,
    serverCenterCertId,
    organizationsView,
    organizationEditId,
    organizationEditTab,
    usersSub,
    selectedUserId,
    userProfileTab,
    caRootWizard,
    selectedRootCaId,
    selectedCertId,
    rootCaProfileTab,
    certProfileTab,
    adminsPage,
    selectedAdminId,
    logsView,
    docsSection,
    settingsSection,
    inviteAdminToken,
    resetAdminPasswordToken,
  } = route;

  const [userToolbarMenuOpen, setUserToolbarMenuOpen] = useState(false);
  const userToolbarMenuRef = useRef(null);

  useEffect(() => {
    setUserToolbarMenuOpen(false);
  }, [location.pathname]);

  useEffect(() => {
    if (location.pathname.replace(/\/+$/, "") === "/settings/profile") {
      navigate(paths.profile(), { replace: true });
    }
  }, [location.pathname, navigate]);

  useEffect(() => {
    if (!userToolbarMenuOpen) return undefined;
    const onDoc = (e) => {
      if (userToolbarMenuRef.current && !userToolbarMenuRef.current.contains(e.target)) {
        setUserToolbarMenuOpen(false);
      }
    };
    const onKey = (e) => {
      if (e.key === "Escape") setUserToolbarMenuOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, [userToolbarMenuOpen]);

  const isAuthorized = useMemo(() => Boolean(token), [token]);

  const tokenRef = useRef(token);
  useEffect(() => {
    tokenRef.current = token;
  }, [token]);

  const sessionAdminId = useMemo(() => {
    if (!token) return "";
    const sub = parseJwtPayload(token)?.sub;
    return sub != null && sub !== "" ? String(sub) : "";
  }, [token]);

  const tokenExpiresAtMs = useMemo(() => {
    if (!token) return null;
    const exp = parseJwtPayload(token)?.exp;
    return typeof exp === "number" ? exp * 1000 : null;
  }, [token]);

  const sessionSecondsLeft = useMemo(() => {
    if (!tokenExpiresAtMs) return 0;
    return Math.max(0, (tokenExpiresAtMs - sessionNow) / 1000);
  }, [tokenExpiresAtMs, sessionNow]);

  const sessionProfileFullName = useMemo(
    () => String(myAdminProfile?.fullName ?? "").trim(),
    [myAdminProfile],
  );

  /** ФИО в шапке (не логин и не email). */
  const sessionToolbarDisplayName = useMemo(() => {
    if (!token) return "";
    if (sessionProfileFullName) return sessionProfileFullName;
    if (myAdminProfileLoading) return "…";
    return "—";
  }, [token, sessionProfileFullName, myAdminProfileLoading]);

  const selectedCert = useMemo(
    () => certificates.find((cert) => cert.id === selectedCertId) || null,
    [certificates, selectedCertId],
  );

  const selectedRootCa = useMemo(
    () => rootCAs.find((c) => c.id === selectedRootCaId) || null,
    [rootCAs, selectedRootCaId],
  );

  const rootSignedUserCertificates = useMemo(() => {
    if (!selectedRootCaId) return [];
    return certificates
      .filter((c) => c.rootCaId === selectedRootCaId)
      .sort((a, b) => (a.commonName || "").localeCompare(b.commonName || "", undefined, { sensitivity: "base" }));
  }, [certificates, selectedRootCaId]);

  const filteredRootSignedUserCertificates = useMemo(() => {
    const q = caSignedListFilter.trim().toLowerCase();
    if (!q) return rootSignedUserCertificates;
    return rootSignedUserCertificates.filter((c) => {
      const cn = String(c.commonName || "").toLowerCase();
      const sn = String(c.serialNumber ?? "").toLowerCase();
      return cn.includes(q) || sn.includes(q);
    });
  }, [rootSignedUserCertificates, caSignedListFilter]);

  const selectedCertClients = useMemo(() => {
    if (!selectedCert) return [];
    return clients.filter((client) => client.commonName === selectedCert.commonName);
  }, [clients, selectedCert]);

  const selectedCertIpHistory = useMemo(() => {
    if (!selectedCert) return [];
    return ipHistory.filter((entry) => entry.commonName === selectedCert.commonName);
  }, [ipHistory, selectedCert]);

  const selectedCertSourceHistory = useMemo(() => {
    if (!selectedCert) return [];
    return sourceIpHistory.filter((entry) => entry.commonName === selectedCert.commonName);
  }, [sourceIpHistory, selectedCert]);

  const selectedTrafficTotals = useMemo(() => {
    let totalIn = 0;
    let totalOut = 0;
    for (const client of selectedCertClients) {
      for (const sample of client.trafficHistory || []) {
        totalIn += Number(sample.inDeltaBytes || 0);
        totalOut += Number(sample.outDeltaBytes || 0);
      }
    }
    return { totalIn, totalOut };
  }, [selectedCertClients]);

  const filteredOverviewServers = useMemo(() => {
    const list =
      Array.isArray(nodes) && nodes.length > 0 ? nodes : (overview?.servers || []);
    const q = serverNameFilter.trim().toLowerCase();
    const filtered = !q ? list : list.filter((s) => String(s.name || "").toLowerCase().includes(q));
    return [...filtered].sort((a, b) =>
      String(a.name || "").localeCompare(String(b.name || ""), "ru", { sensitivity: "base" }),
    );
  }, [nodes, overview, serverNameFilter]);

  const organizationsSortedByName = useMemo(
    () =>
      [...organizations].sort((a, b) =>
        String(a.name || "").localeCompare(String(b.name || ""), "ru", { sensitivity: "base" }),
      ),
    [organizations],
  );

  const selectedServer = useMemo(() => {
    if (!selectedServerId) return null;
    return (
      (overview?.servers || []).find((s) => s.id === selectedServerId) ||
      nodes.find((n) => n.id === selectedServerId) ||
      null
    );
  }, [overview, nodes, selectedServerId]);

  const serverAgentSummary = useMemo(() => {
    if (!selectedServer) return { addr: "—", online: false };
    const online = String(selectedServer.status || "").toUpperCase() === "ONLINE";
    const addr =
      selectedServer.host != null
        ? `${selectedServer.protocol || "http"}://${selectedServer.host}:${selectedServer.port ?? ""}`
        : "—";
    return { addr, online };
  }, [selectedServer]);

  const natOutInterfaceOptions = useMemo(() => {
    const set = new Set();
    const devIface = normalizeIfaceLikeOpenvpnDev(serverOpenVpnSettings?.dev);
    if (devIface) set.add(devIface);
    for (const name of natDetectedInterfaces) {
      const n = String(name || "").trim();
      if (n) set.add(n);
    }
    return [...set].sort((a, b) => a.localeCompare(b, "ru", { sensitivity: "base" }));
  }, [serverOpenVpnSettings?.dev, natDetectedInterfaces]);

  const natToAddressOptions = useMemo(() => {
    const set = new Set();
    for (const addr of natDetectedAddresses) {
      const a = String(addr || "").trim();
      if (a && !a.includes(":")) set.add(a);
    }
    const localAddr = parseHostFromAddr(serverOpenVpnSettings?.local || "");
    if (localAddr) set.add(localAddr);
    return [...set].sort((a, b) => a.localeCompare(b, "ru", { sensitivity: "base" }));
  }, [
    natDetectedAddresses,
    serverOpenVpnSettings?.local,
  ]);

  useEffect(() => {
    if (!firewallRuleModal.open) return;
    if (firewallRuleModal.scope !== "server" || firewallRuleModal.kind !== "nat") return;
    if (!selectedServerId || !tokenRef.current) return;
    let cancelled = false;
    (async () => {
      try {
        const data = await request(
          `/api/panel/nodes/${encodeURIComponent(selectedServerId)}/network-info`,
          "GET",
          tokenRef.current,
        );
        if (cancelled) return;
        const ifaces = Array.isArray(data?.interfaces) ? data.interfaces : [];
        const names = ifaces.map((it) => String(it?.name || "")).filter(Boolean);
        setNatDetectedInterfaces(names);
        const addrsRaw = Array.isArray(data?.addresses) ? data.addresses : [];
        setNatDetectedAddresses(addrsRaw.map((x) => String(x || "")).filter(Boolean));
      } catch (err) {
        if (!cancelled) setError(err.message || "Не удалось получить интерфейсы/адреса с агента");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [firewallRuleModal.open, firewallRuleModal.scope, firewallRuleModal.kind, selectedServerId]);

  useEffect(() => {
    if (!selectedServer) return;
    setServerAgentDraft({
      name: selectedServer.name || "",
      protocol: selectedServer.protocol || "http",
      host: selectedServer.host != null ? String(selectedServer.host) : "",
      port: selectedServer.port != null ? String(selectedServer.port) : "",
      authToken: "",
    });
  }, [
    selectedServer?.id,
    selectedServer?.name,
    selectedServer?.protocol,
    selectedServer?.host,
    selectedServer?.port,
  ]);

  const selectedServerMonitoringSamples = useMemo(() => {
    if (!selectedServer) return [];
    return mergeLiveMetricSamples(selectedServer.recentMetrics, {
      cpuPercent: selectedServer.cpuPercent,
      memoryPercent: selectedServer.memoryPercent,
      diskPercent: selectedServer.diskPercent,
      diskReadBps: selectedServer.diskReadBps,
      diskWriteBps: selectedServer.diskWriteBps,
      networkInBps: selectedServer.networkInBps,
      networkOutBps: selectedServer.networkOutBps,
    });
  }, [selectedServer]);

  /** CN, для которых есть профиль пользователя (VpnUser) в БД */
  const registeredCnSet = useMemo(() => {
    const s = new Set();
    for (const c of certificates) {
      if (c.vpnUserId && c.commonName) s.add(c.commonName);
    }
    return s;
  }, [certificates]);

  const cnProfileMap = useMemo(() => {
    const m = new Map();
    for (const cert of certificates) {
      if (!cert?.commonName || !cert?.vpnUserId) continue;
      const user = vpnUsers.find((u) => u.id === cert.vpnUserId);
      m.set(cert.commonName, { userId: cert.vpnUserId, fullName: user?.fullName || "" });
    }
    return m;
  }, [certificates, vpnUsers]);

  const vpnUsersEnriched = useMemo(() => {
    return vpnUsers
      .map((u) => {
        const certCns = new Set(
          certificates.filter((c) => c.vpnUserId === u.id && c.commonName).map((c) => c.commonName),
        );
        let activeSessions = 0;
        let totalInBps = 0;
        let totalOutBps = 0;
        for (const client of clients) {
          const cn = client.commonName || "";
          if (!cn || !certCns.has(cn)) continue;
          activeSessions += 1;
          totalInBps += Number(client.inBps || 0);
          totalOutBps += Number(client.outBps || 0);
        }
        const linkedCertCount = certificates.filter((c) => c.vpnUserId === u.id).length;
        return { ...u, activeSessions, totalInBps, totalOutBps, linkedCertCount };
      })
      .sort((a, b) =>
        String(a.fullName || "").localeCompare(String(b.fullName || ""), "ru", { sensitivity: "base" }),
      );
  }, [vpnUsers, clients, certificates]);

  const filteredVpnUsersEnriched = useMemo(() => {
    const q = userListFilter.trim().toLowerCase();
    const filtered = !q
      ? vpnUsersEnriched
      : vpnUsersEnriched.filter((u) => {
          const hay = [
            u.fullName,
            u.position,
            u.email,
            u.phone,
            u.organization?.name,
          ]
            .filter(Boolean)
            .join(" ")
            .toLowerCase();
          return hay.includes(q);
        });
    return [...filtered].sort((a, b) =>
      String(a.fullName || "").localeCompare(String(b.fullName || ""), "ru", { sensitivity: "base" }),
    );
  }, [vpnUsersEnriched, userListFilter]);

  const nodeSessions = useMemo(() => {
    if (!selectedServerId) return [];
    const ipKey = (v) =>
      String(v || "")
        .split(".")
        .map((x) => x.padStart(3, "0"))
        .join(".");
    return clients
      .filter((c) => c.nodeId === selectedServerId)
      .sort((a, b) => {
        const aUser = String(cnProfileMap.get(a.commonName || "")?.fullName || "").toLowerCase();
        const bUser = String(cnProfileMap.get(b.commonName || "")?.fullName || "").toLowerCase();
        if (aUser !== bUser) return aUser.localeCompare(bUser, "ru");
        return ipKey(a.virtualIp).localeCompare(ipKey(b.virtualIp), "ru");
      });
  }, [clients, selectedServerId, cnProfileMap]);

  const selectedServerCertificates = useMemo(() => {
    if (!selectedServerId) return [];
    return certificates
      .filter((c) => c.agentNodeId === selectedServerId)
      .sort((a, b) => (a.commonName || "").localeCompare(b.commonName || "", undefined, { sensitivity: "base" }));
  }, [certificates, selectedServerId]);
  /** Сертификаты OpenVPN-сервера узла: без пользователя и только для текущего сохранённого корневого сертификата панели. */
  const keysTabServerCertificates = useMemo(() => {
    if (!selectedServerId) return [];
    const panelRootId = String(serverOpenVpnSettings.panelRootCaId || "").trim();
    if (!panelRootId) return [];
    return selectedServerCertificates.filter((c) => {
      const rid = String(c.rootCaId || c.rootCa?.id || "").trim();
      return !c.vpnUserId && rid === panelRootId;
    });
  }, [selectedServerCertificates, serverOpenVpnSettings.panelRootCaId, selectedServerId]);
  const serverPanelDisplayedServerCert = useMemo(() => {
    if (!keysTabServerCertificates.length) return null;
    const pid = String(serverOpenVpnSettings.panelServerCertId || "").trim();
    if (pid) {
      const hit = keysTabServerCertificates.find((c) => c.id === pid);
      if (hit) return hit;
    }
    return keysTabServerCertificates[0];
  }, [keysTabServerCertificates, serverOpenVpnSettings.panelServerCertId]);
  const serverPanelRootCa = useMemo(
    () => rootCAs.find((r) => r.id === String(serverOpenVpnSettings.panelRootCaId || "").trim()) || null,
    [rootCAs, serverOpenVpnSettings.panelRootCaId],
  );
  const panelRootCaIdForServer = String(serverOpenVpnSettings.panelRootCaId || "").trim();
  const serverRootIssuedCertificates = useMemo(() => {
    if (!panelRootCaIdForServer) return [];
    return certificates
      .filter((c) => String(c.rootCaId || c.rootCa?.id || "").trim() === panelRootCaIdForServer)
      .sort((a, b) => new Date(b.createdAt || 0).getTime() - new Date(a.createdAt || 0).getTime());
  }, [certificates, panelRootCaIdForServer]);
  const filteredServerRootIssuedCertificates = useMemo(() => {
    const q = String(serverCaSignedFilter || "").trim().toLowerCase();
    if (!q) return serverRootIssuedCertificates;
    return serverRootIssuedCertificates.filter((c) => {
      const cn = String(c.commonName || "").toLowerCase();
      const serial = String(c.serialNumber || "").toLowerCase();
      const userName = String(c.vpnUser?.fullName || "").toLowerCase();
      const userEmail = String(c.vpnUser?.email || "").toLowerCase();
      return cn.includes(q) || serial.includes(q) || userName.includes(q) || userEmail.includes(q);
    });
  }, [serverRootIssuedCertificates, serverCaSignedFilter]);
  const serverCenterSelectedCert = useMemo(() => {
    const id = String(serverCenterCertId || "").trim();
    if (!id) return null;
    return serverRootIssuedCertificates.find((c) => c.id === id) || null;
  }, [serverCenterCertId, serverRootIssuedCertificates]);
  const certSummaryTargetId = useMemo(() => {
    if (primaryNav === "servers" && serversView === "detail" && serverDetailTab === "ca-center" && serverCenterSelectedCert?.id) {
      return serverCenterSelectedCert.id;
    }
    return selectedCertId || "";
  }, [primaryNav, serversView, serverDetailTab, serverCenterSelectedCert?.id, selectedCertId]);
  const keysMaxServerCertValidityDays = useMemo(() => {
    const d = daysRemainingUntil(serverPanelRootCa?.expiresAt);
    return Math.min(3650, Math.max(0, d));
  }, [serverPanelRootCa?.expiresAt]);
  const serverOpenVpnDraftRaw = useMemo(
    () => fallbackRawFromSettings(serverOpenVpnSettings),
    [serverOpenVpnSettings],
  );
  const serverOpenVpnActiveRaw = useMemo(
    () => String(serverAgentRawConfig || "").trim() || fallbackRawFromSettings(serverOpenVpnSettings),
    [serverAgentRawConfig, serverOpenVpnSettings],
  );
  const serverOpenVpnConfigDiff = useMemo(
    () => lineDiffLcs(serverOpenVpnActiveRaw, serverOpenVpnDraftRaw),
    [serverOpenVpnActiveRaw, serverOpenVpnDraftRaw],
  );
  const serverOpenVpnClientActiveVersion = useMemo(
    () => serverOpenVpnClientVersions.find((v) => v.id === serverOpenVpnClientActiveVersionId) || null,
    [serverOpenVpnClientVersions, serverOpenVpnClientActiveVersionId],
  );
  const serverOpenVpnClientSelectedVersion = useMemo(
    () => serverOpenVpnClientVersions.find((v) => v.id === serverOpenVpnClientSelectedVersionId) || null,
    [serverOpenVpnClientVersions, serverOpenVpnClientSelectedVersionId],
  );
  const serverOpenVpnClientActiveRaw = useMemo(
    () => fallbackRawFromClientSettings(serverOpenVpnClientActiveVersion?.settings || {}, serverOpenVpnSettings),
    [serverOpenVpnClientActiveVersion, serverOpenVpnSettings],
  );
  const serverOpenVpnClientDraftRaw = useMemo(
    () => fallbackRawFromClientSettings(serverOpenVpnClientSettings, serverOpenVpnSettings),
    [serverOpenVpnClientSettings, serverOpenVpnSettings],
  );
  const serverOpenVpnClientConfigDiff = useMemo(
    () => lineDiffLcs(serverOpenVpnClientActiveRaw, serverOpenVpnClientDraftRaw),
    [serverOpenVpnClientActiveRaw, serverOpenVpnClientDraftRaw],
  );
  const serverOpenVpnClientHasDraftChanges = useMemo(
    () => serverOpenVpnClientConfigDiff.some((d) => d.type === "add" || d.type === "del"),
    [serverOpenVpnClientConfigDiff],
  );
  const serverOpenVpnClientSelectedRaw = useMemo(
    () => fallbackRawFromClientSettings(serverOpenVpnClientSelectedVersion?.settings || {}, serverOpenVpnSettings),
    [serverOpenVpnClientSelectedVersion, serverOpenVpnSettings],
  );
  const serverOpenVpnClientHasUnsavedSelectedChanges = useMemo(
    () => lineDiffLcs(serverOpenVpnClientSelectedRaw, serverOpenVpnClientDraftRaw).some((d) => d.type !== "same"),
    [serverOpenVpnClientSelectedRaw, serverOpenVpnClientDraftRaw],
  );
  const formatTaskStatus = useCallback((statusRaw) => {
    const status = String(statusRaw || "").toLowerCase();
    if (status === "completed") return { cls: "app-status app-status--ok", label: "completed" };
    if (status === "failed") return { cls: "app-status app-status--off", label: "failed" };
    if (status === "processing") return { cls: "app-status", label: "processing" };
    return { cls: "app-status", label: status || "pending" };
  }, []);

  const selectedUser = useMemo(
    () => vpnUsers.find((user) => user.id === selectedUserId) || null,
    [vpnUsers, selectedUserId],
  );
  useEffect(() => {
    if (!selectedUserId) {
      userFirewallHydratedForUserIdRef.current = null;
      setUserFirewallOverrideRules([]);
      setUserFirewallOverrideNatRules([]);
      setUserFirewallMode("merge");
      return;
    }
    const user = vpnUsers.find((u) => u.id === selectedUserId);
    if (!user) return;
    if (userFirewallHydratedForUserIdRef.current === selectedUserId) {
      return;
    }
    userFirewallHydratedForUserIdRef.current = selectedUserId;

    const raw = user.firewallRules;
    if (raw == null) {
      setUserFirewallOverrideRules([]);
      setUserFirewallOverrideNatRules([]);
      setUserFirewallMode("merge");
      return;
    }
    if (Array.isArray(raw)) {
      setUserFirewallOverrideRules(raw);
      setUserFirewallOverrideNatRules([]);
      setUserFirewallMode("merge");
      return;
    }
    if (typeof raw === "object") {
      const mode = String(raw.mode || "merge").toLowerCase() === "replace" ? "replace" : "merge";
      setUserFirewallMode(mode);
      setUserFirewallOverrideRules(Array.isArray(raw.rules) ? raw.rules : []);
      setUserFirewallOverrideNatRules(Array.isArray(raw.natRules) ? raw.natRules : []);
      return;
    }
    setUserFirewallOverrideRules([]);
    setUserFirewallOverrideNatRules([]);
    setUserFirewallMode("merge");
  }, [selectedUserId, vpnUsers]);

  useEffect(() => {
    if (!selectedUserId) {
      userCcdHydratedForUserIdRef.current = null;
      setUserCcdDraft({
        ifconfigPushLocal: "",
        ifconfigPushRemote: "",
        pushRoutes: "",
        iroutes: "",
        dnsServers: "",
        customDirectives: "",
      });
      setUserCcdResult("");
      return;
    }
    const user = vpnUsers.find((u) => u.id === selectedUserId);
    if (!user) return;
    if (userCcdHydratedForUserIdRef.current === selectedUserId) {
      return;
    }
    userCcdHydratedForUserIdRef.current = selectedUserId;
    const c = user.ccdSettings && typeof user.ccdSettings === "object" && !Array.isArray(user.ccdSettings) ? user.ccdSettings : {};
    setUserCcdDraft({
      ifconfigPushLocal: String(c.ifconfigPushLocal || ""),
      ifconfigPushRemote: String(c.ifconfigPushRemote || ""),
      pushRoutes: String(c.pushRoutes || ""),
      iroutes: String(c.iroutes || ""),
      dnsServers: String(c.dnsServers || ""),
      customDirectives: String(c.customDirectives || ""),
    });
    setUserCcdResult("");
  }, [selectedUserId, vpnUsers]);

  const selectedUserCertificates = useMemo(() => {
    if (!selectedUserId) return [];
    return certificates
      .filter((cert) => cert.vpnUserId === selectedUserId)
      .sort((a, b) => {
        const tb = new Date(b.createdAt || 0).getTime();
        const ta = new Date(a.createdAt || 0).getTime();
        if (tb !== ta) return tb - ta;
        return (a.commonName || "").localeCompare(b.commonName || "", undefined, { sensitivity: "base" });
      });
  }, [certificates, selectedUserId]);
  const userFirewallSourceIp = String(userCcdDraft.ifconfigPushLocal || "").trim() || "динамический IP клиента";
  const userFirewallEffectiveRules = useMemo(() => {
    if (userFirewallMode === "replace") {
      return userFirewallOverrideRules.map((r, idx) => ({
        ...r,
        scope: "override",
        order: idx,
        source: userFirewallSourceIp,
      }));
    }
    const base = serverFirewallTunnelRules.map((r, idx) => ({
      ...r,
      scope: "base",
      order: idx,
      source: "VPN clients",
    }));
    const override = userFirewallOverrideRules.map((r, idx) => ({
      ...r,
      scope: "override",
      order: base.length + idx,
      source: userFirewallSourceIp,
    }));
    return [...base, ...override];
  }, [serverFirewallTunnelRules, userFirewallOverrideRules, userFirewallSourceIp, userFirewallMode]);

  const selectedUserUnlinkedCertificates = useMemo(() => {
    return certificates
      .filter((c) => !c.vpnUserId)
      .sort((a, b) => (a.commonName || "").localeCompare(b.commonName || "", undefined, { sensitivity: "base" }));
  }, [certificates]);
  const userCertModalServers = useMemo(() => {
    const fromApi = Array.isArray(userConnectionProfileOptions.servers) ? userConnectionProfileOptions.servers : [];
    if (fromApi.length > 0) {
      return [...fromApi].sort((a, b) =>
        String(a?.name || "").localeCompare(String(b?.name || ""), undefined, { sensitivity: "base" }),
      );
    }
    const nd = Array.isArray(nodes) ? nodes : [];
    return [...nd]
      .map((n) => ({
        id: n.id,
        name: n.name || n.id,
        host: n.host || "",
        panelRootCaId: "",
        openvpnPort: 1194,
        openvpnProto: "udp",
      }))
      .sort((a, b) => String(a?.name || "").localeCompare(String(b?.name || ""), undefined, { sensitivity: "base" }));
  }, [userConnectionProfileOptions.servers, nodes]);
  const userCertBindServer = useMemo(
    () => userCertModalServers.find((s) => s.id === userCertBindServerId) || null,
    [userCertModalServers, userCertBindServerId],
  );
  const userCertBindServerRootCaId = String(userCertBindServer?.panelRootCaId || "").trim();
  const userProfileIssueRootCa = useMemo(
    () => rootCAs.find((r) => r.id === userCertBindServerRootCaId) || null,
    [rootCAs, userCertBindServerRootCaId],
  );
  const userProfileIssueMaxCertValidityDays = useMemo(() => {
    const d = daysRemainingUntil(userProfileIssueRootCa?.expiresAt);
    return Math.min(3650, Math.max(0, d));
  }, [userProfileIssueRootCa?.expiresAt]);
  const userModalBindableCertificates = useMemo(() => {
    if (!userCertBindServerRootCaId) return [];
    return selectedUserUnlinkedCertificates
      .filter((c) => {
        const certRoot = String(c.rootCaId || c.rootCa?.id || "").trim();
        if (certRoot !== userCertBindServerRootCaId) return false;
        if (c.revokedAt) return false;
        const hasKeyMaterial = Boolean(c.hasKeyMaterial ?? (c.certPem && c.keyPem));
        if (!hasKeyMaterial) return false;
        return true;
      })
      .sort((a, b) => (a.commonName || "").localeCompare(b.commonName || "", undefined, { sensitivity: "base" }));
  }, [selectedUserUnlinkedCertificates, userCertBindServerRootCaId]);
  const newUserSelectedIssueServer = useMemo(
    () => newUserIssueServers.find((s) => s.id === newUserCertServerId) || null,
    [newUserIssueServers, newUserCertServerId],
  );
  const newUserCertRootCaId = String(newUserSelectedIssueServer?.panelRootCaId || "").trim();
  const newUserBindableCertificates = useMemo(() => {
    const rootId = newUserCertRootCaId;
    if (!rootId) return [];
    return certificates
      .filter((c) => {
        const rid = String(c.rootCaId || c.rootCa?.id || "").trim();
        const usedByUser = Boolean(c.vpnUserId);
        const hasKeyMaterial = Boolean(c.hasKeyMaterial ?? (c.certPem && c.keyPem));
        return rid === rootId && !c.revokedAt && !usedByUser && hasKeyMaterial;
      })
      .sort((a, b) => (a.commonName || "").localeCompare(b.commonName || "", undefined, { sensitivity: "base" }));
  }, [certificates, newUserCertRootCaId]);
  const newUserSelectedRootCa = useMemo(
    () => rootCAs.find((r) => r.id === newUserCertRootCaId) || null,
    [rootCAs, newUserCertRootCaId],
  );
  const newUserMaxCertValidityDays = useMemo(() => {
    const d = daysRemainingUntil(newUserSelectedRootCa?.expiresAt);
    return Math.min(3650, Math.max(0, d));
  }, [newUserSelectedRootCa?.expiresAt]);

  const userProfileSessionsSorted = useMemo(() => {
    return [...userProfileSessions].sort((a, b) => {
      const tb = new Date(b.lastSeenAt || 0).getTime();
      const ta = new Date(a.lastSeenAt || 0).getTime();
      return tb - ta;
    });
  }, [userProfileSessions]);

  const panelDataSetters = useMemo(
    () => ({
      setOverview,
      setAdmins,
      setCertificates,
      setClients,
      setNodes,
      setIpHistory,
      setSourceIpHistory,
      setAdminActionLogs,
      setRootCAs,
      setOrganizations,
      setVpnUsers,
    }),
    [],
  );

  const panelDataFetchInFlightRef = useRef(false);

  const refreshPanelData = useCallback(
    async (keys) => {
      if (!token || panelDataFetchInFlightRef.current) return;
      const toFetch = keys ?? panelDataKeysForRoute(route);
      if (!toFetch.length) return;
      panelDataFetchInFlightRef.current = true;
      try {
        const patch = await fetchPanelDataKeys(request, token, toFetch, panelDataFetchContext(route));
        applyPanelDataPatch(patch, panelDataSetters);
        setError("");
      } catch (e) {
        setError(e.message);
      } finally {
        panelDataFetchInFlightRef.current = false;
      }
    },
    [token, route, panelDataSetters],
  );

  /** Обновить данные панели: без аргументов — только для текущей страницы; с аргументом — после мутации. */
  const loadData = useCallback(
    async (afterMutationKeys) => {
      const routeKeys = panelDataKeysForRoute(route);
      const keys = afterMutationKeys?.length
        ? [...new Set([...routeKeys, ...afterMutationKeys])]
        : routeKeys;
      await refreshPanelData(keys);
    },
    [route, refreshPanelData],
  );

  const patchAdminIsActive = async (adminId, isActive) => {
    setAdminDetailStatusBusy(true);
    setAdminDetailStatusError("");
    try {
      await request(`/api/admins/${encodeURIComponent(adminId)}`, "PATCH", token, { isActive });
      await loadData(PANEL_DATA_REFRESH.admins);
    } catch (e) {
      setAdminDetailStatusError(e?.message ? String(e.message) : String(e));
    } finally {
      setAdminDetailStatusBusy(false);
    }
  };

  const closeAdminBlockModal = () => {
    setAdminBlockModal({
      open: false,
      adminId: "",
      expectedNormalized: "",
      confirmByFullName: true,
      confirmInput: "",
      busy: false,
      validationError: "",
      error: "",
    });
  };

  const submitAdminBlock = async () => {
    const m = adminBlockModal;
    if (!m.open || !m.adminId) return;
    const typed = normalizeAdminBlockConfirmInput(m.confirmInput);
    if (typed !== m.expectedNormalized) {
      setAdminBlockModal((prev) => ({
        ...prev,
        validationError: prev.confirmByFullName
          ? "Введите ФИО точно так же, как в профиле (учитываются пробелы)."
          : "Введите логин аккаунта без ошибок.",
      }));
      return;
    }
    setAdminBlockModal((prev) => ({ ...prev, validationError: "", error: "", busy: true }));
    try {
      await request(`/api/admins/${encodeURIComponent(m.adminId)}`, "PATCH", token, { isActive: false });
      await loadData(PANEL_DATA_REFRESH.admins);
      closeAdminBlockModal();
    } catch (e) {
      setAdminBlockModal((prev) => ({
        ...prev,
        busy: false,
        error: e?.message ? String(e.message) : String(e),
      }));
    }
  };

  const saveAdminProfile = async (e) => {
    e.preventDefault();
    if (!selectedAdmin) return;
    setAdminProfileSaving(true);
    setAdminProfileFieldError("");
    try {
      await request(`/api/admins/${encodeURIComponent(selectedAdmin.id)}`, "PATCH", token, {
        fullName: adminProfileDraft.fullName.trim(),
        username: adminProfileDraft.username.trim(),
        email: adminProfileDraft.email.trim(),
      });
      await loadData(PANEL_DATA_REFRESH.admins);
    } catch (err) {
      setAdminProfileFieldError(err?.message ? String(err.message) : String(err));
    } finally {
      setAdminProfileSaving(false);
    }
  };

  const closeAdminPasswordResetModal = () => {
    setAdminPasswordResetModal({ open: false, resetUrl: "", busy: false, error: "" });
  };

  const openAdminPasswordResetModal = async () => {
    if (!selectedAdmin || selectedAdmin.invitePending) return;
    setAdminPasswordResetModal({ open: true, resetUrl: "", busy: true, error: "" });
    try {
      const res = await request(`/api/admins/${encodeURIComponent(selectedAdmin.id)}/password-reset-link`, "POST", token, {});
      const path = typeof res?.resetPath === "string" ? res.resetPath : "";
      const resetUrl = path ? `${window.location.origin}${path}` : "";
      setAdminPasswordResetModal({ open: true, resetUrl, busy: false, error: "" });
    } catch (e) {
      setAdminPasswordResetModal({
        open: true,
        resetUrl: "",
        busy: false,
        error: e?.message ? String(e.message) : String(e),
      });
    }
  };

  const loadMyAdminProfile = useCallback(async () => {
    const t = tokenRef.current;
    if (!t) return;
    setMyAdminProfileLoading(true);
    try {
      const data = await request("/api/admins/me", "GET", t);
      setMyAdminProfile(data || null);
      setMyAdminPasswordError("");
      setMyAdminTotpDisableError("");
      setMyAdminRecoveryRegenerateError("");
    } catch (e) {
      setMyAdminProfile(null);
      setMyAdminPasswordError(e?.message ? String(e.message) : String(e));
    } finally {
      setMyAdminProfileLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!token) {
      setMyAdminProfile(null);
      setMyAdminProfileLoading(false);
      return;
    }
    void loadMyAdminProfile();
  }, [token, loadMyAdminProfile]);

  const submitMyAdminPasswordChange = async (e) => {
    e.preventDefault();
    if (myAdminPasswordBusy) return;
    if (myAdminPasswordDraft.newPassword !== myAdminPasswordDraft.confirmPassword) {
      setMyAdminPasswordError("Подтверждение нового пароля не совпадает.");
      return;
    }
    setMyAdminPasswordBusy(true);
    setMyAdminPasswordError("");
    try {
      await request("/api/admins/me/change-password", "POST", token, {
        currentPassword: myAdminPasswordDraft.currentPassword,
        newPassword: myAdminPasswordDraft.newPassword,
      });
      setMyAdminPasswordDraft({ currentPassword: "", newPassword: "", confirmPassword: "" });
      setMyAdminPasswordModalOpen(false);
    } catch (e) {
      setMyAdminPasswordError(e?.message ? String(e.message) : String(e));
    } finally {
      setMyAdminPasswordBusy(false);
    }
  };

  const startMyAdminTotpSetup = async () => {
    setMyAdminTotpSetup((prev) => ({ ...prev, loading: true, error: "" }));
    try {
      const data = await request("/api/admins/me/totp/setup/start", "POST", token, {});
      setMyAdminTotpSetup({
        loading: false,
        qrDataUrl: String(data?.qrDataUrl || ""),
        manualSecret: String(data?.manualSecret || ""),
        expiresAt: String(data?.expiresAt || ""),
        code: "",
        error: "",
        busy: false,
      });
    } catch (e) {
      setMyAdminTotpSetup((prev) => ({
        ...prev,
        loading: false,
        busy: false,
        error: e?.message ? String(e.message) : String(e),
      }));
    }
  };

  const confirmMyAdminTotpSetup = async () => {
    if (!myAdminTotpSetup.code || myAdminTotpSetup.busy) return;
    setMyAdminTotpSetup((prev) => ({ ...prev, busy: true, error: "" }));
    try {
      const data = await request("/api/admins/me/totp/setup/confirm", "POST", token, { totpCode: myAdminTotpSetup.code });
      const codes = Array.isArray(data?.recoveryCodes) ? data.recoveryCodes : [];
      setMyAdminRecoveryCodesDisplay(codes.length ? codes : null);
      setMyAdminTotpSetup({
        loading: false,
        qrDataUrl: "",
        manualSecret: "",
        expiresAt: "",
        code: "",
        error: "",
        busy: false,
      });
      await loadMyAdminProfile();
    } catch (e) {
      setMyAdminTotpSetup((prev) => ({
        ...prev,
        busy: false,
        error: e?.message ? String(e.message) : String(e),
      }));
    }
  };

  const regenerateMyAdminRecoveryCodes = async () => {
    if (!myAdminRecoveryRegenerateCode.trim() || myAdminRecoveryRegenerateBusy) return;
    setMyAdminRecoveryRegenerateBusy(true);
    setMyAdminRecoveryRegenerateError("");
    try {
      const data = await request("/api/admins/me/totp/recovery-codes/regenerate", "POST", token, {
        totpCode: myAdminRecoveryRegenerateCode.trim(),
      });
      const codes = Array.isArray(data?.recoveryCodes) ? data.recoveryCodes : [];
      setMyAdminRecoveryCodesDisplay(codes.length ? codes : null);
      setMyAdminRecoveryRegenerateCode("");
      await loadMyAdminProfile();
    } catch (e) {
      setMyAdminRecoveryRegenerateError(e?.message ? String(e.message) : String(e));
    } finally {
      setMyAdminRecoveryRegenerateBusy(false);
    }
  };

  const disableMyAdminTotp = async () => {
    if (!myAdminTotpDisableCode || myAdminTotpDisableBusy) return;
    setMyAdminTotpDisableBusy(true);
    setMyAdminTotpDisableError("");
    try {
      await request("/api/admins/me/totp/disable", "POST", token, { totpCode: myAdminTotpDisableCode });
      setMyAdminTotpDisableCode("");
      setMyAdminTotpDisableModalOpen(false);
      await loadMyAdminProfile();
    } catch (e) {
      setMyAdminTotpDisableError(e?.message ? String(e.message) : String(e));
    } finally {
      setMyAdminTotpDisableBusy(false);
    }
  };

  useEffect(() => {
    if (!myAdminTotpSetupModalOpen || myAdminProfile?.totpEnabled) return;
    void startMyAdminTotpSetup();
  }, [myAdminTotpSetupModalOpen, myAdminProfile?.totpEnabled]);

  const loadPanelBackups = useCallback(async (opts = {}) => {
    const { syncFormFromServer = false, showLoading = true } = opts;
    const t = tokenRef.current;
    if (!t) return;
    if (showLoading) setPanelBackupsLoading(true);
    try {
      const data = await request("/api/panel/app-backups", "GET", t);
      setPanelBackupsData({
        settings: data.settings,
        backups: Array.isArray(data.backups) ? data.backups : [],
      });
      if (syncFormFromServer && data.settings) {
        setBackupFormInterval(Number(data.settings.intervalMinutes ?? 0));
        setBackupFormRetain(Number(data.settings.retainCount ?? 10));
      }
      setError("");
    } catch (e) {
      setError(e.message);
    } finally {
      if (showLoading) setPanelBackupsLoading(false);
    }
  }, []);

  const saveBackupSettingsHandler = useCallback(async () => {
    if (!token) return;
    setPanelBackupsSaving(true);
    try {
      await request("/api/panel/app-backups/settings", "PUT", token, {
        intervalMinutes: Math.max(0, Math.floor(Number(backupFormInterval))),
        retainCount: Math.max(1, Math.floor(Number(backupFormRetain))),
      });
      await loadPanelBackups({ syncFormFromServer: true, showLoading: false });
      setError("");
    } catch (e) {
      setError(e.message);
    } finally {
      setPanelBackupsSaving(false);
    }
  }, [token, backupFormInterval, backupFormRetain, loadPanelBackups]);

  const runBackupNowHandler = useCallback(async () => {
    if (!token) return;
    setPanelBackupsRunBusy(true);
    try {
      await request("/api/panel/app-backups/run", "POST", token);
      await loadPanelBackups({ showLoading: false });
      setError("");
    } catch (e) {
      setError(e.message);
    } finally {
      setPanelBackupsRunBusy(false);
    }
  }, [token, loadPanelBackups]);

  const deletePanelBackupHandler = useCallback(
    async () => {
      if (!token || !panelBackupDeleteModal.backupId) return;
      setPanelBackupDeleteModal((prev) => ({ ...prev, busy: true, error: "" }));
      try {
        await request(
          `/api/panel/app-backups/archives/${encodeURIComponent(panelBackupDeleteModal.backupId)}`,
          "DELETE",
          token,
        );
        await loadPanelBackups({ showLoading: false });
        setError("");
        setPanelBackupDeleteModal({ open: false, backupId: "", fileName: "", busy: false, error: "" });
      } catch (e) {
        setPanelBackupDeleteModal((prev) => ({
          ...prev,
          busy: false,
          error: e?.message ? String(e.message) : String(e),
        }));
      }
    },
    [token, panelBackupDeleteModal.backupId, loadPanelBackups],
  );

  const restoreFromArchiveHandler = useCallback(async () => {
    if (!token || !restoreFile) return;
    if (!restoreConfirm) return;
    setRestoreBusy(true);
    setRestoreMessage("");
    try {
      const fd = new FormData();
      fd.append("file", restoreFile);
      const res = await fetch(`${API_URL}/api/panel/app-backups/restore`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: fd,
      });
      if (res.status === 401 && token) {
        window.dispatchEvent(new Event(SESSION_INVALID_EVENT));
      }
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(body.error || "Восстановление не удалось");
      }
      setRestoreMessage(typeof body.message === "string" ? body.message : "Готово.");
      setRestoreFile(null);
      setRestoreConfirm(false);
      await loadData(ALL_PANEL_DATA_KEYS);
    } catch (e) {
      setError(e.message || String(e));
    } finally {
      setRestoreBusy(false);
    }
  }, [token, restoreFile, restoreConfirm]);

  const applyServerOpenVpnSettings = useCallback(async () => {
    if (!selectedServerId || !tokenRef.current) return;
    const rawConfig = rawConfigFromServerSettingsDiff(serverOpenVpnConfigDiff);
    if (!String(rawConfig).trim()) {
      setServerOpenVpnError("Нет текста конфигурации для применения.");
      return;
    }
    setServerOpenVpnApplying(true);
    setServerOpenVpnApplyLogVisible(true);
    setServerOpenVpnApplyLog("Запись server.conf и перезапуск OpenVPN...\n");
    setServerOpenVpnApplyResult({ status: "idle", message: "" });
    setServerOpenVpnError("");
    setServerOpenVpnHints([]);
    setError("");
    try {
      const data = await request(
        `/api/panel/nodes/${encodeURIComponent(selectedServerId)}/openvpn-settings-apply`,
        "POST",
        tokenRef.current,
        {
          rawConfig,
          settings: buildOpenVpnSettingsForPanelSave(serverOpenVpnSettings),
        },
      );
      const output = typeof data?.output === "string" ? data.output.trim() : "";
      setServerOpenVpnApplyLog(output || "(нет вывода)");
      setServerOpenVpnApplyResult({
        status: "success",
        message: data?.message || "Конфигурация записана, OpenVPN перезапущен.",
      });
      setServerAgentRawConfig(rawConfig);
      if (data?.settings && typeof data.settings === "object" && !Array.isArray(data.settings)) {
        const saved = { ...data.settings };
        for (const f of OPENVPN_SERVER_SETTINGS_FIELDS) {
          if (f.type === "textarea") {
            const v = saved[f.key];
            if (Array.isArray(v)) saved[f.key] = v;
            else if (typeof v === "string") saved[f.key] = v ? [v] : [];
            else saved[f.key] = [];
          }
        }
        setServerOpenVpnSettings(saved);
      }
    } catch (err) {
      const output = typeof err.output === "string" ? err.output.trim() : "";
      setServerOpenVpnApplyLog(output || String(err.message || "Применение не удалось"));
      setServerOpenVpnApplyResult({
        status: "error",
        message: err.message || "Применение конфигурации завершилось с ошибкой.",
      });
      setServerOpenVpnError(
        `${err.message || "Применение не удалось"}${output ? `\n\n${output}` : ""}`,
      );
      const hints = Array.isArray(err.hints) ? [...err.hints] : [];
      setServerOpenVpnHints(hints);
      throw err;
    } finally {
      setServerOpenVpnApplying(false);
    }
  }, [selectedServerId, serverOpenVpnConfigDiff, serverOpenVpnSettings]);

  const deleteServerOpenVpnClientVersion = useCallback(async () => {
    if (!selectedServerId || !tokenRef.current || !serverOpenVpnClientDeleteVersionModal.versionId) return;
    setServerOpenVpnClientDeleteVersionModal((prev) => ({ ...prev, busy: true, error: "" }));
    try {
      const data = await request(
        `/api/panel/nodes/${encodeURIComponent(selectedServerId)}/openvpn-client-config-versions/${encodeURIComponent(
          serverOpenVpnClientDeleteVersionModal.versionId,
        )}`,
        "DELETE",
        tokenRef.current,
      );
      const versions = Array.isArray(data?.versions) ? data.versions : [];
      const s = data?.settings && typeof data.settings === "object" && !Array.isArray(data.settings) ? data.settings : {};
      setServerOpenVpnClientVersions(versions);
      setServerOpenVpnClientSettings({ ...s });
      const activeVersionId = String(data?.activeVersionId || versions[0]?.id || "");
      setServerOpenVpnClientActiveVersionId(activeVersionId);
      setServerOpenVpnClientSelectedVersionId(activeVersionId);
      setServerOpenVpnClientDeleteVersionModal({
        open: false,
        versionId: "",
        versionLabel: "",
        busy: false,
        error: "",
      });
    } catch (err) {
      setServerOpenVpnClientDeleteVersionModal((prev) => ({
        ...prev,
        busy: false,
        error: err?.message || "Не удалось удалить версию конфигурации клиента",
      }));
    }
  }, [selectedServerId, serverOpenVpnClientDeleteVersionModal.versionId]);

  const applyServerOpenVpnClientSettings = useCallback(async () => {
    if (!selectedServerId || !tokenRef.current || !serverOpenVpnClientSelectedVersionId) return;
    setServerOpenVpnClientApplyConfirmModal((prev) => ({ ...prev, busy: true, error: "" }));
    try {
      const data = await request(
        `/api/panel/nodes/${encodeURIComponent(selectedServerId)}/openvpn-client-config-apply`,
        "POST",
        tokenRef.current,
        { versionId: serverOpenVpnClientSelectedVersionId },
      );
      const versions = Array.isArray(data?.versions) ? data.versions : [];
      const s = data?.settings && typeof data.settings === "object" && !Array.isArray(data.settings) ? data.settings : {};
      const activeVersionId = String(data?.activeVersionId || versions[0]?.id || "");
      setServerOpenVpnClientVersions(versions);
      setServerOpenVpnClientActiveVersionId(activeVersionId);
      setServerOpenVpnClientSelectedVersionId(activeVersionId);
      if (activeVersionId) {
        const hit = versions.find((v) => v.id === activeVersionId);
        const hitSettings = hit && hit.settings && typeof hit.settings === "object" && !Array.isArray(hit.settings)
          ? hit.settings
          : s;
        setServerOpenVpnClientSettings({ ...hitSettings });
      }
      setServerOpenVpnClientApplyConfirmModal({ open: false, busy: false, error: "" });
    } catch (err) {
      setServerOpenVpnClientApplyConfirmModal((prev) => ({
        ...prev,
        busy: false,
        error: err?.message || "Не удалось применить конфигурацию клиента",
      }));
    }
  }, [selectedServerId, serverOpenVpnClientSelectedVersionId]);

  const refreshServerNodeOpenvpnMaterials = useCallback(async (nodeId) => {
    if (!nodeId || !tokenRef.current) return;
    try {
      const [dhRows, tlsRows] = await Promise.all([
        request(
          `/api/panel/nodes/${encodeURIComponent(nodeId)}/openvpn-materials?kind=dh`,
          "GET",
          tokenRef.current,
        ),
        request(
          `/api/panel/nodes/${encodeURIComponent(nodeId)}/openvpn-materials?kind=tls_auth`,
          "GET",
          tokenRef.current,
        ),
      ]);
      setOpenvpnMaterialsDh(Array.isArray(dhRows) ? dhRows : []);
      setOpenvpnMaterialsTls(Array.isArray(tlsRows) ? tlsRows : []);
    } catch {
      setOpenvpnMaterialsDh([]);
      setOpenvpnMaterialsTls([]);
    }
  }, []);

  const persistOpenVpnPanelPartial = useCallback(
    async (partial) => {
      if (!selectedServerId || !tokenRef.current) return;
      await request(
        `/api/panel/nodes/${encodeURIComponent(selectedServerId)}/openvpn-settings`,
        "POST",
        tokenRef.current,
        { settings: partial },
      );
      setServerOpenVpnSettings((prev) => ({ ...prev, ...partial }));
    },
    [selectedServerId],
  );

  const saveServerOpenVpnClientSettings = useCallback(async () => {
    if (!selectedServerId || !tokenRef.current) return;
    setServerOpenVpnClientSaving(true);
    setServerOpenVpnClientError("");
    setError("");
    try {
      const partial = { ...buildOpenVpnClientConfigPayload(serverOpenVpnClientSettings) };
      for (const k of PANEL_CLIENT_PROFILE_KEYS) {
        if (!Object.prototype.hasOwnProperty.call(serverOpenVpnClientSettings, k)) continue;
        const v = serverOpenVpnClientSettings[k];
        if (typeof v === "boolean") partial[k] = v;
        else partial[k] = v === undefined || v === null ? "" : String(v);
      }
      await persistOpenVpnPanelPartial(partial);
      setServerOpenVpnSaveModal({
        open: true,
        text: "Параметры клиентского профиля сохранены в настройках узла.",
      });
    } catch (err) {
      setServerOpenVpnClientError(err?.message || "Не удалось сохранить конфигурацию клиента");
      throw err;
    } finally {
      setServerOpenVpnClientSaving(false);
    }
  }, [selectedServerId, serverOpenVpnClientSettings, persistOpenVpnPanelPartial]);

  const submitSrvCertCreate = async () => {
    const rid = String(serverOpenVpnSettings.panelRootCaId || "").trim();
    if (!selectedServerId || !rid || !tokenRef.current) return;
    const maxD = keysMaxServerCertValidityDays;
    if (maxD < 1) {
      setSrvCertCreateModal((prev) => ({
        ...prev,
        error: "Срок действия корневого сертификата недостаточен для выпуска сертификата",
      }));
      return;
    }
    let vd = Math.max(1, Math.floor(Number(srvCertCreateModal.validityDays) || 0));
    vd = Math.min(vd, maxD, 3650);
    const cn = String(srvCertCreateModal.cn || "").trim();
    if (!cn) {
      setSrvCertCreateModal((prev) => ({ ...prev, error: "Укажите Subject CN" }));
      return;
    }
    setSrvCertCreateModal((prev) => ({ ...prev, busy: true, error: "" }));
    try {
      const created = await request(
        `/api/panel/nodes/${encodeURIComponent(selectedServerId)}/server-certificate`,
        "POST",
        tokenRef.current,
        {
          rootCaId: rid,
          commonName: cn,
          validityDays: vd,
          keySize: Number(srvCertCreateModal.keySize) || 2048,
          signatureAlgorithm: srvCertCreateModal.signatureAlgorithm || "sha256",
        },
      );
      if (created?.id) {
        await persistOpenVpnPanelPartial(
          openvpnCertPathsPartial(serverOpenVpnSettings, { panelServerCertId: created.id }),
        );
      }
      await loadData(PANEL_DATA_REFRESH.certificates);
      setSrvCertCreateModal({
        open: false,
        cn: "",
        validityDays: 825,
        keySize: "2048",
        signatureAlgorithm: "sha256",
        busy: false,
        error: "",
      });
    } catch (e) {
      setSrvCertCreateModal((prev) => ({
        ...prev,
        busy: false,
        error: e.message || "Не удалось выпустить сертификат",
      }));
    }
  };

  const submitServerCaIssueCertificate = async () => {
    const rid = String(panelRootCaIdForServer || "").trim();
    const nodeId = String(selectedServerId || "").trim();
    const auth = tokenRef.current;
    if (!rid || !nodeId || !auth) return;
    const commonName = String(serverCaIssueModal.commonName || "").trim();
    if (!commonName) {
      setServerCaIssueModal((prev) => ({ ...prev, error: "Укажите Subject CN" }));
      return;
    }
    const daysRaw = parseInt(String(serverCaIssueModal.validityDays || "").trim(), 10);
    const days = Number.isFinite(daysRaw) && daysRaw > 0 ? daysRaw : 365;
    const expiresAt = new Date(Date.now() + days * 86400000).toISOString();
    setServerCaIssueModal((prev) => ({ ...prev, busy: true, error: "" }));
    try {
      await request("/api/certificates", "POST", auth, {
        vpnUserId: null,
        commonName,
        rootCaId: rid,
        agentNodeId: nodeId,
        expiresAt,
      });
      await loadData(PANEL_DATA_REFRESH.certificates);
      setServerCaIssueModal({
        open: false,
        commonName: "",
        validityDays: "365",
        busy: false,
        error: "",
      });
    } catch (e) {
      setServerCaIssueModal((prev) => ({
        ...prev,
        busy: false,
        error: e?.message || "Не удалось выпустить сертификат",
      }));
    }
  };

  const submitServerCaImportCertificate = async () => {
    const rid = String(panelRootCaIdForServer || "").trim();
    const nodeId = String(selectedServerId || "").trim();
    const auth = tokenRef.current;
    if (!rid || !nodeId || !auth) return;
    const certPem = String(serverCaImportModal.certPem || "").trim();
    const keyPem = String(serverCaImportModal.keyPem || "").trim();
    if (!certPem || !keyPem) {
      setServerCaImportModal((prev) => ({ ...prev, error: "Заполните поля сертификата и приватного ключа." }));
      return;
    }
    setServerCaImportModal((prev) => ({ ...prev, busy: true, error: "" }));
    try {
      await request("/api/certificates/import", "POST", auth, {
        rootCaId: rid,
        agentNodeId: nodeId,
        certPem,
        keyPem,
      });
      await loadData(PANEL_DATA_REFRESH.certificates);
      setServerCaImportModal({
        open: false,
        certPem: "",
        keyPem: "",
        busy: false,
        error: "",
      });
    } catch (e) {
      setServerCaImportModal((prev) => ({
        ...prev,
        busy: false,
        error: e?.message || "Не удалось импортировать сертификат",
      }));
    }
  };

  const bindServerPanelRootCa = async (rootCaId) => {
    const rid = String(rootCaId || "").trim();
    if (!rid || !selectedServerId || !tokenRef.current) return;
    setServerBindRootCaBusy(true);
    try {
      setError("");
      await persistOpenVpnPanelPartial(
        openvpnCertPathsPartial(serverOpenVpnSettings, { panelRootCaId: rid, panelServerCertId: "" }),
      );
      await loadData(PANEL_DATA_REFRESH.certificates);
    } catch (err) {
      setError(err?.message || String(err));
    } finally {
      setServerBindRootCaBusy(false);
    }
  };

  const submitServerCaImportIndex = async () => {
    const rid = String(panelRootCaIdForServer || "").trim();
    const nodeId = String(selectedServerId || "").trim();
    const auth = tokenRef.current;
    if (!rid || !nodeId || !auth) return;
    const issuedList = String(serverCaIndexImportModal.indexText || "").trim();
    if (!issuedList) {
      setServerCaIndexImportModal((prev) => ({ ...prev, error: "Вставьте содержимое файла index.txt." }));
      return;
    }
    setServerCaIndexImportModal((prev) => ({ ...prev, busy: true, error: "" }));
    try {
      await request(`/api/certificates/root-ca/${encodeURIComponent(rid)}/import-index`, "POST", auth, {
        issuedList,
        agentNodeId: nodeId,
      });
      await loadData(PANEL_DATA_REFRESH.certificates);
      setServerCaIndexImportModal({
        open: false,
        indexText: "",
        busy: false,
        error: "",
      });
    } catch (e) {
      setServerCaIndexImportModal((prev) => ({
        ...prev,
        busy: false,
        error: e?.message || "Не удалось загрузить index.txt",
      }));
    }
  };

  const onServerCaIndexFileChange = (file) => {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      setServerCaIndexImportModal((prev) => ({
        ...prev,
        indexText: String(reader.result || ""),
        error: "",
      }));
    };
    reader.onerror = () => {
      setServerCaIndexImportModal((prev) => ({ ...prev, error: "Не удалось прочитать файл index.txt" }));
    };
    reader.readAsText(file);
  };

  const submitSrvCertImport = async () => {
    const rid = String(serverOpenVpnSettings.panelRootCaId || "").trim();
    if (!selectedServerId || !rid || !tokenRef.current) return;
    setSrvCertImportModal((prev) => ({ ...prev, busy: true, error: "" }));
    try {
      const created = await request(
        `/api/panel/nodes/${encodeURIComponent(selectedServerId)}/server-certificate-import`,
        "POST",
        tokenRef.current,
        { rootCaId: rid, certPem: srvCertImportModal.certPem, keyPem: srvCertImportModal.keyPem },
      );
      if (created?.id) {
        await persistOpenVpnPanelPartial(
          openvpnCertPathsPartial(serverOpenVpnSettings, { panelServerCertId: created.id }),
        );
      }
      await loadData(PANEL_DATA_REFRESH.certificates);
      setSrvCertImportModal({ open: false, certPem: "", keyPem: "", busy: false, error: "" });
    } catch (e) {
      setSrvCertImportModal((prev) => ({
        ...prev,
        busy: false,
        error: e.message || "Не удалось импортировать",
      }));
    }
  };

  const submitDeleteServerServerCert = async () => {
    if (!selectedServerId || !tokenRef.current) return;
    setServerServerCertDeleteModal((prev) => ({ ...prev, busy: true, error: "" }));
    try {
      await request(
        `/api/panel/nodes/${encodeURIComponent(selectedServerId)}/server-certificate`,
        "DELETE",
        tokenRef.current,
      );
      await loadData(PANEL_DATA_REFRESH.certificates);
      setServerServerCertDeleteModal({ open: false, busy: false, error: "" });
    } catch (e) {
      setServerServerCertDeleteModal((prev) => ({
        ...prev,
        busy: false,
        error: e.message || "Не удалось удалить сертификат сервера",
      }));
    }
  };

  const submitDeleteOpenvpnMaterial = async () => {
    const mid = openvpnMaterialDeleteModal.id;
    if (!mid || !tokenRef.current || !selectedServerId) return;
    setOpenvpnMaterialDeleteModal((prev) => ({ ...prev, busy: true, error: "" }));
    try {
      await request(
        `/api/panel/nodes/${encodeURIComponent(selectedServerId)}/openvpn-materials/${encodeURIComponent(mid)}`,
        "DELETE",
        tokenRef.current,
      );
      await refreshServerNodeOpenvpnMaterials(selectedServerId);
      const partial = {};
      if (String(serverOpenVpnSettings.panelDhMaterialId || "") === String(mid)) partial.panelDhMaterialId = "";
      if (String(serverOpenVpnSettings.panelTlsAuthMaterialId || "") === String(mid))
        partial.panelTlsAuthMaterialId = "";
      if (Object.keys(partial).length) await persistOpenVpnPanelPartial(partial);
      await loadData(PANEL_DATA_REFRESH.certificates);
      setOpenvpnMaterialDeleteModal({ open: false, id: null, kindLabel: "", busy: false, error: "" });
    } catch (err) {
      setOpenvpnMaterialDeleteModal((prev) => ({
        ...prev,
        busy: false,
        error: err.message || "Удаление не удалось",
      }));
    }
  };

  const openServiceActionConfirm = useCallback((action) => {
    setServiceActionResult("");
    setServiceActionModal({ open: true, action, busy: false, error: "" });
  }, []);

  const submitServiceAction = useCallback(async () => {
    if (!selectedServerId || !tokenRef.current || !serviceActionModal.action) return;
    setServiceActionModal((prev) => ({ ...prev, busy: true, error: "" }));
    try {
      const data = await request(
        `/api/panel/nodes/${encodeURIComponent(selectedServerId)}/openvpn-service`,
        "POST",
        tokenRef.current,
        { action: serviceActionModal.action },
      );
      setServiceActionResult(
        `Команда "${serviceActionModal.action}" выполнена${data?.output ? `: ${data.output}` : "."}`,
      );
      setServiceActionModal({ open: false, action: "", busy: false, error: "" });
      loadData(PANEL_DATA_REFRESH.servers);
    } catch (err) {
      const details = typeof err.output === "string" && err.output ? `\n${err.output}` : "";
      setServiceActionModal((prev) => ({
        ...prev,
        busy: false,
        error: `${err.message || "Операция не выполнена"}${details}`,
      }));
    }
  }, [selectedServerId, serviceActionModal.action]);

  const loadServerServicesAndDns = useCallback(async () => {
    if (!selectedServerId || !tokenRef.current) return;
    setSystemServicesLoading(true);
    setSystemServicesError("");
    setDnsmasqState((prev) => ({ ...prev, loading: true, error: "", queueMessage: "" }));
    try {
      const [servicesData, dnsData] = await Promise.all([
        request(`/api/panel/nodes/${encodeURIComponent(selectedServerId)}/system-services`, "GET", tokenRef.current),
        request(`/api/panel/nodes/${encodeURIComponent(selectedServerId)}/dnsmasq`, "GET", tokenRef.current),
      ]);
      setSystemServicesRows(Array.isArray(servicesData?.services) ? servicesData.services : []);
      setDnsmasqState((prev) => ({
        ...prev,
        loading: false,
      }));
      setDnsmasqDraft(parseDnsmasqConfigToDraft(dnsData?.config || ""));
    } catch (err) {
      setSystemServicesError(err.message || "Не удалось загрузить список служб");
      setDnsmasqState((prev) => ({
        ...prev,
        loading: false,
        error: err.message || "Не удалось загрузить DNSMasq",
      }));
    } finally {
      setSystemServicesLoading(false);
    }
  }, [selectedServerId]);

  const submitEnqueueDnsmasqApply = useCallback(async () => {
    if (!selectedServerId || !tokenRef.current) return;
    setDnsmasqState((prev) => ({ ...prev, applyBusy: true, error: "", queueMessage: "" }));
    try {
      const data = await request(
        `/api/panel/nodes/${encodeURIComponent(selectedServerId)}/dnsmasq/apply-task`,
        "POST",
        tokenRef.current,
        { config: buildDnsmasqTextFromDraft(dnsmasqDraft) },
      );
      setDnsmasqState((prev) => ({
        ...prev,
        applyBusy: false,
        queueMessage:
          typeof data?.message === "string" && data.message.trim()
            ? data.message.trim()
            : "Задача применения DNSMasq поставлена в очередь.",
      }));
    } catch (err) {
      setDnsmasqState((prev) => ({
        ...prev,
        applyBusy: false,
        error: err.message || "Не удалось поставить задачу в очередь",
      }));
    }
  }, [selectedServerId, dnsmasqDraft]);

  const newDnsRuleDraftByType = useCallback((type) => {
    const t = String(type || "domain-resolver");
    if (t === "domain-resolver") return { domain: "", targetDns: "" };
    if (t === "cache") return { cacheSize: "" };
    if (t === "ip-override") return { domain: "", ip: "" };
    if (t === "arbitrary-address") return { ip: "" };
    if (t === "forward") return { targetDns: "" };
    if (t === "hosts-file") return { path: "" };
    if (t === "listen-interface") return { iface: "" };
    return {};
  }, []);

  const openDnsRuleModal = useCallback((rule = null) => {
    const type = String(rule?.type || "domain-resolver");
    setDnsRuleModal({
      open: true,
      editId: String(rule?.id || ""),
      type,
      draft: rule ? { ...rule } : newDnsRuleDraftByType(type),
      error: "",
    });
  }, [newDnsRuleDraftByType]);

  const submitDnsRuleModal = useCallback(() => {
    const t = String(dnsRuleModal.type || "");
    const d = dnsRuleModal.draft || {};
    const requiredOk =
      (t === "domain-resolver" && String(d.domain || "").trim() && String(d.targetDns || "").trim()) ||
      (t === "cache" && String(d.cacheSize || "").trim()) ||
      (t === "ip-override" && String(d.domain || "").trim() && String(d.ip || "").trim()) ||
      (t === "arbitrary-address" && String(d.ip || "").trim()) ||
      (t === "forward" && String(d.targetDns || "").trim()) ||
      (t === "hosts-file" && String(d.path || "").trim()) ||
      (t === "listen-interface" && String(d.iface || "").trim());
    if (!requiredOk) {
      setDnsRuleModal((prev) => ({ ...prev, error: "Заполните обязательные поля для выбранного типа." }));
      return;
    }
    if (dnsRuleModal.editId) {
      setDnsmasqDraft((prev) => prev.map((r) => (r.id === dnsRuleModal.editId ? { ...r, ...d, type: t } : r)));
    } else {
      setDnsmasqDraft((prev) => [...prev, { id: `dns-${Date.now()}`, type: t, ...newDnsRuleDraftByType(t), ...d }]);
    }
    setDnsRuleModal({ open: false, editId: "", type: "domain-resolver", draft: {}, error: "" });
  }, [dnsRuleModal, newDnsRuleDraftByType]);

  const submitAgentUpdate = useCallback(async () => {
    if (!selectedServerId || !tokenRef.current || !agentUpdateBinaryBase64) return;
    setAgentUpdateBusy(true);
    setAgentUpdateError("");
    setAgentUpdateResult("");
    setAgentUpdateJournalTail("");
    setAgentUpdateUploadPct(0);
    try {
      const data = await postJsonWithUploadProgress(
        `/api/panel/nodes/${encodeURIComponent(selectedServerId)}/agent-update`,
        tokenRef.current,
        {
          fileName: agentUpdateFileName || "agent",
          binaryBase64: agentUpdateBinaryBase64,
          checksumSha256: agentUpdateSha256,
        },
        (p) =>
          setAgentUpdateUploadPct((prev) => Math.max(prev, Math.min(100, Math.round(p * 100)))),
      );
      setAgentUpdateResult(
        typeof data?.message === "string" && data.message
          ? data.message
          : typeof data?.output === "string" && data.output
            ? data.output
            : "Обновление агента выполнено.",
      );
      if (typeof data?.journalTail === "string" && data.journalTail.trim()) {
        setAgentUpdateJournalTail(data.journalTail.trim());
      }
      setAgentUpdateFileName("");
      setAgentUpdateSha256("");
      setAgentUpdateBinaryBase64("");
      await loadData(PANEL_DATA_REFRESH.servers);
    } catch (err) {
      setAgentUpdateUploadPct(0);
      const extra = typeof err.output === "string" && err.output ? `: ${err.output}` : "";
      setAgentUpdateError(`${err.message || "Обновление не выполнено"}${extra}`);
    } finally {
      setAgentUpdateBusy(false);
    }
  }, [selectedServerId, agentUpdateBinaryBase64, agentUpdateFileName, agentUpdateSha256]);

  const loadUserProfileSessions = useCallback(async () => {
    const uid = selectedUserId;
    const auth = tokenRef.current;
    if (!uid || !auth) return;
    try {
      const rows = await request(`/api/vpn-users/${encodeURIComponent(uid)}/vpn-sessions`, "GET", auth);
      setUserProfileSessions(Array.isArray(rows) ? rows : []);
    } catch {
      setUserProfileSessions([]);
    }
  }, [selectedUserId]);

  const openUserSessionDisconnect = useCallback((nodeId, nodeName, sessionId, profileFullName) => {
    userSessionDisconnectTargetRef.current = { nodeId, sessionId };
    const { sessionNumber } = openvpnSessionIdParts(sessionId);
    setUserSessionDisconnectModal({
      open: true,
      nodeName: nodeName || "",
      sessionNumber,
      profileName: profileFullName || "",
      busy: false,
      error: "",
    });
  }, []);

  const submitUserSessionDisconnect = useCallback(async () => {
    const { nodeId, sessionId } = userSessionDisconnectTargetRef.current;
    if (!nodeId || !sessionId || !tokenRef.current) return;
    const sessionKey = `${nodeId}-${sessionId}`;
    setDisconnectingSessionKeys((prev) => {
      const next = prev.includes(sessionKey) ? prev : [...prev, sessionKey];
      try {
        localStorage.setItem(DISCONNECTING_SESSIONS_STORAGE_KEY, JSON.stringify(next));
      } catch {
        /* ignore */
      }
      return next;
    });
    setUserSessionDisconnectModal((m) => ({ ...m, busy: true, error: "" }));
    try {
      await request(
        `/api/clients/${encodeURIComponent(nodeId)}/${encodeURIComponent(sessionId)}/disconnect`,
        "POST",
        tokenRef.current,
      );
      userSessionDisconnectTargetRef.current = { nodeId: "", sessionId: "" };
      setUserSessionDisconnectModal({
        open: false,
        nodeName: "",
        sessionNumber: "",
        profileName: "",
        busy: false,
        error: "",
      });
      await loadData(PANEL_DATA_REFRESH.clients);
      await loadUserProfileSessions();
    } catch (err) {
      setDisconnectingSessionKeys((prev) => {
        const next = prev.filter((x) => x !== sessionKey);
        try {
          localStorage.setItem(DISCONNECTING_SESSIONS_STORAGE_KEY, JSON.stringify(next));
        } catch {
          /* ignore */
        }
        return next;
      });
      setUserSessionDisconnectModal((m) => ({
        ...m,
        busy: false,
        error: err.message || "Не удалось завершить сессию",
      }));
    }
  }, [selectedUserId, loadData, loadUserProfileSessions]);

  useEffect(() => {
    const activeKeys = new Set();
    for (const row of nodeSessions) {
      activeKeys.add(`${row.nodeId}-${row.id}`);
    }
    for (const row of userProfileSessions) {
      if (row.isActive) activeKeys.add(`${row.nodeId}-${row.sessionId}`);
    }
    setDisconnectingSessionKeys((prev) => {
      const next = prev.filter((k) => activeKeys.has(k));
      const changed = next.length !== prev.length || next.some((k, i) => k !== prev[i]);
      if (!changed) return prev;
      try {
        localStorage.setItem(DISCONNECTING_SESSIONS_STORAGE_KEY, JSON.stringify(next));
      } catch {
        /* ignore */
      }
      return next;
    });
  }, [nodeSessions, userProfileSessions]);

  const checkOpenvpnConfig = useCallback(async () => {
    if (!selectedServerId || !tokenRef.current) return;
    setServiceCheckBusy(true);
    try {
      const data = await request(
        `/api/panel/nodes/${encodeURIComponent(selectedServerId)}/openvpn-check-config`,
        "POST",
        tokenRef.current,
        { settings: buildOpenVpnSettingsForPanelSave(serverOpenVpnSettings) },
      );
      const command = String(data?.command || "").trim();
      const configPath = String(data?.configPath || "").trim();
      const checkedSource = String(data?.checkedSource || "").trim();
      const output = String(data?.output || "").trim();
      const details = [
        command ? `$ ${command}` : "",
        output || "(пустой вывод)",
        configPath ? `config: ${configPath}` : "",
        checkedSource ? `источник: ${checkedSource}` : "",
      ]
        .filter(Boolean)
        .join("\n\n");
      setOpenvpnCheckModal({
        open: true,
        title: "Проверка конфигурации",
        message: data?.message || "Конфигурация прошла проверку.",
        details,
        hints: [],
        success: true,
      });
    } catch (err) {
      const command = String(err.command || "").trim();
      const configPath = String(err.configPath || "").trim();
      const output = String(err.output || err.message || "").trim();
      const details = [
        command ? `$ ${command}` : "",
        output || "(пустой вывод)",
        configPath ? `config: ${configPath}` : "",
      ]
        .filter(Boolean)
        .join("\n\n");
      setOpenvpnCheckModal({
        open: true,
        title: "Проверка конфигурации",
        message: err.message || "Проверка не выполнена",
        details,
        hints: Array.isArray(err.hints) ? err.hints : [],
        success: false,
      });
    } finally {
      setServiceCheckBusy(false);
    }
  }, [selectedServerId, serverOpenVpnSettings]);

  useEffect(() => {
    if (!token) return undefined;
    const keys = panelDataKeysForRoute(route);
    const intervalMs = panelDataPollIntervalMs(route);
    if (!keys.length || intervalMs <= 0) return undefined;

    const tick = () => {
      if (typeof document !== "undefined" && document.hidden) return;
      void refreshPanelData(keys);
    };
    tick();
    const timer = setInterval(tick, intervalMs);
    const onVisible = () => {
      if (!document.hidden) tick();
    };
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [token, panelDataRouteKey(route), refreshPanelData]);

  useEffect(() => {
    setAgentUpdateFileName("");
    setAgentUpdateSha256("");
    setAgentUpdateBinaryBase64("");
    setAgentUpdateResult("");
    setAgentUpdateError("");
  }, [selectedServerId]);

  useEffect(() => {
    if (primaryNav !== "servers" || serversView !== "detail" || serverDetailTab !== "overview") {
      setAgentUpdateFileName("");
      setAgentUpdateSha256("");
      setAgentUpdateBinaryBase64("");
      setAgentUpdateResult("");
      setAgentUpdateError("");
    }
  }, [primaryNav, serversView, serverDetailTab]);

  useEffect(() => {
    if (primaryNav !== "users" || usersSub !== "profile" || userProfileTab !== "sessions" || !selectedUserId || !token) {
      return undefined;
    }
    void loadUserProfileSessions();
    const timer = setInterval(() => {
      if (typeof document !== "undefined" && document.hidden) return;
      void loadUserProfileSessions();
    }, 3000);
    return () => clearInterval(timer);
  }, [primaryNav, usersSub, userProfileTab, selectedUserId, token, loadUserProfileSessions]);

  useEffect(() => {
    setTablePages((prev) => ({ ...prev, serverSessions: 1 }));
  }, [serverSessionsSearch]);

  useEffect(() => {
    if (primaryNav !== "users" || usersSub !== "profile" || userProfileTab !== "certs" || !selectedUserId || !token) {
      return undefined;
    }
    let cancelled = false;
    (async () => {
      try {
        const data = await request(
          `/api/vpn-users/${encodeURIComponent(selectedUserId)}/connection-profile/options`,
          "GET",
          token,
        );
        if (cancelled) return;
        const certs = Array.isArray(data?.certificates) ? data.certificates : [];
        const servers = Array.isArray(data?.servers) ? data.servers : [];
        setUserConnectionProfileOptions({
          certificates: certs,
          servers,
          defaultEmail: String(data?.defaultEmail || ""),
        });
        setUserConnectionProfileDraft((prev) => ({
          certificateId: certs[0]?.id || "",
          serverId: "",
          email: prev.email || String(data?.defaultEmail || ""),
        }));
      } catch {
        if (cancelled) return;
        setUserConnectionProfileOptions({ certificates: [], servers: [], defaultEmail: "" });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [primaryNav, usersSub, userProfileTab, selectedUserId, token]);

  useEffect(() => {
    if (
      primaryNav !== "servers" ||
      serversView !== "detail" ||
      (serverDetailTab !== "settings" &&
        serverDetailTab !== "ca-center" &&
        serverDetailTab !== "keys" &&
        serverDetailTab !== "certificates") ||
      !selectedServerId ||
      !isAuthorized
    ) {
      return undefined;
    }
    const auth = tokenRef.current;
    if (!auth) return undefined;
    let cancelled = false;
    (async () => {
      setServerOpenVpnLoading(true);
      setServerOpenVpnError("");
      setServerOpenVpnHints([]);
      try {
        const data = await request(
          `/api/panel/nodes/${encodeURIComponent(selectedServerId)}/openvpn-settings`,
          "GET",
          auth,
        );
        if (cancelled) return;
        const s = { ...(data.settings || {}) };
        for (const f of OPENVPN_SERVER_SETTINGS_FIELDS) {
          if (f.type === "textarea") {
            const v = s[f.key];
            if (Array.isArray(v)) s[f.key] = v;
            else if (typeof v === "string") s[f.key] = v ? [v] : [];
            else s[f.key] = [];
          }
        }
        setServerOpenVpnSettings(s);
        setServerOpenVpnConfigPath(data.configPath || "");
        setServerOpenVpnHints(Array.isArray(data.hints) ? data.hints : []);
      } catch (err) {
        if (cancelled) return;
        setServerOpenVpnSettings({});
        setServerOpenVpnConfigPath("");
        setServerOpenVpnError(err.message || "Ошибка загрузки настроек");
        setServerOpenVpnHints(Array.isArray(err.hints) ? err.hints : []);
      } finally {
        if (!cancelled) setServerOpenVpnLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [primaryNav, serversView, serverDetailTab, selectedServerId, isAuthorized]);

  useEffect(() => {
    if (
      primaryNav !== "servers" ||
      serversView !== "detail" ||
      serverDetailTab !== "client" ||
      !selectedServerId ||
      !isAuthorized
    ) {
      return undefined;
    }
    const auth = tokenRef.current;
    if (!auth) return undefined;
    let cancelled = false;
    (async () => {
      setServerOpenVpnClientLoading(true);
      setServerOpenVpnClientError("");
      try {
        const data = await request(
          `/api/panel/nodes/${encodeURIComponent(selectedServerId)}/openvpn-settings`,
          "GET",
          auth,
        );
        if (cancelled) return;
        const all = data?.settings && typeof data.settings === "object" && !Array.isArray(data.settings) ? data.settings : {};
        const merged = {};
        for (const f of OPENVPN_CLIENT_SETTINGS_FIELDS) {
          if (Object.prototype.hasOwnProperty.call(all, f.key)) merged[f.key] = all[f.key];
        }
        for (const k of PANEL_CLIENT_PROFILE_KEYS) {
          if (Object.prototype.hasOwnProperty.call(all, k)) merged[k] = all[k];
        }
        setServerOpenVpnClientSettings(merged);
        setServerOpenVpnClientVersions([]);
        setServerOpenVpnClientActiveVersionId("");
        setServerOpenVpnClientSelectedVersionId("");
      } catch (err) {
        if (cancelled) return;
        setServerOpenVpnClientSettings({});
        setServerOpenVpnClientVersions([]);
        setServerOpenVpnClientActiveVersionId("");
        setServerOpenVpnClientSelectedVersionId("");
        setServerOpenVpnClientError(err?.message || "Ошибка загрузки конфигурации клиента");
      } finally {
        if (!cancelled) setServerOpenVpnClientLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [primaryNav, serversView, serverDetailTab, selectedServerId, isAuthorized]);

  useEffect(() => {
    if (
      primaryNav !== "servers" ||
      serversView !== "detail" ||
      serverDetailTab !== "settings" ||
      !selectedServerId ||
      !isAuthorized
    ) {
      return undefined;
    }
    const auth = tokenRef.current;
    if (!auth) return undefined;
    let cancelled = false;
    (async () => {
      setServerAgentRawLoading(true);
      try {
        const data = await request(
          `/api/panel/nodes/${encodeURIComponent(selectedServerId)}/openvpn-raw-config`,
          "GET",
          auth,
        );
        if (!cancelled) setServerAgentRawConfig(typeof data?.rawConfig === "string" ? data.rawConfig : "");
      } catch {
        if (!cancelled) setServerAgentRawConfig("");
      } finally {
        if (!cancelled) setServerAgentRawLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [primaryNav, serversView, serverDetailTab, selectedServerId, isAuthorized, serverOpenVpnSettings]);

  useEffect(() => {
    if (
      primaryNav !== "servers" ||
      serversView !== "detail" ||
      (serverDetailTab !== "settings" &&
        serverDetailTab !== "keys" &&
        serverDetailTab !== "certificates") ||
      !selectedServerId ||
      !token
    ) {
      return undefined;
    }
    let cancelled = false;
    (async () => {
      try {
        const [dhRows, tlsRows] = await Promise.all([
          request(
            `/api/panel/nodes/${encodeURIComponent(selectedServerId)}/openvpn-materials?kind=dh`,
            "GET",
            token,
          ),
          request(
            `/api/panel/nodes/${encodeURIComponent(selectedServerId)}/openvpn-materials?kind=tls_auth`,
            "GET",
            token,
          ),
        ]);
        if (!cancelled) {
          setOpenvpnMaterialsDh(Array.isArray(dhRows) ? dhRows : []);
          setOpenvpnMaterialsTls(Array.isArray(tlsRows) ? tlsRows : []);
        }
      } catch {
        if (!cancelled) {
          setOpenvpnMaterialsDh([]);
          setOpenvpnMaterialsTls([]);
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [primaryNav, serversView, serverDetailTab, selectedServerId, token]);

  useEffect(() => {
    if (
      primaryNav !== "servers" ||
      serversView !== "detail" ||
      serverDetailTab !== "certificates" ||
      !selectedServerId
    ) {
      return undefined;
    }
    if (!panelRootCaIdForServer) {
      setServerRootCaSummary({ loading: false, data: null });
      return undefined;
    }
    const auth = tokenRef.current;
    if (!auth) return undefined;
    let cancelled = false;
    setServerRootCaSummary((prev) => {
      const prevId = prev.data?.id ? String(prev.data.id).trim() : "";
      const keepData = Boolean(prev.data) && prevId === panelRootCaIdForServer;
      return { loading: true, data: keepData ? prev.data : null };
    });
    (async () => {
      try {
        const data = await request(
          `/api/certificates/root-ca/${encodeURIComponent(panelRootCaIdForServer)}/summary`,
          "GET",
          auth,
        );
        if (!cancelled) setServerRootCaSummary({ loading: false, data });
      } catch {
        if (!cancelled) {
          setServerRootCaSummary((prev) => ({
            loading: false,
            data: prev.data,
          }));
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [primaryNav, serversView, serverDetailTab, selectedServerId, panelRootCaIdForServer]);

  useEffect(() => {
    if (
      primaryNav !== "servers" ||
      serversView !== "detail" ||
      serverDetailTab !== "certificates" ||
      !selectedServerId
    ) {
      return undefined;
    }
    if (!panelRootCaIdForServer) {
      setServerPanelServerCertMaterials({});
      return undefined;
    }
    const certId = serverPanelDisplayedServerCert?.id;
    if (!certId) {
      setServerPanelServerCertMaterials({});
      return undefined;
    }
    const auth = tokenRef.current;
    if (!auth) return undefined;
    let cancelled = false;
    (async () => {
      try {
        const row = await request(
          `/api/certificates/${encodeURIComponent(certId)}/material-summary`,
          "GET",
          auth,
        );
        if (!cancelled) setServerPanelServerCertMaterials({ [certId]: row });
      } catch {
        if (!cancelled) setServerPanelServerCertMaterials({ [certId]: null });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [
    primaryNav,
    serversView,
    serverDetailTab,
    selectedServerId,
    panelRootCaIdForServer,
    serverPanelDisplayedServerCert?.id,
  ]);

  useEffect(() => {
    if (
      primaryNav !== "servers" ||
      serversView !== "detail" ||
      serverDetailTab !== "journal" ||
      !selectedServerId ||
      !isAuthorized
    ) {
      return undefined;
    }
    const auth = tokenRef.current;
    if (!auth) return undefined;
    let cancelled = false;
    (async () => {
      setJournalLogsLoading(true);
      try {
        const q = new URLSearchParams();
        q.set("page", String(journalLogsPage));
        q.set("pageSize", String(journalLogsPageSize));
        if (journalQuery.trim()) q.set("q", journalQuery.trim());
        const data = await request(
          `/api/panel/nodes/${encodeURIComponent(selectedServerId)}/openvpn-logs?${q.toString()}`,
          "GET",
          auth,
        );
        if (cancelled) return;
        setJournalLogsRows(Array.isArray(data.rows) ? data.rows : []);
        setJournalLogsTotal(Number(data.total || 0));
        setJournalLogsTotalPages(Math.max(1, Number(data.totalPages || 1)));
      } catch (err) {
        if (cancelled) return;
        setJournalLogsRows([]);
        setJournalLogsTotal(0);
        setJournalLogsTotalPages(1);
        setError(err.message || "Ошибка загрузки журнала OpenVPN");
      } finally {
        if (!cancelled) setJournalLogsLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [
    primaryNav,
    serversView,
    serverDetailTab,
    selectedServerId,
    isAuthorized,
    journalLogsPage,
    journalLogsPageSize,
    journalQuery,
  ]);

  useEffect(() => {
    if (
      primaryNav !== "servers" ||
      serversView !== "detail" ||
      (serverDetailTab !== "services" && serverDetailTab !== "dns") ||
      !selectedServerId ||
      !isAuthorized
    ) {
      return;
    }
    void loadServerServicesAndDns();
  }, [primaryNav, serversView, serverDetailTab, selectedServerId, isAuthorized, loadServerServicesAndDns]);

  useEffect(() => {
    if (
      primaryNav !== "servers" ||
      serversView !== "detail" ||
      serverDetailTab !== "services" ||
      !selectedServerId ||
      !isAuthorized
    ) {
      return undefined;
    }
    let cancelled = false;
    const poll = async () => {
      if (!selectedServerId || !tokenRef.current) return;
      try {
        const servicesData = await request(
          `/api/panel/nodes/${encodeURIComponent(selectedServerId)}/system-services`,
          "GET",
          tokenRef.current,
        );
        if (cancelled) return;
        setSystemServicesRows(Array.isArray(servicesData?.services) ? servicesData.services : []);
        setSystemServicesError("");
      } catch (err) {
        if (!cancelled) {
          setSystemServicesError(err.message || "Не удалось обновить список служб");
        }
      }
    };
    const id = setInterval(() => void poll(), 3000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [primaryNav, serversView, serverDetailTab, selectedServerId, isAuthorized]);

  useEffect(() => {
    if (!selectedUserId) return;
    const u = vpnUsers.find((x) => x.id === selectedUserId);
    if (!u) return;
    setUserProfileDraft({
      fullName: u.fullName || "",
      position: u.position || "",
      email: u.email || "",
      phone: u.phone || "",
      organizationId: u.organizationId || "",
      notes: u.notes || "",
    });
  }, [selectedUserId, vpnUsers]);

  useEffect(() => {
    setUserCertBindModalOpen(false);
    setUserCertIssueModalOpen(false);
    setUserCertBindServerId("");
    setUserCertBindSelectedCertId("");
    setUserCertBindBusy(false);
    setProfileIssueCert({ commonName: "", serverId: "", validityDays: "1825" });
  }, [selectedUserId, primaryNav, usersSub]);

  useEffect(() => {
    if (!selectedRootCaId) return;
    setNewUserCert((prev) => ({ ...prev, rootCaId: selectedRootCaId }));
  }, [selectedRootCaId]);

  useEffect(() => {
    if (primaryNav !== "organizations" || organizationsView !== "edit" || !organizationEditId) {
      organizationFirewallHydratedForIdRef.current = null;
      return;
    }
    const org = organizations.find((o) => o.id === organizationEditId);
    if (!org) return;
    setEditOrganization({
      id: org.id,
      name: org.name || "",
      inn: org.inn || "",
      legalAddress: org.legalAddress || "",
      generalDirector: org.generalDirector || "",
      phone: org.phone || "",
      email: org.email || "",
    });
    if (organizationFirewallHydratedForIdRef.current === organizationEditId) {
      return;
    }
    organizationFirewallHydratedForIdRef.current = organizationEditId;
    const raw = org.firewallRules;
    if (raw == null) {
      setOrganizationFirewallMode("merge");
      setOrganizationFirewallRules([]);
      setOrganizationFirewallNatRules([]);
      return;
    }
    if (Array.isArray(raw)) {
      setOrganizationFirewallMode("merge");
      setOrganizationFirewallRules(raw);
      setOrganizationFirewallNatRules([]);
      return;
    }
    if (typeof raw === "object") {
      setOrganizationFirewallMode(String(raw.mode || "").toLowerCase() === "replace" ? "replace" : "merge");
      setOrganizationFirewallRules(Array.isArray(raw.rules) ? raw.rules : []);
      setOrganizationFirewallNatRules(Array.isArray(raw.natRules) ? raw.natRules : []);
    }
  }, [organizationEditId, organizations, organizationsView, primaryNav]);

  useEffect(() => {
    setTablePages((p) => ({ ...p, servers: 1 }));
  }, [serverNameFilter]);

  useEffect(() => {
    setTablePages((p) => ({ ...p, users: 1 }));
  }, [userListFilter]);

  useEffect(() => {
    setTablePages((p) => ({ ...p, serverSessions: 1, serverCerts: 1, serverCaSigned: 1 }));
    setServerCaSignedFilter("");
    setJournalQuery("");
    setJournalLogsPage(1);
  }, [selectedServerId]);

  useEffect(() => {
    setJournalLogsPage(1);
  }, [journalQuery]);

  useEffect(() => {
    setTablePages((p) => ({ ...p, userConnections: 1, userCerts: 1 }));
  }, [selectedUserId]);

  useEffect(() => {
    setCaSignedListFilter("");
    setTablePages((p) => ({ ...p, caSigned: 1 }));
  }, [selectedRootCaId]);

  useEffect(() => {
    setTablePages((p) => ({ ...p, caSigned: 1 }));
  }, [caSignedListFilter]);

  useEffect(() => {
    setTablePages((p) => ({ ...p, serverCaSigned: 1 }));
  }, [serverCaSignedFilter]);

  useEffect(() => {
    if (!certSummaryTargetId) return;
    setTablePages((p) => ({ ...p, certSessions: 1, certIp: 1, certSrc: 1 }));
    setCertKeyUploadDraft({ certPem: "", keyPem: "" });
    setCertKeyImportModalOpen(false);
    setCertMaterialViewModal({ open: false, title: "", pem: "", busy: false });
    setCertMaterialSummary({ loading: false, data: null });
  }, [certSummaryTargetId]);

  useEffect(() => {
    let cancelled = false;
    if (!token || !certSummaryTargetId) return () => {};
    (async () => {
      try {
        setCertMaterialSummary((prev) => ({ loading: true, data: prev.data }));
        const payload = await request(
          `/api/certificates/${encodeURIComponent(certSummaryTargetId)}/material-summary`,
          "GET",
          token,
        );
        if (!cancelled) {
          setCertMaterialSummary({ loading: false, data: payload || null });
        }
      } catch {
        if (!cancelled) {
          setCertMaterialSummary((prev) => ({ loading: false, data: prev.data }));
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [token, certSummaryTargetId]);

  useEffect(() => {
    if (primaryNav === "servers" && serversView === "list") {
      setTablePages((p) => ({ ...p, servers: 1 }));
    }
  }, [primaryNav, serversView]);

  useEffect(() => {
    if (primaryNav === "organizations" && organizationsView === "list") {
      setTablePages((p) => ({ ...p, organizations: 1 }));
    }
  }, [primaryNav, organizationsView]);

  useEffect(() => {
    if (primaryNav === "users" && usersSub === "list") {
      setTablePages((p) => ({ ...p, users: 1 }));
    }
  }, [primaryNav, usersSub]);

  useEffect(() => {
    if (primaryNav !== "users" || usersSub !== "add" || !token) {
      setNewUserIssueServers([]);
      return undefined;
    }
    let cancelled = false;
    void (async () => {
      try {
        const data = await request("/api/vpn-users/issue-certificate/servers", "GET", token);
        const list = Array.isArray(data?.servers) ? data.servers : [];
        if (!cancelled) setNewUserIssueServers(list);
      } catch {
        if (!cancelled) setNewUserIssueServers([]);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [primaryNav, usersSub, token]);

  useEffect(() => {
    if (primaryNav === "settings" && adminsPage === "list") {
      setTablePages((p) => ({ ...p, admins: 1 }));
    }
  }, [primaryNav, adminsPage]);

  useEffect(() => {
    const norm = location.pathname.replace(/\/+$/, "") || "/";
    if (norm !== "/settings/admins/new") return;
    navigate(paths.settings(), { replace: true });
    setNewAdmin({ fullName: "", username: "", email: "" });
    setAddAdminError("");
    setError("");
    setAddAdminInviteResult(null);
    setAddAdminModalOpen(true);
  }, [location.pathname, navigate]);

  useEffect(() => {
    if (primaryNav !== "settings") {
      setAddAdminModalOpen(false);
      setAddAdminBusy(false);
      setAddAdminError("");
      setAddAdminInviteResult(null);
      setNewAdmin({ fullName: "", username: "", email: "" });
    }
  }, [primaryNav]);

  useEffect(() => {
    if (primaryNav !== "settings" || settingsSection !== "backup") return;
    if (!tokenRef.current) return;
    void loadPanelBackups({ syncFormFromServer: true, showLoading: true });
  }, [primaryNav, settingsSection, loadPanelBackups]);

  useEffect(() => {
    if (primaryNav !== "settings" || settingsSection !== "restore") {
      setRestoreFile(null);
      setRestoreConfirm(false);
      setRestoreMessage("");
    }
  }, [primaryNav, settingsSection]);

  useEffect(() => {
    if (primaryNav !== "myProfile") {
      setMyAdminPasswordDraft({ currentPassword: "", newPassword: "", confirmPassword: "" });
      setMyAdminPasswordError("");
      setMyAdminTotpSetup({
        loading: false,
        qrDataUrl: "",
        manualSecret: "",
        expiresAt: "",
        code: "",
        error: "",
        busy: false,
      });
      setMyAdminTotpDisableCode("");
      setMyAdminTotpDisableError("");
      setMyAdminRecoveryCodesDisplay(null);
      setMyAdminRecoveryRegenerateCode("");
      setMyAdminRecoveryRegenerateError("");
      setMyAdminPasswordModalOpen(false);
      setMyAdminTotpSetupModalOpen(false);
      setMyAdminTotpDisableModalOpen(false);
      setMyAdminRecoveryModalOpen(false);
      return;
    }
    void loadMyAdminProfile();
  }, [primaryNav, loadMyAdminProfile]);

  useEffect(() => {
    if (primaryNav === "logs") {
      setTablePages((p) => ({ ...p, logsVpn: 1, logsSrc: 1, logsAdmin: 1 }));
    }
  }, [primaryNav]);

  useEffect(() => {
    setTablePages((p) => ({ ...p, logsVpn: 1 }));
  }, [logsVpnSearch]);

  useEffect(() => {
    setTablePages((p) => ({ ...p, logsSrc: 1 }));
  }, [logsSrcSearch]);

  useEffect(() => {
    setTablePages((p) => ({ ...p, logsAdmin: 1 }));
  }, [logsAdminSearch]);

  useEffect(() => {
    if (!token || primaryNav !== "tasks") return undefined;
    let cancelled = false;
    const loadTasks = async () => {
      try {
        const rows = await request("/api/tasks", "GET", token);
        if (!cancelled) setPanelAsyncTasks(Array.isArray(rows) ? rows : []);
      } catch {
        if (!cancelled) setPanelAsyncTasks([]);
      }
    };
    loadTasks();
    const t = setInterval(loadTasks, 2000);
    return () => {
      cancelled = true;
      clearInterval(t);
    };
  }, [token, primaryNav]);

  useEffect(() => {
    if (!String(newUserCertRootCaId || "").trim()) {
      setNewUserCertChoice("");
      setNewUserCertNewCn("");
    }
  }, [newUserCertRootCaId]);

  useEffect(() => {
    if (!String(newUserCertRootCaId || "").trim()) {
      setNewUserCertValidityDays("1825");
      return;
    }
    const maxDays = Math.max(1, newUserMaxCertValidityDays || 1);
    const raw = parseInt(String(newUserCertValidityDays || "").trim(), 10);
    if (!Number.isFinite(raw) || raw <= 0) {
      setNewUserCertValidityDays(String(Math.min(1825, maxDays)));
      return;
    }
    if (raw > maxDays) {
      setNewUserCertValidityDays(String(maxDays));
    }
  }, [newUserMaxCertValidityDays]);

  useEffect(() => {
    if (!String(userCertBindServerId || "").trim()) {
      setProfileIssueCert((prev) => ({ ...prev, serverId: "", validityDays: "1825" }));
      return;
    }
    setProfileIssueCert((prev) => ({ ...prev, serverId: userCertBindServerId }));
  }, [userCertBindServerId]);

  useEffect(() => {
    const maxDays = Math.max(0, userProfileIssueMaxCertValidityDays || 0);
    setProfileIssueCert((prev) => {
      const raw = parseInt(String(prev.validityDays || "").trim(), 10);
      const def = String(Math.min(1825, Math.max(1, maxDays > 0 ? maxDays : 1825)));
      if (!Number.isFinite(raw) || raw <= 0) {
        return { ...prev, validityDays: def };
      }
      if (maxDays > 0 && raw > maxDays) {
        return { ...prev, validityDays: String(maxDays) };
      }
      return prev;
    });
  }, [userProfileIssueMaxCertValidityDays]);

  useEffect(() => {
    setUserConnectionProfileDraft((prev) => ({
      ...prev,
      serverId: "",
    }));
  }, [userConnectionProfileDraft.certificateId]);

  useEffect(() => {
    if (token) localStorage.setItem(TOKEN_STORAGE_KEY, token);
    else localStorage.removeItem(TOKEN_STORAGE_KEY);
  }, [token]);

  const refreshSession = useCallback(async () => {
    const current = tokenRef.current;
    if (!current) return;
    try {
      const res = await fetch(`${API_URL}/api/auth/refresh`, {
        method: "POST",
        headers: { Authorization: `Bearer ${current}`, "Content-Type": "application/json" },
      });
      if (res.status === 401) {
        window.dispatchEvent(new Event(SESSION_INVALID_EVENT));
        return;
      }
      if (!res.ok) return;
      const data = await res.json();
      if (data?.token) setToken(data.token);
    } catch {
      /* сеть: не завершаем сессию */
    }
  }, []);

  useEffect(() => {
    const onInvalid = () => {
      localStorage.removeItem(TOKEN_STORAGE_KEY);
      setToken("");
      setOverview(null);
      setError("Сессия истекла. Войдите снова.");
      navigate(paths.home(), { replace: true });
    };
    window.addEventListener(SESSION_INVALID_EVENT, onInvalid);
    return () => window.removeEventListener(SESSION_INVALID_EVENT, onInvalid);
  }, [navigate]);

  useEffect(() => {
    if (!token) return undefined;
    const id = setInterval(() => {
      const now = Date.now();
      setSessionNow(now);
      const t = tokenRef.current;
      if (!t) return;
      const exp = parseJwtPayload(t)?.exp;
      const expMs = typeof exp === "number" ? exp * 1000 : null;
      if (expMs && now >= expMs) {
        window.dispatchEvent(new Event(SESSION_INVALID_EVENT));
      }
    }, 1000);
    return () => clearInterval(id);
  }, [token]);

  useEffect(() => {
    setSessionNow(Date.now());
  }, [tokenExpiresAtMs]);

  useEffect(() => {
    if (!token) return undefined;
    let timeoutId;
    const scheduleRefresh = () => {
      clearTimeout(timeoutId);
      timeoutId = setTimeout(() => refreshSession(), 600);
    };
    const opts = { capture: true, passive: true };
    window.addEventListener("pointerdown", scheduleRefresh, opts);
    window.addEventListener("keydown", scheduleRefresh, opts);
    window.addEventListener("wheel", scheduleRefresh, opts);
    window.addEventListener("scroll", scheduleRefresh, opts);
    return () => {
      clearTimeout(timeoutId);
      window.removeEventListener("pointerdown", scheduleRefresh, opts);
      window.removeEventListener("keydown", scheduleRefresh, opts);
      window.removeEventListener("wheel", scheduleRefresh, opts);
      window.removeEventListener("scroll", scheduleRefresh, opts);
    };
  }, [token, refreshSession]);

  const closeMfaModal = () => {
    setMfaModalOpen(false);
    setMfaPendingToken("");
    setMfaTotpCode("");
    setMfaRecoveryCode("");
    setMfaError("");
    setMfaBusy(false);
  };

  const login = async (e) => {
    e.preventDefault();
    try {
      const result = await request("/api/auth/login", "POST", null, { username, password });
      if (result?.mfaRequired && result?.mfaPendingToken) {
        setMfaPendingToken(String(result.mfaPendingToken));
        setMfaModalOpen(true);
        setMfaTotpCode("");
        setMfaRecoveryCode("");
        setMfaError("");
        setError("");
        return;
      }
      if (!result?.token) {
        setError("Сервер не вернул данные для входа. Попробуйте снова.");
        return;
      }
      setToken(result.token);
      setSessionNow(Date.now());
      navigate(paths.home(), { replace: true });
    } catch (e) {
      const extra = typeof e.retryAfterSeconds === "number" ? ` Повтор через ${e.retryAfterSeconds} с.` : "";
      setError(`${e.message}${extra}`);
    }
  };

  const submitMfaLogin = async (e) => {
    e.preventDefault();
    if (!mfaPendingToken || mfaBusy) return;
    setMfaBusy(true);
    setMfaError("");
    try {
      const result = await request("/api/auth/login/mfa", "POST", null, {
        mfaPendingToken,
        totpCode: mfaTotpCode,
        recoveryCode: mfaRecoveryCode.trim() || undefined,
      });
      if (!result?.token) {
        setMfaError("Сервер не вернул токен сессии. Войдите снова.");
        return;
      }
      setToken(result.token);
      setSessionNow(Date.now());
      closeMfaModal();
      navigate(paths.home(), { replace: true });
    } catch (e) {
      const extra = typeof e.retryAfterSeconds === "number" ? ` Повтор через ${e.retryAfterSeconds} с.` : "";
      setMfaError(`${e.message}${extra}`);
    } finally {
      setMfaBusy(false);
    }
  };

  const createAdmin = async (e) => {
    e.preventDefault();
    setAddAdminBusy(true);
    setAddAdminError("");
    try {
      const admin = await request("/api/admins", "POST", token, {
        fullName: newAdmin.fullName.trim(),
        username: newAdmin.username.trim(),
        email: newAdmin.email.trim(),
      });
      const invitePath = typeof admin?.invitePath === "string" ? admin.invitePath : "";
      const inviteUrl = invitePath ? `${window.location.origin}${invitePath}` : "";
      setAddAdminInviteResult(inviteUrl ? { inviteUrl, invitePath } : null);
      setNewAdmin({ fullName: "", username: "", email: "" });
      await loadData(PANEL_DATA_REFRESH.admins);
    } catch (err) {
      setAddAdminError(err.message || String(err));
    } finally {
      setAddAdminBusy(false);
    }
  };

  const confirmUserCertRevoke = async () => {
    const id = userCertRevokeModal.certId;
    if (!id || userCertRevokeModal.busy) return;
    setUserCertRevokeModal((m) => ({ ...m, busy: true, error: "" }));
    try {
      await request(`/api/certificates/${id}/revoke`, "POST", token, { reason: "manual revoke" });
      setUserCertRevokeModal({ open: false, certId: null, commonName: "", busy: false, error: "" });
      loadData(PANEL_DATA_REFRESH.certificates);
    } catch (e) {
      setUserCertRevokeModal((m) => ({
        ...m,
        busy: false,
        error: e?.message ? String(e.message) : "Не удалось отозвать сертификат",
      }));
    }
  };

  const confirmUserCertUnlink = async () => {
    const id = userCertUnlinkModal.certId;
    if (!id || userCertUnlinkModal.busy) return;
    setUserCertUnlinkModal((m) => ({ ...m, busy: true, error: "" }));
    try {
      await request(`/api/certificates/${id}`, "PATCH", token, { vpnUserId: null });
      setUserCertUnlinkModal({ open: false, certId: null, commonName: "", busy: false, error: "" });
      loadData(PANEL_DATA_REFRESH.certificates);
    } catch (e) {
      setUserCertUnlinkModal((m) => ({
        ...m,
        busy: false,
        error: e?.message ? String(e.message) : "Не удалось отвязать сертификат",
      }));
    }
  };

  const createRootCA = async (e) => {
    e.preventDefault();
    try {
      setError("");
      const created = await request("/api/certificates/root-ca/generate", "POST", token, newRootCA);
      setNewRootCA({
        name: "",
        commonName: "",
        days: "3650",
        keySize: "4096",
        signatureAlgorithm: "sha256",
      });
      await loadData(PANEL_DATA_REFRESH.certificates);
      if (created?.id) {
        navigate(paths.caRoot(created.id, "overview"));
      } else {
        navigate(paths.ca());
      }
    } catch (err) {
      setError(err.message || String(err));
    }
  };

  const importRootCaFiles = async (e) => {
    e.preventDefault();
    setCaImportMessage("");
    try {
      const body = {
        name: importRootCA.name,
        commonName: importRootCA.commonName,
        certPem: importRootCA.certPem,
        keyPem: importRootCA.keyPem,
      };
      if (importRootCA.issuedListText?.trim()) body.issuedList = importRootCA.issuedListText;
      if (importRootCA.revokedListText?.trim()) body.revokedList = importRootCA.revokedListText;

      const result = await request("/api/certificates/root-ca/import", "POST", token, body);
      const bits = [];
      if (result.inventory?.issued) {
        const i = result.inventory.issued;
        const u = typeof i.updated === "number" ? i.updated : 0;
        bits.push(
          `index.txt: добавлено ${i.created}, обновлено ${u}, возобновлено ${i.reactivated}, без изменений ${i.skipped}`,
        );
      }
      if (result.inventory?.revoked) {
        const r = result.inventory.revoked;
        if ("revoked" in r) {
          bits.push(
            `crl.pem: отмечено отозванными ${r.revoked}, серийников из CRL нет в БД ${r.notInDb}, пропущено ${r.skipped}`,
          );
        } else {
          bits.push(`отзыв (текст): отозвано ${r.updated}, новых записей ${r.created}, пропущено ${r.skipped}`);
        }
      }
      setCaImportMessage(bits.length ? bits.join(" · ") : "");
      setImportRootCA({
        name: "",
        commonName: "",
        certPem: "",
        keyPem: "",
        issuedListText: "",
        revokedListText: "",
      });
      await loadData(PANEL_DATA_REFRESH.certificates);
      if (result?.id) {
        navigate(paths.caRoot(result.id, "overview"));
      } else {
        navigate(paths.ca());
      }
    } catch (err) {
      setError(err.message);
    }
  };

  const createRootCAForServer = async (e) => {
    e.preventDefault();
    if (!selectedServerId || !tokenRef.current) return;
    if (String(serverOpenVpnSettings.panelRootCaId || "").trim()) {
      setError("Для этого сервера уже задан корневой сертификат. Сначала удалите его на вкладке «Сертификаты».");
      return;
    }
    try {
      setError("");
      const cn = String(newRootCA.commonName || "").trim();
      const created = await request("/api/certificates/root-ca/generate", "POST", token, {
        ...newRootCA,
        name: cn || String(newRootCA.name || "").trim(),
        commonName: cn,
      });
      setNewRootCA({
        name: "",
        commonName: "",
        days: "3650",
        keySize: "4096",
        signatureAlgorithm: "sha256",
      });
      if (created?.id) {
        await persistOpenVpnPanelPartial(
          openvpnCertPathsPartial(serverOpenVpnSettings, { panelRootCaId: created.id, panelServerCertId: "" }),
        );
      }
      await loadData(PANEL_DATA_REFRESH.certificates);
      setServerRootCaCreateModalOpen(false);
    } catch (err) {
      setError(err?.message || String(err));
    }
  };

  const importRootCaForServer = async (e) => {
    e.preventDefault();
    if (!selectedServerId || !tokenRef.current) return;
    if (String(serverOpenVpnSettings.panelRootCaId || "").trim()) {
      setError("Для этого сервера уже задан корневой сертификат. Сначала удалите его на вкладке «Сертификаты».");
      return;
    }
    setCaImportMessage("");
    try {
      const certPem = String(serverPanelRootCaImport.certPem || "").trim();
      const keyPem = String(serverPanelRootCaImport.keyPem || "").trim();
      if (!certPem || !keyPem) {
        setError("Вставьте PEM корневого сертификата и PEM закрытого ключа.");
        return;
      }
      const created = await request("/api/certificates/root-ca/import", "POST", token, { certPem, keyPem });
      setServerPanelRootCaImport({ certPem: "", keyPem: "" });
      if (created?.id) {
        await persistOpenVpnPanelPartial(
          openvpnCertPathsPartial(serverOpenVpnSettings, { panelRootCaId: created.id, panelServerCertId: "" }),
        );
      }
      await loadData(PANEL_DATA_REFRESH.certificates);
      setServerRootCaImportModalOpen(false);
    } catch (err) {
      setError(err?.message || String(err));
    }
  };

  const submitRemoveServerPanelRootCa = async () => {
    if (!selectedServerId || !tokenRef.current || serverRootCaDeleteModal.busy) return;
    if (serverRootCaDeleteModal.step < 2) return;
    const expectedCn = String(
      serverRootCaSummary.data?.commonName ?? serverPanelRootCa?.commonName ?? "",
    ).trim();
    const providedCn = String(serverRootCaDeleteModal.confirmCommonName || "").trim();
    if (!expectedCn) {
      setServerRootCaDeleteModal((m) => ({
        ...m,
        error: "Не удалось определить Common Name корневого сертификата. Обновите страницу и попробуйте снова.",
      }));
      return;
    }
    if (providedCn !== expectedCn) {
      setServerRootCaDeleteModal((m) => ({
        ...m,
        error: "Введите точный Common Name (CN) корневого сертификата.",
      }));
      return;
    }
    setServerRootCaDeleteModal((m) => ({ ...m, busy: true, error: "" }));
    try {
      await request(
        `/api/panel/nodes/${encodeURIComponent(selectedServerId)}/root-ca/remove`,
        "POST",
        tokenRef.current,
        { confirmCommonName: providedCn },
      );
      setServerRootCaSummary({ loading: false, data: null });
      setServerRootCaDeleteModal({ open: false, step: 1, confirmCommonName: "", busy: false, error: "" });
      await loadData(PANEL_DATA_REFRESH.certificates);
      try {
        const refreshed = await request(
          `/api/panel/nodes/${encodeURIComponent(selectedServerId)}/openvpn-settings`,
          "GET",
          tokenRef.current,
        );
        const s = { ...(refreshed.settings || {}) };
        for (const f of OPENVPN_SERVER_SETTINGS_FIELDS) {
          if (f.type === "textarea") {
            const v = s[f.key];
            if (Array.isArray(v)) s[f.key] = v;
            else if (typeof v === "string") s[f.key] = v ? [v] : [];
            else s[f.key] = [];
          }
        }
        setServerOpenVpnSettings(s);
      } catch {
        /* ignore */
      }
    } catch (err) {
      setServerRootCaDeleteModal((m) => ({
        ...m,
        busy: false,
        error: err?.message ? String(err.message) : "Не удалось удалить корневой сертификат",
      }));
    }
  };

  const goUsersList = () => {
    navigate(paths.users());
    setUserListFilter("");
  };

  const submitTaskRetryFromModal = async () => {
    const taskId = taskRetryModal.taskId;
    if (!tokenRef.current || !taskId) return;
    setTaskRetryModal((prev) => ({ ...prev, busy: true, error: "" }));
    try {
      await request(`/api/tasks/${encodeURIComponent(taskId)}/retry`, "POST", tokenRef.current);
      const rows = await request("/api/tasks", "GET", tokenRef.current);
      setPanelAsyncTasks(Array.isArray(rows) ? rows : []);
      setTaskRetryModal({ open: false, taskId: "", taskType: "", busy: false, error: "" });
    } catch (err) {
      setTaskRetryModal((prev) => ({
        ...prev,
        busy: false,
        error: err?.message || "Не удалось поставить задачу в очередь повторно",
      }));
    }
  };

  const submitSystemUnitActionFromModal = async () => {
    const { unit, action } = systemUnitActionModal;
    if (!selectedServerId || !tokenRef.current || !unit || !action) return;
    setSystemUnitActionModal((prev) => ({ ...prev, busy: true, error: "" }));
    try {
      await request(
        `/api/panel/nodes/${encodeURIComponent(selectedServerId)}/system-service-unit`,
        "POST",
        tokenRef.current,
        { unit, action },
      );
      setSystemUnitActionModal({ open: false, unit: "", action: "", busy: false, error: "" });
      await loadServerServicesAndDns();
    } catch (err) {
      const details = typeof err.output === "string" && err.output ? `\n${err.output}` : "";
      setSystemUnitActionModal((prev) => ({
        ...prev,
        busy: false,
        error: `${err.message || "Операция не выполнена"}${details}`,
      }));
    }
  };

  const downloadUserConnectionProfile = useCallback(async () => {
    if (!selectedUserId || !tokenRef.current) return;
    if (!userConnectionProfileDraft.certificateId || !userConnectionProfileDraft.serverId) {
      setError("Выберите сертификат и сервер для генерации конфигурации.");
      return;
    }
    setUserConnectionProfileBusy(true);
    try {
      const data = await request(
        `/api/vpn-users/${encodeURIComponent(selectedUserId)}/connection-profile`,
        "POST",
        tokenRef.current,
        {
          action: "download",
          certificateId: userConnectionProfileDraft.certificateId,
          serverId: userConnectionProfileDraft.serverId,
        },
      );
      const fileName = String(data?.fileName || "client.ovpn");
      const contentBase64 = String(data?.contentBase64 || "");
      const blob = new Blob([Uint8Array.from(atob(contentBase64), (c) => c.charCodeAt(0))], {
        type: "application/octet-stream",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = fileName;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err?.message || "Не удалось сформировать конфигурацию");
    } finally {
      setUserConnectionProfileBusy(false);
    }
  }, [selectedUserId, userConnectionProfileDraft.certificateId, userConnectionProfileDraft.serverId]);

  const emailUserConnectionProfile = useCallback(async () => {
    if (!selectedUserId || !tokenRef.current) return;
    if (!userConnectionProfileDraft.certificateId || !userConnectionProfileDraft.serverId) {
      setError("Выберите сертификат и сервер для отправки конфигурации.");
      return;
    }
    const email = String(userConnectionProfileDraft.email || "").trim();
    if (!email) {
      setError("Укажите email для отправки конфигурации.");
      return;
    }
    setUserConnectionProfileBusy(true);
    try {
      const data = await request(
        `/api/vpn-users/${encodeURIComponent(selectedUserId)}/connection-profile`,
        "POST",
        tokenRef.current,
        {
          action: "email",
          certificateId: userConnectionProfileDraft.certificateId,
          serverId: userConnectionProfileDraft.serverId,
          email,
        },
      );
      setError("");
      if (data?.message) {
        setServerOpenVpnSaveModal({ open: true, text: String(data.message) });
      }
    } catch (err) {
      setError(err?.message || "Не удалось отправить конфигурацию на email");
    } finally {
      setUserConnectionProfileBusy(false);
    }
  }, [selectedUserId, userConnectionProfileDraft.certificateId, userConnectionProfileDraft.serverId, userConnectionProfileDraft.email]);

  const goCaHome = () => {
    navigate(paths.ca());
  };

  const createVpnUser = async (e) => {
    e.preventDefault();
    try {
      setError("");
      const certChoice = String(newUserCertChoice || "").trim();
      const selectedCert =
        certChoice && certChoice !== "__create__"
          ? newUserBindableCertificates.find((c) => c.id === certChoice) || null
          : null;
      const newCn = certChoice === "__create__" ? String(newUserCertNewCn || "").trim() : "";
      if (newCn && !String(newUserCertRootCaId || "").trim()) {
        setError("Для выпуска сертификата по CN выберите корневой сертификат.");
        return;
      }
      const created = await request("/api/vpn-users", "POST", token, {
        fullName: newVpnUser.fullName.trim(),
        position: newVpnUser.position.trim() || null,
        email: newVpnUser.email.trim(),
        phone: newVpnUser.phone.trim() || null,
        organizationId: newVpnUser.organizationId?.trim() || null,
        notes: newVpnUser.notes?.trim() || null,
      });
      if (selectedCert) {
        const bindServerId = String(newUserCertServerId || "").trim();
        if (!bindServerId) {
          setError("Для привязки сертификата выберите сервер.");
          return;
        }
        await request(`/api/certificates/${encodeURIComponent(selectedCert.id)}`, "PATCH", token, {
          vpnUserId: created.id,
          agentNodeId: bindServerId,
        });
      } else if (newCn) {
        const bindServerId = String(newUserCertServerId || "").trim();
        if (!bindServerId) {
          setError("Для выпуска нового сертификата выберите сервер.");
          return;
        }
        const daysRaw = parseInt(String(newUserCertValidityDays || "").trim(), 10);
        const daysCap = Math.max(1, newUserMaxCertValidityDays || 1);
        const validityDays = Number.isFinite(daysRaw) && daysRaw > 0 ? Math.min(daysRaw, daysCap) : Math.min(1825, daysCap);
        const expiresAt = new Date(Date.now() + validityDays * 86400000).toISOString();
        await request("/api/certificates", "POST", token, {
          vpnUserId: created.id,
          commonName: newCn,
          rootCaId: String(newUserCertRootCaId || "").trim(),
          agentNodeId: bindServerId,
          expiresAt,
        });
      } else if (certChoice && certChoice !== "__create__") {
        setError("Выбранный сертификат не найден в списке.");
        return;
      } else if (certChoice === "__create__" && !newCn) {
        setError("Укажите CN для выпуска нового сертификата.");
        return;
      }
      setNewVpnUser({ fullName: "", position: "", email: "", phone: "", organizationId: "", notes: "" });
      setNewUserCertServerId("");
      setNewUserCertChoice("");
      setNewUserCertNewCn("");
      setNewUserCertValidityDays("1825");
      await loadData(PANEL_DATA_REFRESH.vpnUsers);
      if (created?.id) {
        navigate(paths.userProfile(created.id, "overview"));
      } else {
        goUsersList();
      }
    } catch (err) {
      setError(err.message || String(err));
    }
  };

  const saveUserProfile = async (e) => {
    e.preventDefault();
    if (!selectedUserId) return;
    try {
      setError("");
      await request(`/api/vpn-users/${selectedUserId}`, "PATCH", token, {
        fullName: userProfileDraft.fullName.trim(),
        position: userProfileDraft.position.trim() || null,
        email: userProfileDraft.email.trim(),
        phone: userProfileDraft.phone.trim() || null,
        organizationId: userProfileDraft.organizationId?.trim() || null,
        notes: userProfileDraft.notes?.trim() || null,
      });
      loadData(PANEL_DATA_REFRESH.vpnUsers);
    } catch (err) {
      setError(err.message);
    }
  };

  const loadServerFirewall = useCallback(async () => {
    if (!selectedServerId || !tokenRef.current) return;
    try {
      setServerFirewallLoading(true);
      const data = await request(`/api/panel/nodes/${encodeURIComponent(selectedServerId)}/firewall`, "GET", tokenRef.current);
      setServerFirewallTunnelDefaultPolicy(String(data?.tunnel?.defaultPolicy || "deny"));
      setServerFirewallTunnelRules(Array.isArray(data?.tunnel?.rules) ? data.tunnel.rules : []);
      setServerFirewallTunnelNatRules(Array.isArray(data?.tunnel?.natRules) ? data.tunnel.natRules : []);
    } catch (err) {
      setError(err.message || "Не удалось загрузить firewall");
    } finally {
      setServerFirewallLoading(false);
    }
  }, [selectedServerId]);

  const applyServerFirewall = async () => {
    if (!selectedServerId || !tokenRef.current) return;
    try {
      setServerFirewallBusy(true);
      const data = await request(`/api/panel/nodes/${encodeURIComponent(selectedServerId)}/firewall-apply`, "POST", tokenRef.current, {
        tunnel: {
          defaultPolicy: serverFirewallTunnelDefaultPolicy,
          rules: serverFirewallTunnelRules,
          natRules: serverFirewallTunnelNatRules,
        },
      });
      setServerFirewallTunnelDefaultPolicy(String(data?.tunnel?.defaultPolicy || serverFirewallTunnelDefaultPolicy));
      setServerFirewallTunnelRules(Array.isArray(data?.tunnel?.rules) ? data.tunnel.rules : serverFirewallTunnelRules);
      setServerFirewallTunnelNatRules(Array.isArray(data?.tunnel?.natRules) ? data.tunnel.natRules : serverFirewallTunnelNatRules);
    } catch (err) {
      setError(err.message || "Не удалось применить firewall");
    } finally {
      setServerFirewallBusy(false);
    }
  };

  const applyUserFirewall = async () => {
    if (!selectedUserId || !tokenRef.current) return;
    try {
      setUserFirewallBusy(true);
      const data = await request(`/api/vpn-users/${encodeURIComponent(selectedUserId)}/firewall`, "POST", tokenRef.current, {
        mode: userFirewallMode,
        rules: userFirewallOverrideRules,
        natRules: userFirewallOverrideNatRules,
      });
      const rules = Array.isArray(data?.rules) ? data.rules : [];
      const natRules = Array.isArray(data?.natRules) ? data.natRules : [];
      setUserFirewallOverrideRules(rules);
      setUserFirewallOverrideNatRules(natRules);
    } catch (err) {
      setError(err.message || "Не удалось сохранить правила пользователя");
    } finally {
      setUserFirewallBusy(false);
    }
  };

  const applyOrganizationFirewall = async () => {
    if (!organizationEditId || !tokenRef.current) return;
    try {
      setOrganizationFirewallBusy(true);
      const data = await request(`/api/organizations/${encodeURIComponent(organizationEditId)}/firewall`, "POST", tokenRef.current, {
        mode: organizationFirewallMode,
        rules: organizationFirewallRules,
        natRules: organizationFirewallNatRules,
      });
      setOrganizationFirewallMode(String(data?.mode || "merge").toLowerCase() === "replace" ? "replace" : "merge");
      setOrganizationFirewallRules(Array.isArray(data?.rules) ? data.rules : []);
      setOrganizationFirewallNatRules(Array.isArray(data?.natRules) ? data.natRules : []);
    } catch (err) {
      setError(err.message || "Не удалось сохранить правила организации");
    } finally {
      setOrganizationFirewallBusy(false);
    }
  };

  const applyUserCcd = async () => {
    if (!selectedUserId || !tokenRef.current) return;
    try {
      setUserCcdBusy(true);
      setUserCcdResult("");
      const data = await request(`/api/vpn-users/${encodeURIComponent(selectedUserId)}/ccd`, "POST", tokenRef.current, userCcdDraft);
      setUserCcdResult(String(data?.message || "CCD сохранён."));
    } catch (err) {
      setError(err.message || "Не удалось сохранить CCD");
    } finally {
      setUserCcdBusy(false);
    }
  };

  const openServerEffectivePolicyModal = () => {
    const lines = serverFirewallTunnelRules.map(
      (r) => `[base] ${r.action} ${r.proto} ${r.destination || "any"} ${r.ports || "*"}`,
    );
    const emptyHint = "# нет персональных правил — действуют только общие правила туннеля и политика по умолчанию";
    setServerFirewallEffectiveModal({
      open: true,
      title: "Effective Policy · Сервер",
      content: lines.length ? lines.join("\n") : emptyHint,
    });
  };

  const openUserEffectivePolicyModal = () => {
    const lines = userFirewallEffectiveRules.map(
      (r) => `${r.scope === "override" ? "[override]" : "[base]"} ${r.action} ${r.proto} ${r.destination || "any"} ${r.ports || "*"}`,
    );
    const emptyHint =
      userFirewallMode === "replace"
        ? "# замена: персональных правил нет — действует только политика по умолчанию туннеля (общие правила сервера не применяются)"
        : "# нет персональных правил — действуют только общие правила туннеля и политика по умолчанию";
    setUserFirewallEffectiveModal({
      open: true,
      title: "Effective Policy · Пользователь",
      content: lines.length ? lines.join("\n") : emptyHint,
    });
  };

  const openOrganizationEffectivePolicyModal = () => {
    const lines = organizationFirewallRules.map(
      (r) => `[org] ${r.action} ${r.proto} ${r.destination || "any"} ${r.ports || "*"}`,
    );
    setOrganizationFirewallEffectiveModal({
      open: true,
      title: "Effective Policy · Организация",
      content: lines.length ? lines.join("\n") : "# нет правил организации",
    });
  };

  const openFirewallRuleModal = (scope, rule = null, section = "host", kind = "filter") => {
    const outVal = String(rule?.outInterface || "").trim();
    const toVal = String(rule?.toAddress || "").trim();
    setNatOutInterfaceInputMode(outVal ? "preset" : "manual");
    setNatToAddressInputMode(toVal ? "preset" : "manual");
    setFirewallRuleModal({
      open: true,
      scope,
      section,
      kind,
      editId: rule?.id || "",
      draft: {
        action: String(rule?.action || "allow"),
        proto: String(rule?.proto || "tcp"),
        destination: String(rule?.destination || ""),
        ports: String(rule?.ports || ""),
        note: String(rule?.note || ""),
        type: String(rule?.type || "masquerade"),
        src: String(rule?.src || ""),
        dst: String(rule?.dst || ""),
        outInterface: String(rule?.outInterface || ""),
        toAddress: String(rule?.toAddress || ""),
      },
      error: "",
    });
  };

  useEffect(() => {
    if (!firewallRuleModal.open || firewallRuleModal.kind !== "nat") return;
    const outVal = String(firewallRuleModal.draft.outInterface || "").trim();
    const toVal = String(firewallRuleModal.draft.toAddress || "").trim();
    if (outVal && natOutInterfaceOptions.includes(outVal) && natOutInterfaceInputMode === "manual") {
      setNatOutInterfaceInputMode("preset");
    }
    if (toVal && natToAddressOptions.includes(toVal) && natToAddressInputMode === "manual") {
      setNatToAddressInputMode("preset");
    }
  }, [
    firewallRuleModal.open,
    firewallRuleModal.kind,
    firewallRuleModal.draft.outInterface,
    firewallRuleModal.draft.toAddress,
    natOutInterfaceOptions,
    natToAddressOptions,
    natOutInterfaceInputMode,
    natToAddressInputMode,
  ]);

  const submitFirewallRuleModal = () => {
    const d = firewallRuleModal.draft || {};
    if (firewallRuleModal.kind !== "nat" && !String(d.destination || "").trim()) {
      setFirewallRuleModal((prev) => ({ ...prev, error: "Укажите destination (IP/CIDR)." }));
      return;
    }
    const isNat = firewallRuleModal.kind === "nat";
    const nextRule = isNat
      ? {
          id: firewallRuleModal.editId || `nat-${Date.now()}`,
          type: String(d.type || "masquerade"),
          src: String(d.src || "").trim(),
          dst: String(d.dst || "").trim(),
          outInterface: String(d.outInterface || "").trim(),
          toAddress: String(d.toAddress || "").trim(),
          note: String(d.note || "").trim(),
        }
      : {
          id: firewallRuleModal.editId || `rule-${Date.now()}`,
          action: String(d.action || "allow"),
          proto: String(d.proto || "tcp"),
          destination: String(d.destination || "").trim(),
          ports: String(d.ports || "").trim(),
          note: String(d.note || "").trim(),
        };
    if (firewallRuleModal.scope === "server") {
      if (firewallRuleModal.kind === "nat") {
        setServerFirewallTunnelNatRules((prev) => {
          const exists = prev.some((x) => x.id === nextRule.id);
          return exists ? prev.map((x) => (x.id === nextRule.id ? nextRule : x)) : [...prev, nextRule];
        });
      } else {
        setServerFirewallTunnelRules((prev) => {
          const exists = prev.some((x) => x.id === nextRule.id);
          return exists ? prev.map((x) => (x.id === nextRule.id ? nextRule : x)) : [...prev, nextRule];
        });
      }
    } else if (firewallRuleModal.scope === "organization" && firewallRuleModal.kind === "nat") {
      setOrganizationFirewallNatRules((prev) => {
        const exists = prev.some((x) => x.id === nextRule.id);
        return exists ? prev.map((x) => (x.id === nextRule.id ? nextRule : x)) : [...prev, nextRule];
      });
    } else if (firewallRuleModal.scope === "organization") {
      setOrganizationFirewallRules((prev) => {
        const exists = prev.some((x) => x.id === nextRule.id);
        return exists ? prev.map((x) => (x.id === nextRule.id ? nextRule : x)) : [...prev, nextRule];
      });
    } else if (firewallRuleModal.kind === "nat") {
      setUserFirewallOverrideNatRules((prev) => {
        const exists = prev.some((x) => x.id === nextRule.id);
        return exists ? prev.map((x) => (x.id === nextRule.id ? nextRule : x)) : [...prev, nextRule];
      });
    } else {
      setUserFirewallOverrideRules((prev) => {
        const exists = prev.some((x) => x.id === nextRule.id);
        return exists ? prev.map((x) => (x.id === nextRule.id ? nextRule : x)) : [...prev, nextRule];
      });
    }
    setFirewallRuleModal({
      open: false,
      scope: "server",
      section: "tunnel",
      kind: "filter",
      editId: "",
      draft: { action: "allow", proto: "tcp", destination: "", ports: "", note: "", type: "masquerade", src: "", dst: "", outInterface: "", toAddress: "" },
      error: "",
    });
  };

  useEffect(() => {
    if (primaryNav !== "servers" || serversView !== "detail" || serverDetailTab !== "firewall" || !selectedServerId) {
      return;
    }
    void loadServerFirewall();
  }, [primaryNav, serversView, serverDetailTab, selectedServerId, loadServerFirewall]);

  const issueUserCertificate = async (e) => {
    e.preventDefault();
    if (!newUserCert.vpnUserId?.trim()) {
      setError("Выберите пользователя (профиль в разделе «Пользователи»)");
      return;
    }
    if (vpnUsers.length === 0) {
      setError("Сначала создайте профиль пользователя");
      return;
    }
    if (!newUserCert.rootCaId?.trim()) {
      setError("Выберите корневой сертификат");
      return;
    }
    if (!newUserCert.commonName?.trim()) {
      setError("Укажите subject CN для нового сертификата (как в OpenVPN / сертификате)");
      return;
    }
    setError("");
    const daysRaw = parseInt(String(newUserCert.validityDays || "").trim(), 10);
    const days = Number.isFinite(daysRaw) && daysRaw > 0 ? daysRaw : 365;
    const expiresAt = new Date(Date.now() + days * 86400000).toISOString();
    await request("/api/certificates", "POST", token, {
      vpnUserId: newUserCert.vpnUserId.trim(),
      commonName: newUserCert.commonName.trim(),
      rootCaId: newUserCert.rootCaId.trim(),
      agentNodeId: null,
      expiresAt,
    });
    setNewUserCert((prev) => ({
      vpnUserId: "",
      commonName: "",
      rootCaId: prev.rootCaId || "",
      validityDays: "365",
    }));
    if (selectedRootCaId) {
      navigate(paths.caRoot(selectedRootCaId, "user-certs"));
    }
    loadData(PANEL_DATA_REFRESH.certificates);
  };

  const issueProfileCertificate = async (e) => {
    e.preventDefault();
    if (!selectedUserId) return;
    const serverId = String(profileIssueCert.serverId || userCertBindServerId || "").trim();
    if (!serverId) {
      setError("Выберите сервер для выпуска сертификата");
      return;
    }
    const issueServer = userCertModalServers.find((s) => s.id === serverId);
    const issueRootCaId = String(issueServer?.panelRootCaId || "").trim();
    if (!issueRootCaId) {
      setError(
        "Для выбранного сервера не выбран корневой сертификат в панели. Укажите его на вкладке «Сертификаты» в карточке сервера.",
      );
      return;
    }
    if (!profileIssueCert.commonName?.trim()) {
      setError("Укажите subject CN для нового сертификата");
      return;
    }
    const auth = tokenRef.current;
    if (!auth) {
      setError("Нет авторизации");
      return;
    }
    const rawDays = parseInt(String(profileIssueCert.validityDays || "").trim(), 10);
    const capFromCa = userProfileIssueMaxCertValidityDays;
    const maxDays = capFromCa > 0 ? Math.max(1, capFromCa) : 3650;
    const validityDays = Number.isFinite(rawDays) && rawDays > 0 ? Math.min(rawDays, maxDays) : Math.min(1825, maxDays);
    const expiresAt = new Date(Date.now() + validityDays * 86400000).toISOString();
    setError("");
    try {
      await request("/api/certificates", "POST", auth, {
        vpnUserId: selectedUserId,
        commonName: profileIssueCert.commonName.trim(),
        rootCaId: issueRootCaId,
        agentNodeId: serverId,
        expiresAt,
      });
      setProfileIssueCert((prev) => ({
        ...prev,
        commonName: "",
        validityDays: String(Math.min(1825, maxDays)),
      }));
      setUserCertIssueModalOpen(false);
      loadData(PANEL_DATA_REFRESH.certificates);
    } catch (err) {
      setError(err.message || "Не удалось выпустить сертификат");
    }
  };

  const downloadUserCertConfig = async (certificateId, serverId) => {
    if (!selectedUserId || !tokenRef.current) return;
    const certId = String(certificateId || "").trim();
    const nodeId = String(serverId || "").trim();
    if (!certId || !nodeId) {
      setError("Для скачивания требуется сертификат, привязанный к серверу.");
      return;
    }
    setUserConnectionProfileBusy(true);
    try {
      const data = await request(
        `/api/vpn-users/${encodeURIComponent(selectedUserId)}/connection-profile`,
        "POST",
        tokenRef.current,
        {
          action: "download",
          certificateId: certId,
          serverId: nodeId,
        },
      );
      const fileName = String(data?.fileName || "client.ovpn");
      const contentBase64 = String(data?.contentBase64 || "");
      const blob = new Blob([Uint8Array.from(atob(contentBase64), (c) => c.charCodeAt(0))], {
        type: "application/octet-stream",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = fileName;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err?.message || "Не удалось сформировать конфигурацию");
    } finally {
      setUserConnectionProfileBusy(false);
    }
  };

  const downloadBase64File = (contentBase64, fileName) => {
    const blob = new Blob([Uint8Array.from(atob(String(contentBase64 || "")), (c) => c.charCodeAt(0))], {
      type: "application/octet-stream",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = String(fileName || "download.bin");
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const downloadRootCaArtifact = async (kind) => {
    if (!panelRootCaIdForServer || !tokenRef.current) return;
    try {
      setError("");
      const data = await request(
        `/api/certificates/root-ca/${encodeURIComponent(panelRootCaIdForServer)}/export?kind=${encodeURIComponent(
          String(kind || ""),
        )}`,
        "GET",
        tokenRef.current,
      );
      downloadBase64File(data?.contentBase64 || "", data?.fileName || "download.bin");
    } catch (err) {
      setError(err?.message || "Не удалось скачать файл корневого сертификата");
    }
  };

  const downloadServerCertificateArtifact = async (kind) => {
    if (!serverPanelDisplayedServerCert?.id || !tokenRef.current) return;
    try {
      setError("");
      const data = await request(
        `/api/certificates/${encodeURIComponent(serverPanelDisplayedServerCert.id)}/view-material`,
        "POST",
        tokenRef.current,
        { kind: kind === "server_key" ? "private" : "public" },
      );
      const fileName = kind === "server_key" ? "server.key" : "server.crt";
      const pem = String(data?.pem || "");
      const contentBase64 = btoa(unescape(encodeURIComponent(pem)));
      downloadBase64File(contentBase64, fileName);
    } catch (err) {
      setError(err?.message || "Не удалось скачать материал сертификата сервера");
    }
  };

  const downloadSelectedCertificateArtifact = async (kind) => {
    if (!certSummaryTargetId || !tokenRef.current) return;
    try {
      setError("");
      const data = await request(
        `/api/certificates/${encodeURIComponent(certSummaryTargetId)}/view-material`,
        "POST",
        tokenRef.current,
        { kind: kind === "key" ? "private" : "public" },
      );
      const fileName = kind === "key" ? "certificate.key" : "certificate.crt";
      const pem = String(data?.pem || "");
      const contentBase64 = btoa(unescape(encodeURIComponent(pem)));
      downloadBase64File(contentBase64, fileName);
    } catch (err) {
      setError(err?.message || "Не удалось скачать материал сертификата");
    }
  };

  const patchCertificate = async (certId, patch) => {
    await request(`/api/certificates/${certId}`, "PATCH", token, patch);
    loadData(PANEL_DATA_REFRESH.certificates);
  };

  const confirmUserCertBind = async () => {
    const certId = String(userCertBindSelectedCertId || "").trim();
    if (!certId || !selectedUserId || !userCertBindServerId || !tokenRef.current) return;
    setUserCertBindBusy(true);
    setError("");
    try {
      await request(`/api/certificates/${encodeURIComponent(certId)}`, "PATCH", tokenRef.current, {
        vpnUserId: selectedUserId,
        agentNodeId: userCertBindServerId,
      });
      await loadData(PANEL_DATA_REFRESH.certificates);
      setUserCertBindModalOpen(false);
      setUserCertBindSelectedCertId("");
    } catch (err) {
      setError(err.message || "Не удалось привязать сертификат");
    } finally {
      setUserCertBindBusy(false);
    }
  };

  const uploadSelectedCertificateKeyMaterial = async () => {
    if (!selectedCertId) return;
    const certPem = String(certKeyUploadDraft.certPem || "").trim();
    const keyPem = String(certKeyUploadDraft.keyPem || "").trim();
    if (!certPem && !keyPem) {
      setError("Добавьте cert.pem и/или key.pem для догрузки.");
      return;
    }
    try {
      setError("");
      setCertKeyUploadBusy(true);
      await patchCertificate(selectedCertId, {
        ...(certPem ? { certPem } : {}),
        ...(keyPem ? { keyPem } : {}),
      });
      setCertKeyUploadDraft({ certPem: "", keyPem: "" });
      setCertKeyImportModalOpen(false);
    } catch (err) {
      setError(err?.message || "Не удалось догрузить ключевой материал сертификата");
    } finally {
      setCertKeyUploadBusy(false);
    }
  };

  const submitCertMaterialUpload = async () => {
    const certId = String(certMaterialUploadModal.certId || "").trim();
    const pem = String(certMaterialUploadModal.pem || "").trim();
    const kind = certMaterialUploadModal.kind === "key" ? "key" : "cert";
    if (!certId) return;
    if (!pem) {
      setCertMaterialUploadModal((prev) => ({ ...prev, error: "Добавьте PEM содержимое." }));
      return;
    }
    try {
      setCertMaterialUploadModal((prev) => ({ ...prev, busy: true, error: "" }));
      await patchCertificate(certId, kind === "key" ? { keyPem: pem } : { certPem: pem });
      setCertMaterialUploadModal({ open: false, certId: "", kind: "cert", pem: "", busy: false, error: "" });
    } catch (err) {
      setCertMaterialUploadModal((prev) => ({
        ...prev,
        busy: false,
        error: err?.message || "Не удалось загрузить материал сертификата",
      }));
    }
  };

  const openCertificateMaterialPreview = async (kind) => {
    if (!selectedCertId) return;
    const normalizedKind = kind === "private" ? "private" : "public";
    const title = normalizedKind === "private" ? "Закрытый ключ" : "Открытый ключ";
    try {
      setError("");
      setCertMaterialViewModal({ open: true, title, pem: "", busy: true });
      const payload = await request(
        `/api/certificates/${encodeURIComponent(selectedCertId)}/view-material`,
        "POST",
        token,
        { kind: normalizedKind },
      );
      setCertMaterialViewModal({
        open: true,
        title: payload?.label || title,
        pem: String(payload?.pem || ""),
        busy: false,
      });
    } catch (err) {
      setCertMaterialViewModal({ open: false, title: "", pem: "", busy: false });
      setError(err?.message || "Не удалось открыть материал ключа");
    }
  };

  const readFileToText = (file, onLoaded) => {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => onLoaded(String(reader.result || ""));
    reader.readAsText(file);
  };

  const createNode = async (e) => {
    e.preventDefault();
    try {
      setError("");
      const agent = await request("/api/agent/nodes", "POST", token, { ...newNode, port: Number(newNode.port) });
      setNewNode({ name: "", protocol: "http", host: "", port: "9443", authToken: "" });
      await loadData(PANEL_DATA_REFRESH.servers);
      if (agent?.id) {
        navigate(paths.serverDetail(agent.id, "service"));
      } else {
        navigate(paths.servers());
      }
    } catch (err) {
      setError(err.message || String(err));
    }
  };

  const saveServerAgentConfig = async (e) => {
    e.preventDefault();
    if (!selectedServerId) return;
    try {
      setError("");
      const body = {
        name: serverAgentDraft.name.trim(),
        protocol: serverAgentDraft.protocol,
        host: serverAgentDraft.host.trim(),
        port: Number(serverAgentDraft.port),
      };
      if (serverAgentDraft.authToken.trim()) {
        body.authToken = serverAgentDraft.authToken.trim();
      }
      await request(`/api/agent/nodes/${encodeURIComponent(selectedServerId)}`, "PATCH", token, body);
      setServerAgentDraft((prev) => ({ ...prev, authToken: "" }));
      loadData(PANEL_DATA_REFRESH.servers);
    } catch (err) {
      setError(err.message || String(err));
    }
  };

  const goServersList = () => {
    navigate(paths.servers());
  };

  const goOrganizationsList = () => {
    navigate(paths.organizations());
    setEditOrganization({
      id: "",
      name: "",
      inn: "",
      legalAddress: "",
      generalDirector: "",
      phone: "",
      email: "",
    });
  };

  const openOrganizationEdit = (org) => {
    setError("");
    navigate(paths.organizationEdit(org.id));
  };

  const createOrganization = async (e) => {
    e.preventDefault();
    if (!newOrganization.name?.trim()) {
      setError("Укажите название организации");
      return;
    }
    try {
      setError("");
      const created = await request("/api/organizations", "POST", token, {
        name: newOrganization.name.trim(),
        inn: newOrganization.inn || null,
        legalAddress: newOrganization.legalAddress || null,
        generalDirector: newOrganization.generalDirector || null,
        phone: newOrganization.phone || null,
        email: newOrganization.email || null,
      });
      setNewOrganization({
        name: "",
        inn: "",
        legalAddress: "",
        generalDirector: "",
        phone: "",
        email: "",
      });
      await loadData(PANEL_DATA_REFRESH.organizations);
      if (created?.id) {
        navigate(paths.organizationEdit(created.id));
      } else {
        navigate(paths.organizations());
      }
    } catch (err) {
      setError(err.message);
    }
  };

  const updateOrganization = async (e) => {
    e.preventDefault();
    if (!editOrganization.name?.trim()) {
      setError("Укажите название организации");
      return;
    }
    if (!editOrganization.id) {
      setError("Не выбрана организация");
      return;
    }
    try {
      setError("");
      await request(`/api/organizations/${editOrganization.id}`, "PATCH", token, {
        name: editOrganization.name.trim(),
        inn: editOrganization.inn || null,
        legalAddress: editOrganization.legalAddress || null,
        generalDirector: editOrganization.generalDirector || null,
        phone: editOrganization.phone || null,
        email: editOrganization.email || null,
      });
      goOrganizationsList();
      loadData(PANEL_DATA_REFRESH.organizations);
    } catch (err) {
      setError(err.message);
    }
  };

  const logout = () => {
    setToken("");
    setMyAdminProfile(null);
    setMyAdminProfileLoading(false);
    setOverview(null);
    setError("");
    setEditOrganization({
      id: "",
      name: "",
      inn: "",
      legalAddress: "",
      generalDirector: "",
      phone: "",
      email: "",
    });
    setUserListFilter("");
    setServerNameFilter("");
    navigate(paths.home());
  };

  const serversTablePage = useMemo(
    () => sliceTablePage(filteredOverviewServers, tablePages.servers),
    [filteredOverviewServers, tablePages.servers],
  );
  const organizationsTablePage = useMemo(
    () => sliceTablePage(organizationsSortedByName, tablePages.organizations),
    [organizationsSortedByName, tablePages.organizations],
  );
  const usersTablePage = useMemo(
    () => sliceTablePage(filteredVpnUsersEnriched, tablePages.users),
    [filteredVpnUsersEnriched, tablePages.users],
  );
  const adminsTablePage = useMemo(() => sliceTablePage(admins, tablePages.admins), [admins, tablePages.admins]);

  const selectedAdmin = useMemo(
    () => (selectedAdminId ? admins.find((a) => a.id === selectedAdminId) ?? null : null),
    [admins, selectedAdminId],
  );

  useEffect(() => {
    setAdminDetailStatusError("");
  }, [selectedAdminId]);

  useEffect(() => {
    if (!selectedAdmin) return;
    setAdminProfileDraft({
      fullName: selectedAdmin.fullName || "",
      username: selectedAdmin.username || "",
      email: selectedAdmin.email || "",
    });
    setAdminProfileFieldError("");
  }, [selectedAdmin?.id, selectedAdmin?.updatedAt]);

  const caRootsTablePage = useMemo(() => sliceTablePage(rootCAs, tablePages.caRoots), [rootCAs, tablePages.caRoots]);
  const caSignedTablePage = useMemo(
    () => sliceTablePage(filteredRootSignedUserCertificates, tablePages.caSigned),
    [filteredRootSignedUserCertificates, tablePages.caSigned],
  );
  const serverCaSignedTablePage = useMemo(
    () => sliceTablePage(filteredServerRootIssuedCertificates, tablePages.serverCaSigned),
    [filteredServerRootIssuedCertificates, tablePages.serverCaSigned],
  );
  const filteredNodeSessions = useMemo(() => {
    const q = String(serverSessionsSearch || "").trim().toLowerCase();
    if (!q) return nodeSessions;
    return nodeSessions.filter((row) => {
      const cn = String(row.commonName || "").toLowerCase();
      const remoteIp = String(remoteAddrHostOnlyDisplay(row.remoteIp) || "").toLowerCase();
      const virtualIp = String(row.virtualIp || "").toLowerCase();
      const sid = String(row.id || "").toLowerCase();
      const profile = cnProfileMap.get(String(row.commonName || ""));
      const fullName = String(profile?.fullName || "").toLowerCase();
      return (
        cn.includes(q) ||
        remoteIp.includes(q) ||
        virtualIp.includes(q) ||
        sid.includes(q) ||
        fullName.includes(q)
      );
    });
  }, [nodeSessions, serverSessionsSearch, cnProfileMap]);
  const nodeSessionsTablePage = useMemo(
    () => sliceTablePage(filteredNodeSessions, tablePages.serverSessions),
    [filteredNodeSessions, tablePages.serverSessions],
  );
  const userConnectionsTablePage = useMemo(
    () => sliceTablePage(userProfileSessionsSorted, tablePages.userConnections),
    [userProfileSessionsSorted, tablePages.userConnections],
  );
  const userCertsTablePage = useMemo(
    () => sliceTablePage(selectedUserCertificates, tablePages.userCerts),
    [selectedUserCertificates, tablePages.userCerts],
  );
  const logsVpnFiltered = useMemo(() => {
    const q = logsVpnSearch.trim().toLowerCase();
    const base = !q
      ? ipHistory
      : ipHistory.filter((item) => {
          const parts = [
            item.commonName,
            item.virtualIp,
            remoteAddrHostOnlyDisplay(item.realIp),
            item.connectedAt,
            item.vpnUserFullName,
            item.vpnUserEmail,
            item.vpnUserId,
            item.agentNode?.name,
            formatMaybeDate(item.firstSeenAt),
            formatMaybeDate(item.lastSeenAt),
            formatDurationSeconds(clientIpAssignmentDurationSeconds(item)),
          ];
          return parts.some((x) => String(x || "").toLowerCase().includes(q));
        });
    return sortRowsByLastSeenDesc(base);
  }, [ipHistory, logsVpnSearch]);
  const logsSrcFiltered = useMemo(() => {
    const q = logsSrcSearch.trim().toLowerCase();
    const base = !q
      ? sourceIpHistory
      : sourceIpHistory.filter((item) => {
          const parts = [
            item.commonName,
            remoteAddrHostOnlyDisplay(item.realIp),
            item.connectedAt,
            item.vpnUserFullName,
            item.vpnUserEmail,
            item.vpnUserId,
            item.agentNode?.name,
            formatMaybeDate(item.firstSeenAt),
            formatMaybeDate(item.lastSeenAt),
            formatMaybeDate(item.endedAt),
            formatDurationSeconds(clientSourceHistoryDurationSeconds(item)),
          ];
          return parts.some((x) => String(x || "").toLowerCase().includes(q));
        });
    return sortRowsByLastSeenDesc(base);
  }, [sourceIpHistory, logsSrcSearch]);
  const logsAdminFiltered = useMemo(() => {
    const q = logsAdminSearch.trim().toLowerCase();
    const base = !q
      ? adminActionLogs
      : adminActionLogs.filter((item) => {
          const parts = [
            item.adminUsername,
            item.admin?.username,
            item.action,
            item.method,
            item.path,
            item.ipAddress,
            item.targetType,
            item.targetId,
            String(item.statusCode ?? ""),
            formatMaybeDate(item.createdAt),
          ];
          return parts.some((x) => String(x || "").toLowerCase().includes(q));
        });
    return sortRowsByCreatedDesc(base);
  }, [adminActionLogs, logsAdminSearch]);
  const logsVpnTablePage = useMemo(() => sliceTablePage(logsVpnFiltered, tablePages.logsVpn), [logsVpnFiltered, tablePages.logsVpn]);
  const logsSrcTablePage = useMemo(
    () => sliceTablePage(logsSrcFiltered, tablePages.logsSrc),
    [logsSrcFiltered, tablePages.logsSrc],
  );
  const logsAdminTablePage = useMemo(
    () => sliceTablePage(logsAdminFiltered, tablePages.logsAdmin),
    [logsAdminFiltered, tablePages.logsAdmin],
  );
  const tasksTablePage = useMemo(
    () => sliceTablePage(panelAsyncTasks, tablePages.tasks),
    [panelAsyncTasks, tablePages.tasks],
  );
  const certSessionsTablePage = useMemo(
    () => sliceTablePage(selectedCertClients, tablePages.certSessions),
    [selectedCertClients, tablePages.certSessions],
  );
  const certIpTablePage = useMemo(
    () => sliceTablePage(selectedCertIpHistory, tablePages.certIp),
    [selectedCertIpHistory, tablePages.certIp],
  );
  const certSrcTablePage = useMemo(
    () => sliceTablePage(selectedCertSourceHistory, tablePages.certSrc),
    [selectedCertSourceHistory, tablePages.certSrc],
  );
  const filteredSystemServicesRows = useMemo(() => {
    const q = String(systemServicesQuery || "").trim().toLowerCase();
    const base = (systemServicesRows || []).filter((row) => {
      const load = String(row?.loadState || "").trim().toLowerCase();
      if (load === "not-found") return false;
      const unit = String(row?.unit || "").toLowerCase();
      const desc = String(row?.description || "").toLowerCase();
      const text = `${unit} ${desc}`;
      const isOpenvpn = text.includes("openvpn");
      const isDnsmasq = text.includes("dnsmasq");
      const isFirewall =
        text.includes("nftables") ||
        text.includes("iptables") ||
        text.includes("firewalld") ||
        text.includes("ufw");
      return isOpenvpn || isDnsmasq || isFirewall;
    });
    if (!q) return base;
    return base.filter((row) => {
      const unit = String(row?.unit || "").toLowerCase();
      const desc = String(row?.description || "").toLowerCase();
      const active = String(row?.activeState || "").toLowerCase();
      const sub = String(row?.subState || "").toLowerCase();
      const load = String(row?.loadState || "").toLowerCase();
      return unit.includes(q) || desc.includes(q) || active.includes(q) || sub.includes(q) || load.includes(q);
    });
  }, [systemServicesRows, systemServicesQuery]);
  const userConnectionSelectedCert = useMemo(
    () =>
      userConnectionProfileOptions.certificates.find((c) => c.id === userConnectionProfileDraft.certificateId) || null,
    [userConnectionProfileOptions.certificates, userConnectionProfileDraft.certificateId],
  );
  const userConnectionServersFiltered = useMemo(() => {
    const rootId = String(userConnectionSelectedCert?.rootCaId || "").trim();
    if (!rootId) return [];
    return userConnectionProfileOptions.servers.filter((s) => String(s.panelRootCaId || "").trim() === rootId);
  }, [userConnectionProfileOptions.servers, userConnectionSelectedCert?.rootCaId]);

  if (primaryNav === "resetAdminPassword") {
    return <AdminPasswordResetAccept apiUrl={API_URL} token={resetAdminPasswordToken} />;
  }

  if (primaryNav === "inviteAdmin") {
    return <AdminInviteAccept apiUrl={API_URL} token={inviteAdminToken} />;
  }

  if (!isAuthorized) {
    return (
      <main className="auth-shell">
        <div className="auth-inner">
          <div className="auth-card">
            <h2 className="auth-card-title">Вход администратора</h2>
            <form className="auth-form" onSubmit={login}>
              <div className="auth-field">
                <label className="auth-label" htmlFor="auth-login-username">
                  Логин
                </label>
                <input
                  id="auth-login-username"
                  className="auth-input"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  autoComplete="username"
                  placeholder="Имя пользователя"
                  disabled={mfaModalOpen}
                />
              </div>
              <div className="auth-field">
                <label className="auth-label" htmlFor="auth-login-password">
                  Пароль
                </label>
                <input
                  id="auth-login-password"
                  className="auth-input"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  type="password"
                  autoComplete="current-password"
                  placeholder="••••••••"
                  disabled={mfaModalOpen}
                />
              </div>
              {error ? (
                <div className="auth-alert auth-alert--error" role="alert">
                  {error}
                </div>
              ) : null}
              <button type="submit" className="auth-submit btn-app-primary" disabled={mfaModalOpen}>
                Войти
              </button>
            </form>
          </div>
          <p className="auth-footer-note">Доступ только для авторизованных администраторов.</p>

          {mfaModalOpen ? (
            <div
              className="modal-backdrop"
              role="presentation"
              onClick={(e) => {
                if (e.target === e.currentTarget) closeMfaModal();
              }}
            >
              <div className="modal-dialog" role="dialog" aria-modal="true" aria-labelledby="mfa-login-title">
                <div className="modal-dialog-header">
                  <h2 id="mfa-login-title" className="modal-dialog-title">
                    Двухфакторная аутентификация
                  </h2>
                  <button type="button" className="modal-close" aria-label="Закрыть" onClick={closeMfaModal}>
                    ×
                  </button>
                </div>
                <p className="muted" style={{ marginTop: 0 }}>
                  Введите код из приложения-аутентификатора или одноразовый резервный код. Доступ к панели будет выдан
                  только после проверки.
                </p>
                <form className="auth-form" onSubmit={submitMfaLogin} style={{ marginTop: 12 }}>
                  <div className="auth-field">
                    <label className="auth-label" htmlFor="mfa-totp-code">
                      Код из приложения (TOTP)
                    </label>
                    <input
                      id="mfa-totp-code"
                      className="auth-input"
                      value={mfaTotpCode}
                      onChange={(e) => setMfaTotpCode(e.target.value)}
                      inputMode="numeric"
                      autoComplete="one-time-code"
                      placeholder="123456"
                      disabled={mfaBusy}
                      autoFocus
                    />
                  </div>
                  <div className="auth-field">
                    <label className="auth-label" htmlFor="mfa-recovery-code">
                      Резервный код
                    </label>
                    <input
                      id="mfa-recovery-code"
                      className="auth-input app-table-mono"
                      value={mfaRecoveryCode}
                      onChange={(e) => setMfaRecoveryCode(e.target.value)}
                      autoComplete="off"
                      placeholder="xxxx-xxxx-xxxx-xxxx"
                      disabled={mfaBusy}
                    />
                  </div>
                  {mfaError ? (
                    <div className="auth-alert auth-alert--error" role="alert">
                      {mfaError}
                    </div>
                  ) : null}
                  <div className="row-inline" style={{ flexWrap: "wrap", gap: 8, marginTop: 8 }}>
                    <button type="submit" className="btn-app-primary" disabled={mfaBusy}>
                      {mfaBusy ? "Проверка…" : "Подтвердить и войти"}
                    </button>
                    <button type="button" className="btn-secondary" disabled={mfaBusy} onClick={closeMfaModal}>
                      Отмена
                    </button>
                  </div>
                </form>
              </div>
            </div>
          ) : null}
        </div>
      </main>
    );
  }

  const goHome = () => {
    navigate(paths.home());
  };

  let breadcrumbs = [{ label: "OVPN Control", onClick: goHome }];
  let pageTitle = "";
  let primaryAction = null;
  let subnav = [];
  let showServerFilter = false;
  let showUserListFilter = false;

  if (primaryNav === "servers") {
    subnav = [];
    if (serversView === "list") {
      breadcrumbs = [...breadcrumbs, { label: "Серверы" }];
      pageTitle = "Серверы VPN";
      showServerFilter = true;
      primaryAction = {
        label: "Новый сервер",
        onClick: () => {
          navigate(paths.serverNew());
        },
      };
    } else if (serversView === "detail") {
      const srv = selectedServer;
      breadcrumbs = [
        ...breadcrumbs,
        { label: "Серверы", onClick: goServersList },
        { label: srv?.name || "Сервер", onClick: () => navigate(paths.serverDetail(selectedServerId, "overview")) },
      ];
      if (serverDetailTab === "ca-center") {
        breadcrumbs.push(
          { label: "Центр сертификации", onClick: () => navigate(paths.serverDetail(selectedServerId, "ca-center")) },
          ...(serverCenterSelectedCert ? [{ label: serverCenterSelectedCert.commonName || "Сертификат" }] : []),
        );
      }
      pageTitle = srv?.name || "Сервер";
    } else if (serversView === "add") {
      breadcrumbs = [
        ...breadcrumbs,
        { label: "Серверы", onClick: goServersList },
        { label: "Новый сервер" },
      ];
      pageTitle = "Новый сервер";
    }
  } else if (primaryNav === "organizations") {
    subnav = [];
    if (organizationsView === "list") {
      breadcrumbs = [...breadcrumbs, { label: "Организации" }];
      pageTitle = "Организации";
      primaryAction = {
        label: "Добавить организацию",
        onClick: () => {
          navigate(paths.organizationNew());
        },
      };
    } else if (organizationsView === "add") {
      breadcrumbs = [
        ...breadcrumbs,
        { label: "Организации", onClick: goOrganizationsList },
        { label: "Новая организация" },
      ];
      pageTitle = "Новая организация";
    } else if (organizationsView === "edit") {
      const editTitle = editOrganization.name?.trim() || "Редактирование";
      breadcrumbs = [
        ...breadcrumbs,
        { label: "Организации", onClick: goOrganizationsList },
        { label: editTitle, onClick: () => navigate(paths.organizationEdit(organizationEditId, "overview")) },
      ];
      pageTitle = organizationEditTab === "firewall" ? `Межсетевой экран: ${editTitle}` : `Редактирование: ${editTitle}`;
    }
  } else if (primaryNav === "users") {
    breadcrumbs = [...breadcrumbs, { label: "Пользователи", onClick: goUsersList }];
    subnav = [];
    if (usersSub === "list") {
      pageTitle = "Пользователи";
      showUserListFilter = true;
      primaryAction = {
        label: "Добавить пользователя",
        onClick: () => {
          navigate(paths.userNew());
        },
      };
    } else if (usersSub === "add") {
      breadcrumbs = [...breadcrumbs, { label: "Новый пользователь" }];
      pageTitle = "Новый пользователь";
    } else if (usersSub === "profile") {
      const profileLabel = selectedUser?.fullName || "Профиль";
      breadcrumbs = [...breadcrumbs, { label: profileLabel }];
      pageTitle = selectedUser ? `Профиль: ${selectedUser.fullName}` : "Профиль";
    }
  } else if (primaryNav === "myProfile") {
    breadcrumbs = [...breadcrumbs, { label: "Мой профиль" }];
    pageTitle = "Профиль администратора";
    subnav = [];
  } else if (primaryNav === "settings") {
    breadcrumbs = [...breadcrumbs, { label: "Настройки", onClick: () => navigate(paths.settings()) }];
    subnav = [];
    if (settingsSection === "backup") {
      breadcrumbs.push({ label: "Резервное копирование" });
      pageTitle = "Резервное копирование";
    } else if (settingsSection === "restore") {
      breadcrumbs.push({ label: "Восстановление" });
      pageTitle = "Восстановление";
    } else if (adminsPage === "detail" && selectedAdminId) {
      const uname = selectedAdmin?.username || "—";
      breadcrumbs.push(
        { label: "Администраторы", onClick: () => navigate(paths.settings()) },
        { label: uname },
      );
      pageTitle = `Администратор: ${uname}`;
    } else {
      breadcrumbs.push({ label: "Администраторы" });
      pageTitle = "Администраторы";
    }
  } else if (primaryNav === "logs") {
    const logsSectionLabels = {
      "vpn-ip": "Назначение VPN-IP",
      "source-ip": "Исходные IP",
      admin: "Действия администраторов",
    };
    const logsSection = logsSectionLabels[logsView] || "Журнал";
    breadcrumbs = [
      ...breadcrumbs,
      { label: "Журнал", onClick: () => navigate(paths.logs()) },
      { label: logsSection },
    ];
    pageTitle = logsSection;
  } else if (primaryNav === "tasks") {
    breadcrumbs = [...breadcrumbs, { label: "Задачи" }];
    pageTitle = "Задачи";
    subnav = [];
  } else if (primaryNav === "documentation") {
    breadcrumbs = [...breadcrumbs, { label: "Документация" }];
    pageTitle = "Документация";
    subnav = [];
  }

  const hideMainPageChrome =
    (primaryNav === "users" && usersSub === "profile") ||
    (primaryNav === "organizations" && organizationsView === "edit") ||
    (primaryNav === "servers" && serversView === "detail") ||
    primaryNav === "logs" ||
    primaryNav === "myProfile" ||
    primaryNav === "settings" ||
    primaryNav === "documentation";

  const organizationEditMissing =
    primaryNav === "organizations" &&
    organizationsView === "edit" &&
    Boolean(organizationEditId) &&
    organizations.length > 0 &&
    !organizations.some((o) => o.id === organizationEditId);

  return (
    <div className="app-shell">
      <div className="app-body">
        <aside className="sidebar-rail" aria-label="Разделы">
          <button type="button" className="sidebar-rail-brand" title="OVPN Control — на главную" onClick={goHome}>
            <span className="sidebar-rail-brand-icon" aria-hidden>
              <svg viewBox="0 0 32 32" width="22" height="22">
                <circle cx="16" cy="16" r="14" fill="#f97316" />
                <path
                  d="M16 8c-3 0-5 2.2-5 5v6c0 1.7 1.3 3 3 3h4c1.7 0 3-1.3 3-3v-6c0-2.8-2-5-5-5zm-1 9h2v4h-2v-4z"
                  fill="#fff"
                />
              </svg>
            </span>
          </button>
          <nav className="sidebar-rail-nav">
            <button
              type="button"
              className={sidebarRailClass(primaryNav === "servers")}
              title="Серверы"
              aria-label="Серверы"
              onClick={() => {
                navigate(paths.servers());
              }}
            >
              <IconServers />
            </button>
            <button
              type="button"
              className={sidebarRailClass(primaryNav === "organizations")}
              title="Организации"
              aria-label="Организации"
              onClick={() => {
                navigate(paths.organizations());
              }}
            >
              <IconOrganizations />
            </button>
            <button
              type="button"
              className={sidebarRailClass(primaryNav === "users")}
              title="Пользователи"
              aria-label="Пользователи"
              onClick={() => {
                navigate(paths.users());
              }}
            >
              <IconUsers />
            </button>
            <button
              type="button"
              className={sidebarRailClass(primaryNav === "tasks")}
              title="Задачи"
              aria-label="Задачи"
              onClick={() => {
                navigate(paths.tasks());
              }}
            >
              <IconTasks />
            </button>
            <button
              type="button"
              className={sidebarRailClass(primaryNav === "logs")}
              title="Журнал"
              aria-label="Журнал"
              onClick={() => {
                navigate(paths.logs());
              }}
            >
              <IconLogs />
            </button>
            <button
              type="button"
              className={sidebarRailClass(primaryNav === "settings")}
              title="Настройки"
              aria-label="Настройки"
              onClick={() => {
                navigate(paths.settings());
              }}
            >
              <IconSettings />
            </button>
          </nav>
          <div className="sidebar-rail-spacer" aria-hidden />
          <nav className="sidebar-rail-footer" aria-label="Справка">
            <button
              type="button"
              className={sidebarRailClass(primaryNav === "documentation")}
              title="Документация"
              aria-label="Документация"
              onClick={() => {
                navigate(paths.documentation());
              }}
            >
              <IconDocumentation />
            </button>
          </nav>
        </aside>

        <div className="main-column">
          <header className="app-top-row">
            <nav className="app-breadcrumbs" aria-label="Путь">
              {breadcrumbs.map((crumb, i) => {
                const isLast = i === breadcrumbs.length - 1;
                const showLink = Boolean(crumb.onClick) && !isLast;
                return (
                  <span key={`${crumb.label}-${i}`} className="app-breadcrumb-part">
                    {i > 0 ? <span className="app-breadcrumb-sep" aria-hidden>/</span> : null}
                    {showLink ? (
                      <button type="button" className="app-breadcrumb-link" onClick={crumb.onClick}>
                        {crumb.label}
                      </button>
                    ) : (
                      <span className="app-breadcrumb-current">{crumb.label}</span>
                    )}
                  </span>
                );
              })}
            </nav>
            <div className="app-top-user">
              <span className="user-session-countdown" title="До конца сессии" aria-live="polite">
                {formatSessionCountdown(sessionSecondsLeft)}
              </span>
              <div className="user-toolbar-menu" ref={userToolbarMenuRef}>
                <button
                  type="button"
                  className={`user-toolbar-menu-trigger${userToolbarMenuOpen ? " is-open" : ""}`}
                  aria-expanded={userToolbarMenuOpen}
                  aria-haspopup="menu"
                  id="user-toolbar-menu-button"
                  onClick={() => setUserToolbarMenuOpen((open) => !open)}
                >
                  <div className="user-avatar user-avatar--toolbar" aria-hidden="true">
                    {avatarInitials(sessionProfileFullName)}
                  </div>
                  <div className="user-meta user-meta--toolbar">
                    <span className="user-label">{sessionToolbarDisplayName}</span>
                  </div>
                </button>
                {userToolbarMenuOpen ? (
                  <div className="user-toolbar-menu-panel" role="menu" aria-labelledby="user-toolbar-menu-button">
                    <button
                      type="button"
                      className="user-toolbar-menu-item"
                      role="menuitem"
                      onClick={() => {
                        setUserToolbarMenuOpen(false);
                        navigate(paths.profile());
                      }}
                    >
                      Мой профиль
                    </button>
                    <button
                      type="button"
                      className="btn-logout btn-logout--toolbar user-toolbar-menu-item user-toolbar-menu-item--logout"
                      role="menuitem"
                      onClick={() => {
                        setUserToolbarMenuOpen(false);
                        logout();
                      }}
                    >
                      Выйти
                    </button>
                  </div>
                ) : null}
              </div>
            </div>
          </header>

          {error || restoreMessage ? (
            <div className="app-page-alert-host" aria-live="polite">
              {error ? (
                <div className="auth-alert auth-alert--error" role="alert">
                  {error}
                </div>
              ) : restoreMessage ? (
                <div className="auth-alert auth-alert--success" role="status">
                  {restoreMessage}
                </div>
              ) : null}
            </div>
          ) : null}

          <main className={`main-area${hideMainPageChrome ? " main-area--resource" : ""}`}>
          <div className={`main-area-body${hideMainPageChrome ? " main-area-body--resource" : ""}`}>
          {!hideMainPageChrome ? (
            <>
              <div className="app-page-bar">
                <h1 className="app-page-title">{pageTitle}</h1>
                {primaryAction ? (
                  <button type="button" className="btn-app-primary" onClick={primaryAction.onClick}>
                    <span className="btn-app-primary-plus" aria-hidden>
                      +
                    </span>
                    {primaryAction.label}
                  </button>
                ) : null}
              </div>

              {subnav.length > 0 ? (
                <nav className="app-subnav" aria-label="Подраздел">
                  {subnav.map((item) => (
                    <button key={item.key} type="button" className={item.active ? "app-subnav-link is-active" : "app-subnav-link"} onClick={item.go}>
                      {item.label}
                    </button>
                  ))}
                </nav>
              ) : null}

              {showServerFilter ? (
                <div className="app-list-toolbar">
                  <input
                    type="search"
                    className="app-filter-input"
                    placeholder="Фильтр по имени"
                    value={serverNameFilter}
                    onChange={(e) => setServerNameFilter(e.target.value)}
                    autoComplete="off"
                  />
                </div>
              ) : null}

              {showUserListFilter ? (
                <div className="app-list-toolbar">
                  <input
                    type="search"
                    className="app-filter-input"
                    placeholder="Поиск: ФИО, должность, организация, email, телефон…"
                    value={userListFilter}
                    onChange={(e) => setUserListFilter(e.target.value)}
                    autoComplete="off"
                  />
                </div>
              ) : null}
            </>
          ) : null}

          {primaryNav === "servers" && serversView === "list" && (
            <div className="app-table-with-pagination">
              <div className="app-table-scroll">
              <table className="app-table app-table--fixed-cols">
                <thead>
                  <tr>
                    <th>Имя</th>
                    <th>Статус</th>
                    <th>Адрес агента</th>
                    <th>CPU</th>
                    <th>RAM</th>
                    <th>Сеть</th>
                    <th>Сессии</th>
                  </tr>
                </thead>
                <tbody>
                  {serversTablePage.slice.map((server) => {
                    const online = String(server.status || "").toUpperCase() === "ONLINE";
                    const addr =
                      server.host != null
                        ? `${server.protocol || "http"}://${server.host}:${server.port ?? ""}`
                        : "—";
                    return (
                      <tr
                        key={server.id}
                        className="app-table-click-row"
                        tabIndex={0}
                        role="button"
                        onClick={() => {
                          navigate(paths.serverDetail(server.id));
                        }}
                        onKeyDown={(e) => {
                          if (e.key === "Enter" || e.key === " ") {
                            e.preventDefault();
                            navigate(paths.serverDetail(server.id));
                          }
                        }}
                      >
                        <td className="app-table-cell-strong">{server.name}</td>
                        <td className="app-table-td-clip-none">
                          <span className={`app-status ${online ? "app-status--ok" : "app-status--off"}`}>
                            {online ? "Running" : server.status || "Unknown"}
                          </span>
                        </td>
                        <td className="app-table-mono">{addr}</td>
                        <td>{Math.round(server.cpuPercent || 0)}%</td>
                        <td>{Math.round(server.memoryPercent || 0)}%</td>
                        <td className="app-table-nowrap">
                          ↑ {formatBps(server.networkOutBps)} · ↓ {formatBps(server.networkInBps)}
                        </td>
                        <td>{server.activeClients ?? 0}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              </div>
              <TablePagination
                page={serversTablePage.page}
                totalPages={serversTablePage.totalPages}
                total={serversTablePage.total}
                onPageChange={(p) => setTablePages((prev) => ({ ...prev, servers: p }))}
              />
            </div>
          )}

          {primaryNav === "servers" && serversView === "detail" && (
            <div className={`resource-layout${!selectedServer ? " resource-layout--empty" : ""}`}>
              {!selectedServer ? (
                <section className="card">
                  <p className="muted">Сервер не найден. Вернитесь к списку.</p>
                </section>
              ) : (
                <>
                  <aside className="resource-sidebar" aria-label="Разделы сервера">
                    <div className="resource-sidebar-header">
                      <h2 className="resource-sidebar-title">{selectedServer.name}</h2>
                      <p className="resource-sidebar-sub">Сервер (агент)</p>
                    </div>
                    <nav className="resource-nav" aria-label="Навигация по серверу">
                      <button
                        type="button"
                        className={`resource-nav-item${serverDetailTab === "overview" ? " is-active" : ""}`}
                        aria-current={serverDetailTab === "overview" ? "page" : undefined}
                        onClick={() => navigate(paths.serverDetail(selectedServerId, "overview"))}
                      >
                        <IconNavOperations />
                        Обзор
                      </button>
                      <button
                        type="button"
                        className={`resource-nav-item${serverDetailTab === "sessions" ? " is-active" : ""}`}
                        aria-current={serverDetailTab === "sessions" ? "page" : undefined}
                        onClick={() => navigate(paths.serverDetail(selectedServerId, "sessions"))}
                      >
                        <IconNavSessions />
                        Активные сессии
                      </button>
                      <button
                        type="button"
                        className={`resource-nav-item${serverDetailTab === "monitoring" ? " is-active" : ""}`}
                        aria-current={serverDetailTab === "monitoring" ? "page" : undefined}
                        onClick={() => navigate(paths.serverDetail(selectedServerId, "monitoring"))}
                      >
                        <IconNavMonitoring />
                        Мониторинг
                      </button>
                      <button
                        type="button"
                        className={`resource-nav-item${serverDetailTab === "agent" ? " is-active" : ""}`}
                        aria-current={serverDetailTab === "agent" ? "page" : undefined}
                        onClick={() => navigate(paths.serverDetail(selectedServerId, "agent"))}
                      >
                        <IconNavOverview />
                        Агент
                      </button>
                      <button
                        type="button"
                        className={`resource-nav-item${serverDetailTab === "certificates" || serverDetailTab === "keys" ? " is-active" : ""}`}
                        aria-current={serverDetailTab === "certificates" || serverDetailTab === "keys" ? "page" : undefined}
                        onClick={() => navigate(paths.serverDetail(selectedServerId, "certificates"))}
                      >
                        <IconNavCertificate />
                        Сертификаты и ключи
                      </button>
                      <button
                        type="button"
                        className={`resource-nav-item${serverDetailTab === "ca-center" ? " is-active" : ""}`}
                        aria-current={serverDetailTab === "ca-center" ? "page" : undefined}
                        onClick={() => navigate(paths.serverDetail(selectedServerId, "ca-center"))}
                      >
                        <IconNavCertificate />
                        Центр сертификации
                      </button>
                      <button
                        type="button"
                        className={`resource-nav-item${serverDetailTab === "settings" ? " is-active" : ""}`}
                        aria-current={serverDetailTab === "settings" ? "page" : undefined}
                        onClick={() => navigate(paths.serverDetail(selectedServerId, "settings"))}
                      >
                        <IconSettings />
                        Служба OpenVPN
                      </button>
                      <button
                        type="button"
                        className={`resource-nav-item${serverDetailTab === "dns" ? " is-active" : ""}`}
                        aria-current={serverDetailTab === "dns" ? "page" : undefined}
                        onClick={() => navigate(paths.serverDetail(selectedServerId, "dns"))}
                      >
                        <IconNavOperations />
                        Служба DNS
                      </button>
                      <button
                        type="button"
                        className={`resource-nav-item${serverDetailTab === "firewall" ? " is-active" : ""}`}
                        aria-current={serverDetailTab === "firewall" ? "page" : undefined}
                        onClick={() => navigate(paths.serverDetail(selectedServerId, "firewall"))}
                      >
                        <IconSettings />
                        Межсетевой экран
                      </button>
                      <button
                        type="button"
                        className={`resource-nav-item${serverDetailTab === "journal" ? " is-active" : ""}`}
                        aria-current={serverDetailTab === "journal" ? "page" : undefined}
                        onClick={() => navigate(paths.serverDetail(selectedServerId, "journal"))}
                      >
                        <IconLogs />
                        Журнал
                      </button>
                    </nav>
                  </aside>
                  <div className="resource-main">
                    {serverDetailTab === "agent" && (
                      <div className="user-profile-blocks user-profile-blocks--stack">
                        <h2 className="server-detail-section-title" style={{ margin: 0 }}>
                          Агент
                        </h2>
                        <form className="user-profile-blocks--stack" onSubmit={saveServerAgentConfig}>
                          <div className="user-profile-field-block">
                            <div className="user-profile-field-label">
                              Имя узла <span className="error">*</span>
                            </div>
                            <input
                              required
                              value={serverAgentDraft.name}
                              onChange={(e) => setServerAgentDraft((prev) => ({ ...prev, name: e.target.value }))}
                            />
                          </div>
                          <div className="user-profile-field-block">
                            <div className="user-profile-field-label">Протокол</div>
                            <select
                              value={serverAgentDraft.protocol}
                              onChange={(e) => setServerAgentDraft((prev) => ({ ...prev, protocol: e.target.value }))}
                            >
                              <option value="http">http</option>
                              <option value="https">https</option>
                            </select>
                            <p className="user-profile-field-hint">Протокол доступа к API агента.</p>
                          </div>
                          <div className="user-profile-field-block">
                            <div className="user-profile-field-label">
                              Хост <span className="error">*</span>
                            </div>
                            <input
                              required
                              value={serverAgentDraft.host}
                              onChange={(e) => setServerAgentDraft((prev) => ({ ...prev, host: e.target.value }))}
                            />
                            <p className="user-profile-field-hint">Имя хоста или IP-адрес узла с агентом.</p>
                          </div>
                          <div className="user-profile-field-block">
                            <div className="user-profile-field-label">
                              Порт <span className="error">*</span>
                            </div>
                            <input
                              required
                              type="number"
                              min={1}
                              max={65535}
                              value={serverAgentDraft.port}
                              onChange={(e) => setServerAgentDraft((prev) => ({ ...prev, port: e.target.value }))}
                            />
                            <p className="user-profile-field-hint">Порт прослушивания агента.</p>
                          </div>
                          <div className="user-profile-field-block">
                            <div className="user-profile-field-label">Токен агента</div>
                            <input
                              type="password"
                              autoComplete="new-password"
                              value={serverAgentDraft.authToken}
                              onChange={(e) => setServerAgentDraft((prev) => ({ ...prev, authToken: e.target.value }))}
                              placeholder=""
                            />
                            <p className="user-profile-field-hint">
                              Оставьте поле пустым, чтобы не менять токен. Укажите новый токен только при смене секрета на
                              узле.
                            </p>
                          </div>
                          <div className="row-inline server-agent-form-actions" style={{ gap: 8, flexWrap: "wrap", marginTop: 4 }}>
                            <button type="submit">Сохранить</button>
                            <button
                              type="button"
                              className="btn-secondary"
                              disabled={!selectedServerId}
                              onClick={() => {
                                setAgentUpdateModalOpen(true);
                                setAgentUpdateError("");
                                setAgentUpdateResult("");
                                setAgentUpdateJournalTail("");
                                setAgentUpdateUploadPct(0);
                                setAgentUpdateFileName("");
                                setAgentUpdateSha256("");
                                setAgentUpdateBinaryBase64("");
                              }}
                            >
                              Обновить
                            </button>
                          </div>
                        </form>
                      </div>
                    )}

                    {serverDetailTab === "monitoring" && (
                      <>
                        <h2 className="server-detail-section-title">Мониторинг</h2>
                        <MonitoringCharts
                          samples={selectedServerMonitoringSamples}
                          current={selectedServer}
                          historyMinutes={overview?.metricHistoryMinutes ?? 15}
                        />
                      </>
                    )}

                    {serverDetailTab === "sessions" && (
                      <>
                        <h2 className="server-detail-section-title">Активные сессии</h2>
                        <div className="app-table-filters" style={{ marginBottom: 12 }}>
                          <input
                            className="app-filter-input"
                            type="search"
                            placeholder="Поиск: пользователь, CN, IP, ID сессии"
                            value={serverSessionsSearch}
                            onChange={(e) => setServerSessionsSearch(e.target.value)}
                            aria-label="Поиск по активным сессиям"
                          />
                        </div>
                        {filteredNodeSessions.length === 0 ? (
                          <p className="muted">Нет активных сессий на этом сервере.</p>
                        ) : (
                          <div className="app-table-with-pagination">
                          <div className="app-table-scroll">
                            <table className="app-table app-table--compact app-table--fixed-cols table-server-sessions">
                              <thead>
                                <tr>
                                  <th>Пользователь</th>
                                  <th>CN</th>
                                  <th>Внешний IP адрес</th>
                                  <th>Внутренний IP адрес</th>
                                  <th>Продолжительность сессии</th>
                                  <th>Трафик in / out</th>
                                  <th className="app-table-col-actions">Действия</th>
                                </tr>
                              </thead>
                              <tbody>
                                {nodeSessionsTablePage.slice.map((client) => {
                                  const cn = client.commonName || "";
                                  const inSys = cn && registeredCnSet.has(cn);
                                  const profile = cnProfileMap.get(cn);
                                  const goProfile = () => {
                                    if (!profile?.userId) return;
                                    navigate(paths.userProfile(profile.userId, "overview"));
                                  };
                                  return (
                                    <tr key={`${client.nodeId}-${client.id}`}>
                                      <td className={inSys ? "app-table-cell-strong" : undefined}>
                                        {inSys ? (
                                          <button
                                            type="button"
                                            className="app-link-btn"
                                            style={{ color: "inherit", textDecoration: "underline" }}
                                            onClick={goProfile}
                                          >
                                            {profile?.fullName || "—"}
                                          </button>
                                        ) : (
                                          <span className="muted" title="Нет профиля пользователя в базе данных">
                                            Не в системе
                                          </span>
                                        )}
                                      </td>
                                      <td className="app-table-cell-strong">{cn || "—"}</td>
                                      <td className="app-table-mono">{remoteAddrHostOnlyDisplay(client.remoteIp) || "—"}</td>
                                      <td className="app-table-mono">{client.virtualIp || "—"}</td>
                                      <td
                                        className="app-table-nowrap"
                                        title={formatSessionConnectedTitle(client.connectedSince || client.connectedAt)}
                                      >
                                        {formatSessionConnectedLabel(client.connectedSince || client.connectedAt, sessionNow)}
                                      </td>
                                      <td className="app-table-nowrap">
                                        {formatBps(client.inBps)} / {formatBps(client.outBps)}
                                      </td>
                                      <td className="app-table-td-clip-none">
                                        {disconnectingSessionKeys.includes(`${client.nodeId}-${client.id}`) ? (
                                          <span className="muted" style={{ fontSize: "12px" }}>Завершается...</span>
                                        ) : (
                                          <button
                                            type="button"
                                            className="app-link-btn app-link-btn--danger"
                                            onClick={() =>
                                              openUserSessionDisconnect(
                                                client.nodeId,
                                                client.nodeName || selectedServer?.name || client.nodeId,
                                                client.id,
                                                profile?.fullName || cn || "—",
                                              )
                                            }
                                          >
                                            Завершить
                                          </button>
                                        )}
                                      </td>
                                    </tr>
                                  );
                                })}
                              </tbody>
                            </table>
                          </div>
                          <TablePagination
                            page={nodeSessionsTablePage.page}
                            totalPages={nodeSessionsTablePage.totalPages}
                            total={nodeSessionsTablePage.total}
                            onPageChange={(p) => setTablePages((prev) => ({ ...prev, serverSessions: p }))}
                          />
                          </div>
                        )}
                      </>
                    )}

                    {(serverDetailTab === "certificates" || serverDetailTab === "keys") && (
                      <div className="user-profile-blocks user-profile-blocks--stack user-profile-blocks--full">
                        <div className="user-profile-field-block">
                          <div className="user-profile-field-label">Корневой сертификат узла</div>
                          {!panelRootCaIdForServer ? (
                            <div className="row-inline" style={{ gap: 8, flexWrap: "wrap", marginTop: 8 }}>
                              <button
                                type="button"
                                className="btn-secondary"
                                disabled={serverOpenVpnLoading}
                                onClick={() => setServerRootCaCreateModalOpen(true)}
                              >
                                Создать корневой сертификат
                              </button>
                              <button
                                type="button"
                                className="btn-secondary"
                                disabled={serverOpenVpnLoading}
                                onClick={() => setServerRootCaImportModalOpen(true)}
                              >
                                Импортировать
                              </button>
                            </div>
                          ) : (
                            <>
                              {serverRootCaSummary.loading && !serverRootCaSummary.data ? null : serverRootCaSummary.data ? (
                                <div className="app-table-scroll" style={{ marginTop: 12 }}>
                                  <table className="app-table app-table--compact server-root-ca-summary">
                                    <tbody>
                                      <tr>
                                        <th scope="row" className="app-table-nowrap">
                                          Common Name
                                        </th>
                                        <td className="app-table-mono">{serverRootCaSummary.data.commonName || "—"}</td>
                                      </tr>
                                      {(() => {
                                        const fp = panelCertFingerprintRow(serverRootCaSummary.data);
                                        return (
                                          <tr>
                                            <th scope="row" className="app-table-nowrap">
                                              {fp.label}
                                            </th>
                                            <td className="app-table-mono">{fp.value}</td>
                                          </tr>
                                        );
                                      })()}
                                      <tr>
                                        <th scope="row" className="app-table-nowrap">
                                          Серийный номер
                                        </th>
                                        <td className="app-table-mono">{serverRootCaSummary.data.serialNumber || "—"}</td>
                                      </tr>
                                      <tr>
                                        <th scope="row" className="app-table-nowrap">
                                          Алгоритм ключа
                                        </th>
                                        <td>
                                          {serverRootCaSummary.data.algorithm || "—"}
                                          {serverRootCaSummary.data.keySize
                                            ? ` · ${serverRootCaSummary.data.keySize} бит`
                                            : ""}
                                        </td>
                                      </tr>
                                      <tr>
                                        <th scope="row" className="app-table-nowrap">
                                          Действителен до
                                        </th>
                                        <td className="app-table-nowrap">
                                          {formatMaybeDate(serverRootCaSummary.data.validTo)}
                                        </td>
                                      </tr>
                                      {(() => {
                                        const v = panelCertValidityPresentation(serverRootCaSummary.data.validTo);
                                        return (
                                          <tr>
                                            <th scope="row" className="app-table-nowrap">
                                              Состояние
                                            </th>
                                            <td>
                                              <span
                                                style={{
                                                  fontWeight: 600,
                                                  color: v.active ? "#1a7f37" : "#c62828",
                                                }}
                                              >
                                                {v.text}
                                              </span>
                                            </td>
                                          </tr>
                                        );
                                      })()}
                                    </tbody>
                                  </table>
                                </div>
                              ) : (
                                <p className="muted" style={{ marginTop: 12 }}>
                                  Не удалось загрузить техническую сводку по корневому сертификату (проверьте права или
                                  обновите страницу).
                                </p>
                              )}
                              <div className="row-inline" style={{ gap: 8, marginTop: 16, flexWrap: "wrap" }}>
                                <button
                                  type="button"
                                  className="btn-secondary"
                                  disabled={serverOpenVpnLoading || serverRootCaDeleteModal.busy}
                                  onClick={() => void downloadRootCaArtifact("root_crt")}
                                >
                                  root.crt
                                </button>
                                <button
                                  type="button"
                                  className="btn-secondary"
                                  disabled={serverOpenVpnLoading || serverRootCaDeleteModal.busy}
                                  onClick={() => void downloadRootCaArtifact("root_key")}
                                >
                                  root.key
                                </button>
                                <button
                                  type="button"
                                  className="btn-secondary"
                                  disabled={serverOpenVpnLoading || serverRootCaDeleteModal.busy}
                                  onClick={() => void downloadRootCaArtifact("index")}
                                >
                                  index.txt
                                </button>
                                <button
                                  type="button"
                                  className="btn-secondary"
                                  disabled={serverOpenVpnLoading || serverRootCaDeleteModal.busy}
                                  onClick={() => void downloadRootCaArtifact("crl")}
                                >
                                  crl.pem
                                </button>
                                <button
                                  type="button"
                                  className="btn-danger"
                                  disabled={serverOpenVpnLoading || serverRootCaDeleteModal.busy}
                                  onClick={() =>
                                    setServerRootCaDeleteModal({
                                      open: true,
                                      step: 1,
                                      confirmCommonName: "",
                                      busy: false,
                                      error: "",
                                    })
                                  }
                                >
                                  Удалить корневой сертификат
                                </button>
                              </div>
                            </>
                          )}
                        </div>
                        <div className="user-profile-field-block">
                          <div className="user-profile-field-label">Сертификат сервера</div>
                          {!panelRootCaIdForServer ? (
                            <p className="muted" style={{ marginBottom: 12 }}>
                              Сначала создайте или импортируйте корневой сертификат для этого сервера.
                            </p>
                          ) : keysTabServerCertificates.length === 0 ? (
                            <>
                              <p className="muted" style={{ marginTop: 0 }}>
                                Пока нет сертификата сервера для текущего корневого сертификата. Создайте или
                                импортируйте сертификат сервера.
                              </p>
                              <div className="row-inline" style={{ gap: 8, marginTop: 16, flexWrap: "wrap" }}>
                                <button
                                  type="button"
                                  className="btn-secondary"
                                  disabled={
                                    !panelRootCaIdForServer ||
                                    keysMaxServerCertValidityDays < 1 ||
                                    serverOpenVpnLoading
                                  }
                                  onClick={() => {
                                    const nodeName = selectedServer?.name || selectedServerId || "node";
                                    const safe = String(nodeName).replace(/[^\w.\-:@]/g, "_").slice(0, 48);
                                    const defCn = `server:${safe || "node"}`;
                                    const vd = Math.min(825, Math.max(1, keysMaxServerCertValidityDays));
                                    setSrvCertCreateModal({
                                      open: true,
                                      cn: defCn,
                                      validityDays: vd,
                                      keySize: "2048",
                                      signatureAlgorithm: "sha256",
                                      busy: false,
                                      error: "",
                                    });
                                  }}
                                >
                                  Создать
                                </button>
                                <button
                                  type="button"
                                  className="btn-secondary"
                                  disabled={!panelRootCaIdForServer || serverOpenVpnLoading}
                                  onClick={() =>
                                    setSrvCertImportModal({
                                      open: true,
                                      certPem: "",
                                      keyPem: "",
                                      busy: false,
                                      error: "",
                                    })
                                  }
                                >
                                  Импортировать
                                </button>
                              </div>
                            </>
                          ) : (
                            <>
                              {serverPanelDisplayedServerCert ? (
                                <ServerPanelCertificateSummaryTable
                                  cert={serverPanelDisplayedServerCert}
                                  summary={
                                    serverPanelServerCertMaterials[serverPanelDisplayedServerCert.id]
                                  }
                                />
                              ) : null}
                              <div className="row-inline" style={{ gap: 8, marginTop: 16, flexWrap: "wrap" }}>
                                <button
                                  type="button"
                                  className="btn-secondary"
                                  disabled={
                                    serverOpenVpnLoading ||
                                    serverServerCertDeleteModal.busy ||
                                    serverRootCaDeleteModal.busy
                                  }
                                  onClick={() => void downloadServerCertificateArtifact("server_crt")}
                                >
                                  server.crt
                                </button>
                                <button
                                  type="button"
                                  className="btn-secondary"
                                  disabled={
                                    serverOpenVpnLoading ||
                                    serverServerCertDeleteModal.busy ||
                                    serverRootCaDeleteModal.busy
                                  }
                                  onClick={() => void downloadServerCertificateArtifact("server_key")}
                                >
                                  server.key
                                </button>
                                <button
                                  type="button"
                                  className="btn-danger"
                                  disabled={
                                    serverOpenVpnLoading ||
                                    serverServerCertDeleteModal.busy ||
                                    serverRootCaDeleteModal.busy
                                  }
                                  onClick={() =>
                                    setServerServerCertDeleteModal({ open: true, busy: false, error: "" })
                                  }
                                >
                                  Удалить сертификат сервера
                                </button>
                              </div>
                            </>
                          )}
                        </div>
                        <div className="user-profile-field-block">
                          <div className="user-profile-field-label">DH (Diffie–Hellman)</div>
                          {openvpnMaterialsDh.length === 0 ? (
                            <>
                              <p className="muted" style={{ marginTop: 0 }}>
                                Нет сохранённых DH — импортируйте PEM или создайте новый.
                              </p>
                              <div className="row-inline" style={{ gap: 8, marginTop: 12, flexWrap: "wrap" }}>
                                <button
                                  type="button"
                                  className="btn-secondary"
                                  onClick={() =>
                                    setServerKeyMaterialModal({
                                      mode: "import",
                                      kind: "dh",
                                      busy: false,
                                      error: "",
                                      importPem: "",
                                    })
                                  }
                                >
                                  Импортировать
                                </button>
                                <button
                                  type="button"
                                  className="btn-secondary"
                                  onClick={() =>
                                    setServerKeyMaterialModal({
                                      mode: "create",
                                      kind: "dh",
                                      busy: false,
                                      error: "",
                                      importPem: "",
                                    })
                                  }
                                >
                                  Создать
                                </button>
                              </div>
                            </>
                          ) : (
                            openvpnMaterialsDh.map((m) => (
                              <div key={m.id}>
                                <OpenvpnPanelMaterialSummaryTable material={m} />
                                <div className="row-inline" style={{ gap: 8, marginTop: 16, flexWrap: "wrap" }}>
                                  <button
                                    type="button"
                                    className="btn-danger"
                                    disabled={openvpnMaterialDeleteModal.busy}
                                    onClick={() =>
                                      setOpenvpnMaterialDeleteModal({
                                        open: true,
                                        id: m.id,
                                        kindLabel: "DH",
                                        busy: false,
                                        error: "",
                                      })
                                    }
                                  >
                                    Удалить
                                  </button>
                                </div>
                              </div>
                            ))
                          )}
                        </div>
                        <div className="user-profile-field-block">
                          <div className="user-profile-field-label">TLS-auth</div>
                          {openvpnMaterialsTls.length === 0 ? (
                            <>
                              <p className="muted" style={{ marginTop: 0 }}>
                                Нет ключей tls-auth — импортируйте ta.key или создайте новый.
                              </p>
                              <div className="row-inline" style={{ gap: 8, marginTop: 12, flexWrap: "wrap" }}>
                                <button
                                  type="button"
                                  className="btn-secondary"
                                  onClick={() =>
                                    setServerKeyMaterialModal({
                                      mode: "import",
                                      kind: "tls_auth",
                                      busy: false,
                                      error: "",
                                      importPem: "",
                                    })
                                  }
                                >
                                  Импортировать
                                </button>
                                <button
                                  type="button"
                                  className="btn-secondary"
                                  onClick={() =>
                                    setServerKeyMaterialModal({
                                      mode: "create",
                                      kind: "tls_auth",
                                      busy: false,
                                      error: "",
                                      importPem: "",
                                    })
                                  }
                                >
                                  Создать
                                </button>
                              </div>
                            </>
                          ) : (
                            openvpnMaterialsTls.map((m) => (
                              <div key={m.id}>
                                <OpenvpnPanelMaterialSummaryTable material={m} />
                                <div className="row-inline" style={{ gap: 8, marginTop: 16, flexWrap: "wrap" }}>
                                  <button
                                    type="button"
                                    className="btn-danger"
                                    disabled={openvpnMaterialDeleteModal.busy}
                                    onClick={() =>
                                      setOpenvpnMaterialDeleteModal({
                                        open: true,
                                        id: m.id,
                                        kindLabel: "TLS-auth",
                                        busy: false,
                                        error: "",
                                      })
                                    }
                                  >
                                    Удалить
                                  </button>
                                </div>
                              </div>
                            ))
                          )}
                        </div>
                      </div>
                    )}

                    {serverDetailTab === "ca-center" && (
                      <div className="user-profile-blocks user-profile-blocks--stack user-profile-blocks--full">
                        <div className="user-profile-field-block">
                          <div className="resource-main-toolbar">
                            <div className="user-profile-field-label">
                              {serverCenterSelectedCert
                                ? `Сертификат ${serverCenterSelectedCert.serialNumber || "—"}`
                                : "Центр сертификации"}
                            </div>
                            {!serverCenterSelectedCert ? (
                              <div className="row-inline" style={{ gap: 8, flexWrap: "wrap" }}>
                                <button
                                  type="button"
                                  className="btn-app-primary"
                                  disabled={!panelRootCaIdForServer}
                                  onClick={() =>
                                    setServerCaIssueModal({
                                      open: true,
                                      commonName: "",
                                      validityDays: "365",
                                      busy: false,
                                      error: "",
                                    })
                                  }
                                >
                                  <span className="btn-app-primary-plus" aria-hidden>
                                    +
                                  </span>
                                  Выпустить сертификат
                                </button>
                                <button
                                  type="button"
                                  className="btn-app-primary"
                                  disabled={!panelRootCaIdForServer}
                                  onClick={() =>
                                    setServerCaImportModal({
                                      open: true,
                                      certPem: "",
                                      keyPem: "",
                                      busy: false,
                                      error: "",
                                    })
                                  }
                                >
                                  Импортировать сертификат
                                </button>
                                <button
                                  type="button"
                                  className="btn-app-primary"
                                  disabled={!panelRootCaIdForServer}
                                  onClick={() =>
                                    setServerCaIndexImportModal({
                                      open: true,
                                      indexText: "",
                                      busy: false,
                                      error: "",
                                    })
                                  }
                                >
                                  Загрузить индекс сертификатов
                                </button>
                              </div>
                            ) : null}
                          </div>
                          {!panelRootCaIdForServer ? (
                            <div style={{ marginTop: 12 }}>
                              <p className="muted" style={{ marginTop: 0 }}>
                                Кнопки выпуска и импорта сертификатов неактивны, пока к серверу не привязан корневой УЦ.
                                {rootCAs.length > 0
                                  ? " Выберите уже созданный корневой сертификат или назначьте его на вкладке «Сертификаты»."
                                  : " Сначала создайте корневой сертификат на вкладке «Сертификаты»."}
                              </p>
                              {rootCAs.length > 0 ? (
                                <div className="row-inline" style={{ gap: 8, flexWrap: "wrap", marginTop: 12 }}>
                                  <select
                                    className="app-filter-input"
                                    value={serverBindRootCaPick || rootCAs[0]?.id || ""}
                                    disabled={serverBindRootCaBusy || serverOpenVpnLoading}
                                    onChange={(e) => setServerBindRootCaPick(e.target.value)}
                                    aria-label="Корневой сертификат для привязки"
                                  >
                                    {rootCAs.map((r) => (
                                      <option key={r.id} value={r.id}>
                                        {r.name || r.commonName || r.id}
                                      </option>
                                    ))}
                                  </select>
                                  <button
                                    type="button"
                                    className="btn-secondary"
                                    disabled={serverBindRootCaBusy || serverOpenVpnLoading}
                                    onClick={() =>
                                      void bindServerPanelRootCa(serverBindRootCaPick || rootCAs[0]?.id || "")
                                    }
                                  >
                                    {serverBindRootCaBusy ? "Привязка…" : "Привязать к серверу"}
                                  </button>
                                </div>
                              ) : null}
                            </div>
                          ) : serverCenterSelectedCert ? (
                            <>
                              <div className="app-table-scroll">
                                <table className="app-table app-table--compact server-root-ca-summary">
                                  <tbody>
                                    <tr>
                                      <th scope="row" className="app-table-nowrap">Статус</th>
                                      <td className="app-table-nowrap">
                                        <span className={userCertRowStatusPresentation(serverCenterSelectedCert).statusClass}>
                                          {userCertRowStatusPresentation(serverCenterSelectedCert).text}
                                        </span>
                                      </td>
                                    </tr>
                                    <tr>
                                      <th scope="row" className="app-table-nowrap">Пара cert/key</th>
                                      <td>
                                        {certMaterialSummary.data?.pairMatches == null
                                          ? "не определено"
                                          : certMaterialSummary.data.pairMatches
                                            ? "совпадает"
                                            : "не совпадает"}
                                      </td>
                                    </tr>
                                    <tr>
                                      <th scope="row" className="app-table-nowrap">Fingerprint SHA-256</th>
                                      <td className="app-table-mono">{certMaterialSummary.data?.fingerprintSha256 || "—"}</td>
                                    </tr>
                                    <tr>
                                      <th scope="row" className="app-table-nowrap">Serial</th>
                                      <td className="app-table-mono">{certMaterialSummary.data?.serialNumber || serverCenterSelectedCert.serialNumber || "—"}</td>
                                    </tr>
                                    <tr>
                                      <th scope="row" className="app-table-nowrap">Algorithm</th>
                                      <td>{String(certMaterialSummary.data?.algorithm || "—").toUpperCase()}</td>
                                    </tr>
                                    <tr>
                                      <th scope="row" className="app-table-nowrap">Key size</th>
                                      <td>{certMaterialSummary.data?.keySize ? `${certMaterialSummary.data.keySize} bit` : "—"}</td>
                                    </tr>
                                    <tr>
                                      <th scope="row" className="app-table-nowrap">Valid to</th>
                                      <td className="app-table-nowrap">
                                        {formatMaybeDate(certMaterialSummary.data?.validTo || serverCenterSelectedCert.expiresAt) || "—"}
                                      </td>
                                    </tr>
                                    <tr>
                                      <th scope="row" className="app-table-nowrap">EKU</th>
                                      <td>
                                        {Array.isArray(certMaterialSummary.data?.eku) && certMaterialSummary.data.eku.length > 0
                                          ? certMaterialSummary.data.eku.map(formatEkuValue).join(", ")
                                          : "—"}
                                      </td>
                                    </tr>
                                    <tr>
                                      <th scope="row" className="app-table-nowrap">Encrypted key</th>
                                      <td>
                                        {certMaterialSummary.data?.encryptedPrivateKey == null
                                          ? "—"
                                          : certMaterialSummary.data.encryptedPrivateKey
                                            ? "да"
                                            : "нет"}
                                      </td>
                                    </tr>
                                  </tbody>
                                </table>
                              </div>
                              <div className="row-inline" style={{ gap: 8, flexWrap: "wrap", marginTop: 12 }}>
                                {serverCenterSelectedCert.hasCertPem || serverCenterSelectedCert.hasKeyMaterial ? (
                                  <button
                                    type="button"
                                    className="btn-secondary"
                                    onClick={() => void downloadSelectedCertificateArtifact("cert")}
                                  >
                                    Скачать сертификат
                                  </button>
                                ) : (
                                  <button
                                    type="button"
                                    className="btn-app-primary"
                                    onClick={() =>
                                      setCertMaterialUploadModal({
                                        open: true,
                                        certId: serverCenterSelectedCert.id,
                                        kind: "cert",
                                        pem: "",
                                        busy: false,
                                        error: "",
                                      })
                                    }
                                  >
                                    Добавить сертификат
                                  </button>
                                )}
                                {serverCenterSelectedCert.hasKeyPem || serverCenterSelectedCert.hasKeyMaterial ? (
                                  <button
                                    type="button"
                                    className="btn-secondary"
                                    onClick={() => void downloadSelectedCertificateArtifact("key")}
                                  >
                                    Скачать приватный ключ
                                  </button>
                                ) : (
                                  <button
                                    type="button"
                                    className="btn-app-primary"
                                    onClick={() =>
                                      setCertMaterialUploadModal({
                                        open: true,
                                        certId: serverCenterSelectedCert.id,
                                        kind: "key",
                                        pem: "",
                                        busy: false,
                                        error: "",
                                      })
                                    }
                                  >
                                    Добавить приватный ключ
                                  </button>
                                )}
                                {!serverCenterSelectedCert.revokedAt ? (
                                  <button
                                    type="button"
                                    className="btn-danger"
                                    onClick={() =>
                                      setUserCertRevokeModal({
                                        open: true,
                                        certId: serverCenterSelectedCert.id,
                                        commonName: serverCenterSelectedCert.commonName || "",
                                        busy: false,
                                        error: "",
                                      })
                                    }
                                  >
                                    Отозвать сертификат
                                  </button>
                                ) : null}
                              </div>
                            </>
                          ) : (
                            <>
                              {serverRootIssuedCertificates.length > 0 ? (
                                <div className="app-list-toolbar" style={{ marginTop: 8 }}>
                                  <input
                                    type="search"
                                    className="app-filter-input"
                                    placeholder="Поиск по серийному номеру, CN или пользователю…"
                                    value={serverCaSignedFilter}
                                    onChange={(e) => setServerCaSignedFilter(e.target.value)}
                                    autoComplete="off"
                                  />
                                </div>
                              ) : null}
                              <div className="app-table-with-pagination" style={{ marginTop: 8 }}>
                                <div className="app-table-scroll">
                                  <table className="app-table app-table--compact">
                                    <thead>
                                      <tr>
                                        <th>Серийный номер</th>
                                        <th>CN</th>
                                        <th>Пользователь</th>
                                        <th>Срок действия</th>
                                        <th>Статус</th>
                                        <th>Материалы</th>
                                        <th className="app-table-col-actions">Действия</th>
                                      </tr>
                                    </thead>
                                    <tbody>
                                      {serverRootIssuedCertificates.length === 0 ? (
                                        <tr>
                                          <td colSpan={7} className="muted">
                                            Пока нет сертификатов, выпущенных этим корневым сертификатом.
                                          </td>
                                        </tr>
                                      ) : filteredServerRootIssuedCertificates.length === 0 ? (
                                        <tr>
                                          <td colSpan={7} className="muted">
                                            Нет совпадений с поиском.
                                          </td>
                                        </tr>
                                      ) : (
                                        serverCaSignedTablePage.slice.map((cert) => {
                                          const hasMaterialPair = Boolean(cert.hasKeyMaterial ?? (cert.hasCertPem && cert.hasKeyPem));
                                          const statusRow = userCertRowStatusPresentation(cert);
                                          return (
                                            <tr key={cert.id}>
                                              <td className="app-table-mono">{cert.serialNumber || "—"}</td>
                                              <td>{cert.commonName || "—"}</td>
                                              <td>
                                                {cert.vpnUserId ? (
                                                  <button
                                                    type="button"
                                                    className="app-link-btn"
                                                    style={{ color: "#111827", fontWeight: 700, textDecoration: "underline" }}
                                                    onClick={() => navigate(paths.userProfile(cert.vpnUserId, "certs"))}
                                                  >
                                                    {cert.vpnUser?.fullName || "Открыть профиль"}
                                                  </button>
                                                ) : (
                                                  "—"
                                                )}
                                              </td>
                                              <td className="app-table-nowrap">{formatMaybeDate(cert.expiresAt)}</td>
                                              <td className="app-table-nowrap">
                                                <span className={statusRow.statusClass}>{statusRow.text}</span>
                                              </td>
                                              <td className="app-table-nowrap">
                                                {hasMaterialPair ? (
                                                  <span className="app-status app-status--ok">ok</span>
                                                ) : (
                                                  <span title="В системе отсутствует открытый и/или закрытый ключ" style={{ color: "#ea580c", fontWeight: 700 }}>
                                                    !
                                                  </span>
                                                )}
                                              </td>
                                              <td className="app-table-col-actions app-table-nowrap">
                                                <div className="row-inline" style={{ gap: 8, flexWrap: "wrap" }}>
                                                  <button
                                                    type="button"
                                                    className="app-link-btn"
                                                    onClick={() => navigate(paths.serverCaCenterCert(selectedServerId, cert.id))}
                                                  >
                                                    Открыть
                                                  </button>
                                                  {!cert.revokedAt ? (
                                                    <button
                                                      type="button"
                                                      className="app-link-btn app-link-btn--danger"
                                                      onClick={() =>
                                                        setUserCertRevokeModal({
                                                          open: true,
                                                          certId: cert.id,
                                                          commonName: cert.commonName || "",
                                                          busy: false,
                                                          error: "",
                                                        })
                                                      }
                                                    >
                                                      Отозвать
                                                    </button>
                                                  ) : null}
                                                </div>
                                              </td>
                                            </tr>
                                          );
                                        })
                                      )}
                                    </tbody>
                                  </table>
                                </div>
                                {filteredServerRootIssuedCertificates.length > 0 ? (
                                  <TablePagination
                                    page={serverCaSignedTablePage.page}
                                    totalPages={serverCaSignedTablePage.totalPages}
                                    total={serverCaSignedTablePage.total}
                                    onPageChange={(p) => setTablePages((prev) => ({ ...prev, serverCaSigned: p }))}
                                  />
                                ) : null}
                              </div>
                            </>
                          )}
                        </div>
                      </div>
                    )}

                    {serverDetailTab === "settings" && (
                        <div className="server-settings-layout server-settings-layout--stack server-settings-layout--stack-full">
                        <div className="server-settings-main">
                        <h2 className="server-detail-section-title">Служба OpenVPN</h2>
                        {serverOpenVpnError ? (
                          <div className="server-openvpn-alert" role="alert">
                            <div className="auth-alert auth-alert--error" style={{ marginBottom: 8 }}>
                              {serverOpenVpnError}
                            </div>
                            {serverOpenVpnHints.length > 0 ? (
                              <div>
                                <p className="muted" style={{ margin: "0 0 6px" }}>
                                  Что можно сделать:
                                </p>
                                <ul className="server-openvpn-hints">
                                  {serverOpenVpnHints.map((h, i) => (
                                    <li key={i}>{h}</li>
                                  ))}
                                </ul>
                              </div>
                            ) : null}
                          </div>
                        ) : null}
                        {!serverOpenVpnLoading && !serverOpenVpnError ? (
                          <>
                          <form
                            id="openvpn-server-settings-form"
                            className="user-profile-blocks--stack server-openvpn-form"
                            onSubmit={(e) => {
                              e.preventDefault();
                            }}
                          >
                            {OPENVPN_SERVER_SETTINGS_FIELDS.map((field) => (
                              <div key={field.key} className="user-profile-field-block">
                                <div className="user-profile-field-label">
                                  {field.label}{" "}
                                  <span
                                    className={`directive-kind-badge ${
                                      OPENVPN_SERVER_FORM_SHARED_DIRECTIVES.has(field.key)
                                        ? "directive-kind-badge--shared"
                                        : OPENVPN_SERVER_FORM_CLIENT_DIRECTIVES.has(field.key)
                                        ? "directive-kind-badge--client"
                                        : "directive-kind-badge--server"
                                    }`}
                                  >
                                    {OPENVPN_SERVER_FORM_SHARED_DIRECTIVES.has(field.key)
                                      ? "server/client"
                                      : OPENVPN_SERVER_FORM_CLIENT_DIRECTIVES.has(field.key)
                                      ? "client"
                                      : "server"}
                                  </span>
                                </div>
                                {field.type === "checkbox" ? (
                                  <select
                                    value={Boolean(serverOpenVpnSettings[field.key]) ? "true" : "false"}
                                    onChange={(e) =>
                                      setServerOpenVpnSettings((prev) => ({
                                        ...prev,
                                        [field.key]: e.target.value === "true",
                                      }))
                                    }
                                  >
                                    <option value="true">Да</option>
                                    <option value="false">Нет</option>
                                  </select>
                                ) : null}
                                {field.type === "number" ? (
                                  <input
                                    type="number"
                                    value={
                                      serverOpenVpnSettings[field.key] === undefined ||
                                      serverOpenVpnSettings[field.key] === null
                                        ? ""
                                        : String(serverOpenVpnSettings[field.key])
                                    }
                                    placeholder={field.placeholder || ""}
                                    onChange={(e) =>
                                      setServerOpenVpnSettings((prev) => ({
                                        ...prev,
                                        [field.key]: e.target.value,
                                      }))
                                    }
                                  />
                                ) : null}
                                {field.type === "text" ? (
                                  <input
                                    type="text"
                                    value={
                                      serverOpenVpnSettings[field.key] === undefined ||
                                      serverOpenVpnSettings[field.key] === null
                                        ? ""
                                        : String(serverOpenVpnSettings[field.key])
                                    }
                                    placeholder={field.placeholder || ""}
                                    onChange={(e) =>
                                      setServerOpenVpnSettings((prev) => ({
                                        ...prev,
                                        [field.key]: e.target.value,
                                      }))
                                    }
                                  />
                                ) : null}
                                {field.type === "select" ? (
                                  <select
                                    value={
                                      serverOpenVpnSettings[field.key] === undefined ||
                                      serverOpenVpnSettings[field.key] === null
                                        ? ""
                                        : String(serverOpenVpnSettings[field.key])
                                    }
                                    onChange={(e) =>
                                      setServerOpenVpnSettings((prev) => ({
                                        ...prev,
                                        [field.key]: e.target.value,
                                      }))
                                    }
                                  >
                                    {(field.options || []).map((opt) => (
                                      <option key={String(opt.value)} value={opt.value}>
                                        {opt.label}
                                      </option>
                                    ))}
                                  </select>
                                ) : null}
                                {field.type === "textarea" ? (
                                  <textarea
                                    rows={4}
                                    value={(Array.isArray(serverOpenVpnSettings[field.key])
                                      ? serverOpenVpnSettings[field.key]
                                      : []
                                    ).join("\n")}
                                    placeholder={field.placeholder || ""}
                                    onChange={(e) =>
                                      setServerOpenVpnSettings((prev) => ({
                                        ...prev,
                                        [field.key]: e.target.value
                                          .split("\n")
                                          .map((x) => x.trim())
                                          .filter(Boolean),
                                      }))
                                    }
                                  />
                                ) : null}
                                {field.description ? (
                                  <p className="user-profile-field-hint">{field.description}</p>
                                ) : null}
                              </div>
                            ))}
                          </form>
                          </>
                        ) : null}
                        </div>
                        {!serverOpenVpnLoading && !serverOpenVpnError ? (
                          <aside className="server-settings-raw-col" aria-label="Сравнение конфигурации OpenVPN">
                            <div className="server-openvpn-actions-bar server-openvpn-actions-bar--raw-fixed row-inline" style={{ gap: 8, flexWrap: "wrap" }}>
                              <button
                                type="button"
                                className="server-openvpn-apply-btn"
                                disabled={serverOpenVpnApplying}
                                onClick={() => {
                                  setServerOpenVpnApplyLogVisible(false);
                                  setServerOpenVpnApplyLog("");
                                  setServerOpenVpnApplyResult({ status: "idle", message: "" });
                                  setServerOpenVpnApplyConfirmModal({ open: true, done: false });
                                }}
                              >
                                {serverOpenVpnApplying ? "Применение..." : "Применить"}
                              </button>
                              <button
                                type="button"
                                className="btn-secondary"
                                disabled={serviceCheckBusy || serverOpenVpnApplying}
                                onClick={checkOpenvpnConfig}
                              >
                                {serviceCheckBusy ? "Проверка..." : "Проверить конфиг"}
                              </button>
                            </div>
                            <div className="server-settings-raw-sticky">
                              <div className="server-settings-diff-sticky-head" />
                              {serverAgentRawLoading ? null : (
                                <div
                                  className="server-settings-raw-box server-settings-diff-view server-settings-diff-view--sticky"
                                  role="region"
                                  aria-label="Сравнение конфигурации OpenVPN"
                                >
                                  <div className="server-settings-diff-body">
                                    {serverOpenVpnConfigDiff.map((d, idx) => (
                                      <div
                                        key={`d-${idx}`}
                                        className={`server-settings-diff-line server-settings-diff-line--${d.type}`}
                                      >
                                        <span className="server-settings-diff-prefix" aria-hidden>
                                          {d.type === "add" ? "+" : d.type === "del" ? "-" : " "}
                                        </span>
                                        <span className="server-settings-diff-text">{d.line}</span>
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              )}
                            </div>
                          </aside>
                        ) : null}
                      </div>
                    )}

                    {serverDetailTab === "client" && (
                      <div className="server-settings-layout">
                        <div className="server-settings-main">
                          <div className="user-profile-field-block">
                            <div className="server-detail-section-title" style={{ margin: "0 0 8px" }}>
                              Версия конфигурации
                            </div>
                            <div className="server-version-select-row">
                              <select
                                value={serverOpenVpnClientSelectedVersionId}
                                disabled={serverOpenVpnClientVersions.length === 0}
                                onChange={(e) => {
                                  const id = String(e.target.value || "");
                                  setServerOpenVpnClientSelectedVersionId(id);
                                  const hit = serverOpenVpnClientVersions.find((v) => v.id === id);
                                  const settings = hit && hit.settings && typeof hit.settings === "object" ? hit.settings : null;
                                  if (!settings || Array.isArray(settings)) return;
                                  setServerOpenVpnClientSettings({ ...settings });
                                }}
                              >
                                {serverOpenVpnClientVersions.length > 0 ? (
                                  serverOpenVpnClientVersions.map((v) => {
                                    const applied = formatMaybeDate(v.createdAt);
                                    const serverName = selectedServer?.name || "Сервер";
                                    const isActive = v.id === serverOpenVpnClientActiveVersionId;
                                    return (
                                      <option key={v.id} value={v.id}>
                                        {`${isActive ? "● " : ""}${serverName} · v${v.version} · ${applied}${isActive ? " · активная" : ""}`}
                                      </option>
                                    );
                                  })
                                ) : (
                                  <option value="">Версий пока нет</option>
                                )}
                              </select>
                              <button
                                type="button"
                                className="server-version-delete-btn"
                                disabled={!serverOpenVpnClientSelectedVersionId || serverOpenVpnClientVersions.length === 0}
                                aria-label="Удалить выбранную версию конфигурации"
                                onClick={() => {
                                  const hit = serverOpenVpnClientVersions.find((v) => v.id === serverOpenVpnClientSelectedVersionId);
                                  if (!hit) return;
                                  const applied = formatMaybeDate(hit.createdAt);
                                  const serverName = selectedServer?.name || "Сервер";
                                  setServerOpenVpnClientDeleteVersionModal({
                                    open: true,
                                    versionId: hit.id,
                                    versionLabel: `${serverName} · v${hit.version} · ${applied}`,
                                    busy: false,
                                    error: "",
                                  });
                                }}
                              >
                                Удалить версию
                              </button>
                            </div>
                            <p className="user-profile-field-hint">
                              Активная конфигурация:{" "}
                              <span className="app-table-mono">
                                {serverOpenVpnClientActiveVersion
                                  ? `v${serverOpenVpnClientActiveVersion.version} (${formatMaybeDate(
                                      serverOpenVpnClientActiveVersion.createdAt,
                                    )})`
                                  : "—"}
                              </span>
                            </p>
                          </div>
                          <h2 className="server-detail-section-title">Конфигурация клиента</h2>
                          {serverOpenVpnClientError ? (
                            <div className="server-openvpn-alert" role="alert">
                              <div className="auth-alert auth-alert--error" style={{ marginBottom: 8 }}>
                                {serverOpenVpnClientError}
                              </div>
                            </div>
                          ) : null}
                          {!serverOpenVpnClientLoading && !serverOpenVpnClientError ? (
                            <form
                              id="openvpn-client-settings-form"
                              className="user-profile-blocks--stack server-openvpn-form"
                              onSubmit={(e) => {
                                e.preventDefault();
                                void saveServerOpenVpnClientSettings();
                              }}
                            >
                              {OPENVPN_CLIENT_SETTINGS_FIELDS.map((field) => (
                                <div key={field.key} className="user-profile-field-block">
                                  <div className="user-profile-field-label">
                                    {field.label} <span className="directive-kind-badge directive-kind-badge--client">client</span>
                                  </div>
                                  {field.type === "checkbox" ? (
                                    <select
                                      value={Boolean(serverOpenVpnClientSettings[field.key]) ? "true" : "false"}
                                      onChange={(e) =>
                                        setServerOpenVpnClientSettings((prev) => ({
                                          ...prev,
                                          [field.key]: e.target.value === "true",
                                        }))
                                      }
                                    >
                                      <option value="true">Да</option>
                                      <option value="false">Нет</option>
                                    </select>
                                  ) : null}
                                  {field.type === "number" ? (
                                    <input
                                      type="number"
                                      value={
                                        serverOpenVpnClientSettings[field.key] === undefined ||
                                        serverOpenVpnClientSettings[field.key] === null
                                          ? ""
                                          : String(serverOpenVpnClientSettings[field.key])
                                      }
                                      placeholder={field.placeholder || ""}
                                      onChange={(e) =>
                                        setServerOpenVpnClientSettings((prev) => ({
                                          ...prev,
                                          [field.key]: e.target.value,
                                        }))
                                      }
                                    />
                                  ) : null}
                                  {field.type === "text" ? (
                                    <input
                                      type="text"
                                      value={
                                        serverOpenVpnClientSettings[field.key] === undefined ||
                                        serverOpenVpnClientSettings[field.key] === null
                                          ? ""
                                          : String(serverOpenVpnClientSettings[field.key])
                                      }
                                      placeholder={field.placeholder || ""}
                                      onChange={(e) =>
                                        setServerOpenVpnClientSettings((prev) => ({
                                          ...prev,
                                          [field.key]: e.target.value,
                                        }))
                                      }
                                    />
                                  ) : null}
                                  {field.type === "select" ? (
                                    <select
                                      value={
                                        serverOpenVpnClientSettings[field.key] === undefined ||
                                        serverOpenVpnClientSettings[field.key] === null
                                          ? ""
                                          : String(serverOpenVpnClientSettings[field.key])
                                      }
                                      onChange={(e) =>
                                        setServerOpenVpnClientSettings((prev) => ({
                                          ...prev,
                                          [field.key]: e.target.value,
                                        }))
                                      }
                                    >
                                      {(field.options || []).map((opt) => (
                                        <option key={String(opt.value)} value={opt.value}>
                                          {opt.label}
                                        </option>
                                      ))}
                                    </select>
                                  ) : null}
                                  {field.description ? (
                                    <p className="user-profile-field-hint">{field.description}</p>
                                  ) : null}
                                </div>
                              ))}
                            </form>
                          ) : null}
                        </div>
                        {!serverOpenVpnClientLoading && !serverOpenVpnClientError ? (
                          <aside className="server-settings-raw-col" aria-label="Предпросмотр клиентской конфигурации">
                            <div className="server-openvpn-actions-bar server-openvpn-actions-bar--raw-fixed row-inline" style={{ gap: 8, flexWrap: "wrap" }}>
                              <button
                                type="submit"
                                form="openvpn-client-settings-form"
                                disabled={serverOpenVpnClientSaving}
                              >
                                {serverOpenVpnClientSaving ? "Сохранение..." : "Сохранить"}
                              </button>
                              <button
                                type="button"
                                className="btn-secondary"
                                disabled={
                                  serverOpenVpnClientSaving ||
                                  !serverOpenVpnClientSelectedVersionId ||
                                  serverOpenVpnClientSelectedVersionId === serverOpenVpnClientActiveVersionId ||
                                  serverOpenVpnClientHasUnsavedSelectedChanges
                                }
                                onClick={() =>
                                  setServerOpenVpnClientApplyConfirmModal({ open: true, busy: false, error: "" })
                                }
                              >
                                Применить
                              </button>
                            </div>
                            {serverOpenVpnClientHasUnsavedSelectedChanges ? (
                              <p className="user-profile-field-hint" style={{ marginTop: 8 }}>
                                Чтобы применить конфигурацию, сначала сохраните изменения как новую версию и выберите её.
                              </p>
                            ) : null}
                            <div className="server-settings-raw-sticky">
                              <div className="server-settings-diff-sticky-head" />
                              <div
                                className="server-settings-raw-box server-settings-diff-view server-settings-diff-view--sticky"
                                role="region"
                                aria-label="Предпросмотр шаблона клиентской конфигурации"
                              >
                                <div className="server-settings-diff-body">
                                  {serverOpenVpnClientConfigDiff.map((d, idx) => (
                                    <div
                                      key={`client-diff-${idx}`}
                                      className={`server-settings-diff-line server-settings-diff-line--${d.type}`}
                                    >
                                      <span className="server-settings-diff-prefix" aria-hidden>
                                        {d.type === "add" ? "+" : d.type === "del" ? "-" : " "}
                                      </span>
                                      <span className="server-settings-diff-text">{d.line}</span>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            </div>
                          </aside>
                        ) : null}
                      </div>
                    )}

                    {serverDetailTab === "firewall" && (
                      <div className="user-profile-blocks user-profile-blocks--full">
                        <h2 className="server-detail-section-title">Межсетевой экран</h2>
                        <div className="server-settings-layout server-settings-layout--stack server-settings-layout--stack-full">
                          <div className="server-settings-main">
                            <div className="server-version-select-row">
                              <select value={serverFirewallTunnelDefaultPolicy} onChange={(e) => setServerFirewallTunnelDefaultPolicy(String(e.target.value || "deny"))}>
                                <option value="deny">Tunnel policy: deny all</option>
                                <option value="allow">Tunnel policy: allow all</option>
                              </select>
                              <button type="button" className="btn-secondary" onClick={() => openFirewallRuleModal("server", null, "tunnel", "filter")}>
                                + Правило
                              </button>
                              <button type="button" className="btn-secondary" onClick={() => openFirewallRuleModal("server", null, "tunnel", "nat")}>
                                + NAT
                              </button>
                            </div>
                            <div className="app-table-scroll" style={{ marginTop: 8 }}>
                              <table className="app-table app-table--compact table-server-firewall">
                                <thead>
                                  <tr>
                                    <th>Action</th>
                                    <th>Proto</th>
                                    <th>Destination</th>
                                    <th>Ports</th>
                                    <th>Описание</th>
                                    <th className="app-table-col-actions">Действия</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {serverFirewallTunnelRules.length === 0 ? (
                                    <tr>
                                      <td colSpan={6} className="muted">
                                        Нет правил.
                                      </td>
                                    </tr>
                                  ) : (
                                    serverFirewallTunnelRules.map((rule) => (
                                      <tr
                                        key={rule.id}
                                        className={rowReorderClass("server-filter", rule.id, tableDrag)}
                                        draggable={!serverFirewallLoading}
                                        onDragStart={(e) => {
                                          beginTableRowDragPreview(e.currentTarget, e, rule.id);
                                          setTableDrag({ scope: "server-filter", dragId: rule.id, overId: "", placeAfter: false });
                                        }}
                                        onDragOver={(e) => tableRowDragOverHandler(e, "server-filter", rule.id, setTableDrag)}
                                        onDragEnd={() => {
                                          endTableRowDragPreview();
                                          setTableDrag(emptyTableDrag());
                                        }}
                                        onDrop={(e) => {
                                          e.preventDefault();
                                          setTableDrag((td) => {
                                            if (td.scope !== "server-filter" || !td.dragId) return emptyTableDrag();
                                            setServerFirewallTunnelRules((prev) => reorderRowInList(prev, td.dragId, rule.id, td.placeAfter));
                                            return emptyTableDrag();
                                          });
                                        }}
                                      >
                                        <td><span className={rule.action === "deny" ? "app-status app-status--bad" : "app-status app-status--ok"}>{rule.action}</span></td>
                                        <td className="app-table-mono">{rule.proto}</td>
                                        <td className="app-table-mono">{rule.destination || "—"}</td>
                                        <td className="app-table-mono">{rule.ports || "*"}</td>
                                        <td>{rule.note || "—"}</td>
                                        <td className="app-table-td-clip-none">
                                          <button type="button" className="app-link-btn" onClick={() => openFirewallRuleModal("server", rule, "tunnel", "filter")}>
                                            Изменить
                                          </button>{" "}
                                          <button
                                            type="button"
                                            className="app-link-btn app-link-btn--danger"
                                            onClick={() => setServerFirewallTunnelRules((prev) => prev.filter((x) => x.id !== rule.id))}
                                          >
                                            Удалить
                                          </button>
                                        </td>
                                      </tr>
                                    ))
                                  )}
                                </tbody>
                              </table>
                            </div>
                            <div className="app-table-scroll" style={{ marginTop: 8 }}>
                                <table className="app-table app-table--compact table-server-firewall">
                                  <thead>
                                    <tr>
                                      <th>Type</th>
                                      <th>Hook</th>
                                      <th>Src</th>
                                      <th>Dst</th>
                                      <th>Out iface</th>
                                      <th>To address</th>
                                      <th>Описание</th>
                                      <th className="app-table-col-actions">Действия</th>
                                    </tr>
                                  </thead>
                                  <tbody>
                                    {serverFirewallTunnelNatRules.length === 0 ? (
                                      <tr>
                                        <td colSpan={8} className="muted">
                                          Нет NAT-правил.
                                        </td>
                                      </tr>
                                    ) : (
                                      serverFirewallTunnelNatRules.map((rule) => (
                                        <tr
                                          key={rule.id}
                                          className={rowReorderClass("server-nat", rule.id, tableDrag)}
                                          draggable={!serverFirewallLoading}
                                          onDragStart={(e) => {
                                            beginTableRowDragPreview(e.currentTarget, e, rule.id);
                                            setTableDrag({ scope: "server-nat", dragId: rule.id, overId: "", placeAfter: false });
                                          }}
                                          onDragOver={(e) => tableRowDragOverHandler(e, "server-nat", rule.id, setTableDrag)}
                                          onDragEnd={() => {
                                            endTableRowDragPreview();
                                            setTableDrag(emptyTableDrag());
                                          }}
                                          onDrop={(e) => {
                                            e.preventDefault();
                                            setTableDrag((td) => {
                                              if (td.scope !== "server-nat" || !td.dragId) return emptyTableDrag();
                                              setServerFirewallTunnelNatRules((prev) => reorderRowInList(prev, td.dragId, rule.id, td.placeAfter));
                                              return emptyTableDrag();
                                            });
                                          }}
                                        >
                                          <td className="app-table-mono">{rule.type}</td>
                                          <td className="app-table-mono">
                                            {rule.type === "dnat" ? "PREROUTING" : "POSTROUTING"}
                                          </td>
                                          <td className="app-table-mono">{rule.src || "—"}</td>
                                          <td className="app-table-mono">{rule.dst || "—"}</td>
                                          <td className="app-table-mono">{rule.outInterface || "—"}</td>
                                          <td className="app-table-mono">{rule.toAddress || "—"}</td>
                                          <td>{rule.note || "—"}</td>
                                          <td className="app-table-td-clip-none">
                                            <button
                                              type="button"
                                              className="app-link-btn"
                                              onClick={() => openFirewallRuleModal("server", rule, "tunnel", "nat")}
                                            >
                                              Изменить
                                            </button>{" "}
                                            <button
                                              type="button"
                                              className="app-link-btn app-link-btn--danger"
                                              onClick={() => setServerFirewallTunnelNatRules((prev) => prev.filter((x) => x.id !== rule.id))}
                                            >
                                              Удалить
                                            </button>
                                          </td>
                                        </tr>
                                      ))
                                    )}
                                  </tbody>
                                </table>
                              </div>
                            <div className="row-inline" style={{ gap: 8, marginTop: 12, flexWrap: "wrap" }}>
                              <button type="button" disabled={serverFirewallBusy} onClick={() => void applyServerFirewall()}>
                                {serverFirewallBusy ? "Применение..." : "Применить"}
                              </button>
                              <button type="button" className="btn-secondary" onClick={openServerEffectivePolicyModal}>
                                Effective Policy
                              </button>
                            </div>
                          </div>
                        </div>
                        {firewallRuleModal.open ? (
                          <div
                            className="modal-backdrop"
                            role="presentation"
                            onClick={(e) => {
                              if (e.target === e.currentTarget) {
                                setFirewallRuleModal((prev) => ({ ...prev, open: false, error: "" }));
                              }
                            }}
                          >
                            <div className="modal-dialog" role="dialog" aria-modal="true" aria-labelledby="firewall-rule-modal-title">
                              <div className="modal-dialog-header">
                                <h2 id="firewall-rule-modal-title" className="modal-dialog-title">
                                  {firewallRuleModal.editId ? "Редактирование правила" : "Новое правило"} · Межсетевой экран
                                </h2>
                                <button type="button" className="modal-close" aria-label="Закрыть" onClick={() => setFirewallRuleModal((prev) => ({ ...prev, open: false, error: "" }))}>
                                  ×
                                </button>
                              </div>
                              {firewallRuleModal.kind !== "nat" ? (
                                <>
                                  <div className="user-profile-field-block">
                                    <div className="user-profile-field-label">Action</div>
                                    <select
                                      value={firewallRuleModal.draft.action}
                                      onChange={(e) => setFirewallRuleModal((prev) => ({ ...prev, draft: { ...prev.draft, action: e.target.value } }))}
                                    >
                                      <option value="allow">allow</option>
                                      <option value="deny">deny</option>
                                    </select>
                                  </div>
                                  <div className="user-profile-field-block">
                                    <div className="user-profile-field-label">Proto</div>
                                    <select
                                      value={firewallRuleModal.draft.proto}
                                      onChange={(e) => setFirewallRuleModal((prev) => ({ ...prev, draft: { ...prev.draft, proto: e.target.value } }))}
                                    >
                                      <option value="tcp">tcp</option>
                                      <option value="udp">udp</option>
                                      <option value="icmp">icmp</option>
                                      <option value="any">any</option>
                                    </select>
                                  </div>
                                  <div className="user-profile-field-block">
                                    <div className="user-profile-field-label">Destination</div>
                                    <input
                                      value={firewallRuleModal.draft.destination}
                                      onChange={(e) => setFirewallRuleModal((prev) => ({ ...prev, draft: { ...prev.draft, destination: e.target.value } }))}
                                      placeholder="172.16.0.0/24"
                                    />
                                  </div>
                                  <div className="user-profile-field-block">
                                    <div className="user-profile-field-label">Ports</div>
                                    <input
                                      value={firewallRuleModal.draft.ports}
                                      onChange={(e) => setFirewallRuleModal((prev) => ({ ...prev, draft: { ...prev.draft, ports: e.target.value } }))}
                                      placeholder="80,443"
                                    />
                                  </div>
                                </>
                              ) : (
                                <>
                                  <div className="user-profile-field-block">
                                    <div className="user-profile-field-label">NAT type</div>
                                    <select
                                      value={firewallRuleModal.draft.type}
                                      onChange={(e) => setFirewallRuleModal((prev) => ({ ...prev, draft: { ...prev.draft, type: e.target.value } }))}
                                    >
                                      <option value="masquerade">masquerade</option>
                                      <option value="snat">snat</option>
                                      <option value="dnat">dnat</option>
                                    </select>
                                  </div>
                                  <div className="user-profile-field-block">
                                    <div className="user-profile-field-label">Src</div>
                                    <input
                                      value={firewallRuleModal.draft.src}
                                      onChange={(e) => setFirewallRuleModal((prev) => ({ ...prev, draft: { ...prev.draft, src: e.target.value } }))}
                                      placeholder="10.220.0.0/22"
                                    />
                                  </div>
                                  <div className="user-profile-field-block">
                                    <div className="user-profile-field-label">Dst</div>
                                    <input
                                      value={firewallRuleModal.draft.dst}
                                      onChange={(e) => setFirewallRuleModal((prev) => ({ ...prev, draft: { ...prev.draft, dst: e.target.value } }))}
                                      placeholder="172.16.0.10/32"
                                    />
                                  </div>
                                  <div className="user-profile-field-block">
                                    <div className="user-profile-field-label">Out interface</div>
                                    <div className="row-inline" style={{ gap: 8, flexWrap: "nowrap" }}>
                                      <select
                                        value={natOutInterfaceInputMode === "manual" ? "__manual__" : firewallRuleModal.draft.outInterface}
                                        onChange={(e) => {
                                          const v = String(e.target.value || "");
                                          if (v === "__manual__") {
                                            setNatOutInterfaceInputMode("manual");
                                            setFirewallRuleModal((prev) => ({
                                              ...prev,
                                              draft: { ...prev.draft, outInterface: "" },
                                            }));
                                            return;
                                          }
                                          setNatOutInterfaceInputMode("preset");
                                          setFirewallRuleModal((prev) => ({ ...prev, draft: { ...prev.draft, outInterface: v } }));
                                        }}
                                        style={{ width: 180, flex: "0 0 180px" }}
                                      >
                                        <option value="__manual__">Вручную</option>
                                        {natOutInterfaceOptions.map((itf) => (
                                          <option key={itf} value={itf}>{itf}</option>
                                        ))}
                                      </select>
                                      <input
                                        value={firewallRuleModal.draft.outInterface}
                                        onChange={(e) => setFirewallRuleModal((prev) => ({ ...prev, draft: { ...prev.draft, outInterface: e.target.value } }))}
                                        placeholder="eth0"
                                        disabled={natOutInterfaceInputMode !== "manual"}
                                        style={{ flex: "1 1 auto", minWidth: 0 }}
                                      />
                                    </div>
                                  </div>
                                  <div className="user-profile-field-block">
                                    <div className="user-profile-field-label">To address</div>
                                    <div className="row-inline" style={{ gap: 8, flexWrap: "nowrap" }}>
                                      <select
                                        value={natToAddressInputMode === "manual" ? "__manual__" : firewallRuleModal.draft.toAddress}
                                        onChange={(e) => {
                                          const v = String(e.target.value || "");
                                          if (v === "__manual__") {
                                            setNatToAddressInputMode("manual");
                                            setFirewallRuleModal((prev) => ({
                                              ...prev,
                                              draft: { ...prev.draft, toAddress: "" },
                                            }));
                                            return;
                                          }
                                          setNatToAddressInputMode("preset");
                                          setFirewallRuleModal((prev) => ({ ...prev, draft: { ...prev.draft, toAddress: v } }));
                                        }}
                                        style={{ width: 180, flex: "0 0 180px" }}
                                      >
                                        <option value="__manual__">Вручную</option>
                                        {natToAddressOptions.map((addr) => (
                                          <option key={addr} value={addr}>{addr}</option>
                                        ))}
                                      </select>
                                      <input
                                        value={firewallRuleModal.draft.toAddress}
                                        onChange={(e) => setFirewallRuleModal((prev) => ({ ...prev, draft: { ...prev.draft, toAddress: e.target.value } }))}
                                        placeholder="203.0.113.10"
                                        disabled={natToAddressInputMode !== "manual"}
                                        style={{ flex: "1 1 auto", minWidth: 0 }}
                                      />
                                    </div>
                                  </div>
                                </>
                              )}
                              <div className="user-profile-field-block">
                                <div className="user-profile-field-label">Описание</div>
                                <input
                                  value={firewallRuleModal.draft.note}
                                  onChange={(e) => setFirewallRuleModal((prev) => ({ ...prev, draft: { ...prev.draft, note: e.target.value } }))}
                                />
                              </div>
                              {firewallRuleModal.error ? (
                                <div className="auth-alert auth-alert--error" role="alert">
                                  {firewallRuleModal.error}
                                </div>
                              ) : null}
                              <div className="row-inline" style={{ justifyContent: "flex-end", gap: 8, marginTop: 12 }}>
                                <button type="button" className="btn-secondary" onClick={() => setFirewallRuleModal((prev) => ({ ...prev, open: false, error: "" }))}>
                                  Отмена
                                </button>
                                <button type="button" onClick={submitFirewallRuleModal}>Сохранить</button>
                              </div>
                            </div>
                          </div>
                        ) : null}

                        {serverFirewallEffectiveModal.open ? (
                          <div
                            className="modal-backdrop"
                            role="presentation"
                            onClick={(e) => {
                              if (e.target === e.currentTarget) setServerFirewallEffectiveModal({ open: false, title: "", content: "" });
                            }}
                          >
                            <div className="modal-dialog modal-dialog--wide" role="dialog" aria-modal="true">
                              <div className="modal-dialog-header">
                                <h2 className="modal-dialog-title">{serverFirewallEffectiveModal.title}</h2>
                                <button type="button" className="modal-close" aria-label="Закрыть" onClick={() => setServerFirewallEffectiveModal({ open: false, title: "", content: "" })}>
                                  ×
                                </button>
                              </div>
                              <pre className="server-settings-raw-pre" style={{ maxHeight: "60vh", overflow: "auto" }}>
                                {serverFirewallEffectiveModal.content}
                              </pre>
                            </div>
                          </div>
                        ) : null}

                      </div>
                    )}

                    {serverDetailTab === "overview" && (
                      <div className="user-profile-blocks user-profile-blocks--stack">
                        <h2 className="server-detail-section-title" style={{ margin: 0 }}>
                          Обзор
                        </h2>
                        <div className="app-table-scroll">
                          <table className="app-table app-table--compact server-root-ca-summary">
                            <tbody>
                              <tr>
                                <th scope="row" className="app-table-nowrap">Адрес API агента</th>
                                <td className="app-table-mono">{serverAgentSummary.addr}</td>
                              </tr>
                              <tr>
                                <th scope="row" className="app-table-nowrap">Версия агента</th>
                                <td>{selectedServer.agentVersion || "—"}</td>
                              </tr>
                              <tr>
                                <th scope="row" className="app-table-nowrap">Связь с агентом</th>
                                <td>
                                  <span className={`app-status ${serverAgentSummary.online ? "app-status--ok" : "app-status--off"}`}>
                                    {selectedServer.status || "Unknown"}
                                  </span>
                                </td>
                              </tr>
                              <tr>
                                <th scope="row" className="app-table-nowrap">Последний опрос метрик узла</th>
                                <td>{formatMaybeDate(selectedServer.lastSeenAt)}</td>
                              </tr>
                              <tr>
                                <th scope="row" className="app-table-nowrap">OpenVPN (статус)</th>
                                <td>
                                  <span className={`app-status ${isOpenvpnUp(selectedServer) ? "app-status--ok" : "app-status--off"}`}>
                                    {openvpnStatusLabel(selectedServer)}
                                  </span>
                                </td>
                              </tr>
                              <tr>
                                <th scope="row" className="app-table-nowrap">Служба systemd</th>
                                <td className="app-table-mono">
                                  {selectedServer.openvpnServiceActiveState || "—"} / {selectedServer.openvpnServiceSubState || "—"}
                                  {Number(selectedServer.openvpnServiceMainPid) > 0
                                    ? ` · PID ${selectedServer.openvpnServiceMainPid}`
                                    : ""}
                                </td>
                              </tr>
                              <tr>
                                <th scope="row" className="app-table-nowrap">OpenVPN (версия)</th>
                                <td>{selectedServer.openvpnVersion || "—"}</td>
                              </tr>
                              <tr>
                                <th scope="row" className="app-table-nowrap">OpenVPN (сборка)</th>
                                <td>{selectedServer.openvpnBuild || "—"}</td>
                              </tr>
                              <tr>
                                <th scope="row" className="app-table-nowrap">Бинарник OpenVPN</th>
                                <td className="app-table-mono">{selectedServer.openvpnBinaryPath || "—"}</td>
                              </tr>
                              <tr>
                                <th scope="row" className="app-table-nowrap">Конфиг OpenVPN</th>
                                <td className="app-table-mono">{selectedServer.openvpnConfigPath || "—"}</td>
                              </tr>
                              <tr>
                                <th scope="row" className="app-table-nowrap">Лог-файл OpenVPN</th>
                                <td className="app-table-mono">{selectedServer.openvpnServerLogPath || "—"}</td>
                              </tr>
                              <tr>
                                <th scope="row" className="app-table-nowrap">Имя unit</th>
                                <td className="app-table-mono">{selectedServer.openvpnServiceUnit || "—"}</td>
                              </tr>
                              <tr>
                                <th scope="row" className="app-table-nowrap">Активна с</th>
                                <td>{selectedServer.openvpnServiceActiveSince || "—"}</td>
                              </tr>
                              <tr>
                                <th scope="row" className="app-table-nowrap">Последний опрос</th>
                                <td>{formatMaybeDate(selectedServer.openvpnInfoSeenAt)}</td>
                              </tr>
                              <tr>
                                <th scope="row" className="app-table-nowrap">Management endpoint</th>
                                <td className="app-table-mono">{selectedServer.openvpnManagementAddr || "—"}</td>
                              </tr>
                              {selectedServer.openvpnInfoError ? (
                                <tr>
                                  <th scope="row" className="app-table-nowrap">Ошибка OpenVPN info</th>
                                  <td>
                                    <span style={{ color: "#b91c1c" }}>{selectedServer.openvpnInfoError}</span>
                                  </td>
                                </tr>
                              ) : null}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}

                    {serverDetailTab === "dns" && (
                      <div className="user-profile-blocks user-profile-blocks--full">
                        <h2 className="server-detail-section-title">Служба DNS</h2>
                        <div className="row-inline" style={{ gap: 8, marginBottom: 8, flexWrap: "wrap" }}>
                          <button type="button" className="btn-secondary" onClick={() => openDnsRuleModal(null)}>
                            + Правило/настройка
                          </button>
                          <button type="button" disabled={dnsmasqState.applyBusy} onClick={() => void submitEnqueueDnsmasqApply()}>
                            {dnsmasqState.applyBusy ? "Постановка…" : "Применить"}
                          </button>
                        </div>
                        <div className="app-table-scroll">
                          <table className="app-table app-table--compact">
                            <thead>
                              <tr>
                                <th style={{ width: 220 }}>Тип</th>
                                <th>Параметры</th>
                                <th className="app-table-col-actions">Действия</th>
                              </tr>
                            </thead>
                            <tbody>
                              {dnsmasqDraft.length === 0 ? (
                                <tr>
                                  <td colSpan={3} className="muted">Нет правил и настроек.</td>
                                </tr>
                              ) : (
                                dnsmasqDraft.map((rule) => {
                                  let summary = "";
                                  if (rule.type === "domain-resolver") summary = `domain=${rule.domain || "—"}, dns=${rule.targetDns || "—"}`;
                                  else if (rule.type === "cache") summary = `cache-size=${rule.cacheSize || "—"}`;
                                  else if (rule.type === "ip-override") summary = `domain=${rule.domain || "—"}, ip=${rule.ip || "—"}`;
                                  else if (rule.type === "arbitrary-address") summary = `ip=${rule.ip || "—"}`;
                                  else if (rule.type === "forward") summary = `dns=${rule.targetDns || "—"}`;
                                  else if (rule.type === "hosts-file") summary = `path=${rule.path || "—"}`;
                                  else if (rule.type === "listen-interface") summary = `interface=${rule.iface || "—"}`;
                                  return (
                                    <tr
                                      key={rule.id}
                                      className={rowReorderClass("dns", rule.id, tableDrag)}
                                      draggable
                                      onDragStart={(e) => {
                                        beginTableRowDragPreview(e.currentTarget, e, rule.id);
                                        setTableDrag({ scope: "dns", dragId: rule.id, overId: "", placeAfter: false });
                                      }}
                                      onDragOver={(e) => tableRowDragOverHandler(e, "dns", rule.id, setTableDrag)}
                                      onDragEnd={() => {
                                        endTableRowDragPreview();
                                        setTableDrag(emptyTableDrag());
                                      }}
                                      onDrop={(e) => {
                                        e.preventDefault();
                                        setTableDrag((td) => {
                                          if (td.scope !== "dns" || !td.dragId) return emptyTableDrag();
                                          setDnsmasqDraft((prev) => reorderRowInList(prev, td.dragId, rule.id, td.placeAfter));
                                          return emptyTableDrag();
                                        });
                                      }}
                                    >
                                      <td>{dnsTypeLabel(rule.type)}</td>
                                      <td>{summary}</td>
                                      <td className="app-table-td-clip-none">
                                        <button type="button" className="app-link-btn" onClick={() => openDnsRuleModal(rule)}>Изменить</button>{" "}
                                        <button type="button" className="app-link-btn app-link-btn--danger" onClick={() => setDnsmasqDraft((prev) => prev.filter((x) => x.id !== rule.id))}>Удалить</button>
                                      </td>
                                    </tr>
                                  );
                                })
                              )}
                            </tbody>
                          </table>
                        </div>
                        {dnsRuleModal.open ? (
                          <div
                            className="modal-backdrop"
                            role="presentation"
                            onClick={(e) => {
                              if (e.target === e.currentTarget) setDnsRuleModal({ open: false, editId: "", type: "domain-resolver", draft: {}, error: "" });
                            }}
                          >
                            <div className="modal-dialog" role="dialog" aria-modal="true">
                              <div className="modal-dialog-header">
                                <h2 className="modal-dialog-title">{dnsRuleModal.editId ? "Редактирование DNS-правила" : "Новое DNS-правило"}</h2>
                                <button type="button" className="modal-close" aria-label="Закрыть" onClick={() => setDnsRuleModal({ open: false, editId: "", type: "domain-resolver", draft: {}, error: "" })}>×</button>
                              </div>
                              <div className="user-profile-field-block">
                                <div className="user-profile-field-label">Тип параметра</div>
                                <select
                                  value={dnsRuleModal.type}
                                  onChange={(e) => {
                                    const t = String(e.target.value || "domain-resolver");
                                    setDnsRuleModal((prev) => ({ ...prev, type: t, draft: newDnsRuleDraftByType(t), error: "" }));
                                  }}
                                  disabled={Boolean(dnsRuleModal.editId)}
                                >
                                  <option value="domain-resolver">Перевод запросов на другой DNS-сервер для определенного домена</option>
                                  <option value="cache">Настройка кэширования</option>
                                  <option value="ip-override">Подмена IP-адресов</option>
                                  <option value="arbitrary-address">Произвольный адрес</option>
                                  <option value="forward">Форвард запросов на другой сервер</option>
                                  <option value="hosts-file">Файл hosts</option>
                                  <option value="listen-interface">Прослушивание на интерфейсах</option>
                                </select>
                              </div>
                              {dnsRuleModal.type === "domain-resolver" ? (
                                <>
                                  <div className="user-profile-field-block"><div className="user-profile-field-label">Домен</div><input value={dnsRuleModal.draft.domain || ""} onChange={(e) => setDnsRuleModal((prev) => ({ ...prev, draft: { ...prev.draft, domain: e.target.value } }))} placeholder="corp.local" /></div>
                                  <div className="user-profile-field-block"><div className="user-profile-field-label">DNS-сервер</div><input value={dnsRuleModal.draft.targetDns || ""} onChange={(e) => setDnsRuleModal((prev) => ({ ...prev, draft: { ...prev.draft, targetDns: e.target.value } }))} placeholder="10.0.0.53" /></div>
                                </>
                              ) : null}
                              {dnsRuleModal.type === "cache" ? (
                                <div className="user-profile-field-block"><div className="user-profile-field-label">cache-size</div><input value={dnsRuleModal.draft.cacheSize || ""} onChange={(e) => setDnsRuleModal((prev) => ({ ...prev, draft: { ...prev.draft, cacheSize: e.target.value } }))} placeholder="1000" /></div>
                              ) : null}
                              {dnsRuleModal.type === "ip-override" ? (
                                <>
                                  <div className="user-profile-field-block"><div className="user-profile-field-label">Домен</div><input value={dnsRuleModal.draft.domain || ""} onChange={(e) => setDnsRuleModal((prev) => ({ ...prev, draft: { ...prev.draft, domain: e.target.value } }))} placeholder="app.local" /></div>
                                  <div className="user-profile-field-block"><div className="user-profile-field-label">IP</div><input value={dnsRuleModal.draft.ip || ""} onChange={(e) => setDnsRuleModal((prev) => ({ ...prev, draft: { ...prev.draft, ip: e.target.value } }))} placeholder="10.220.0.2" /></div>
                                </>
                              ) : null}
                              {dnsRuleModal.type === "arbitrary-address" ? (
                                <div className="user-profile-field-block"><div className="user-profile-field-label">IP</div><input value={dnsRuleModal.draft.ip || ""} onChange={(e) => setDnsRuleModal((prev) => ({ ...prev, draft: { ...prev.draft, ip: e.target.value } }))} placeholder="10.220.0.1" /></div>
                              ) : null}
                              {dnsRuleModal.type === "forward" ? (
                                <div className="user-profile-field-block"><div className="user-profile-field-label">DNS-сервер</div><input value={dnsRuleModal.draft.targetDns || ""} onChange={(e) => setDnsRuleModal((prev) => ({ ...prev, draft: { ...prev.draft, targetDns: e.target.value } }))} placeholder="8.8.8.8" /></div>
                              ) : null}
                              {dnsRuleModal.type === "hosts-file" ? (
                                <div className="user-profile-field-block"><div className="user-profile-field-label">Путь к файлу</div><input value={dnsRuleModal.draft.path || ""} onChange={(e) => setDnsRuleModal((prev) => ({ ...prev, draft: { ...prev.draft, path: e.target.value } }))} placeholder="/etc/hosts.extra" /></div>
                              ) : null}
                              {dnsRuleModal.type === "listen-interface" ? (
                                <div className="user-profile-field-block"><div className="user-profile-field-label">Интерфейс</div><input value={dnsRuleModal.draft.iface || ""} onChange={(e) => setDnsRuleModal((prev) => ({ ...prev, draft: { ...prev.draft, iface: e.target.value } }))} placeholder="eth0" /></div>
                              ) : null}
                              {dnsRuleModal.error ? (
                                <div className="auth-alert auth-alert--error" role="alert">
                                  {dnsRuleModal.error}
                                </div>
                              ) : null}
                              <div className="row-inline" style={{ justifyContent: "flex-end", gap: 8, marginTop: 12 }}>
                                <button type="button" className="btn-secondary" onClick={() => setDnsRuleModal({ open: false, editId: "", type: "domain-resolver", draft: {}, error: "" })}>Отмена</button>
                                <button type="button" onClick={submitDnsRuleModal}>Сохранить</button>
                              </div>
                            </div>
                          </div>
                        ) : null}
                        {dnsmasqState.queueMessage ? (
                          <div className="auth-alert auth-alert--success" role="status">
                            {dnsmasqState.queueMessage}
                          </div>
                        ) : null}
                        {dnsmasqState.error ? (
                          <div className="auth-alert auth-alert--error" role="alert">
                            {dnsmasqState.error}
                          </div>
                        ) : null}
                      </div>
                    )}

                    {serverDetailTab === "journal" && (
                      <>
                        <h2 className="server-detail-section-title">Журнал OpenVPN</h2>
                        {!selectedServer.openvpnLogsEnabled ? (
                          <p className="muted">
                            {selectedServer.openvpnLogsNote || "Логи OpenVPN server не включены."}
                          </p>
                        ) : (
                          <>
                            <div className="app-list-toolbar journal-filters">
                              <input
                                className="app-filter-input journal-filter-input"
                                value={journalQuery}
                                onChange={(e) => setJournalQuery(e.target.value)}
                                placeholder="Поиск: пользователь, событие, время, IP"
                              />
                            </div>
                            <div className="app-table-with-pagination">
                              <div className="app-table-scroll">
                                <table className="app-table app-table--compact">
                                  <thead>
                                    <tr>
                                      <th>Время</th>
                                      <th>Событие</th>
                                      <th>Пользователь</th>
                                      <th>IP</th>
                                    </tr>
                                  </thead>
                                  <tbody>
                                    {journalLogsLoading ? null : journalLogsRows.length === 0 ? (
                                      <tr>
                                        <td colSpan={4} className="muted">
                                          Нет записей по текущему фильтру.
                                        </td>
                                      </tr>
                                    ) : (
                                      journalLogsRows.map((row) => (
                                        <tr key={row.id}>
                                          <td className="app-table-mono app-table-nowrap">
                                            {row.occurredRaw || formatMaybeDate(row.occurredAt)}
                                          </td>
                                          <td>{row.event}</td>
                                          <td>{row.username || "—"}</td>
                                          <td className="app-table-mono app-table-nowrap">{row.ipAddress || "—"}</td>
                                        </tr>
                                      ))
                                    )}
                                  </tbody>
                                </table>
                              </div>
                              <TablePagination
                                page={journalLogsPage}
                                totalPages={journalLogsTotalPages}
                                total={journalLogsTotal}
                                onPageChange={setJournalLogsPage}
                              />
                            </div>
                          </>
                        )}
                      </>
                    )}

                  </div>
                </>
              )}
            </div>
          )}

          {primaryNav === "organizations" && organizationsView === "list" && (
            <section className="card card--flush-table">
              <div className="app-table-with-pagination">
              <div className="app-table-scroll">
                <table className="app-table">
                  <thead>
                    <tr>
                      <th>Название</th>
                      <th>ИНН</th>
                      <th>Юридический адрес</th>
                      <th>Генеральный директор</th>
                      <th>Телефон</th>
                      <th>Электронная почта</th>
                    </tr>
                  </thead>
                  <tbody>
                    {organizations.length === 0 ? (
                      <tr>
                        <td colSpan={6} className="muted">
                          Организаций пока нет. Нажмите «Добавить организацию», чтобы создать запись.
                        </td>
                      </tr>
                    ) : (
                      organizationsTablePage.slice.map((org) => (
                        <tr
                          key={org.id}
                          className="app-table-click-row"
                          tabIndex={0}
                          role="button"
                          onClick={() => openOrganizationEdit(org)}
                          onKeyDown={(e) => {
                            if (e.key === "Enter" || e.key === " ") {
                              e.preventDefault();
                              openOrganizationEdit(org);
                            }
                          }}
                        >
                          <td className="app-table-cell-strong">{org.name}</td>
                          <td>{org.inn || "—"}</td>
                          <td>{org.legalAddress || "—"}</td>
                          <td>{org.generalDirector || "—"}</td>
                          <td>{org.phone || "—"}</td>
                          <td>{org.email || "—"}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
              {organizations.length > 0 ? (
                <TablePagination
                  page={organizationsTablePage.page}
                  totalPages={organizationsTablePage.totalPages}
                  total={organizationsTablePage.total}
                  onPageChange={(p) => setTablePages((prev) => ({ ...prev, organizations: p }))}
                />
              ) : null}
              </div>
            </section>
          )}

          {primaryNav === "organizations" && organizationsView === "add" && (
            <section className="card card--flush-form">
              <div className="user-profile-blocks user-profile-blocks--stack">
                <form className="user-profile-blocks--stack" onSubmit={createOrganization}>
                  <div className="user-profile-field-block">
                    <div className="user-profile-field-label">
                      Название организации <span className="error">*</span>
                    </div>
                    <input
                      required
                      value={newOrganization.name}
                      onChange={(e) => setNewOrganization((prev) => ({ ...prev, name: e.target.value }))}
                      placeholder="ООО «Пример»"
                    />
                  </div>
                  <div className="user-profile-field-block">
                    <div className="user-profile-field-label">ИНН</div>
                    <input
                      value={newOrganization.inn}
                      onChange={(e) => setNewOrganization((prev) => ({ ...prev, inn: e.target.value }))}
                      placeholder="Необязательно"
                    />
                    <p className="user-profile-field-hint">Необязательно.</p>
                  </div>
                  <div className="user-profile-field-block">
                    <div className="user-profile-field-label">Юридический адрес</div>
                    <input
                      value={newOrganization.legalAddress}
                      onChange={(e) => setNewOrganization((prev) => ({ ...prev, legalAddress: e.target.value }))}
                      placeholder="Необязательно"
                    />
                    <p className="user-profile-field-hint">Необязательно.</p>
                  </div>
                  <div className="user-profile-field-block">
                    <div className="user-profile-field-label">Генеральный директор</div>
                    <input
                      value={newOrganization.generalDirector}
                      onChange={(e) => setNewOrganization((prev) => ({ ...prev, generalDirector: e.target.value }))}
                      placeholder="Необязательно"
                    />
                    <p className="user-profile-field-hint">Необязательно.</p>
                  </div>
                  <div className="user-profile-field-block">
                    <div className="user-profile-field-label">Телефон</div>
                    <input
                      type="tel"
                      value={newOrganization.phone}
                      onChange={(e) => setNewOrganization((prev) => ({ ...prev, phone: e.target.value }))}
                      placeholder="Необязательно"
                    />
                    <p className="user-profile-field-hint">Необязательно.</p>
                  </div>
                  <div className="user-profile-field-block">
                    <div className="user-profile-field-label">Адрес электронной почты</div>
                    <input
                      type="email"
                      value={newOrganization.email}
                      onChange={(e) => setNewOrganization((prev) => ({ ...prev, email: e.target.value }))}
                      placeholder="Необязательно"
                    />
                    <p className="user-profile-field-hint">Необязательно.</p>
                  </div>
                  <div className="user-profile-field-block">
                    <button type="submit">Сохранить организацию</button>
                  </div>
                </form>
              </div>
            </section>
          )}

          {primaryNav === "organizations" && organizationsView === "edit" && (
            <div className={`resource-layout${organizationEditMissing ? " resource-layout--empty" : ""}`}>
              {organizationEditMissing ? (
                <section className="card">
                  <p>Организация не найдена.</p>
                  <button type="button" className="linkish" onClick={goOrganizationsList}>
                    К списку организаций
                  </button>
                </section>
              ) : (
                <>
                  <aside className="resource-sidebar" aria-label="Разделы организации">
                    <div className="resource-sidebar-header">
                      <h2 className="resource-sidebar-title">
                        {editOrganization.name?.trim() || "Организация"}
                      </h2>
                      <p className="resource-sidebar-sub">Карточка организации</p>
                    </div>
                    <nav className="resource-nav" aria-label="Навигация по организации">
                      <button
                        type="button"
                        className={`resource-nav-item${organizationEditTab === "overview" ? " is-active" : ""}`}
                        aria-current={organizationEditTab === "overview" ? "page" : undefined}
                        onClick={() => navigate(paths.organizationEdit(organizationEditId, "overview"))}
                      >
                        <IconNavOrganizations />
                        Организация
                      </button>
                      <button
                        type="button"
                        className={`resource-nav-item${organizationEditTab === "firewall" ? " is-active" : ""}`}
                        aria-current={organizationEditTab === "firewall" ? "page" : undefined}
                        onClick={() => navigate(paths.organizationEdit(organizationEditId, "firewall"))}
                      >
                        <IconSettings />
                        Межсетевой экран
                      </button>
                    </nav>
                  </aside>
                  <div className="resource-main">
                    {organizationEditTab === "overview" ? (
                    <div className="user-profile-blocks user-profile-blocks--stack">
                      <form className="user-profile-blocks--stack" onSubmit={updateOrganization}>
                        <div className="user-profile-field-block">
                          <div className="user-profile-field-label">
                            Название организации <span className="error">*</span>
                          </div>
                          <input
                            required
                            value={editOrganization.name}
                            onChange={(e) => setEditOrganization((prev) => ({ ...prev, name: e.target.value }))}
                            placeholder="ООО «Пример»"
                          />
                          <p className="user-profile-field-hint">Краткое наименование для списков и привязки пользователей.</p>
                        </div>
                        <div className="user-profile-field-block">
                          <div className="user-profile-field-label">ИНН</div>
                          <input
                            value={editOrganization.inn}
                            onChange={(e) => setEditOrganization((prev) => ({ ...prev, inn: e.target.value }))}
                            placeholder=""
                          />
                          <p className="user-profile-field-hint">Необязательно.</p>
                        </div>
                        <div className="user-profile-field-block">
                          <div className="user-profile-field-label">Юридический адрес</div>
                          <input
                            value={editOrganization.legalAddress}
                            onChange={(e) => setEditOrganization((prev) => ({ ...prev, legalAddress: e.target.value }))}
                            placeholder=""
                          />
                          <p className="user-profile-field-hint">Необязательно.</p>
                        </div>
                        <div className="user-profile-field-block">
                          <div className="user-profile-field-label">Генеральный директор</div>
                          <input
                            value={editOrganization.generalDirector}
                            onChange={(e) => setEditOrganization((prev) => ({ ...prev, generalDirector: e.target.value }))}
                            placeholder=""
                          />
                          <p className="user-profile-field-hint">Необязательно.</p>
                        </div>
                        <div className="user-profile-field-block">
                          <div className="user-profile-field-label">Телефон</div>
                          <input
                            type="tel"
                            value={editOrganization.phone}
                            onChange={(e) => setEditOrganization((prev) => ({ ...prev, phone: e.target.value }))}
                            placeholder=""
                          />
                          <p className="user-profile-field-hint">Необязательно.</p>
                        </div>
                        <div className="user-profile-field-block">
                          <div className="user-profile-field-label">Адрес электронной почты</div>
                          <input
                            type="email"
                            value={editOrganization.email}
                            onChange={(e) => setEditOrganization((prev) => ({ ...prev, email: e.target.value }))}
                            placeholder=""
                          />
                          <p className="user-profile-field-hint">Необязательно.</p>
                        </div>
                        <div className="user-profile-field-block">
                          <button type="submit">Сохранить изменения</button>
                        </div>
                      </form>
                    </div>
                    ) : (
                    <div className="user-profile-blocks user-profile-blocks--full">
                      <h2 className="server-detail-section-title">Межсетевой экран</h2>
                      <div className="server-settings-layout server-settings-layout--stack server-settings-layout--stack-full">
                        <div className="server-settings-main">
                          <div className="server-version-select-row">
                            <select
                              value={organizationFirewallMode}
                              onChange={(e) => setOrganizationFirewallMode(e.target.value === "replace" ? "replace" : "merge")}
                            >
                              <option value="merge">Дополнять общие правила туннеля</option>
                              <option value="replace">Заменить для этой организации (только правила организации)</option>
                            </select>
                            <button type="button" className="btn-secondary" onClick={() => openFirewallRuleModal("organization", null, "tunnel", "filter")}>
                              + Правило
                            </button>
                            <button type="button" className="btn-secondary" onClick={() => openFirewallRuleModal("organization", null, "tunnel", "nat")}>
                              + NAT
                            </button>
                          </div>
                          <div className="app-table-scroll" style={{ marginTop: 8 }}>
                            <table className="app-table app-table--compact table-org-firewall">
                              <thead>
                                <tr>
                                  <th>Action</th>
                                  <th>Proto</th>
                                  <th>Destination</th>
                                  <th>Ports</th>
                                  <th>Описание</th>
                                  <th className="app-table-col-actions">Действия</th>
                                </tr>
                              </thead>
                              <tbody>
                                {organizationFirewallRules.length === 0 ? (
                                  <tr>
                                    <td colSpan={6} className="muted">Нет правил.</td>
                                  </tr>
                                ) : (
                                  organizationFirewallRules.map((rule) => (
                                    <tr
                                      key={rule.id}
                                      className={rowReorderClass("org-filter", rule.id, tableDrag)}
                                      draggable={!organizationFirewallBusy}
                                      onDragStart={(e) => {
                                        beginTableRowDragPreview(e.currentTarget, e, rule.id);
                                        setTableDrag({ scope: "org-filter", dragId: rule.id, overId: "", placeAfter: false });
                                      }}
                                      onDragOver={(e) => tableRowDragOverHandler(e, "org-filter", rule.id, setTableDrag)}
                                      onDragEnd={() => {
                                        endTableRowDragPreview();
                                        setTableDrag(emptyTableDrag());
                                      }}
                                      onDrop={(e) => {
                                        e.preventDefault();
                                        setTableDrag((td) => {
                                          if (td.scope !== "org-filter" || !td.dragId) return emptyTableDrag();
                                          setOrganizationFirewallRules((prev) => reorderRowInList(prev, td.dragId, rule.id, td.placeAfter));
                                          return emptyTableDrag();
                                        });
                                      }}
                                    >
                                      <td><span className={rule.action === "deny" ? "app-status app-status--bad" : "app-status app-status--ok"}>{rule.action}</span></td>
                                      <td className="app-table-mono">{rule.proto}</td>
                                      <td className="app-table-mono">{rule.destination || "—"}</td>
                                      <td className="app-table-mono">{rule.ports || "*"}</td>
                                      <td>{rule.note || "—"}</td>
                                      <td className="app-table-td-clip-none">
                                        <button type="button" className="app-link-btn" onClick={() => openFirewallRuleModal("organization", rule, "tunnel", "filter")}>Изменить</button>{" "}
                                        <button type="button" className="app-link-btn app-link-btn--danger" onClick={() => setOrganizationFirewallRules((prev) => prev.filter((x) => x.id !== rule.id))}>Удалить</button>
                                      </td>
                                    </tr>
                                  ))
                                )}
                              </tbody>
                            </table>
                          </div>
                          <div className="app-table-scroll" style={{ marginTop: 8 }}>
                            <table className="app-table app-table--compact table-org-firewall">
                              <thead>
                                <tr>
                                  <th>Type</th>
                                  <th>Hook</th>
                                  <th>Src</th>
                                  <th>Dst</th>
                                  <th>Out iface</th>
                                  <th>To address</th>
                                  <th>Описание</th>
                                  <th className="app-table-col-actions">Действия</th>
                                </tr>
                              </thead>
                              <tbody>
                                {organizationFirewallNatRules.length === 0 ? (
                                  <tr>
                                    <td colSpan={8} className="muted">Нет NAT-правил.</td>
                                  </tr>
                                ) : (
                                  organizationFirewallNatRules.map((rule) => (
                                    <tr
                                      key={rule.id}
                                      className={rowReorderClass("org-nat", rule.id, tableDrag)}
                                      draggable={!organizationFirewallBusy}
                                      onDragStart={(e) => {
                                        beginTableRowDragPreview(e.currentTarget, e, rule.id);
                                        setTableDrag({ scope: "org-nat", dragId: rule.id, overId: "", placeAfter: false });
                                      }}
                                      onDragOver={(e) => tableRowDragOverHandler(e, "org-nat", rule.id, setTableDrag)}
                                      onDragEnd={() => {
                                        endTableRowDragPreview();
                                        setTableDrag(emptyTableDrag());
                                      }}
                                      onDrop={(e) => {
                                        e.preventDefault();
                                        setTableDrag((td) => {
                                          if (td.scope !== "org-nat" || !td.dragId) return emptyTableDrag();
                                          setOrganizationFirewallNatRules((prev) => reorderRowInList(prev, td.dragId, rule.id, td.placeAfter));
                                          return emptyTableDrag();
                                        });
                                      }}
                                    >
                                      <td className="app-table-mono">{rule.type}</td>
                                      <td className="app-table-mono">{rule.type === "dnat" ? "PREROUTING" : "POSTROUTING"}</td>
                                      <td className="app-table-mono">{rule.src || "—"}</td>
                                      <td className="app-table-mono">{rule.dst || "—"}</td>
                                      <td className="app-table-mono">{rule.outInterface || "—"}</td>
                                      <td className="app-table-mono">{rule.toAddress || "—"}</td>
                                      <td>{rule.note || "—"}</td>
                                      <td className="app-table-td-clip-none">
                                        <button type="button" className="app-link-btn" onClick={() => openFirewallRuleModal("organization", rule, "tunnel", "nat")}>Изменить</button>{" "}
                                        <button type="button" className="app-link-btn app-link-btn--danger" onClick={() => setOrganizationFirewallNatRules((prev) => prev.filter((x) => x.id !== rule.id))}>Удалить</button>
                                      </td>
                                    </tr>
                                  ))
                                )}
                              </tbody>
                            </table>
                          </div>
                          <div className="row-inline" style={{ gap: 8, marginTop: 12, flexWrap: "wrap" }}>
                            <button type="button" disabled={organizationFirewallBusy} onClick={() => void applyOrganizationFirewall()}>
                              {organizationFirewallBusy ? "Применение..." : "Применить"}
                            </button>
                            <button type="button" className="btn-secondary" onClick={openOrganizationEffectivePolicyModal}>
                              Effective Policy
                            </button>
                          </div>
                        </div>
                      </div>
                    </div>
                    )}
                  </div>
                </>
              )}
            </div>
          )}

          {organizationFirewallEffectiveModal.open ? (
            <div
              className="modal-backdrop"
              role="presentation"
              onClick={(e) => {
                if (e.target === e.currentTarget) setOrganizationFirewallEffectiveModal({ open: false, title: "", content: "" });
              }}
            >
              <div className="modal-dialog modal-dialog--wide" role="dialog" aria-modal="true">
                <div className="modal-dialog-header">
                  <h2 className="modal-dialog-title">{organizationFirewallEffectiveModal.title}</h2>
                  <button type="button" className="modal-close" aria-label="Закрыть" onClick={() => setOrganizationFirewallEffectiveModal({ open: false, title: "", content: "" })}>
                    ×
                  </button>
                </div>
                <pre className="server-settings-raw-pre" style={{ maxHeight: "60vh", overflow: "auto" }}>
                  {organizationFirewallEffectiveModal.content}
                </pre>
              </div>
            </div>
          ) : null}

          {firewallRuleModal.open && !(primaryNav === "servers" && serversView === "detail" && serverDetailTab === "firewall") ? (
            <div
              className="modal-backdrop"
              role="presentation"
              onClick={(e) => {
                if (e.target === e.currentTarget) {
                  setFirewallRuleModal((prev) => ({ ...prev, open: false, error: "" }));
                }
              }}
            >
              <div className="modal-dialog" role="dialog" aria-modal="true" aria-labelledby="firewall-rule-modal-title-global">
                <div className="modal-dialog-header">
                  <h2 id="firewall-rule-modal-title-global" className="modal-dialog-title">
                    {firewallRuleModal.editId ? "Редактирование правила" : "Новое правило"} · Межсетевой экран
                  </h2>
                  <button type="button" className="modal-close" aria-label="Закрыть" onClick={() => setFirewallRuleModal((prev) => ({ ...prev, open: false, error: "" }))}>
                    ×
                  </button>
                </div>
                {firewallRuleModal.kind !== "nat" ? (
                  <>
                    <div className="user-profile-field-block">
                      <div className="user-profile-field-label">Action</div>
                      <select
                        value={firewallRuleModal.draft.action}
                        onChange={(e) => setFirewallRuleModal((prev) => ({ ...prev, draft: { ...prev.draft, action: e.target.value } }))}
                      >
                        <option value="allow">allow</option>
                        <option value="deny">deny</option>
                      </select>
                    </div>
                    <div className="user-profile-field-block">
                      <div className="user-profile-field-label">Proto</div>
                      <select
                        value={firewallRuleModal.draft.proto}
                        onChange={(e) => setFirewallRuleModal((prev) => ({ ...prev, draft: { ...prev.draft, proto: e.target.value } }))}
                      >
                        <option value="tcp">tcp</option>
                        <option value="udp">udp</option>
                        <option value="icmp">icmp</option>
                        <option value="any">any</option>
                      </select>
                    </div>
                    <div className="user-profile-field-block">
                      <div className="user-profile-field-label">Destination</div>
                      <input
                        value={firewallRuleModal.draft.destination}
                        onChange={(e) => setFirewallRuleModal((prev) => ({ ...prev, draft: { ...prev.draft, destination: e.target.value } }))}
                        placeholder="172.16.0.0/24"
                      />
                    </div>
                    <div className="user-profile-field-block">
                      <div className="user-profile-field-label">Ports</div>
                      <input
                        value={firewallRuleModal.draft.ports}
                        onChange={(e) => setFirewallRuleModal((prev) => ({ ...prev, draft: { ...prev.draft, ports: e.target.value } }))}
                        placeholder="80,443"
                      />
                    </div>
                  </>
                ) : (
                  <>
                    <div className="user-profile-field-block">
                      <div className="user-profile-field-label">NAT type</div>
                      <select
                        value={firewallRuleModal.draft.type}
                        onChange={(e) => setFirewallRuleModal((prev) => ({ ...prev, draft: { ...prev.draft, type: e.target.value } }))}
                      >
                        <option value="masquerade">masquerade</option>
                        <option value="snat">snat</option>
                        <option value="dnat">dnat</option>
                      </select>
                    </div>
                    <div className="user-profile-field-block">
                      <div className="user-profile-field-label">Src</div>
                      <input
                        value={firewallRuleModal.draft.src}
                        onChange={(e) => setFirewallRuleModal((prev) => ({ ...prev, draft: { ...prev.draft, src: e.target.value } }))}
                        placeholder="10.220.0.0/22"
                      />
                    </div>
                    <div className="user-profile-field-block">
                      <div className="user-profile-field-label">Dst</div>
                      <input
                        value={firewallRuleModal.draft.dst}
                        onChange={(e) => setFirewallRuleModal((prev) => ({ ...prev, draft: { ...prev.draft, dst: e.target.value } }))}
                        placeholder="172.16.0.10/32"
                      />
                    </div>
                    <div className="user-profile-field-block">
                      <div className="user-profile-field-label">Out interface</div>
                      <div className="row-inline" style={{ gap: 8, flexWrap: "nowrap" }}>
                        <select
                          value={natOutInterfaceInputMode === "manual" ? "__manual__" : firewallRuleModal.draft.outInterface}
                          onChange={(e) => {
                            const v = String(e.target.value || "");
                            if (v === "__manual__") {
                              setNatOutInterfaceInputMode("manual");
                              setFirewallRuleModal((prev) => ({
                                ...prev,
                                draft: { ...prev.draft, outInterface: "" },
                              }));
                              return;
                            }
                            setNatOutInterfaceInputMode("preset");
                            setFirewallRuleModal((prev) => ({ ...prev, draft: { ...prev.draft, outInterface: v } }));
                          }}
                          style={{ width: 180, flex: "0 0 180px" }}
                        >
                          <option value="__manual__">Вручную</option>
                          {natOutInterfaceOptions.map((itf) => (
                            <option key={itf} value={itf}>{itf}</option>
                          ))}
                        </select>
                        <input
                          value={firewallRuleModal.draft.outInterface}
                          onChange={(e) => setFirewallRuleModal((prev) => ({ ...prev, draft: { ...prev.draft, outInterface: e.target.value } }))}
                          placeholder="eth0"
                          disabled={natOutInterfaceInputMode !== "manual"}
                          style={{ flex: "1 1 auto", minWidth: 0 }}
                        />
                      </div>
                    </div>
                    <div className="user-profile-field-block">
                      <div className="user-profile-field-label">To address</div>
                      <div className="row-inline" style={{ gap: 8, flexWrap: "nowrap" }}>
                        <select
                          value={natToAddressInputMode === "manual" ? "__manual__" : firewallRuleModal.draft.toAddress}
                          onChange={(e) => {
                            const v = String(e.target.value || "");
                            if (v === "__manual__") {
                              setNatToAddressInputMode("manual");
                              setFirewallRuleModal((prev) => ({
                                ...prev,
                                draft: { ...prev.draft, toAddress: "" },
                              }));
                              return;
                            }
                            setNatToAddressInputMode("preset");
                            setFirewallRuleModal((prev) => ({ ...prev, draft: { ...prev.draft, toAddress: v } }));
                          }}
                          style={{ width: 180, flex: "0 0 180px" }}
                        >
                          <option value="__manual__">Вручную</option>
                          {natToAddressOptions.map((addr) => (
                            <option key={addr} value={addr}>{addr}</option>
                          ))}
                        </select>
                        <input
                          value={firewallRuleModal.draft.toAddress}
                          onChange={(e) => setFirewallRuleModal((prev) => ({ ...prev, draft: { ...prev.draft, toAddress: e.target.value } }))}
                          placeholder="203.0.113.10"
                          disabled={natToAddressInputMode !== "manual"}
                          style={{ flex: "1 1 auto", minWidth: 0 }}
                        />
                      </div>
                    </div>
                  </>
                )}
                <div className="user-profile-field-block">
                  <div className="user-profile-field-label">Описание</div>
                  <input
                    value={firewallRuleModal.draft.note}
                    onChange={(e) => setFirewallRuleModal((prev) => ({ ...prev, draft: { ...prev.draft, note: e.target.value } }))}
                  />
                </div>
                {firewallRuleModal.error ? (
                  <div className="auth-alert auth-alert--error" role="alert">
                    {firewallRuleModal.error}
                  </div>
                ) : null}
                <div className="row-inline" style={{ justifyContent: "flex-end", gap: 8, marginTop: 12 }}>
                  <button type="button" className="btn-secondary" onClick={() => setFirewallRuleModal((prev) => ({ ...prev, open: false, error: "" }))}>
                    Отмена
                  </button>
                  <button type="button" onClick={submitFirewallRuleModal}>Сохранить</button>
                </div>
              </div>
            </div>
          ) : null}

          {primaryNav === "users" && usersSub === "list" && (
            <section className="card card--flush-table">
              <div className="app-table-with-pagination">
              <div className="app-table-scroll">
                <table className="app-table app-table--fixed-cols">
                  <thead>
                    <tr>
                      <th>ФИО</th>
                      <th>Электронная почта</th>
                      <th>Должность</th>
                      <th>Организация</th>
                      <th>Трафик in/out</th>
                      <th>Последняя активность</th>
                    </tr>
                  </thead>
                  <tbody>
                    {vpnUsersEnriched.length === 0 ? (
                      <tr>
                        <td colSpan={6} className="muted">
                          Пользователей пока нет. Нажмите «Добавить пользователя», чтобы создать профиль.
                        </td>
                      </tr>
                    ) : filteredVpnUsersEnriched.length === 0 ? (
                      <tr>
                        <td colSpan={6} className="muted">
                          Нет совпадений с фильтром.
                        </td>
                      </tr>
                    ) : (
                      usersTablePage.slice.map((user) => (
                        <tr
                          key={user.id}
                          className="app-table-click-row"
                          tabIndex={0}
                          role="button"
                          onClick={() => {
                            navigate(paths.userProfile(user.id, "overview"));
                          }}
                          onKeyDown={(e) => {
                            if (e.key === "Enter" || e.key === " ") {
                              e.preventDefault();
                              navigate(paths.userProfile(user.id, "overview"));
                            }
                          }}
                        >
                          <td className="app-table-cell-strong">{user.fullName}</td>
                          <td>{user.email || "—"}</td>
                          <td>{user.position || "—"}</td>
                          <td>{user.organization?.name || "—"}</td>
                          <td>
                            {formatBps(user.totalInBps)} / {formatBps(user.totalOutBps)}
                          </td>
                          <td className="app-table-nowrap">
                            {(() => {
                              const { label, title } = formatUserLastActivityCell(user, sessionNow);
                              return <span title={title}>{label}</span>;
                            })()}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
              {vpnUsersEnriched.length > 0 && filteredVpnUsersEnriched.length > 0 ? (
                <TablePagination
                  page={usersTablePage.page}
                  totalPages={usersTablePage.totalPages}
                  total={usersTablePage.total}
                  onPageChange={(p) => setTablePages((prev) => ({ ...prev, users: p }))}
                />
              ) : null}
              </div>
            </section>
          )}

          {primaryNav === "users" && usersSub === "add" && (
            <section className="card card--flush-form">
              <div className="user-profile-blocks user-profile-blocks--stack">
                <form className="user-profile-blocks--stack" onSubmit={createVpnUser}>
                  <div className="user-profile-field-block">
                    <div className="user-profile-field-label">
                      ФИО <span className="error">*</span>
                    </div>
                    <input
                      required
                      value={newVpnUser.fullName}
                      onChange={(e) => setNewVpnUser((prev) => ({ ...prev, fullName: e.target.value }))}
                      placeholder="Иванов Иван Иванович"
                    />
                  </div>
                  <div className="user-profile-field-block">
                    <div className="user-profile-field-label">
                      Электронная почта <span className="error">*</span>
                    </div>
                    <input
                      type="email"
                      required
                      value={newVpnUser.email}
                      onChange={(e) => setNewVpnUser((prev) => ({ ...prev, email: e.target.value }))}
                      placeholder="user@company.ru"
                    />
                    <p className="user-profile-field-hint">Логин и контакт для уведомлений.</p>
                  </div>
                  <div className="user-profile-field-block">
                    <div className="user-profile-field-label">Должность</div>
                    <input
                      value={newVpnUser.position}
                      onChange={(e) => setNewVpnUser((prev) => ({ ...prev, position: e.target.value }))}
                      placeholder="Необязательно"
                    />
                    <p className="user-profile-field-hint">Необязательно.</p>
                  </div>
                  <div className="user-profile-field-block">
                    <div className="user-profile-field-label">Организация</div>
                    <select
                      value={newVpnUser.organizationId}
                      onChange={(e) => setNewVpnUser((prev) => ({ ...prev, organizationId: e.target.value }))}
                      disabled={organizations.length === 0}
                    >
                      {organizations.length === 0 ? (
                        <option value="">Нет организаций — можно создать пользователя без организации</option>
                      ) : (
                        <>
                          <option value="">— не указано —</option>
                          {organizationsSortedByName.map((org) => (
                            <option key={org.id} value={org.id}>
                              {org.name}
                            </option>
                          ))}
                        </>
                      )}
                    </select>
                    <p className="user-profile-field-hint">Привязка к организации из справочника.</p>
                  </div>
                  <div className="user-profile-field-block">
                    <div className="user-profile-field-label">Мобильный телефон</div>
                    <input
                      type="tel"
                      value={newVpnUser.phone}
                      onChange={(e) => setNewVpnUser((prev) => ({ ...prev, phone: e.target.value }))}
                      placeholder="Необязательно"
                    />
                    <p className="user-profile-field-hint">Необязательно.</p>
                  </div>
                  <div className="user-profile-field-block">
                    <div className="user-profile-field-label">Заметки</div>
                    <textarea
                      value={newVpnUser.notes}
                      onChange={(e) => setNewVpnUser((prev) => ({ ...prev, notes: e.target.value }))}
                      placeholder="Необязательно"
                      rows={3}
                    />
                    <p className="user-profile-field-hint">Внутренние заметки, видны только администраторам.</p>
                  </div>
                  <div className="user-profile-field-block">
                    <div className="user-profile-field-label">Сервер \ корневой сертификат</div>
                    <select
                      value={newUserCertServerId}
                      onChange={(e) => setNewUserCertServerId(e.target.value)}
                      disabled={
                        newUserIssueServers.filter((s) => String(s.panelRootCaId || "").trim()).length === 0
                      }
                    >
                      <option value="">— без сертификата / для привязки существующего —</option>
                      {[...newUserIssueServers]
                        .filter((s) => String(s.panelRootCaId || "").trim())
                        .sort((a, b) =>
                          String(a?.name || "").localeCompare(String(b?.name || ""), undefined, {
                            sensitivity: "base",
                          }),
                        )
                        .map((s) => {
                          const ca = rootCAs.find((r) => r.id === String(s.panelRootCaId || "").trim());
                          const caLabel = ca?.name || ca?.commonName || s.panelRootCaId;
                          return (
                            <option key={s.id} value={s.id}>
                              {`${s.name} \\ ${caLabel}`}
                            </option>
                          );
                        })}
                    </select>
                    <p className="user-profile-field-hint">
                      Выберите сервер VPN и привязанный к нему в настройках OpenVPN корневой сертификат панели. Поле
                      можно оставить пустым, если сертификат не нужен. Если список пуст, задайте корневой сертификат на
                      узле в разделе сервера.
                    </p>
                  </div>
                  <div className="user-profile-field-block">
                    <div className="user-profile-field-label">Сертификат или CN</div>
                    <select
                      value={newUserCertChoice}
                      onChange={(e) => setNewUserCertChoice(e.target.value)}
                      disabled={!String(newUserCertRootCaId || "").trim()}
                    >
                      <option value="">— без сертификата —</option>
                      <option value="__create__">Создать новый сертификат</option>
                      {newUserBindableCertificates.map((c) => (
                        <option key={c.id} value={c.id}>
                          {`${c.commonName} · ${String(c.serialNumber || "").slice(0, 12)}…`}
                        </option>
                      ))}
                    </select>
                    {newUserCertChoice === "__create__" ? (
                      <>
                        <div className="user-profile-field-block">
                          <div className="user-profile-field-label user-profile-field-label--small">CN</div>
                          <input
                            value={newUserCertNewCn}
                            onChange={(e) => setNewUserCertNewCn(e.target.value)}
                            placeholder="CN сертификата"
                          />
                        </div>
                        <div className="user-profile-field-block">
                          <div className="user-profile-field-label user-profile-field-label--small">Срок действия, суток</div>
                          <input
                            type="number"
                            min={1}
                            max={Math.max(1, newUserMaxCertValidityDays)}
                            value={newUserCertValidityDays}
                            onChange={(e) => setNewUserCertValidityDays(e.target.value)}
                            placeholder="1825"
                          />
                        </div>
                      </>
                    ) : null}
                  </div>
                  <div className="user-profile-field-block">
                    <button type="submit">Создать профиль</button>
                  </div>
                </form>
              </div>
            </section>
          )}

          {primaryNav === "users" && usersSub === "profile" && (
            <div className={`resource-layout${!selectedUser ? " resource-layout--empty" : ""}`}>
              {!selectedUser ? (
                <section className="card">
                  <p>Пользователь не выбран.</p>
                </section>
              ) : (
                <>
                  <aside className="resource-sidebar" aria-label="Разделы профиля">
                    <div className="resource-sidebar-header">
                      <h2 className="resource-sidebar-title">{selectedUser.fullName}</h2>
                      <p className="resource-sidebar-sub">Профиль пользователя</p>
                    </div>
                    <nav className="resource-nav" aria-label="Навигация по профилю">
                      <button
                        type="button"
                        className={`resource-nav-item${userProfileTab === "overview" ? " is-active" : ""}`}
                        aria-current={userProfileTab === "overview" ? "page" : undefined}
                        onClick={() => navigate(paths.userProfile(selectedUserId, "overview"))}
                      >
                        <IconNavOverview />
                        Профиль
                      </button>
                      <button
                        type="button"
                        className={`resource-nav-item${userProfileTab === "certs" ? " is-active" : ""}`}
                        aria-current={userProfileTab === "certs" ? "page" : undefined}
                        onClick={() => navigate(paths.userProfile(selectedUserId, "certs"))}
                      >
                        <IconNavCertificate />
                        Сертификаты
                      </button>
                      <button
                        type="button"
                        className={`resource-nav-item${userProfileTab === "sessions" ? " is-active" : ""}`}
                        aria-current={userProfileTab === "sessions" ? "page" : undefined}
                        onClick={() => navigate(paths.userProfile(selectedUserId, "sessions"))}
                      >
                        <IconNavSessions />
                        Сессии
                      </button>
                      <button
                        type="button"
                        className={`resource-nav-item${userProfileTab === "ccd" || userProfileTab === "vpn" ? " is-active" : ""}`}
                        aria-current={userProfileTab === "ccd" || userProfileTab === "vpn" ? "page" : undefined}
                        onClick={() => navigate(paths.userProfile(selectedUserId, "ccd"))}
                      >
                        <IconNavVpn />
                        Настройки OpenVPN
                      </button>
                      <button
                        type="button"
                        className={`resource-nav-item${userProfileTab === "firewall" ? " is-active" : ""}`}
                        aria-current={userProfileTab === "firewall" ? "page" : undefined}
                        onClick={() => navigate(paths.userProfile(selectedUserId, "firewall"))}
                      >
                        <IconSettings />
                        Межсетевой экран
                      </button>
                    </nav>
                  </aside>
                  <div className="resource-main">
                    {userProfileTab === "overview" && (
                      <div className="user-profile-blocks user-profile-blocks--stack">
                        <form className="user-profile-blocks--stack" onSubmit={saveUserProfile}>
                          <div className="user-profile-field-block">
                            <div className="user-profile-field-label">
                              ФИО <span className="error">*</span>
                            </div>
                            <input
                              required
                              value={userProfileDraft.fullName}
                              onChange={(e) => setUserProfileDraft((prev) => ({ ...prev, fullName: e.target.value }))}
                            />
                          </div>
                          <div className="user-profile-field-block">
                            <div className="user-profile-field-label">
                              Электронная почта <span className="error">*</span>
                            </div>
                            <input
                              type="email"
                              required
                              value={userProfileDraft.email}
                              onChange={(e) => setUserProfileDraft((prev) => ({ ...prev, email: e.target.value }))}
                            />
                            <p className="user-profile-field-hint">Логин и контакт для уведомлений.</p>
                          </div>
                          <div className="user-profile-field-block">
                            <div className="user-profile-field-label">Должность</div>
                            <input
                              value={userProfileDraft.position}
                              onChange={(e) => setUserProfileDraft((prev) => ({ ...prev, position: e.target.value }))}
                              placeholder=""
                            />
                            <p className="user-profile-field-hint">Необязательно.</p>
                          </div>
                          <div className="user-profile-field-block">
                            <div className="user-profile-field-label">Организация</div>
                            <select
                              value={userProfileDraft.organizationId}
                              onChange={(e) => setUserProfileDraft((prev) => ({ ...prev, organizationId: e.target.value }))}
                            >
                              <option value="">— не указано —</option>
                              {organizationsSortedByName.map((org) => (
                                <option key={org.id} value={org.id}>
                                  {org.name}
                                </option>
                              ))}
                            </select>
                            <p className="user-profile-field-hint">Привязка к организации из справочника.</p>
                          </div>
                          <div className="user-profile-field-block">
                            <div className="user-profile-field-label">Мобильный телефон</div>
                            <input
                              type="tel"
                              value={userProfileDraft.phone}
                              onChange={(e) => setUserProfileDraft((prev) => ({ ...prev, phone: e.target.value }))}
                              placeholder=""
                            />
                            <p className="user-profile-field-hint">Необязательно.</p>
                          </div>
                          <div className="user-profile-field-block">
                            <div className="user-profile-field-label">Заметки</div>
                            <textarea
                              value={userProfileDraft.notes}
                              onChange={(e) => setUserProfileDraft((prev) => ({ ...prev, notes: e.target.value }))}
                              rows={3}
                            />
                            <p className="user-profile-field-hint">Внутренние заметки, видны только администраторам.</p>
                          </div>
                          <div className="user-profile-field-block">
                            <button type="submit">Сохранить данные профиля</button>
                          </div>
                        </form>
                      </div>
                    )}

                    {userProfileTab === "certs" && (
                      <>
                        <div className="resource-main-toolbar">
                          <h2 className="server-detail-section-title">Сертификаты</h2>
                          <div className="row-inline" style={{ gap: 8, flexWrap: "wrap" }}>
                            <button
                              type="button"
                              className="btn-app-primary"
                              onClick={() => {
                                if (!userCertBindServerId && userCertModalServers[0]?.id) {
                                  setUserCertBindServerId(String(userCertModalServers[0].id));
                                }
                                setUserCertBindSelectedCertId("");
                                setUserCertBindModalOpen(true);
                              }}
                            >
                              Привязать
                            </button>
                            <button
                              type="button"
                              className="btn-app-primary"
                              onClick={() => {
                                if (!userCertBindServerId && userCertModalServers[0]?.id) {
                                  setUserCertBindServerId(String(userCertModalServers[0].id));
                                }
                                setUserCertIssueModalOpen(true);
                              }}
                            >
                              Выпустить новый
                            </button>
                          </div>
                        </div>
                        <div className="app-table-with-pagination">
                        <div className="app-table-scroll">
                          <table className="app-table app-table--compact table-user-certs">
                            <thead>
                              <tr>
                                <th>Сервер</th>
                                <th>Subject CN</th>
                                <th>Серийный номер</th>
                                <th>Статус</th>
                                <th>Действителен до</th>
                                <th>Корневой сертификат</th>
                                <th>Конфигурация</th>
                                <th className="app-table-col-actions">Действия</th>
                              </tr>
                            </thead>
                            <tbody>
                              {selectedUserCertificates.length === 0 ? (
                                <tr>
                                  <td colSpan={8} className="muted">
                                    Нет привязанных сертификатов.
                                  </td>
                                </tr>
                              ) : (
                                userCertsTablePage.slice.map((cert) => {
                                  const statusRow = userCertRowStatusPresentation(cert);
                                  const showConfigDl = userCertCanShowConfigDownload(cert);
                                  const certRootId = String(cert.rootCaId || cert.rootCa?.id || "").trim();
                                  const fallbackServers = certRootId
                                    ? userCertModalServers.filter((s) => String(s.panelRootCaId || "").trim() === certRootId)
                                    : [];
                                  const fallbackServer = fallbackServers.length === 1 ? fallbackServers[0] : null;
                                  const resolvedServerId = cert.agentNodeId || fallbackServer?.id || "";
                                  const resolvedServerName = cert.agentNode?.name || fallbackServer?.name || "";
                                  return (
                                  <tr key={cert.id}>
                                    <td>
                                      {resolvedServerId ? (
                                        <button
                                          type="button"
                                          className="app-link-btn"
                                          style={{ color: "#111827", fontWeight: 700, textDecoration: "underline" }}
                                          onClick={() => navigate(paths.serverDetail(resolvedServerId, "overview"))}
                                        >
                                          {resolvedServerName || "Открыть сервер"}
                                        </button>
                                      ) : (
                                        "—"
                                      )}
                                    </td>
                                    <td className="app-table-mono">{cert.commonName}</td>
                                    <td>
                                      {cert.agentNodeId ? (
                                        <button
                                          type="button"
                                          className="app-link-btn"
                                          style={{ color: "#111827", fontWeight: 700, textDecoration: "underline" }}
                                          onClick={() => navigate(paths.serverCaCenterCert(cert.agentNodeId, cert.id))}
                                        >
                                          {cert.serialNumber || "—"}
                                        </button>
                                      ) : (
                                        cert.serialNumber || "—"
                                      )}
                                    </td>
                                    <td>
                                      <span className={statusRow.statusClass}>{statusRow.text}</span>
                                    </td>
                                    <td>{formatMaybeDate(cert.expiresAt)}</td>
                                    <td>{cert.rootCa?.name || cert.issuedBy || "—"}</td>
                                    <td className="app-table-nowrap">
                                      {showConfigDl ? (
                                        <button
                                          type="button"
                                          className="app-link-btn"
                                          disabled={userConnectionProfileBusy}
                                          onClick={() => void downloadUserCertConfig(cert.id, cert.agentNodeId)}
                                        >
                                          Скачать
                                        </button>
                                      ) : (
                                        <span className="muted">—</span>
                                      )}
                                    </td>
                                    <td>
                                      {!cert.revokedAt ? (
                                        <div className="row-inline" style={{ gap: 8, flexWrap: "wrap" }}>
                                          <button
                                            type="button"
                                            className="app-link-btn app-link-btn--danger"
                                            onClick={() =>
                                              setUserCertRevokeModal({
                                                open: true,
                                                certId: cert.id,
                                                commonName: cert.commonName || "",
                                                busy: false,
                                                error: "",
                                              })
                                            }
                                          >
                                            Отозвать
                                          </button>
                                          <button
                                            type="button"
                                            className="app-link-btn app-link-btn--danger"
                                            onClick={() =>
                                              setUserCertUnlinkModal({
                                                open: true,
                                                certId: cert.id,
                                                commonName: cert.commonName || "",
                                                busy: false,
                                                error: "",
                                              })
                                            }
                                          >
                                            Отвязать
                                          </button>
                                        </div>
                                      ) : null}
                                    </td>
                                  </tr>
                                  );
                                })
                              )}
                            </tbody>
                          </table>
                        </div>
                        {selectedUserCertificates.length > 0 ? (
                          <TablePagination
                            page={userCertsTablePage.page}
                            totalPages={userCertsTablePage.totalPages}
                            total={userCertsTablePage.total}
                            onPageChange={(p) => setTablePages((prev) => ({ ...prev, userCerts: p }))}
                          />
                        ) : null}
                        </div>
                      </>
                    )}

                    {userProfileTab === "sessions" && (
                      <>
                        <h2 className="server-detail-section-title">Сессии</h2>
                        <div className="app-table-with-pagination">
                          <div className="app-table-scroll">
                            <table className="app-table app-table--compact app-table--fixed-cols table-user-sessions">
                              <thead>
                                <tr>
                                  <th>Узел</th>
                                  <th>CN</th>
                                  <th>Идентификатор</th>
                                  <th>Внешний IP адрес</th>
                                  <th>Внутренний IP адрес</th>
                                  <th>Продолжительность сессии</th>
                                  <th>Трафик in / out</th>
                                  <th className="app-table-col-actions">Действия</th>
                                </tr>
                              </thead>
                              <tbody>
                                {userProfileSessions.length === 0 ? (
                                  <tr>
                                    <td colSpan={8} className="muted">
                                      Нет записей о сессиях для сертификатов этого пользователя.
                                    </td>
                                  </tr>
                                ) : (
                                  userConnectionsTablePage.slice.map((row) => {
                                    const sid = openvpnSessionIdParts(row.sessionId);
                                    const cnCell = String(row.commonName || "").trim() || sid.commonName;
                                    const endedStyle = !row.isActive ? { color: "#64748b" } : undefined;
                                    return (
                                      <tr key={`${row.nodeId}-${row.sessionId}`} style={endedStyle}>
                                        <td className="app-table-td-clip-none" style={endedStyle}>{row.nodeName || row.nodeId}</td>
                                        <td className="app-table-mono" style={endedStyle}>{cnCell}</td>
                                        <td className="app-table-mono" style={endedStyle}>{sid.sessionNumber}</td>
                                        <td className="app-table-mono" style={endedStyle}>
                                          {remoteAddrHostOnlyDisplay(row.remoteIp) || "—"}
                                        </td>
                                        <td className="app-table-mono" style={endedStyle}>{row.virtualIp || "—"}</td>
                                        <td
                                          className="app-table-nowrap"
                                          style={endedStyle}
                                          title={
                                            row.isActive
                                              ? formatSessionConnectedTitle(row.connectedAt)
                                              : formatUserSessionEndedTitle(row)
                                          }
                                        >
                                          {row.isActive
                                            ? formatSessionConnectedLabel(row.connectedAt, sessionNow)
                                            : formatUserSessionEndedLabel(row)}
                                        </td>
                                        <td className="app-table-nowrap" style={endedStyle}>
                                          {row.isActive ? (
                                            <>
                                              {formatBps(row.inBps)} / {formatBps(row.outBps)}
                                            </>
                                          ) : (
                                            <span
                                              title="Последнее известное значение скорости по синку"
                                              style={endedStyle}
                                            >
                                              {formatBps(row.inBps)} / {formatBps(row.outBps)}
                                            </span>
                                          )}
                                        </td>
                                        <td className="app-table-td-clip-none">
                                          {row.isActive ? (
                                            disconnectingSessionKeys.includes(`${row.nodeId}-${row.sessionId}`) ? (
                                              <span className="muted" style={{ ...endedStyle, fontSize: "12px" }}>Завершается...</span>
                                            ) : (
                                              <button
                                                type="button"
                                                className="app-link-btn app-link-btn--danger"
                                                onClick={() =>
                                                  openUserSessionDisconnect(
                                                    row.nodeId,
                                                    row.nodeName,
                                                    row.sessionId,
                                                    selectedUser?.fullName || "",
                                                  )
                                                }
                                              >
                                                Завершить
                                              </button>
                                            )
                                          ) : (
                                            <span className="muted">—</span>
                                          )}
                                        </td>
                                      </tr>
                                    );
                                  })
                                )}
                              </tbody>
                            </table>
                          </div>
                          {userProfileSessions.length > 0 ? (
                            <TablePagination
                              page={userConnectionsTablePage.page}
                              totalPages={userConnectionsTablePage.totalPages}
                              total={userConnectionsTablePage.total}
                              onPageChange={(p) => setTablePages((prev) => ({ ...prev, userConnections: p }))}
                            />
                          ) : null}
                        </div>
                      </>
                    )}

                    {(userProfileTab === "vpn" || userProfileTab === "ccd" || userProfileTab === "firewall") && (
                      <div className="user-profile-blocks user-profile-blocks--full">
                        {userProfileTab === "firewall" ? (
                          <h2 className="server-detail-section-title">Межсетевой экран</h2>
                        ) : (
                          <h2 className="server-detail-section-title">Настройки OpenVPN</h2>
                        )}
                        <div className="server-settings-layout server-settings-layout--stack server-settings-layout--stack-full">
                          {userProfileTab === "firewall" ? (
                            <div className="server-settings-main">
                              <div className="server-version-select-row">
                                <select
                                  value={userFirewallMode}
                                  onChange={(e) => setUserFirewallMode(e.target.value === "replace" ? "replace" : "merge")}
                                >
                                  <option value="merge">Дополнять общие правила туннеля</option>
                                  <option value="replace">Заменить для этого пользователя (только персональные правила)</option>
                                </select>
                                <button type="button" className="btn-secondary" onClick={() => openFirewallRuleModal("user", null, "tunnel", "filter")}>
                                  + Правило
                                </button>
                                <button type="button" className="btn-secondary" onClick={() => openFirewallRuleModal("user", null, "tunnel", "nat")}>
                                  + NAT
                                </button>
                              </div>
                              <div className="app-table-scroll" style={{ marginTop: 8 }}>
                                <table className="app-table app-table--compact table-user-firewall">
                                  <thead>
                                    <tr>
                                      <th>Action</th>
                                      <th>Proto</th>
                                      <th>Destination</th>
                                      <th>Ports</th>
                                      <th>Описание</th>
                                      <th className="app-table-col-actions">Действия</th>
                                    </tr>
                                  </thead>
                                  <tbody>
                                    {userFirewallOverrideRules.length === 0 ? (
                                      <tr>
                                        <td colSpan={6} className="muted">
                                          Нет правил.
                                        </td>
                                      </tr>
                                    ) : (
                                      userFirewallOverrideRules.map((rule) => (
                                        <tr
                                          key={rule.id}
                                          className={rowReorderClass("user-filter", rule.id, tableDrag)}
                                          draggable={!userFirewallBusy}
                                          onDragStart={(e) => {
                                            beginTableRowDragPreview(e.currentTarget, e, rule.id);
                                            setTableDrag({ scope: "user-filter", dragId: rule.id, overId: "", placeAfter: false });
                                          }}
                                          onDragOver={(e) => tableRowDragOverHandler(e, "user-filter", rule.id, setTableDrag)}
                                          onDragEnd={() => {
                                            endTableRowDragPreview();
                                            setTableDrag(emptyTableDrag());
                                          }}
                                          onDrop={(e) => {
                                            e.preventDefault();
                                            setTableDrag((td) => {
                                              if (td.scope !== "user-filter" || !td.dragId) return emptyTableDrag();
                                              setUserFirewallOverrideRules((prev) => reorderRowInList(prev, td.dragId, rule.id, td.placeAfter));
                                              return emptyTableDrag();
                                            });
                                          }}
                                        >
                                          <td><span className={rule.action === "deny" ? "app-status app-status--bad" : "app-status app-status--ok"}>{rule.action}</span></td>
                                          <td className="app-table-mono">{rule.proto}</td>
                                          <td className="app-table-mono">{rule.destination || "—"}</td>
                                          <td className="app-table-mono">{rule.ports || "*"}</td>
                                          <td>{rule.note || "—"}</td>
                                          <td className="app-table-td-clip-none">
                                            <button type="button" className="app-link-btn" onClick={() => openFirewallRuleModal("user", rule)}>Изменить</button>{" "}
                                            <button
                                              type="button"
                                              className="app-link-btn app-link-btn--danger"
                                              onClick={() =>
                                                setUserFirewallOverrideRules((prev) => prev.filter((x) => x.id !== rule.id))
                                              }
                                            >
                                              Удалить
                                            </button>
                                          </td>
                                        </tr>
                                      ))
                                    )}
                                  </tbody>
                                </table>
                              </div>
                              <div className="app-table-scroll" style={{ marginTop: 8 }}>
                                <table className="app-table app-table--compact table-user-firewall">
                                  <thead>
                                    <tr>
                                      <th>Type</th>
                                      <th>Hook</th>
                                      <th>Src</th>
                                      <th>Dst</th>
                                      <th>Out iface</th>
                                      <th>To address</th>
                                      <th>Описание</th>
                                      <th className="app-table-col-actions">Действия</th>
                                    </tr>
                                  </thead>
                                  <tbody>
                                    {userFirewallOverrideNatRules.length === 0 ? (
                                      <tr>
                                        <td colSpan={8} className="muted">
                                          Нет NAT-правил.
                                        </td>
                                      </tr>
                                    ) : (
                                      userFirewallOverrideNatRules.map((rule) => (
                                        <tr
                                          key={rule.id}
                                          className={rowReorderClass("user-nat", rule.id, tableDrag)}
                                          draggable={!userFirewallBusy}
                                          onDragStart={(e) => {
                                            beginTableRowDragPreview(e.currentTarget, e, rule.id);
                                            setTableDrag({ scope: "user-nat", dragId: rule.id, overId: "", placeAfter: false });
                                          }}
                                          onDragOver={(e) => tableRowDragOverHandler(e, "user-nat", rule.id, setTableDrag)}
                                          onDragEnd={() => {
                                            endTableRowDragPreview();
                                            setTableDrag(emptyTableDrag());
                                          }}
                                          onDrop={(e) => {
                                            e.preventDefault();
                                            setTableDrag((td) => {
                                              if (td.scope !== "user-nat" || !td.dragId) return emptyTableDrag();
                                              setUserFirewallOverrideNatRules((prev) => reorderRowInList(prev, td.dragId, rule.id, td.placeAfter));
                                              return emptyTableDrag();
                                            });
                                          }}
                                        >
                                          <td className="app-table-mono">{rule.type}</td>
                                          <td className="app-table-mono">
                                            {rule.type === "dnat" ? "PREROUTING" : "POSTROUTING"}
                                          </td>
                                          <td className="app-table-mono">{rule.src || "—"}</td>
                                          <td className="app-table-mono">{rule.dst || "—"}</td>
                                          <td className="app-table-mono">{rule.outInterface || "—"}</td>
                                          <td className="app-table-mono">{rule.toAddress || "—"}</td>
                                          <td>{rule.note || "—"}</td>
                                          <td className="app-table-td-clip-none">
                                            <button
                                              type="button"
                                              className="app-link-btn"
                                              onClick={() => openFirewallRuleModal("user", rule, "tunnel", "nat")}
                                            >
                                              Изменить
                                            </button>{" "}
                                            <button
                                              type="button"
                                              className="app-link-btn app-link-btn--danger"
                                              onClick={() =>
                                                setUserFirewallOverrideNatRules((prev) => prev.filter((x) => x.id !== rule.id))
                                              }
                                            >
                                              Удалить
                                            </button>
                                          </td>
                                        </tr>
                                      ))
                                    )}
                                  </tbody>
                                </table>
                              </div>
                              <div className="row-inline" style={{ gap: 8, marginTop: 12, flexWrap: "wrap" }}>
                                <button type="button" disabled={userFirewallBusy} onClick={() => void applyUserFirewall()}>
                                  {userFirewallBusy ? "Применение..." : "Применить"}
                                </button>
                                <button type="button" className="btn-secondary" onClick={openUserEffectivePolicyModal}>
                                  Effective Policy
                                </button>
                              </div>
                            </div>
                          ) : (
                          <div className="user-profile-blocks--stack">
                            <div className="user-profile-field-block">
                              <div className="user-profile-field-label">ifconfig-push: локальный IP</div>
                              <input
                                value={userCcdDraft.ifconfigPushLocal}
                                onChange={(e) =>
                                  setUserCcdDraft((prev) => ({ ...prev, ifconfigPushLocal: e.target.value }))
                                }
                                placeholder="10.220.0.10"
                              />
                            </div>
                            <div className="user-profile-field-block">
                              <div className="user-profile-field-label">ifconfig-push: remote/netmask</div>
                              <input
                                value={userCcdDraft.ifconfigPushRemote}
                                onChange={(e) =>
                                  setUserCcdDraft((prev) => ({ ...prev, ifconfigPushRemote: e.target.value }))
                                }
                                placeholder="255.255.252.0"
                              />
                              <p className="user-profile-field-hint">
                                Для `ifconfig-push` укажите оба значения, иначе директива не попадет в итоговый ccd.
                              </p>
                            </div>
                            <div className="user-profile-field-block">
                              <div className="user-profile-field-label">Push routes (по одной на строку)</div>
                              <textarea
                                rows={4}
                                value={userCcdDraft.pushRoutes}
                                onChange={(e) => setUserCcdDraft((prev) => ({ ...prev, pushRoutes: e.target.value }))}
                                placeholder={"10.10.0.0 255.255.0.0\n172.16.5.0 255.255.255.0"}
                              />
                            </div>
                            <div className="user-profile-field-block">
                              <div className="user-profile-field-label">Iroute (по одной на строку)</div>
                              <textarea
                                rows={3}
                                value={userCcdDraft.iroutes}
                                onChange={(e) => setUserCcdDraft((prev) => ({ ...prev, iroutes: e.target.value }))}
                                placeholder={"10.50.0.0 255.255.0.0"}
                              />
                            </div>
                            <div className="user-profile-field-block">
                              <div className="user-profile-field-label">DNS серверы (по одной на строку)</div>
                              <textarea
                                rows={3}
                                value={userCcdDraft.dnsServers}
                                onChange={(e) => setUserCcdDraft((prev) => ({ ...prev, dnsServers: e.target.value }))}
                                placeholder={"1.1.1.1\n8.8.8.8"}
                              />
                            </div>
                            <div className="user-profile-field-block">
                              <div className="user-profile-field-label">Дополнительные директивы</div>
                              <textarea
                                rows={4}
                                value={userCcdDraft.customDirectives}
                                onChange={(e) =>
                                  setUserCcdDraft((prev) => ({ ...prev, customDirectives: e.target.value }))
                                }
                                placeholder={"push \"redirect-gateway def1\"\nkeepalive 10 120"}
                              />
                            </div>
                            <div className="row-inline" style={{ gap: 8, flexWrap: "wrap" }}>
                              <button type="button" disabled={userCcdBusy} onClick={() => void applyUserCcd()}>
                                {userCcdBusy ? "Сохранение..." : "Сохранить"}
                              </button>
                            </div>
                            {userCcdResult ? <p className="user-profile-field-hint">{userCcdResult}</p> : null}
                          </div>
                          )}
                        </div>
                      </div>
                    )}

                    {userFirewallEffectiveModal.open ? (
                      <div
                        className="modal-backdrop"
                        role="presentation"
                        onClick={(e) => {
                          if (e.target === e.currentTarget) setUserFirewallEffectiveModal({ open: false, title: "", content: "" });
                        }}
                      >
                        <div className="modal-dialog modal-dialog--wide" role="dialog" aria-modal="true">
                          <div className="modal-dialog-header">
                            <h2 className="modal-dialog-title">{userFirewallEffectiveModal.title}</h2>
                            <button type="button" className="modal-close" aria-label="Закрыть" onClick={() => setUserFirewallEffectiveModal({ open: false, title: "", content: "" })}>
                              ×
                            </button>
                          </div>
                          <pre className="server-settings-raw-pre" style={{ maxHeight: "60vh", overflow: "auto" }}>
                            {userFirewallEffectiveModal.content}
                          </pre>
                        </div>
                      </div>
                    ) : null}

                  </div>

                  {false && serviceActionModal.open ? (
                    <div
                      className="modal-backdrop"
                      role="presentation"
                      onClick={(e) => {
                        if (e.target === e.currentTarget && !serviceActionModal.busy) {
                          setServiceActionModal({ open: false, action: "", busy: false, error: "" });
                        }
                      }}
                    >
                      <div className="modal-dialog" role="dialog" aria-modal="true" aria-labelledby="service-action-modal-title">
                        <div className="modal-dialog-header">
                          <h2 id="service-action-modal-title" className="modal-dialog-title">
                            Подтверждение действия
                          </h2>
                          <button
                            type="button"
                            className="modal-close"
                            aria-label="Закрыть"
                            disabled={serviceActionModal.busy}
                            onClick={() => setServiceActionModal({ open: false, action: "", busy: false, error: "" })}
                          >
                            ×
                          </button>
                        </div>
                        <p>
                          Вы уверены, что хотите выполнить команду{" "}
                          <strong>{String(serviceActionModal.action || "").toUpperCase()}</strong> для службы OpenVPN?
                        </p>
                        {serviceActionModal.error ? (
                          <div className="auth-alert auth-alert--error" role="alert">
                            {serviceActionModal.error}
                          </div>
                        ) : null}
                        <div className="row-inline" style={{ justifyContent: "flex-end", gap: 8 }}>
                          <button
                            type="button"
                            className="btn-secondary"
                            disabled={serviceActionModal.busy}
                            onClick={() => setServiceActionModal({ open: false, action: "", busy: false, error: "" })}
                          >
                            Отмена
                          </button>
                          <button type="button" disabled={serviceActionModal.busy} onClick={submitServiceAction}>
                            {serviceActionModal.busy ? "Выполняется…" : "Подтвердить"}
                          </button>
                        </div>
                      </div>
                    </div>
                  ) : null}

                  {userCertRevokeModal.open ? (
                    <div
                      className="modal-backdrop"
                      role="presentation"
                      onClick={(e) => {
                        if (e.target === e.currentTarget && !userCertRevokeModal.busy) {
                          setUserCertRevokeModal({ open: false, certId: null, commonName: "", busy: false, error: "" });
                        }
                      }}
                    >
                      <div
                        className="modal-dialog"
                        role="dialog"
                        aria-modal="true"
                        aria-labelledby="user-cert-revoke-modal-title"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <div className="modal-dialog-header">
                          <h2 id="user-cert-revoke-modal-title" className="modal-dialog-title">
                            Отзыв сертификата
                          </h2>
                          <button
                            type="button"
                            className="modal-close"
                            aria-label="Закрыть"
                            disabled={userCertRevokeModal.busy}
                            onClick={() =>
                              setUserCertRevokeModal({ open: false, certId: null, commonName: "", busy: false, error: "" })
                            }
                          >
                            ×
                          </button>
                        </div>
                        <p className="user-cert-modal-intro">
                          Отозвать сертификат{" "}
                          <span className="user-cert-modal-cn">{userCertRevokeModal.commonName || "—"}</span>? После отзыва
                          подключение по нему будет невозможно.
                        </p>
                        {userCertRevokeModal.error ? (
                          <div className="auth-alert auth-alert--error" role="alert">
                            {userCertRevokeModal.error}
                          </div>
                        ) : null}
                        <div className="row-inline" style={{ justifyContent: "flex-end", gap: 8, marginTop: 16 }}>
                          <button
                            type="button"
                            className="btn-secondary"
                            disabled={userCertRevokeModal.busy}
                            onClick={() =>
                              setUserCertRevokeModal({ open: false, certId: null, commonName: "", busy: false, error: "" })
                            }
                          >
                            Отмена
                          </button>
                          <button
                            type="button"
                            className="btn-danger"
                            disabled={userCertRevokeModal.busy}
                            onClick={confirmUserCertRevoke}
                          >
                            {userCertRevokeModal.busy ? "Отзыв…" : "Отозвать"}
                          </button>
                        </div>
                      </div>
                    </div>
                  ) : null}

                  {userCertUnlinkModal.open && selectedUser ? (
                    <div
                      className="modal-backdrop"
                      role="presentation"
                      onClick={(e) => {
                        if (e.target === e.currentTarget && !userCertUnlinkModal.busy) {
                          setUserCertUnlinkModal({ open: false, certId: null, commonName: "", busy: false, error: "" });
                        }
                      }}
                    >
                      <div
                        className="modal-dialog"
                        role="dialog"
                        aria-modal="true"
                        aria-labelledby="user-cert-unlink-modal-title"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <div className="modal-dialog-header">
                          <h2 id="user-cert-unlink-modal-title" className="modal-dialog-title">
                            Отвязать сертификат
                          </h2>
                          <button
                            type="button"
                            className="modal-close"
                            aria-label="Закрыть"
                            disabled={userCertUnlinkModal.busy}
                            onClick={() =>
                              setUserCertUnlinkModal({ open: false, certId: null, commonName: "", busy: false, error: "" })
                            }
                          >
                            ×
                          </button>
                        </div>
                        <p className="user-cert-modal-intro">
                          Отвязать сертификат{" "}
                          <span className="user-cert-modal-cn">{userCertUnlinkModal.commonName || "—"}</span> от этого профиля?
                          Запись сертификата в системе сохранится, но связь с пользователем будет снята.
                        </p>
                        {userCertUnlinkModal.error ? (
                          <div className="auth-alert auth-alert--error" role="alert">
                            {userCertUnlinkModal.error}
                          </div>
                        ) : null}
                        <div className="row-inline" style={{ justifyContent: "flex-end", gap: 8, marginTop: 16 }}>
                          <button
                            type="button"
                            className="btn-secondary"
                            disabled={userCertUnlinkModal.busy}
                            onClick={() =>
                              setUserCertUnlinkModal({ open: false, certId: null, commonName: "", busy: false, error: "" })
                            }
                          >
                            Отмена
                          </button>
                          <button
                            type="button"
                            className="btn-danger"
                            disabled={userCertUnlinkModal.busy}
                            onClick={confirmUserCertUnlink}
                          >
                            {userCertUnlinkModal.busy ? "Отвязка…" : "Отвязать"}
                          </button>
                        </div>
                      </div>
                    </div>
                  ) : null}

                  {userCertBindModalOpen && selectedUser ? (
                    <div
                      className="modal-backdrop"
                      role="presentation"
                      onClick={(e) => {
                        if (e.target === e.currentTarget && !userCertBindBusy) {
                          setUserCertBindModalOpen(false);
                          setUserCertBindSelectedCertId("");
                        }
                      }}
                    >
                      <div
                        className="modal-dialog"
                        role="dialog"
                        aria-modal="true"
                        aria-labelledby="user-cert-bind-modal-title"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <div className="modal-dialog-header">
                          <h2 id="user-cert-bind-modal-title" className="modal-dialog-title">
                            Привязать сертификат
                          </h2>
                          <button
                            type="button"
                            className="modal-close"
                            aria-label="Закрыть"
                            disabled={userCertBindBusy}
                            onClick={() => {
                              setUserCertBindModalOpen(false);
                              setUserCertBindSelectedCertId("");
                            }}
                          >
                            ×
                          </button>
                        </div>
                        <p className="modal-dialog-body-text" style={{ marginTop: 0 }}>
                          Выберите сервер и сертификат без привязки к пользователю (с тем же корневым сертификатом, что у
                          сервера), затем нажмите «Привязать».
                        </p>
                        <h3 className="modal-section-title">Сервер</h3>
                        <div className="row-inline modal-field-block">
                          <select
                            value={userCertBindServerId}
                            onChange={(e) => {
                              setUserCertBindServerId(e.target.value);
                              setUserCertBindSelectedCertId("");
                            }}
                            disabled={userCertModalServers.length === 0 || userCertBindBusy}
                          >
                            <option value="">
                              {userCertModalServers.length === 0 ? "Нет доступных серверов" : "Выберите сервер…"}
                            </option>
                            {userCertModalServers.map((s) => (
                              <option key={s.id} value={s.id}>
                                {`${s.name} · ${s.host}:${s.openvpnPort} ${s.openvpnProto}`}
                              </option>
                            ))}
                          </select>
                        </div>
                        {userModalBindableCertificates.length > 0 ? (
                          <>
                            <h3 className="modal-section-title">Сертификат</h3>
                            <div className="row-inline modal-field-block">
                              <select
                                value={userCertBindSelectedCertId}
                                onChange={(e) => setUserCertBindSelectedCertId(e.target.value)}
                                disabled={!userCertBindServerId || userCertBindBusy}
                              >
                                <option value="">Выберите сертификат…</option>
                                {userModalBindableCertificates.map((c) => (
                                  <option key={c.id} value={c.id}>
                                    {c.commonName} · {String(c.serialNumber).slice(0, 14)}… ·{" "}
                                    {formatMaybeDate(c.expiresAt)}
                                  </option>
                                ))}
                              </select>
                            </div>
                          </>
                        ) : null}
                        <div className="row-inline" style={{ justifyContent: "flex-end", gap: 8, marginTop: 16 }}>
                          <button
                            type="button"
                            className="btn-secondary"
                            disabled={userCertBindBusy}
                            onClick={() => {
                              setUserCertBindModalOpen(false);
                              setUserCertBindSelectedCertId("");
                            }}
                          >
                            Отмена
                          </button>
                          <button
                            type="button"
                            disabled={
                              userCertBindBusy ||
                              !userCertBindSelectedCertId ||
                              !userCertBindServerId ||
                              userModalBindableCertificates.length === 0
                            }
                            onClick={() => void confirmUserCertBind()}
                          >
                            {userCertBindBusy ? "Привязка…" : "Привязать"}
                          </button>
                        </div>
                      </div>
                    </div>
                  ) : null}
                  {userCertIssueModalOpen && selectedUser ? (
                    <div
                      className="modal-backdrop"
                      role="presentation"
                      onClick={(e) => {
                        if (e.target === e.currentTarget) setUserCertIssueModalOpen(false);
                      }}
                    >
                      <div
                        className="modal-dialog"
                        role="dialog"
                        aria-modal="true"
                        aria-labelledby="user-cert-issue-modal-title"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <div className="modal-dialog-header">
                          <h2 id="user-cert-issue-modal-title" className="modal-dialog-title">
                            Выпустить новый сертификат
                          </h2>
                          <button
                            type="button"
                            className="modal-close"
                            aria-label="Закрыть"
                            onClick={() => setUserCertIssueModalOpen(false)}
                          >
                            ×
                          </button>
                        </div>
                        <p className="modal-dialog-body-text" style={{ marginTop: 0 }}>
                          Клиентский сертификат будет подписан корневым сертификатом, выбранным для этого сервера в
                          панели (вкладка «Сертификаты» в карточке узла), и сразу привязан к пользователю и узлу.
                        </p>
                        <h3 className="modal-section-title">Сервер</h3>
                        <div className="row-inline modal-field-block">
                          <select
                            value={userCertBindServerId}
                            onChange={(e) => setUserCertBindServerId(e.target.value)}
                            disabled={userCertModalServers.length === 0}
                          >
                            <option value="">
                              {userCertModalServers.length === 0 ? "Нет доступных серверов" : "Выберите сервер…"}
                            </option>
                            {userCertModalServers.map((s) => (
                              <option key={s.id} value={s.id}>
                                {`${s.name} · ${s.host}:${s.openvpnPort} ${s.openvpnProto}`}
                              </option>
                            ))}
                          </select>
                        </div>
                        <form onSubmit={issueProfileCertificate}>
                          <h3 className="modal-section-title">Параметры сертификата</h3>
                          <div className="user-profile-field-block" style={{ marginTop: 8 }}>
                            <div className="user-profile-field-label">Subject CN</div>
                            <input
                              required
                              value={profileIssueCert.commonName}
                              onChange={(e) =>
                                setProfileIssueCert((prev) => ({ ...prev, commonName: e.target.value }))
                              }
                              style={{ width: "100%", maxWidth: "100%", minWidth: 0 }}
                            />
                          </div>
                          <div className="user-profile-field-block" style={{ marginTop: 12 }}>
                            <div className="user-profile-field-label">Срок действия, суток</div>
                            <input
                              type="number"
                              min={1}
                              value={profileIssueCert.validityDays}
                              onChange={(e) =>
                                setProfileIssueCert((prev) => ({ ...prev, validityDays: e.target.value }))
                              }
                              style={{ width: "100%", maxWidth: 280, minWidth: 0 }}
                            />
                          </div>
                          <div className="row-inline" style={{ justifyContent: "flex-end", gap: 8, marginTop: 16 }}>
                            <button
                              type="button"
                              className="btn-secondary"
                              onClick={() => setUserCertIssueModalOpen(false)}
                            >
                              Отмена
                            </button>
                            <button type="submit">Выпустить</button>
                          </div>
                        </form>
                      </div>
                    </div>
                  ) : null}
                </>
              )}
            </div>
          )}

          {primaryNav === "servers" && serversView === "add" && (
            <section className="card card--flush-form">
              <div className="user-profile-blocks user-profile-blocks--stack">
                <form className="user-profile-blocks--stack" onSubmit={createNode}>
                  <div className="user-profile-field-block">
                    <div className="user-profile-field-label">
                      Имя узла <span className="error">*</span>
                    </div>
                    <input
                      required
                      value={newNode.name}
                      onChange={(e) => setNewNode((prev) => ({ ...prev, name: e.target.value }))}
                    />
                  </div>
                  <div className="user-profile-field-block">
                    <div className="user-profile-field-label">Протокол</div>
                    <select
                      value={newNode.protocol}
                      onChange={(e) => setNewNode((prev) => ({ ...prev, protocol: e.target.value }))}
                    >
                      <option value="http">http</option>
                      <option value="https">https</option>
                    </select>
                    <p className="user-profile-field-hint">Протокол доступа к API агента.</p>
                  </div>
                  <div className="user-profile-field-block">
                    <div className="user-profile-field-label">
                      Хост <span className="error">*</span>
                    </div>
                    <input
                      required
                      value={newNode.host}
                      onChange={(e) => setNewNode((prev) => ({ ...prev, host: e.target.value }))}
                    />
                    <p className="user-profile-field-hint">Имя хоста или IP-адрес узла с агентом.</p>
                  </div>
                  <div className="user-profile-field-block">
                    <div className="user-profile-field-label">
                      Порт <span className="error">*</span>
                    </div>
                    <input
                      required
                      type="number"
                      min={1}
                      max={65535}
                      value={newNode.port}
                      onChange={(e) => setNewNode((prev) => ({ ...prev, port: e.target.value }))}
                    />
                    <p className="user-profile-field-hint">Порт прослушивания агента.</p>
                  </div>
                  <div className="user-profile-field-block">
                    <div className="user-profile-field-label">
                      Токен агента <span className="error">*</span>
                    </div>
                    <input
                      required
                      type="password"
                      autoComplete="new-password"
                      value={newNode.authToken}
                      onChange={(e) => setNewNode((prev) => ({ ...prev, authToken: e.target.value }))}
                    />
                    <p className="user-profile-field-hint">Секрет, которым панель авторизуется на агенте.</p>
                  </div>
                  <div className="user-profile-field-block">
                    <button type="submit">Добавить агента</button>
                  </div>
                </form>
              </div>
            </section>
          )}

          {primaryNav === "tasks" && (
            <section className="card card--flush-table">
              <div className="app-table-scroll">
                <table className="app-table app-table--compact app-table--tasks">
                  <thead>
                    <tr>
                      <th>Создана</th>
                      <th>Тип</th>
                      <th>Статус</th>
                      <th>Узел</th>
                      <th>Payload</th>
                      <th>Ошибка</th>
                      <th>Завершена</th>
                      <th className="app-table-col-actions">Действия</th>
                    </tr>
                  </thead>
                  <tbody>
                    {tasksTablePage.total === 0 ? (
                      <tr>
                        <td colSpan={8} className="muted">
                          Нет задач
                        </td>
                      </tr>
                    ) : (
                      tasksTablePage.slice.map((t) => {
                        const st = String(t.status || "").toLowerCase();
                        const retryLocked = st === "processing" || st === "pending";
                        return (
                          <tr key={t.id}>
                            <td className="app-table-nowrap">{formatMaybeDate(t.createdAt)}</td>
                            <td className="app-table-mono app-table-cell-tight">{t.type}</td>
                            <td>
                              {(() => {
                                const s = formatTaskStatus(t.status);
                                return <span className={s.cls}>{s.label}</span>;
                              })()}
                            </td>
                            <td className="app-table-cell-tight">{t.agentNode?.name ?? "—"}</td>
                            <td
                              className="app-table-mono app-table-cell-tight"
                              style={{ maxWidth: 160, overflow: "hidden", textOverflow: "ellipsis" }}
                              title={
                                typeof t.payload === "object" && t.payload !== null
                                  ? JSON.stringify(t.payload)
                                  : String(t.payload ?? "")
                              }
                            >
                              {typeof t.payload === "object" && t.payload !== null
                                ? JSON.stringify(t.payload)
                                : String(t.payload ?? "")}
                            </td>
                            <td
                              className="app-table-mono app-table-cell-tight"
                              style={{ maxWidth: 140, overflow: "hidden", textOverflow: "ellipsis" }}
                              title={t.lastError || ""}
                            >
                              {t.lastError || "—"}
                            </td>
                            <td className="app-table-nowrap">{formatMaybeDate(t.completedAt)}</td>
                            <td className="app-table-col-actions">
                              {retryLocked ? (
                                <span className="muted">—</span>
                              ) : (
                                <button
                                  type="button"
                                  className="app-link-btn"
                                  onClick={() =>
                                    setTaskRetryModal({
                                      open: true,
                                      taskId: t.id,
                                      taskType: String(t.type || ""),
                                      busy: false,
                                      error: "",
                                    })
                                  }
                                >
                                  Повторить
                                </button>
                              )}
                            </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>
              <TablePagination
                page={tasksTablePage.page}
                totalPages={tasksTablePage.totalPages}
                total={tasksTablePage.total}
                onPageChange={(p) => setTablePages((prev) => ({ ...prev, tasks: p }))}
              />
            </section>
          )}

          {primaryNav === "documentation" && <DocumentationPage section={docsSection} navigate={navigate} />}

          {primaryNav === "logs" && (
            <div className="resource-layout">
              <aside className="resource-sidebar" aria-label="Разделы журнала">
                <div className="resource-sidebar-header">
                  <h2 className="resource-sidebar-title">Журнал</h2>
                  <p className="resource-sidebar-sub">События и аудит</p>
                </div>
                <nav className="resource-nav" aria-label="Навигация по журналу">
                  <button
                    type="button"
                    className={`resource-nav-item${logsView === "vpn-ip" ? " is-active" : ""}`}
                    aria-current={logsView === "vpn-ip" ? "page" : undefined}
                    onClick={() => navigate(paths.logs("vpn-ip"))}
                  >
                    <IconLogs />
                    Назначение VPN-IP
                  </button>
                  <button
                    type="button"
                    className={`resource-nav-item${logsView === "source-ip" ? " is-active" : ""}`}
                    aria-current={logsView === "source-ip" ? "page" : undefined}
                    onClick={() => navigate(paths.logs("source-ip"))}
                  >
                    <IconNavOperations />
                    Исходные IP
                  </button>
                  <button
                    type="button"
                    className={`resource-nav-item${logsView === "admin" ? " is-active" : ""}`}
                    aria-current={logsView === "admin" ? "page" : undefined}
                    onClick={() => navigate(paths.logs("admin"))}
                  >
                    <IconSettings />
                    Действия администраторов
                  </button>
                </nav>
              </aside>
              <div className="resource-main">
                {logsView === "vpn-ip" ? (
                  <section className="card logs-journal-section">
                    <h2 className="server-detail-section-title">Назначение VPN-IP</h2>
                    <div className="app-table-filters" style={{ marginBottom: 12 }}>
                      <input
                        className="app-filter-input"
                        type="search"
                        value={logsVpnSearch}
                        onChange={(e) => setLogsVpnSearch(e.target.value)}
                        placeholder="Поиск: пользователь, CN, VPN IP, сервер, даты…"
                        aria-label="Поиск по назначению VPN-IP"
                      />
                    </div>
                    <div className="app-table-with-pagination">
                      <div className="app-table-scroll">
                        <table className="app-table app-table--compact">
                          <thead>
                            <tr>
                              <th>Пользователь</th>
                              <th>Сервер</th>
                              <th>CN</th>
                              <th>Внутренний IP адрес</th>
                              <th>Сессия</th>
                              <th>Длительность</th>
                            </tr>
                          </thead>
                          <tbody>
                            {logsVpnTablePage.slice.length === 0 ? (
                              <tr>
                                <td colSpan={6} className="muted">
                                  {logsVpnSearch.trim() ? "Нет записей по текущему запросу." : "Нет записей."}
                                </td>
                              </tr>
                            ) : (
                              logsVpnTablePage.slice.map((item) => (
                                <tr key={`log-vpn-${item.id}`}>
                                  <td className="app-table-td-clip-none">
                                    {item.vpnUserId ? (
                                      <button
                                        type="button"
                                        className="logs-user-profile-link"
                                        onClick={() => navigate(paths.userProfile(item.vpnUserId, "overview"))}
                                      >
                                        {item.vpnUserFullName || item.vpnUserEmail || "Профиль"}
                                      </button>
                                    ) : (
                                      <span className="muted">—</span>
                                    )}
                                  </td>
                                  <td>{item.agentNode?.name ?? "—"}</td>
                                  <td>{item.commonName}</td>
                                  <td className="app-table-mono">{item.virtualIp}</td>
                                  <td className="app-table-nowrap">{item.connectedAt}</td>
                                  <td
                                    className="app-table-nowrap"
                                    title={item.endedAt ? "" : "Сессия активна; длительность с первой фиксации на панели"}
                                  >
                                    {formatDurationSeconds(clientIpAssignmentDurationSeconds(item))}
                                  </td>
                                </tr>
                              ))
                            )}
                          </tbody>
                        </table>
                      </div>
                      <TablePagination
                        page={logsVpnTablePage.page}
                        totalPages={logsVpnTablePage.totalPages}
                        total={logsVpnTablePage.total}
                        onPageChange={(p) => setTablePages((prev) => ({ ...prev, logsVpn: p }))}
                      />
                    </div>
                  </section>
                ) : null}
                {logsView === "source-ip" ? (
                  <section className="card logs-journal-section">
                    <h2 className="server-detail-section-title">Исходные IP</h2>
                    <div className="app-table-filters" style={{ marginBottom: 12 }}>
                      <input
                        className="app-filter-input"
                        type="search"
                        value={logsSrcSearch}
                        onChange={(e) => setLogsSrcSearch(e.target.value)}
                        placeholder="Поиск: пользователь, CN, IP, сервер, длительность, даты…"
                        aria-label="Поиск по исходным IP"
                      />
                    </div>
                    <div className="app-table-with-pagination">
                      <div className="app-table-scroll">
                        <table className="app-table app-table--compact">
                          <thead>
                            <tr>
                              <th>Пользователь</th>
                              <th>Сервер</th>
                              <th>CN</th>
                              <th>Внешний IP адрес</th>
                              <th>Сессия</th>
                              <th>Длительность</th>
                            </tr>
                          </thead>
                          <tbody>
                            {logsSrcTablePage.slice.length === 0 ? (
                              <tr>
                                <td colSpan={6} className="muted">
                                  {logsSrcSearch.trim() ? "Нет записей по текущему запросу." : "Нет записей."}
                                </td>
                              </tr>
                            ) : (
                              logsSrcTablePage.slice.map((item) => (
                                <tr key={`log-src-${item.id}`}>
                                  <td className="app-table-td-clip-none">
                                    {item.vpnUserId ? (
                                      <button
                                        type="button"
                                        className="logs-user-profile-link"
                                        onClick={() => navigate(paths.userProfile(item.vpnUserId, "overview"))}
                                      >
                                        {item.vpnUserFullName || item.vpnUserEmail || "Профиль"}
                                      </button>
                                    ) : (
                                      <span className="muted">—</span>
                                    )}
                                  </td>
                                  <td>{item.agentNode?.name ?? "—"}</td>
                                  <td>{item.commonName}</td>
                                  <td className="app-table-mono">{remoteAddrHostOnlyDisplay(item.realIp)}</td>
                                  <td className="app-table-nowrap">{item.connectedAt || "—"}</td>
                                  <td
                                    className="app-table-nowrap"
                                    title={item.endedAt ? "" : "Сессия активна; длительность с первой фиксации на панели"}
                                  >
                                    {formatDurationSeconds(clientSourceHistoryDurationSeconds(item))}
                                  </td>
                                </tr>
                              ))
                            )}
                          </tbody>
                        </table>
                      </div>
                      <TablePagination
                        page={logsSrcTablePage.page}
                        totalPages={logsSrcTablePage.totalPages}
                        total={logsSrcTablePage.total}
                        onPageChange={(p) => setTablePages((prev) => ({ ...prev, logsSrc: p }))}
                      />
                    </div>
                  </section>
                ) : null}
                {logsView === "admin" ? (
                  <section className="card logs-journal-section">
                    <h2 className="server-detail-section-title">Действия администраторов</h2>
                    <div className="app-table-filters" style={{ marginBottom: 12 }}>
                      <input
                        className="app-filter-input"
                        type="search"
                        value={logsAdminSearch}
                        onChange={(e) => setLogsAdminSearch(e.target.value)}
                        placeholder="Поиск: администратор, действие, путь, IP, статус, дата…"
                        aria-label="Поиск по действиям администраторов"
                      />
                    </div>
                    <div className="app-table-with-pagination">
                      <div className="app-table-scroll">
                        <table className="app-table app-table--compact">
                          <thead>
                            <tr>
                              <th>Последний раз</th>
                              <th>Кто</th>
                              <th>Метод</th>
                              <th>Действие</th>
                              <th>URL</th>
                              <th>IP</th>
                              <th>Статус</th>
                            </tr>
                          </thead>
                          <tbody>
                            {logsAdminTablePage.slice.length === 0 ? (
                              <tr>
                                <td colSpan={7} className="muted">
                                  {logsAdminSearch.trim() ? "Нет записей по текущему запросу." : "Нет записей."}
                                </td>
                              </tr>
                            ) : (
                              logsAdminTablePage.slice.map((item) => (
                                <tr key={`log-admin-${item.id}`}>
                                  <td className="app-table-nowrap">{formatMaybeDate(item.createdAt)}</td>
                                  <td>{item.adminUsername || item.admin?.username || "—"}</td>
                                  <td className="app-table-td-clip-none">
                                    <span className={adminLogMethodClass(item.method)}>
                                      {String(item.method || "—").toUpperCase()}
                                    </span>
                                  </td>
                                  <td>{item.action || "—"}</td>
                                  <td className="app-table-mono">{item.path}</td>
                                  <td>{item.ipAddress || "—"}</td>
                                  <td className="app-table-td-clip-none">
                                    <span className={adminLogStatusClass(item.statusCode)}>{item.statusCode}</span>
                                  </td>
                                </tr>
                              ))
                            )}
                          </tbody>
                        </table>
                      </div>
                      <TablePagination
                        page={logsAdminTablePage.page}
                        totalPages={logsAdminTablePage.totalPages}
                        total={logsAdminTablePage.total}
                        onPageChange={(p) => setTablePages((prev) => ({ ...prev, logsAdmin: p }))}
                      />
                    </div>
                  </section>
                ) : null}
              </div>
            </div>
          )}

          

          {primaryNav === "myProfile" && (
            <div className="resource-layout">
              <div className="resource-main">
                <section className="card card--flush-form">
                    <h2 className="server-detail-section-title">Профиль администратора</h2>
                    {myAdminProfileLoading ? (
                      <p className="muted">Загрузка профиля…</p>
                    ) : !myAdminProfile ? (
                      <p className="muted">Не удалось загрузить профиль текущего администратора.</p>
                    ) : (
                      <>
                        <div className="app-table-scroll" style={{ marginBottom: 16 }}>
                          <table className="app-table app-table--compact server-root-ca-summary">
                            <tbody>
                              <tr>
                                <th scope="row" className="app-table-nowrap">Логин</th>
                                <td className="app-table-mono">{myAdminProfile.username || "—"}</td>
                              </tr>
                              <tr>
                                <th scope="row" className="app-table-nowrap">ФИО</th>
                                <td>{myAdminProfile.fullName || "—"}</td>
                              </tr>
                              <tr>
                                <th scope="row" className="app-table-nowrap">E-mail</th>
                                <td>{myAdminProfile.email || "—"}</td>
                              </tr>
                            </tbody>
                          </table>
                        </div>

                        <div className="user-profile-field-block" style={{ marginTop: 16 }}>
                          <div className="user-profile-field-label">Безопасность учётной записи</div>
                          <div className="row-inline" style={{ flexWrap: "wrap", gap: 8, marginTop: 8 }}>
                            <button
                              type="button"
                              className="btn-app-primary"
                              onClick={() => {
                                setMyAdminPasswordError("");
                                setMyAdminPasswordModalOpen(true);
                              }}
                            >
                              Сменить пароль
                            </button>
                          </div>
                        </div>

                        <div className="user-profile-field-block" style={{ marginTop: 24 }}>
                          <div className="user-profile-field-label">
						    Двухфакторная авторизация
							&nbsp;
							{myAdminProfile.totpEnabled ? (
                              <span className="app-status app-status--ok">включена</span>
                            ) : (
                              <span className="app-status app-status--off">отключена</span>
                            )}
						  </div>
                          <div style={{ marginTop: 8 }}>
                          </div>
                          {myAdminProfile.totpEnabled ? (
                            <p className="muted" style={{ margin: "8px 0 0" }}>
                              Резервные коды:{" "}
                              <span className="app-table-mono">
                                {Number(myAdminProfile.totpRecoveryCodesRemaining ?? 0)} не использовано
                              </span>
                            </p>
                          ) : null}
                          <div className="row-inline" style={{ flexWrap: "wrap", gap: 8, marginTop: 12 }}>
                            {!myAdminProfile.totpEnabled ? (
                              <button
                                type="button"
                                className="btn-app-primary"
                                onClick={() => {
                                  setMyAdminTotpSetup((prev) => ({ ...prev, error: "" }));
                                  setMyAdminTotpSetupModalOpen(true);
                                }}
                              >
                                Настроить TOTP
                              </button>
                            ) : (
                              <>
                                <button
                                  type="button"
                                  className="btn-app-primary"
                                  onClick={() => {
                                    setMyAdminRecoveryRegenerateError("");
                                    setMyAdminRecoveryRegenerateCode("");
                                    setMyAdminRecoveryModalOpen(true);
                                  }}
                                >
                                  Новые резервные коды
                                </button>
                                <button
                                  type="button"
                                  className="btn-danger"
                                  onClick={() => {
                                    setMyAdminTotpDisableError("");
                                    setMyAdminTotpDisableCode("");
                                    setMyAdminTotpDisableModalOpen(true);
                                  }}
                                >
                                  Отключить TOTP
                                </button>
                              </>
                            )}
                          </div>
                        </div>
                      </>
                    )}
                </section>
              </div>
            </div>
          )}

          {primaryNav === "myProfile" && myAdminPasswordModalOpen ? (
            <div
              className="modal-backdrop"
              role="presentation"
              onClick={(e) => {
                if (e.target === e.currentTarget && !myAdminPasswordBusy) {
                  setMyAdminPasswordModalOpen(false);
                  setMyAdminPasswordDraft({ currentPassword: "", newPassword: "", confirmPassword: "" });
                  setMyAdminPasswordError("");
                }
              }}
            >
              <div className="modal-dialog" role="dialog" aria-modal="true" aria-labelledby="my-admin-password-modal-title">
                <div className="modal-dialog-header">
                  <h2 id="my-admin-password-modal-title" className="modal-dialog-title">
                    Смена пароля
                  </h2>
                  <button
                    type="button"
                    className="modal-close"
                    aria-label="Закрыть"
                    disabled={myAdminPasswordBusy}
                    onClick={() => {
                      setMyAdminPasswordModalOpen(false);
                      setMyAdminPasswordDraft({ currentPassword: "", newPassword: "", confirmPassword: "" });
                      setMyAdminPasswordError("");
                    }}
                  >
                    ×
                  </button>
                </div>
                <form className="user-profile-blocks user-profile-blocks--stack" onSubmit={submitMyAdminPasswordChange}>
                  <div className="user-profile-field-block">
                    <div className="user-profile-field-label">Текущий пароль</div>
                    <input
                      type="password"
                      value={myAdminPasswordDraft.currentPassword}
                      onChange={(e) => setMyAdminPasswordDraft((prev) => ({ ...prev, currentPassword: e.target.value }))}
                      placeholder="Текущий пароль"
                      autoComplete="current-password"
                      disabled={myAdminPasswordBusy}
                      autoFocus
                    />
                  </div>
                  <div className="user-profile-field-block">
                    <div className="user-profile-field-label">Новый пароль</div>
                    <input
                      type="password"
                      value={myAdminPasswordDraft.newPassword}
                      onChange={(e) => setMyAdminPasswordDraft((prev) => ({ ...prev, newPassword: e.target.value }))}
                      placeholder="Минимум 10 символов"
                      autoComplete="new-password"
                      disabled={myAdminPasswordBusy}
                    />
                  </div>
                  <div className="user-profile-field-block">
                    <div className="user-profile-field-label">Подтверждение</div>
                    <input
                      type="password"
                      value={myAdminPasswordDraft.confirmPassword}
                      onChange={(e) => setMyAdminPasswordDraft((prev) => ({ ...prev, confirmPassword: e.target.value }))}
                      placeholder="Повторите новый пароль"
                      autoComplete="new-password"
                      disabled={myAdminPasswordBusy}
                    />
                  </div>
                  {myAdminPasswordError ? (
                    <div className="auth-alert auth-alert--error" role="alert" style={{ marginBottom: 0 }}>
                      {myAdminPasswordError}
                    </div>
                  ) : null}
                  <div className="row-inline" style={{ justifyContent: "flex-end", gap: 8, flexWrap: "wrap", marginTop: 12 }}>
                    <button
                      type="button"
                      className="btn-secondary"
                      disabled={myAdminPasswordBusy}
                      onClick={() => {
                        setMyAdminPasswordModalOpen(false);
                        setMyAdminPasswordDraft({ currentPassword: "", newPassword: "", confirmPassword: "" });
                        setMyAdminPasswordError("");
                      }}
                    >
                      Отмена
                    </button>
                    <button type="submit" className="btn-app-primary" disabled={myAdminPasswordBusy}>
                      {myAdminPasswordBusy ? "Сохранение…" : "Обновить пароль"}
                    </button>
                  </div>
                </form>
              </div>
            </div>
          ) : null}

          {primaryNav === "myProfile" && myAdminTotpSetupModalOpen ? (
            <div
              className="modal-backdrop"
              role="presentation"
              onClick={(e) => {
                if (e.target === e.currentTarget && !myAdminTotpSetup.busy) {
                  setMyAdminTotpSetupModalOpen(false);
                  setMyAdminTotpSetup({
                    loading: false,
                    qrDataUrl: "",
                    manualSecret: "",
                    expiresAt: "",
                    code: "",
                    error: "",
                    busy: false,
                  });
                  setMyAdminRecoveryCodesDisplay(null);
                }
              }}
            >
              <div className="modal-dialog" role="dialog" aria-modal="true" aria-labelledby="my-admin-totp-setup-modal-title">
                <div className="modal-dialog-header">
                  <h2 id="my-admin-totp-setup-modal-title" className="modal-dialog-title">
                    Настройка двухфакторной авторизации (TOTP)
                  </h2>
                  <button
                    type="button"
                    className="modal-close"
                    aria-label="Закрыть"
                    disabled={myAdminTotpSetup.busy}
                    onClick={() => {
                      setMyAdminTotpSetupModalOpen(false);
                      setMyAdminTotpSetup({
                        loading: false,
                        qrDataUrl: "",
                        manualSecret: "",
                        expiresAt: "",
                        code: "",
                        error: "",
                        busy: false,
                      });
                      setMyAdminRecoveryCodesDisplay(null);
                    }}
                  >
                    ×
                  </button>
                </div>
                <p className="muted" style={{ marginTop: 0 }}>
                  После включения код из приложения-аутентификатора будет обязателен при каждом входе.
                </p>
                {myAdminTotpSetup.loading ? <p className="muted">Подготовка QR-кода…</p> : null}
                {!myAdminTotpSetup.loading && myAdminTotpSetup.error && !myAdminTotpSetup.qrDataUrl ? (
                  <div className="auth-alert auth-alert--error" role="alert">
                    {myAdminTotpSetup.error}
                  </div>
                ) : null}
                {myAdminTotpSetup.qrDataUrl ? (
                  <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                    <div className="user-profile-field-label">Привязка приложения</div>
                    <img src={myAdminTotpSetup.qrDataUrl} alt="QR-код для TOTP" style={{ width: 180, height: 180 }} />
                    <div className="app-table-mono">{myAdminTotpSetup.manualSecret}</div>
                    <p className="user-profile-field-hint">Срок действия QR: {formatMaybeDate(myAdminTotpSetup.expiresAt)}</p>
                    <div className="row-inline" style={{ flexWrap: "wrap", gap: 8 }}>
                      <input
                        value={myAdminTotpSetup.code}
                        onChange={(e) => setMyAdminTotpSetup((prev) => ({ ...prev, code: e.target.value }))}
                        placeholder="Код подтверждения из приложения"
                        inputMode="numeric"
                        disabled={myAdminTotpSetup.busy}
                      />
                      <button
                        type="button"
                        className="btn-app-primary"
                        disabled={myAdminTotpSetup.busy}
                        onClick={() => void confirmMyAdminTotpSetup()}
                      >
                        {myAdminTotpSetup.busy ? "Проверка…" : "Подтвердить и включить"}
                      </button>
                    </div>
                    {myAdminTotpSetup.error ? (
                      <div className="auth-alert auth-alert--error" role="alert" style={{ marginBottom: 0 }}>
                        {myAdminTotpSetup.error}
                      </div>
                    ) : null}
                  </div>
                ) : null}
                {myAdminRecoveryCodesDisplay && myAdminRecoveryCodesDisplay.length > 0 ? (
                  <div style={{ marginTop: 16 }}>
                    <div className="user-profile-field-label">Сохраните резервные коды</div>
                    <p className="user-profile-field-hint">
                      Они больше не будут показаны. Каждый код одноразовый при входе вместо TOTP.
                    </p>
                    <ol className="app-table-mono" style={{ margin: "8px 0 0", paddingLeft: 20 }}>
                      {myAdminRecoveryCodesDisplay.map((c, idx) => (
                        <li key={`${idx}-${c}`} style={{ marginBottom: 4 }}>
                          {c}
                        </li>
                      ))}
                    </ol>
                  </div>
                ) : null}
                {myAdminRecoveryCodesDisplay && myAdminRecoveryCodesDisplay.length > 0 ? (
                  <div className="row-inline" style={{ justifyContent: "flex-end", marginTop: 12 }}>
                    <button
                      type="button"
                      className="btn-app-primary"
                      onClick={() => {
                        setMyAdminTotpSetupModalOpen(false);
                        setMyAdminTotpSetup({
                          loading: false,
                          qrDataUrl: "",
                          manualSecret: "",
                          expiresAt: "",
                          code: "",
                          error: "",
                          busy: false,
                        });
                        setMyAdminRecoveryCodesDisplay(null);
                      }}
                    >
                      Готово
                    </button>
                  </div>
                ) : null}
              </div>
            </div>
          ) : null}

          {primaryNav === "myProfile" && myAdminTotpDisableModalOpen ? (
            <div
              className="modal-backdrop"
              role="presentation"
              onClick={(e) => {
                if (e.target === e.currentTarget && !myAdminTotpDisableBusy) {
                  setMyAdminTotpDisableModalOpen(false);
                  setMyAdminTotpDisableCode("");
                  setMyAdminTotpDisableError("");
                }
              }}
            >
              <div className="modal-dialog" role="dialog" aria-modal="true" aria-labelledby="my-admin-totp-disable-modal-title">
                <div className="modal-dialog-header">
                  <h2 id="my-admin-totp-disable-modal-title" className="modal-dialog-title">
                    Отключить TOTP
                  </h2>
                  <button
                    type="button"
                    className="modal-close"
                    aria-label="Закрыть"
                    disabled={myAdminTotpDisableBusy}
                    onClick={() => {
                      setMyAdminTotpDisableModalOpen(false);
                      setMyAdminTotpDisableCode("");
                      setMyAdminTotpDisableError("");
                    }}
                  >
                    ×
                  </button>
                </div>
                <p className="muted" style={{ marginTop: 0 }}>
                  Введите текущий код из приложения-аутентификатора, чтобы отключить двухфакторную аутентификацию.
                </p>
                <div className="user-profile-field-block">
                  <input
                    value={myAdminTotpDisableCode}
                    onChange={(e) => setMyAdminTotpDisableCode(e.target.value)}
                    inputMode="numeric"
                    placeholder="Код из приложения"
                    disabled={myAdminTotpDisableBusy}
                    autoFocus
                  />
                </div>
                {myAdminTotpDisableError ? (
                  <div className="auth-alert auth-alert--error" role="alert" style={{ marginBottom: 0 }}>
                    {myAdminTotpDisableError}
                  </div>
                ) : null}
                <div className="row-inline" style={{ justifyContent: "flex-end", gap: 8, flexWrap: "wrap", marginTop: 12 }}>
                  <button
                    type="button"
                    className="btn-secondary"
                    disabled={myAdminTotpDisableBusy}
                    onClick={() => {
                      setMyAdminTotpDisableModalOpen(false);
                      setMyAdminTotpDisableCode("");
                      setMyAdminTotpDisableError("");
                    }}
                  >
                    Отмена
                  </button>
                  <button
                    type="button"
                    className="btn-danger"
                    disabled={myAdminTotpDisableBusy}
                    onClick={() => void disableMyAdminTotp()}
                  >
                    {myAdminTotpDisableBusy ? "Отключение…" : "Отключить TOTP"}
                  </button>
                </div>
              </div>
            </div>
          ) : null}

          {primaryNav === "myProfile" && myAdminRecoveryModalOpen ? (
            <div
              className="modal-backdrop"
              role="presentation"
              onClick={(e) => {
                if (e.target === e.currentTarget && !myAdminRecoveryRegenerateBusy) {
                  setMyAdminRecoveryModalOpen(false);
                  setMyAdminRecoveryRegenerateCode("");
                  setMyAdminRecoveryRegenerateError("");
                  setMyAdminRecoveryCodesDisplay(null);
                }
              }}
            >
              <div className="modal-dialog" role="dialog" aria-modal="true" aria-labelledby="my-admin-recovery-modal-title">
                <div className="modal-dialog-header">
                  <h2 id="my-admin-recovery-modal-title" className="modal-dialog-title">
                    Новые резервные коды
                  </h2>
                  <button
                    type="button"
                    className="modal-close"
                    aria-label="Закрыть"
                    disabled={myAdminRecoveryRegenerateBusy}
                    onClick={() => {
                      setMyAdminRecoveryModalOpen(false);
                      setMyAdminRecoveryRegenerateCode("");
                      setMyAdminRecoveryRegenerateError("");
                      setMyAdminRecoveryCodesDisplay(null);
                    }}
                  >
                    ×
                  </button>
                </div>
                <p className="muted" style={{ marginTop: 0 }}>
                  Каждый код одноразовый. Для выдачи нового набора нужен текущий код из приложения TOTP.
                </p>
                {!myAdminRecoveryCodesDisplay || myAdminRecoveryCodesDisplay.length === 0 ? (
                  <>
                    <div className="user-profile-field-block">
                      <input
                        value={myAdminRecoveryRegenerateCode}
                        onChange={(e) => setMyAdminRecoveryRegenerateCode(e.target.value)}
                        inputMode="numeric"
                        placeholder="Код TOTP"
                        disabled={myAdminRecoveryRegenerateBusy}
                        autoFocus
                      />
                    </div>
                    {myAdminRecoveryRegenerateError ? (
                      <div className="auth-alert auth-alert--error" role="alert" style={{ marginBottom: 0 }}>
                        {myAdminRecoveryRegenerateError}
                      </div>
                    ) : null}
                    <div className="row-inline" style={{ justifyContent: "flex-end", gap: 8, flexWrap: "wrap", marginTop: 12 }}>
                      <button
                        type="button"
                        className="btn-secondary"
                        disabled={myAdminRecoveryRegenerateBusy}
                        onClick={() => {
                          setMyAdminRecoveryModalOpen(false);
                          setMyAdminRecoveryRegenerateCode("");
                          setMyAdminRecoveryRegenerateError("");
                        }}
                      >
                        Отмена
                      </button>
                      <button
                        type="button"
                        className="btn-app-primary"
                        disabled={myAdminRecoveryRegenerateBusy}
                        onClick={() => void regenerateMyAdminRecoveryCodes()}
                      >
                        {myAdminRecoveryRegenerateBusy ? "Генерация…" : "Сгенерировать новые коды"}
                      </button>
                    </div>
                  </>
                ) : (
                  <>
                    <div className="user-profile-field-label">Сохраните резервные коды</div>
                    <ol className="app-table-mono" style={{ margin: "8px 0 0", paddingLeft: 20 }}>
                      {myAdminRecoveryCodesDisplay.map((c, idx) => (
                        <li key={`${idx}-${c}`} style={{ marginBottom: 4 }}>
                          {c}
                        </li>
                      ))}
                    </ol>
                    <div className="row-inline" style={{ justifyContent: "flex-end", marginTop: 12 }}>
                      <button
                        type="button"
                        className="btn-app-primary"
                        onClick={() => {
                          setMyAdminRecoveryModalOpen(false);
                          setMyAdminRecoveryRegenerateCode("");
                          setMyAdminRecoveryRegenerateError("");
                          setMyAdminRecoveryCodesDisplay(null);
                        }}
                      >
                        Готово
                      </button>
                    </div>
                  </>
                )}
              </div>
            </div>
          ) : null}

          {primaryNav === "settings" && (
            <div className="resource-layout">
              <aside className="resource-sidebar" aria-label="Разделы настроек">
                <div className="resource-sidebar-header">
                  <h2 className="resource-sidebar-title">Настройки</h2>
                  <p className="resource-sidebar-sub">Панель управления</p>
                </div>
                <nav className="resource-nav" aria-label="Навигация по настройкам">
                  <button
                    type="button"
                    className={`resource-nav-item${settingsSection === "admins" && (adminsPage === "list" || adminsPage === "detail") && !addAdminModalOpen ? " is-active" : ""}`}
                    aria-current={
                      settingsSection === "admins" && !addAdminModalOpen && (adminsPage === "list" || adminsPage === "detail")
                        ? "page"
                        : undefined
                    }
                    onClick={() => {
                      setAddAdminModalOpen(false);
                      setAddAdminBusy(false);
                      setNewAdmin({ fullName: "", username: "", email: "" });
                      setAddAdminInviteResult(null);
                      setAddAdminError("");
                      setError("");
                      navigate(paths.settings());
                    }}
                  >
                    <IconUsers />
                    Администраторы
                  </button>
                  <button
                    type="button"
                    className={`resource-nav-item${settingsSection === "backup" ? " is-active" : ""}`}
                    aria-current={settingsSection === "backup" ? "page" : undefined}
                    onClick={() => {
                      setAddAdminModalOpen(false);
                      setError("");
                      navigate(paths.settingsBackup());
                    }}
                  >
                    <IconBackup />
                    Резервное копирование
                  </button>
                  <button
                    type="button"
                    className={`resource-nav-item${settingsSection === "restore" ? " is-active" : ""}`}
                    aria-current={settingsSection === "restore" ? "page" : undefined}
                    onClick={() => {
                      setAddAdminModalOpen(false);
                      setError("");
                      navigate(paths.settingsRestore());
                    }}
                  >
                    <IconRestore />
                    Восстановление
                  </button>
                </nav>
              </aside>
              <div className="resource-main">

                {settingsSection === "admins" && adminsPage === "list" && (
                  <section className="card logs-journal-section">
                    <div className="resource-main-toolbar">
                      <h2 className="server-detail-section-title">Администраторы</h2>
                      <button
                        type="button"
                        className="btn-app-primary"
                        onClick={() => {
                          setNewAdmin({ fullName: "", username: "", email: "" });
                          setAddAdminInviteResult(null);
                          setAddAdminError("");
                          setError("");
                          setAddAdminModalOpen(true);
                        }}
                      >
                        <span className="btn-app-primary-plus" aria-hidden>
                          +
                        </span>
                        Добавить администратора
                      </button>
                    </div>
                    <div className="app-table-with-pagination">
                      <div className="app-table-scroll">
                        <table className="app-table">
                          <thead>
                            <tr>
                              <th>ФИО</th>
                              <th>Аккаунт</th>
                              <th>Электронная почта</th>
                              <th>Статус</th>
                            </tr>
                          </thead>
                          <tbody>
                            {adminsTablePage.slice.map((admin) => (
                              <tr
                                key={admin.id}
                                className="app-table-click-row"
                                tabIndex={0}
                                role="button"
                                onClick={() => navigate(paths.settingsAdmin(admin.id))}
                                onKeyDown={(e) => {
                                  if (e.key === "Enter" || e.key === " ") {
                                    e.preventDefault();
                                    navigate(paths.settingsAdmin(admin.id));
                                  }
                                }}
                              >
                                <td>{admin.fullName || "—"}</td>
                                <td className="app-table-mono">{admin.username}</td>
                                <td>{admin.email || "—"}</td>
                                <td>
                                  {admin.invitePending ? (
                                    <span className="app-status app-status--bad">ожидает приглашения</span>
                                  ) : admin.isActive ? (
                                    <span className="app-status app-status--ok">активен</span>
                                  ) : (
                                    <span className="app-status app-status--off">заблокирован</span>
                                  )}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                      <TablePagination
                        page={adminsTablePage.page}
                        totalPages={adminsTablePage.totalPages}
                        total={adminsTablePage.total}
                        onPageChange={(p) => setTablePages((prev) => ({ ...prev, admins: p }))}
                      />
                    </div>
                  </section>
                )}

                {settingsSection === "admins" && adminsPage === "detail" && (
                  <section className="card card--flush-form">
                    <h2 className="server-detail-section-title">Администратор</h2>
                    {!selectedAdmin ? (
                      <p className="muted">Администратор не найден. Вернитесь к списку.</p>
                    ) : (
                      <>
                        <div className="app-table-scroll" style={{ marginBottom: 16 }}>
                          <table className="app-table app-table--compact server-root-ca-summary">
                            <tbody>
                              <tr>
                                <th scope="row" className="app-table-nowrap">
                                  Администратор (статус)
                                </th>
                                <td>
                                  {selectedAdmin.invitePending ? (
                                    <span className="app-status app-status--bad">ожидает перехода по приглашению</span>
                                  ) : selectedAdmin.isActive ? (
                                    <span className="app-status app-status--ok">активен</span>
                                  ) : (
                                    <span className="app-status app-status--off">заблокирован</span>
                                  )}
                                </td>
                              </tr>
                            </tbody>
                          </table>
                        </div>
                        <form className="user-profile-blocks user-profile-blocks--stack" onSubmit={saveAdminProfile}>
                          <div className="user-profile-field-block">
                            <div className="user-profile-field-label">
                              ФИО <span className="error">*</span>
                            </div>
                            <input
                              required
                              value={adminProfileDraft.fullName}
                              onChange={(e) => setAdminProfileDraft((prev) => ({ ...prev, fullName: e.target.value }))}
                              disabled={adminProfileSaving}
                              placeholder="Иванов Иван Иванович"
                            />
                          </div>
                          <div className="user-profile-field-block">
                            <div className="user-profile-field-label">
                              Аккаунт <span className="error">*</span>
                            </div>
                            <input
                              required
                              className="app-table-mono"
                              value={adminProfileDraft.username}
                              onChange={(e) => setAdminProfileDraft((prev) => ({ ...prev, username: e.target.value }))}
                              disabled={adminProfileSaving}
                              autoComplete="username"
                            />
                          </div>
                          <div className="user-profile-field-block">
                            <div className="user-profile-field-label">
                              Электронная почта <span className="error">*</span>
                            </div>
                            <input
                              type="email"
                              required
                              value={adminProfileDraft.email}
                              onChange={(e) => setAdminProfileDraft((prev) => ({ ...prev, email: e.target.value }))}
                              disabled={adminProfileSaving}
                              autoComplete="email"
                              placeholder="user@company.ru"
                            />
                            <p className="user-profile-field-hint">Логин и контакт для уведомлений.</p>
                          </div>
                          {adminProfileFieldError ? (
                            <div className="auth-alert auth-alert--error" role="alert">
                              {adminProfileFieldError}
                            </div>
                          ) : null}
                          <div className="user-profile-field-block">
                            <div className="user-profile-field-label">Доступ к панели</div>
                            <div className="row-inline" style={{ flexWrap: "wrap", gap: 8, alignItems: "center" }}>
                              <button
                                type="submit"
                                className="btn-app-primary"
                                disabled={adminProfileSaving}
                              >
                                {adminProfileSaving ? "Сохранение…" : "Сохранить"}
                              </button>
                              {!selectedAdmin.invitePending ? (
                                <button
                                  type="button"
                                  className="btn-app-primary"
                                  disabled={adminProfileSaving || adminPasswordResetModal.busy}
                                  onClick={() => void openAdminPasswordResetModal()}
                                >
                                  Сменить пароль
                                </button>
                              ) : null}
                              {sessionAdminId && String(selectedAdmin.id) === sessionAdminId ? (
                                <p className="user-profile-field-hint" style={{ margin: 0 }}>
                                  Нельзя заблокировать свою учётную запись.
                                </p>
                              ) : selectedAdmin.isActive ? (
                                <button
                                  type="button"
                                  className="btn-danger"
                                  disabled={adminDetailStatusBusy || adminBlockModal.busy || adminProfileSaving}
                                  onClick={() => {
                                    const fn = String(adminProfileDraft.fullName || "").trim();
                                    const un = String(adminProfileDraft.username || "").trim();
                                    const expectedNormalized = fn
                                      ? normalizeAdminBlockConfirmInput(fn)
                                      : normalizeAdminBlockConfirmInput(un);
                                    setAdminBlockModal({
                                      open: true,
                                      adminId: selectedAdmin.id,
                                      expectedNormalized,
                                      confirmByFullName: Boolean(fn),
                                      confirmInput: "",
                                      busy: false,
                                      validationError: "",
                                      error: "",
                                    });
                                  }}
                                >
                                  Заблокировать
                                </button>
                              ) : (
                                <button
                                  type="button"
                                  className="btn-outline-navy"
                                  disabled={adminDetailStatusBusy || adminProfileSaving}
                                  onClick={() => void patchAdminIsActive(selectedAdmin.id, true)}
                                >
                                  {adminDetailStatusBusy ? "Сохранение…" : "Разблокировать"}
                                </button>
                              )}
                            </div>
                            {adminDetailStatusError ? (
                              <div className="auth-alert auth-alert--error" role="alert" style={{ marginTop: 8, marginBottom: 0 }}>
                                {adminDetailStatusError}
                              </div>
                            ) : null}
                          </div>
                        </form>
                      </>
                    )}
                  </section>
                )}

                {settingsSection === "backup" && (
                  <section className="card logs-journal-section">
                    <h2 className="server-detail-section-title">Резервное копирование</h2>
                    <div className="user-profile-blocks user-profile-blocks--stack" style={{ marginBottom: 20 }}>
                      <div className="user-profile-field-block">
                        <div className="user-profile-field-label">Периодичность (минуты)</div>
                        <input
                          type="number"
                          min={0}
                          max={10080}
                          value={backupFormInterval}
                          onChange={(e) => setBackupFormInterval(Number(e.target.value))}
                          disabled={panelBackupsSaving}
                          aria-label="Интервал в минутах"
                        />
                        <p className="user-profile-field-hint">0 — только вручную; максимум 10080 (7 суток).</p>
                      </div>
                      <div className="user-profile-field-block">
                        <div className="user-profile-field-label">Хранить последних копий</div>
                        <input
                          type="number"
                          min={1}
                          max={500}
                          value={backupFormRetain}
                          onChange={(e) => setBackupFormRetain(Number(e.target.value))}
                          disabled={panelBackupsSaving}
                          aria-label="Количество копий"
                        />
                      </div>
                      <div className="row-inline panel-backup-actions" style={{ gap: 8, alignItems: "center" }}>
                        <button
                          type="button"
                          className="panel-backup-action-btn"
                          disabled={panelBackupsSaving}
                          onClick={() => void saveBackupSettingsHandler()}
                        >
                          {panelBackupsSaving ? "Сохранение…" : "Сохранить настройки"}
                        </button>
                        <button
                          type="button"
                          className="panel-backup-action-btn"
                          disabled={panelBackupsRunBusy || panelBackupsLoading}
                          onClick={() => void runBackupNowHandler()}
                        >
                          {panelBackupsRunBusy ? "Создание…" : "Создать копию сейчас"}
                        </button>
                      </div>
                      {panelBackupsData.settings?.lastScheduledAt ? (
                        <p className="muted" style={{ marginTop: 8, fontSize: 11 }}>
                          Последний учёт автокопии: {formatMaybeDate(panelBackupsData.settings.lastScheduledAt)}
                        </p>
                      ) : null}
                    </div>
                    <h3 className="server-detail-section-title" style={{ fontSize: 13, marginBottom: 8 }}>
                      Доступные копии
                    </h3>
                    <div className="app-table-scroll">
                      <table className="app-table app-table--compact table-settings-backups">
                        <thead>
                          <tr>
                            <th>Дата</th>
                            <th>Имя файла</th>
                            <th>Размер</th>
                            <th>Тип</th>
                            <th className="app-table-col-actions">Действия</th>
                          </tr>
                        </thead>
                        <tbody>
                          {panelBackupsData.backups.length === 0 ? (
                            <tr>
                              <td colSpan={5} className="muted">
                                Нет сохранённых копий
                              </td>
                            </tr>
                          ) : (
                            panelBackupsData.backups.map((b) => (
                              <tr key={b.id}>
                                <td className="app-table-nowrap">{formatMaybeDate(b.createdAt)}</td>
                                <td className="app-table-mono">{b.fileName}</td>
                                <td>{formatBytes(b.sizeBytes)}</td>
                                <td>{b.trigger === "scheduled" ? "по расписанию" : "вручную"}</td>
                                <td className="app-table-col-actions">
                                  <div className="row-inline" style={{ gap: 6, flexWrap: "nowrap", whiteSpace: "nowrap" }}>
                                    <button
                                      type="button"
                                      className="app-link-btn"
                                      onClick={() => void downloadBackupArchive(API_URL, token, b.id, b.fileName)}
                                    >
                                      Скачать
                                    </button>
                                    <button
                                      type="button"
                                      className="app-link-btn app-link-btn--danger"
                                      onClick={() =>
                                        setPanelBackupDeleteModal({
                                          open: true,
                                          backupId: String(b.id || ""),
                                          fileName: String(b.fileName || ""),
                                          busy: false,
                                          error: "",
                                        })
                                      }
                                    >
                                      Удалить
                                    </button>
                                  </div>
                                </td>
                              </tr>
                            ))
                          )}
                        </tbody>
                      </table>
                    </div>
                  </section>
                )}

                {settingsSection === "restore" && (
                  <section className="card logs-journal-section settings-restore-section">
                    <h2 className="server-detail-section-title">Восстановление</h2>
                    <div className="auth-alert auth-alert--error" role="alert" style={{ marginTop: 8, marginBottom: 12 }}>
                      Внимание: загрузка архива полностью заменит текущие данные панели (включая администраторов и
                      сертификаты). После восстановления может потребоваться повторный вход.
                    </div>
                    <div className="user-profile-field-block">
                      <div className="user-profile-field-label">Архив резервной копии (.zip)</div>
                      <input
                        type="file"
                        accept=".zip,application/zip"
                        disabled={restoreBusy}
                        onChange={(e) => {
                          const f = e.target.files?.[0];
                          setRestoreFile(f || null);
                          setRestoreMessage("");
                        }}
                      />
                    </div>
                    <label className="row-inline" style={{ marginTop: 12, gap: 8, alignItems: "center" }}>
                      <input type="checkbox" checked={restoreConfirm} disabled={restoreBusy} onChange={(e) => setRestoreConfirm(e.target.checked)} />
                      <span>Я понимаю последствия и хочу заменить данные из архива</span>
                    </label>
                    <div className="row-inline" style={{ marginTop: 16, gap: 8 }}>
                      <button
                        type="button"
                        disabled={restoreBusy || !restoreFile || !restoreConfirm}
                        onClick={() => void restoreFromArchiveHandler()}
                      >
                        {restoreBusy ? "Восстановление…" : "Восстановить из архива"}
                      </button>
                    </div>
                  </section>
                )}

              </div>
            </div>
          )}
          {addAdminModalOpen && primaryNav === "settings" && settingsSection === "admins" ? (
            <div
              className="modal-backdrop"
              role="presentation"
              onClick={(e) => {
                if (e.target === e.currentTarget && !addAdminBusy) {
                  setAddAdminModalOpen(false);
                  setAddAdminBusy(false);
                  setAddAdminError("");
                  setAddAdminInviteResult(null);
                  setNewAdmin({ fullName: "", username: "", email: "" });
                  setError("");
                }
              }}
            >
              <div className="modal-dialog" role="dialog" aria-modal="true" aria-labelledby="add-admin-modal-title">
                <div className="modal-dialog-header">
                  <h2 id="add-admin-modal-title" className="modal-dialog-title">
                    {addAdminInviteResult ? "Приглашение создано" : "Новый администратор"}
                  </h2>
                  <button
                    type="button"
                    className="modal-close"
                    aria-label="Закрыть"
                    disabled={addAdminBusy}
                    onClick={() => {
                      setAddAdminModalOpen(false);
                      setAddAdminBusy(false);
                      setAddAdminError("");
                      setAddAdminInviteResult(null);
                      setNewAdmin({ fullName: "", username: "", email: "" });
                      setError("");
                    }}
                  >
                    ×
                  </button>
                </div>
                {addAdminInviteResult ? (
                  <div className="form-stack">
                    <p className="modal-dialog-body-text">
                      Ссылка-приглашение действует 7 дней. Новый администратор откроет её, проверит данные и задаст пароль.
                    </p>
                    <input
                      readOnly
                      className="app-table-mono"
                      value={addAdminInviteResult.inviteUrl}
                      aria-label="Ссылка-приглашение"
                      onFocus={(e) => e.target.select()}
                    />
                    <div className="row-inline" style={{ justifyContent: "flex-end", gap: 8, flexWrap: "wrap" }}>
                      <button
                        type="button"
                        className="btn-secondary"
                        onClick={() => {
                          void navigator.clipboard.writeText(addAdminInviteResult.inviteUrl);
                        }}
                      >
                        Копировать ссылку
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          setAddAdminModalOpen(false);
                          setAddAdminInviteResult(null);
                          setNewAdmin({ fullName: "", username: "", email: "" });
                          setError("");
                        }}
                      >
                        Готово
                      </button>
                    </div>
                  </div>
                ) : (
                  <form className="form-stack" onSubmit={createAdmin}>
                    <div className="user-profile-field-block">
                      <div className="user-profile-field-label">
                        ФИО <span className="error">*</span>
                      </div>
                      <input
                        value={newAdmin.fullName}
                        onChange={(e) => setNewAdmin((prev) => ({ ...prev, fullName: e.target.value }))}
                        autoComplete="name"
                        disabled={addAdminBusy}
                        placeholder="Иванов Иван Иванович"
                      />
                    </div>
                    <div className="user-profile-field-block">
                      <div className="user-profile-field-label">
                        Аккаунт <span className="error">*</span>
                      </div>
                      <input
                        value={newAdmin.username}
                        onChange={(e) => setNewAdmin((prev) => ({ ...prev, username: e.target.value }))}
                        autoComplete="username"
                        disabled={addAdminBusy}
                        placeholder="Логин для входа"
                      />
                    </div>
                    <div className="user-profile-field-block">
                      <div className="user-profile-field-label">
                        Электронная почта <span className="error">*</span>
                      </div>
                      <input
                        type="email"
                        value={newAdmin.email}
                        onChange={(e) => setNewAdmin((prev) => ({ ...prev, email: e.target.value }))}
                        autoComplete="email"
                        disabled={addAdminBusy}
                        placeholder="user@company.ru"
                      />
                    </div>
                    {addAdminError ? (
                      <div className="auth-alert auth-alert--error" role="alert">
                        {addAdminError}
                      </div>
                    ) : null}
                    <div className="row-inline" style={{ justifyContent: "flex-end", gap: 8 }}>
                      <button
                        type="button"
                        className="btn-secondary"
                        disabled={addAdminBusy}
                        onClick={() => {
                          setAddAdminModalOpen(false);
                          setAddAdminBusy(false);
                          setAddAdminError("");
                          setAddAdminInviteResult(null);
                          setNewAdmin({ fullName: "", username: "", email: "" });
                          setError("");
                        }}
                      >
                        Отмена
                      </button>
                      <button type="submit" disabled={addAdminBusy}>
                        {addAdminBusy ? "Создание…" : "Создать и получить ссылку"}
                      </button>
                    </div>
                  </form>
                )}
              </div>
            </div>
          ) : null}
          {panelBackupDeleteModal.open && primaryNav === "settings" && settingsSection === "backup" ? (
            <div
              className="modal-backdrop"
              role="presentation"
              onClick={(e) => {
                if (e.target === e.currentTarget && !panelBackupDeleteModal.busy) {
                  setPanelBackupDeleteModal({ open: false, backupId: "", fileName: "", busy: false, error: "" });
                }
              }}
            >
              <div
                className="modal-dialog"
                role="dialog"
                aria-modal="true"
                aria-labelledby="panel-backup-delete-title"
                onClick={(e) => e.stopPropagation()}
              >
                <div className="modal-dialog-header">
                  <h2 id="panel-backup-delete-title" className="modal-dialog-title">
                    Удалить резервную копию
                  </h2>
                  <button
                    type="button"
                    className="modal-close"
                    aria-label="Закрыть"
                    disabled={panelBackupDeleteModal.busy}
                    onClick={() => setPanelBackupDeleteModal({ open: false, backupId: "", fileName: "", busy: false, error: "" })}
                  >
                    ×
                  </button>
                </div>
                <p className="modal-dialog-body-text" style={{ marginTop: 0 }}>
                  Удалить резервную копию{" "}
                  <span className="app-table-mono">{panelBackupDeleteModal.fileName || panelBackupDeleteModal.backupId}</span>?
                  Это действие нельзя отменить.
                </p>
                {panelBackupDeleteModal.error ? (
                  <div className="auth-alert auth-alert--error" role="alert">
                    {panelBackupDeleteModal.error}
                  </div>
                ) : null}
                <div className="row-inline" style={{ justifyContent: "flex-end", gap: 8 }}>
                  <button
                    type="button"
                    className="btn-secondary"
                    disabled={panelBackupDeleteModal.busy}
                    onClick={() => setPanelBackupDeleteModal({ open: false, backupId: "", fileName: "", busy: false, error: "" })}
                  >
                    Отмена
                  </button>
                  <button type="button" className="btn-danger" disabled={panelBackupDeleteModal.busy} onClick={() => void deletePanelBackupHandler()}>
                    {panelBackupDeleteModal.busy ? "Удаление…" : "Удалить"}
                  </button>
                </div>
              </div>
            </div>
          ) : null}
          {adminBlockModal.open ? (
            <div
              className="modal-backdrop"
              role="presentation"
              onClick={(e) => {
                if (e.target === e.currentTarget && !adminBlockModal.busy) {
                  closeAdminBlockModal();
                }
              }}
            >
              <div
                className="modal-dialog"
                role="dialog"
                aria-modal="true"
                aria-labelledby="admin-block-modal-title"
                onClick={(e) => e.stopPropagation()}
              >
                <div className="modal-dialog-header">
                  <h2 id="admin-block-modal-title" className="modal-dialog-title">
                    Блокировка администратора
                  </h2>
                  <button
                    type="button"
                    className="modal-close"
                    aria-label="Закрыть"
                    disabled={adminBlockModal.busy}
                    onClick={closeAdminBlockModal}
                  >
                    ×
                  </button>
                </div>
                <p className="modal-dialog-body-text">
                  После блокировки вход в панель под этой учётной записью будет невозможен. Действие можно отменить,
                  разблокировав администратора на этой же странице.
                </p>
                <p className="modal-dialog-body-text">
                  {adminBlockModal.confirmByFullName ? (
                    <>
                      Для подтверждения введите <strong>ФИО</strong> этого администратора.
                    </>
                  ) : (
                    <>
                      В профиле не указано ФИО. Для подтверждения введите <strong>логин (аккаунт)</strong> этого
                      администратора.
                    </>
                  )}
                </p>
                <div className="user-profile-field-block" style={{ marginTop: 12 }}>
                  <div className="user-profile-field-label">
                    {adminBlockModal.confirmByFullName ? "ФИО для подтверждения" : "Логин для подтверждения"}
                  </div>
                  <input
                    value={adminBlockModal.confirmInput}
                    onChange={(e) =>
                      setAdminBlockModal((prev) => ({
                        ...prev,
                        confirmInput: e.target.value,
                        validationError: "",
                        error: "",
                      }))
                    }
                    disabled={adminBlockModal.busy}
                    autoComplete="off"
                    aria-invalid={Boolean(adminBlockModal.validationError)}
                  />
                </div>
                {adminBlockModal.validationError ? (
                  <div className="auth-alert auth-alert--error" role="alert">
                    {adminBlockModal.validationError}
                  </div>
                ) : null}
                {adminBlockModal.error ? (
                  <div className="auth-alert auth-alert--error" role="alert">
                    {adminBlockModal.error}
                  </div>
                ) : null}
                <div className="row-inline" style={{ justifyContent: "flex-end", gap: 8, marginTop: 16 }}>
                  <button
                    type="button"
                    className="btn-secondary"
                    disabled={adminBlockModal.busy}
                    onClick={closeAdminBlockModal}
                  >
                    Отмена
                  </button>
                  <button
                    type="button"
                    className="btn-danger"
                    disabled={
                      adminBlockModal.busy || !normalizeAdminBlockConfirmInput(adminBlockModal.confirmInput)
                    }
                    onClick={() => void submitAdminBlock()}
                  >
                    {adminBlockModal.busy ? "Блокировка…" : "Заблокировать"}
                  </button>
                </div>
              </div>
            </div>
          ) : null}
          {adminPasswordResetModal.open ? (
            <div
              className="modal-backdrop"
              role="presentation"
              onClick={(e) => {
                if (e.target === e.currentTarget && !adminPasswordResetModal.busy) {
                  closeAdminPasswordResetModal();
                }
              }}
            >
              <div
                className="modal-dialog"
                role="dialog"
                aria-modal="true"
                aria-labelledby="admin-password-reset-modal-title"
                onClick={(e) => e.stopPropagation()}
              >
                <div className="modal-dialog-header">
                  <h2 id="admin-password-reset-modal-title" className="modal-dialog-title">
                    Ссылка для сброса пароля
                  </h2>
                  <button
                    type="button"
                    className="modal-close"
                    aria-label="Закрыть"
                    disabled={adminPasswordResetModal.busy}
                    onClick={closeAdminPasswordResetModal}
                  >
                    ×
                  </button>
                </div>
                <p className="modal-dialog-body-text">
                  Отправьте эту ссылку администратору (например, в письме). По ней откроется форма установки нового
                  пароля. Ссылка действует ограниченное время; после смены пароля станет недействительна.
                </p>
                {adminPasswordResetModal.busy ? (
                  <p className="muted modal-dialog-body-text">Создание ссылки…</p>
                ) : adminPasswordResetModal.error ? (
                  <div className="auth-alert auth-alert--error" role="alert">
                    {adminPasswordResetModal.error}
                  </div>
                ) : (
                  <div className="user-profile-field-block" style={{ marginTop: 8 }}>
                    <div className="user-profile-field-label">Адрес ссылки</div>
                    <textarea
                      readOnly
                      className="app-table-mono"
                      rows={3}
                      value={adminPasswordResetModal.resetUrl}
                      onFocus={(e) => e.target.select()}
                      aria-label="Ссылка сброса пароля"
                      style={{ width: "100%", resize: "vertical", minHeight: 72, boxSizing: "border-box" }}
                    />
                  </div>
                )}
                <div className="row-inline" style={{ justifyContent: "flex-end", gap: 8, marginTop: 16, flexWrap: "wrap" }}>
                  <button
                    type="button"
                    className="btn-secondary"
                    disabled={adminPasswordResetModal.busy}
                    onClick={closeAdminPasswordResetModal}
                  >
                    Закрыть
                  </button>
                  {!adminPasswordResetModal.busy && adminPasswordResetModal.resetUrl ? (
                    <button
                      type="button"
                      className="btn-app-primary"
                      onClick={() => void navigator.clipboard.writeText(adminPasswordResetModal.resetUrl)}
                    >
                      Копировать ссылку
                    </button>
                  ) : null}
                </div>
              </div>
            </div>
          ) : null}
          {serviceActionModal.open ? (
            <div
              className="modal-backdrop"
              role="presentation"
              onClick={(e) => {
                if (e.target === e.currentTarget && !serviceActionModal.busy) {
                  setServiceActionModal({ open: false, action: "", busy: false, error: "" });
                }
              }}
            >
              <div className="modal-dialog" role="dialog" aria-modal="true" aria-labelledby="service-action-modal-title">
                <div className="modal-dialog-header">
                  <h2 id="service-action-modal-title" className="modal-dialog-title">
                    Подтверждение действия
                  </h2>
                  <button
                    type="button"
                    className="modal-close"
                    aria-label="Закрыть"
                    disabled={serviceActionModal.busy}
                    onClick={() => setServiceActionModal({ open: false, action: "", busy: false, error: "" })}
                  >
                    ×
                  </button>
                </div>
                <p className="modal-dialog-body-text">
                  Вы уверены, что хотите выполнить команду{" "}
                  <strong>{String(serviceActionModal.action || "").toUpperCase()}</strong> для службы OpenVPN?
                </p>
                {serviceActionModal.error ? (
                  <div className="auth-alert auth-alert--error" role="alert">
                    {serviceActionModal.error}
                  </div>
                ) : null}
                <div className="row-inline" style={{ justifyContent: "flex-end", gap: 8 }}>
                  <button
                    type="button"
                    className="btn-secondary"
                    disabled={serviceActionModal.busy}
                    onClick={() => setServiceActionModal({ open: false, action: "", busy: false, error: "" })}
                  >
                    Отмена
                  </button>
                  <button type="button" disabled={serviceActionModal.busy} onClick={submitServiceAction}>
                    {serviceActionModal.busy ? "Выполняется…" : "Подтвердить"}
                  </button>
                </div>
              </div>
            </div>
          ) : null}
          {taskRetryModal.open ? (
            <div
              className="modal-backdrop"
              role="presentation"
              onClick={(e) => {
                if (e.target === e.currentTarget && !taskRetryModal.busy) {
                  setTaskRetryModal({ open: false, taskId: "", taskType: "", busy: false, error: "" });
                }
              }}
            >
              <div className="modal-dialog" role="dialog" aria-modal="true" aria-labelledby="task-retry-modal-title">
                <div className="modal-dialog-header">
                  <h2 id="task-retry-modal-title" className="modal-dialog-title">
                    Повтор задачи
                  </h2>
                  <button
                    type="button"
                    className="modal-close"
                    aria-label="Закрыть"
                    disabled={taskRetryModal.busy}
                    onClick={() => setTaskRetryModal({ open: false, taskId: "", taskType: "", busy: false, error: "" })}
                  >
                    ×
                  </button>
                </div>
                <p className="modal-dialog-body-text">
                  Поставить задачу в очередь повторно?
                  {taskRetryModal.taskType ? (
                    <>
                      {" "}
                      Тип: <span className="app-table-mono">{taskRetryModal.taskType}</span>
                    </>
                  ) : null}
                </p>
                {taskRetryModal.error ? (
                  <div className="auth-alert auth-alert--error" role="alert">
                    {taskRetryModal.error}
                  </div>
                ) : null}
                <div className="row-inline" style={{ justifyContent: "flex-end", gap: 8 }}>
                  <button
                    type="button"
                    className="btn-secondary"
                    disabled={taskRetryModal.busy}
                    onClick={() => setTaskRetryModal({ open: false, taskId: "", taskType: "", busy: false, error: "" })}
                  >
                    Отмена
                  </button>
                  <button type="button" disabled={taskRetryModal.busy} onClick={() => void submitTaskRetryFromModal()}>
                    {taskRetryModal.busy ? "Выполняется…" : "Подтвердить"}
                  </button>
                </div>
              </div>
            </div>
          ) : null}
          {systemUnitActionModal.open ? (
            <div
              className="modal-backdrop"
              role="presentation"
              onClick={(e) => {
                if (e.target === e.currentTarget && !systemUnitActionModal.busy) {
                  setSystemUnitActionModal({ open: false, unit: "", action: "", busy: false, error: "" });
                }
              }}
            >
              <div className="modal-dialog" role="dialog" aria-modal="true" aria-labelledby="system-unit-action-modal-title">
                <div className="modal-dialog-header">
                  <h2 id="system-unit-action-modal-title" className="modal-dialog-title">
                    Управление службой
                  </h2>
                  <button
                    type="button"
                    className="modal-close"
                    aria-label="Закрыть"
                    disabled={systemUnitActionModal.busy}
                    onClick={() =>
                      setSystemUnitActionModal({ open: false, unit: "", action: "", busy: false, error: "" })
                    }
                  >
                    ×
                  </button>
                </div>
                <p className="modal-dialog-body-text">
                  Выполнить{" "}
                  <strong>
                    {systemUnitActionModal.action === "start"
                      ? "запуск"
                      : systemUnitActionModal.action === "stop"
                        ? "остановку"
                        : "перезапуск"}
                  </strong>{" "}
                  службы <span className="app-table-mono">{systemUnitActionModal.unit || "—"}</span> на узле через{" "}
                  <span className="app-table-mono">systemctl</span>?
                </p>
                {systemUnitActionModal.error ? (
                  <div className="auth-alert auth-alert--error" role="alert">
                    {systemUnitActionModal.error}
                  </div>
                ) : null}
                <div className="row-inline" style={{ justifyContent: "flex-end", gap: 8 }}>
                  <button
                    type="button"
                    className="btn-secondary"
                    disabled={systemUnitActionModal.busy}
                    onClick={() =>
                      setSystemUnitActionModal({ open: false, unit: "", action: "", busy: false, error: "" })
                    }
                  >
                    Отмена
                  </button>
                  <button type="button" disabled={systemUnitActionModal.busy} onClick={() => void submitSystemUnitActionFromModal()}>
                    {systemUnitActionModal.busy ? "Выполняется…" : "Подтвердить"}
                  </button>
                </div>
              </div>
            </div>
          ) : null}
          {agentUpdateModalOpen ? (
            <div
              className="modal-backdrop"
              role="presentation"
              onClick={(e) => {
                if (e.target === e.currentTarget && !agentUpdateBusy) {
                  setAgentUpdateModalOpen(false);
                }
              }}
            >
              <div
                className="modal-dialog modal-dialog--wide"
                role="dialog"
                aria-modal="true"
                aria-labelledby="agent-update-modal-title"
              >
                <div className="modal-dialog-header">
                  <h2 id="agent-update-modal-title" className="modal-dialog-title">
                    Обновление агента
                  </h2>
                  <button
                    type="button"
                    className="modal-close"
                    aria-label="Закрыть"
                    disabled={agentUpdateBusy}
                    onClick={() => {
                      if (!agentUpdateBusy) setAgentUpdateModalOpen(false);
                    }}
                  >
                    ×
                  </button>
                </div>
                <p className="modal-dialog-body-text">
                  Выберите новый бинарник агента. На узел отправляются файл (Base64) и контрольная сумма SHA-256, затем на
                  узле выполняется замена бинарника и перезапуск службы агента.
                </p>
                <div className="user-profile-field-block" style={{ marginTop: 12 }}>
                  <div className="user-profile-field-label">Файл</div>
                  <input
                    type="file"
                    disabled={agentUpdateBusy}
                    onChange={async (e) => {
                      const f = e.target.files?.[0];
                      e.target.value = "";
                      setAgentUpdateError("");
                      setAgentUpdateResult("");
                      setAgentUpdateJournalTail("");
                      setAgentUpdateUploadPct(0);
                      if (!f) {
                        setAgentUpdateFileName("");
                        setAgentUpdateSha256("");
                        setAgentUpdateBinaryBase64("");
                        return;
                      }
                      try {
                        const { base64, sha256 } = await fileToBase64AndSha256(f);
                        setAgentUpdateFileName(f.name);
                        setAgentUpdateSha256(sha256);
                        setAgentUpdateBinaryBase64(base64);
                      } catch (err) {
                        setAgentUpdateFileName("");
                        setAgentUpdateSha256("");
                        setAgentUpdateBinaryBase64("");
                        setAgentUpdateError(err?.message || String(err));
                      }
                    }}
                  />
                  {agentUpdateFileName ? (
                    <p className="user-profile-field-hint" style={{ marginTop: 8 }}>
                      Файл: <span className="app-table-mono">{agentUpdateFileName}</span> · SHA-256:{" "}
                      <span className="app-table-mono">{agentUpdateSha256}</span>
                    </p>
                  ) : null}
                </div>
                <div className="agent-update-progress-stack">
                  <div className="agent-update-progress-block">
                    <div className="agent-update-progress-label">Отправка на узел</div>
                    <div
                      className="agent-update-progress-track"
                      role="progressbar"
                      aria-valuemin={0}
                      aria-valuemax={100}
                      aria-valuenow={agentUpdateUploadPct}
                    >
                      <div className="agent-update-progress-fill" style={{ width: `${agentUpdateUploadPct}%` }} />
                    </div>
                  </div>
                </div>
                {agentUpdateError ? (
                  <div className="auth-alert auth-alert--error" role="alert">
                    {agentUpdateError}
                  </div>
                ) : null}
                {agentUpdateResult ? (
                  <div className="auth-alert auth-alert--success" role="status">
                    {agentUpdateResult}
                  </div>
                ) : null}
                {agentUpdateJournalTail ? (
                  <div className="user-profile-field-block" style={{ marginTop: 12 }}>
                    <div className="user-profile-field-label">Журнал службы агента (до перезапуска)</div>
                    <pre className="agent-update-journal-pre" tabIndex={0}>
                      {agentUpdateJournalTail}
                    </pre>
                  </div>
                ) : null}
                <div className="row-inline" style={{ justifyContent: "flex-end", gap: 8, marginTop: 16, flexWrap: "wrap" }}>
                  <button
                    type="button"
                    className="btn-secondary"
                    disabled={agentUpdateBusy}
                    onClick={() => {
                      if (!agentUpdateBusy) setAgentUpdateModalOpen(false);
                    }}
                  >
                    Закрыть
                  </button>
                  <button
                    type="button"
                    disabled={agentUpdateBusy || !agentUpdateBinaryBase64 || !selectedServerId}
                    onClick={() => void submitAgentUpdate()}
                  >
                    {agentUpdateBusy ? "Отправка…" : "Отправить на узел"}
                  </button>
                </div>
              </div>
            </div>
          ) : null}
          {serverKeyMaterialModal.mode === "import" && serverKeyMaterialModal.kind && selectedServerId ? (
            <div
              className="modal-backdrop"
              role="presentation"
              onClick={(e) => {
                if (e.target === e.currentTarget && !serverKeyMaterialModal.busy) {
                  setServerKeyMaterialModal({ mode: null, kind: null, busy: false, error: "", importPem: "" });
                }
              }}
            >
              <div
                className="modal-dialog"
                role="dialog"
                aria-modal="true"
                aria-labelledby="server-key-import-modal-title"
                onClick={(e) => e.stopPropagation()}
              >
                <div className="modal-dialog-header">
                  <h2 id="server-key-import-modal-title" className="modal-dialog-title">
                    {serverKeyMaterialModal.kind === "dh" ? "Импорт DH" : "Импорт ключа tls-auth"}
                  </h2>
                  <button
                    type="button"
                    className="modal-close"
                    aria-label="Закрыть"
                    disabled={serverKeyMaterialModal.busy}
                    onClick={() =>
                      setServerKeyMaterialModal({ mode: null, kind: null, busy: false, error: "", importPem: "" })
                    }
                  >
                    ×
                  </button>
                </div>
                <p className="modal-dialog-body-text" style={{ marginTop: 0 }}>
                  {serverKeyMaterialModal.kind === "dh"
                    ? "Вставьте PEM с блоком BEGIN DH PARAMETERS или выберите файл (результат openssl dhparam)."
                    : "Вставьте содержимое ta.key (BEGIN OpenVPN Static key V1) или выберите файл."}
                </p>
                <input
                  ref={serverKeyImportFileRef}
                  type="file"
                  accept=".pem,.key,.txt,text/*,*/*"
                  style={{ display: "none" }}
                  onChange={(e) => {
                    const f = e.target.files?.[0];
                    e.target.value = "";
                    if (!f) return;
                    const reader = new FileReader();
                    reader.onload = () =>
                      setServerKeyMaterialModal((prev) => ({
                        ...prev,
                        importPem: String(reader.result ?? ""),
                      }));
                    reader.readAsText(f);
                  }}
                />
                <div className="row-inline" style={{ gap: 8, marginBottom: 10 }}>
                  <button
                    type="button"
                    className="btn-secondary"
                    disabled={serverKeyMaterialModal.busy}
                    onClick={() => serverKeyImportFileRef.current?.click()}
                  >
                    Выбрать файл…
                  </button>
                </div>
                <textarea
                  rows={10}
                  className="app-filter-input"
                  style={{ width: "100%", fontFamily: "ui-monospace, monospace", fontSize: 12 }}
                  value={serverKeyMaterialModal.importPem}
                  onChange={(e) =>
                    setServerKeyMaterialModal((prev) => ({ ...prev, importPem: e.target.value, error: "" }))
                  }
                  placeholder="-----BEGIN …"
                />
                {serverKeyMaterialModal.error ? (
                  <div className="auth-alert auth-alert--error" role="alert" style={{ marginTop: 8 }}>
                    {serverKeyMaterialModal.error}
                  </div>
                ) : null}
                <div className="row-inline" style={{ justifyContent: "flex-end", gap: 8, marginTop: 16 }}>
                  <button
                    type="button"
                    className="btn-secondary"
                    disabled={serverKeyMaterialModal.busy}
                    onClick={() =>
                      setServerKeyMaterialModal({ mode: null, kind: null, busy: false, error: "", importPem: "" })
                    }
                  >
                    Отмена
                  </button>
                  <button
                    type="button"
                    disabled={serverKeyMaterialModal.busy || !String(serverKeyMaterialModal.importPem || "").trim()}
                    onClick={async () => {
                      if (!tokenRef.current || !selectedServerId || !serverKeyMaterialModal.kind) return;
                      setServerKeyMaterialModal((prev) => ({ ...prev, busy: true, error: "" }));
                      try {
                        const created = await request(
                          `/api/panel/nodes/${encodeURIComponent(selectedServerId)}/openvpn-materials`,
                          "POST",
                          tokenRef.current,
                          { kind: serverKeyMaterialModal.kind, pem: serverKeyMaterialModal.importPem },
                        );
                        if (created?.id) {
                          const partial =
                            serverKeyMaterialModal.kind === "dh"
                              ? {
                                  panelDhMaterialId: created.id,
                                  dh: String(serverOpenVpnSettings.dh || "").trim() || "/etc/openvpn/dh.pem",
                                }
                              : {
                                  panelTlsAuthMaterialId: created.id,
                                  "tls-auth":
                                    String(serverOpenVpnSettings["tls-auth"] || "").trim() ||
                                    "/etc/openvpn/ta.key 0",
                                };
                          await persistOpenVpnPanelPartial(partial);
                        }
                        await refreshServerNodeOpenvpnMaterials(selectedServerId);
                        await loadData(PANEL_DATA_REFRESH.certificates);
                        setServerKeyMaterialModal({ mode: null, kind: null, busy: false, error: "", importPem: "" });
                      } catch (err) {
                        setServerKeyMaterialModal((prev) => ({
                          ...prev,
                          busy: false,
                          error: err.message || "Импорт не удался",
                        }));
                      }
                    }}
                  >
                    {serverKeyMaterialModal.busy ? "Импорт…" : "Импортировать"}
                  </button>
                </div>
              </div>
            </div>
          ) : null}
          {serverKeyMaterialModal.mode === "create" && serverKeyMaterialModal.kind && selectedServerId ? (
            <div
              className="modal-backdrop"
              role="presentation"
              onClick={(e) => {
                if (e.target === e.currentTarget && !serverKeyMaterialModal.busy) {
                  setServerKeyMaterialModal({ mode: null, kind: null, busy: false, error: "", importPem: "" });
                }
              }}
            >
              <div
                className="modal-dialog"
                role="dialog"
                aria-modal="true"
                aria-labelledby="server-key-create-modal-title"
                onClick={(e) => e.stopPropagation()}
              >
                <div className="modal-dialog-header">
                  <h2 id="server-key-create-modal-title" className="modal-dialog-title">
                    {serverKeyMaterialModal.kind === "dh" ? "Создание DH" : "Создание ключа tls-auth"}
                  </h2>
                  <button
                    type="button"
                    className="modal-close"
                    aria-label="Закрыть"
                    disabled={serverKeyMaterialModal.busy}
                    onClick={() =>
                      setServerKeyMaterialModal({ mode: null, kind: null, busy: false, error: "", importPem: "" })
                    }
                  >
                    ×
                  </button>
                </div>
                <p className="modal-dialog-body-text" style={{ marginTop: 0 }}>
                  {serverKeyMaterialModal.kind === "dh"
                    ? "Будет сгенерирован новый набор параметров DH (2048 бит) и сохранён для этого узла."
                    : "Будет сгенерирован новый статический ключ OpenVPN (tls-auth) и сохранён для этого узла."}
                </p>
                {serverKeyMaterialModal.error ? (
                  <div className="auth-alert auth-alert--error" role="alert">
                    {serverKeyMaterialModal.error}
                  </div>
                ) : null}
                <div className="row-inline" style={{ justifyContent: "flex-end", gap: 8, marginTop: 16 }}>
                  <button
                    type="button"
                    className="btn-secondary"
                    disabled={serverKeyMaterialModal.busy}
                    onClick={() =>
                      setServerKeyMaterialModal({ mode: null, kind: null, busy: false, error: "", importPem: "" })
                    }
                  >
                    Отмена
                  </button>
                  <button
                    type="button"
                    disabled={serverKeyMaterialModal.busy}
                    onClick={async () => {
                      if (!tokenRef.current || !selectedServerId || !serverKeyMaterialModal.kind) return;
                      setServerKeyMaterialModal((prev) => ({ ...prev, busy: true, error: "" }));
                      try {
                        const created = await request(
                          `/api/panel/nodes/${encodeURIComponent(selectedServerId)}/openvpn-materials`,
                          "POST",
                          tokenRef.current,
                          { kind: serverKeyMaterialModal.kind },
                        );
                        if (created?.id) {
                          const partial =
                            serverKeyMaterialModal.kind === "dh"
                              ? {
                                  panelDhMaterialId: created.id,
                                  dh: String(serverOpenVpnSettings.dh || "").trim() || "/etc/openvpn/dh.pem",
                                }
                              : {
                                  panelTlsAuthMaterialId: created.id,
                                  "tls-auth":
                                    String(serverOpenVpnSettings["tls-auth"] || "").trim() ||
                                    "/etc/openvpn/ta.key 0",
                                };
                          await persistOpenVpnPanelPartial(partial);
                        }
                        await refreshServerNodeOpenvpnMaterials(selectedServerId);
                        await loadData(PANEL_DATA_REFRESH.certificates);
                        setServerKeyMaterialModal({ mode: null, kind: null, busy: false, error: "", importPem: "" });
                      } catch (err) {
                        setServerKeyMaterialModal((prev) => ({
                          ...prev,
                          busy: false,
                          error: err.message || "Не удалось создать",
                        }));
                      }
                    }}
                  >
                    {serverKeyMaterialModal.busy ? "Создание…" : "Создать"}
                  </button>
                </div>
              </div>
            </div>
          ) : null}
          {openvpnMaterialDeleteModal.open && openvpnMaterialDeleteModal.id && selectedServerId ? (
            <div
              className="modal-backdrop"
              role="presentation"
              onClick={(e) => {
                if (e.target === e.currentTarget && !openvpnMaterialDeleteModal.busy) {
                  setOpenvpnMaterialDeleteModal({ open: false, id: null, kindLabel: "", busy: false, error: "" });
                }
              }}
            >
              <div
                className="modal-dialog modal-dialog--wide"
                role="dialog"
                aria-modal="true"
                aria-labelledby="openvpn-material-delete-title"
                onClick={(e) => e.stopPropagation()}
              >
                <div className="modal-dialog-header">
                  <h2 id="openvpn-material-delete-title" className="modal-dialog-title">
                    Удаление {openvpnMaterialDeleteModal.kindLabel || "материала"}
                  </h2>
                  <button
                    type="button"
                    className="modal-close"
                    aria-label="Закрыть"
                    disabled={openvpnMaterialDeleteModal.busy}
                    onClick={() =>
                      setOpenvpnMaterialDeleteModal({ open: false, id: null, kindLabel: "", busy: false, error: "" })
                    }
                  >
                    ×
                  </button>
                </div>
                <p className="modal-dialog-body-text" style={{ marginTop: 0 }}>
                  {openvpnMaterialDeleteModal.kindLabel === "DH"
                    ? "Параметры DH будут безвозвратно удалены на панели; в настройках узла сбросится привязка к этому материалу, если она была задана. Продолжайте только если осознаёте последствия."
                    : openvpnMaterialDeleteModal.kindLabel === "TLS-auth"
                      ? "Статический ключ tls-auth будет безвозвратно удалён на панели; в настройках узла сбросится привязка к этому материалу, если она была задана. Продолжайте только если осознаёте последствия."
                      : "Материал будет безвозвратно удалён на панели; в настройках узла сбросится привязка, если она была задана. Продолжайте только если осознаёте последствия."}
                </p>
                {openvpnMaterialDeleteModal.error ? (
                  <div className="auth-alert auth-alert--error" role="alert">
                    {openvpnMaterialDeleteModal.error}
                  </div>
                ) : null}
                <div className="row-inline" style={{ justifyContent: "flex-end", gap: 8, marginTop: 16 }}>
                  <button
                    type="button"
                    className="btn-secondary"
                    disabled={openvpnMaterialDeleteModal.busy}
                    onClick={() =>
                      setOpenvpnMaterialDeleteModal({ open: false, id: null, kindLabel: "", busy: false, error: "" })
                    }
                  >
                    Отмена
                  </button>
                  <button
                    type="button"
                    className="btn-danger"
                    disabled={openvpnMaterialDeleteModal.busy}
                    onClick={() => void submitDeleteOpenvpnMaterial()}
                  >
                    {openvpnMaterialDeleteModal.busy ? "Удаление…" : "Удалить безвозвратно"}
                  </button>
                </div>
              </div>
            </div>
          ) : null}
          {serverOpenVpnClientDeleteVersionModal.open ? (
            <div
              className="modal-backdrop"
              role="presentation"
              onClick={(e) => {
                if (e.target === e.currentTarget && !serverOpenVpnClientDeleteVersionModal.busy) {
                  setServerOpenVpnClientDeleteVersionModal({
                    open: false,
                    versionId: "",
                    versionLabel: "",
                    busy: false,
                    error: "",
                  });
                }
              }}
            >
              <div
                className="modal-dialog"
                role="dialog"
                aria-modal="true"
                aria-labelledby="openvpn-client-version-delete-title"
                onClick={(e) => e.stopPropagation()}
              >
                <div className="modal-dialog-header">
                  <h2 id="openvpn-client-version-delete-title" className="modal-dialog-title">
                    Удалить конфигурацию клиента
                  </h2>
                  <button
                    type="button"
                    className="modal-close"
                    aria-label="Закрыть"
                    disabled={serverOpenVpnClientDeleteVersionModal.busy}
                    onClick={() =>
                      setServerOpenVpnClientDeleteVersionModal({
                        open: false,
                        versionId: "",
                        versionLabel: "",
                        busy: false,
                        error: "",
                      })
                    }
                  >
                    ×
                  </button>
                </div>
                <p className="modal-dialog-body-text" style={{ marginTop: 0 }}>
                  Удалить сохраненную конфигурацию клиента `{serverOpenVpnClientDeleteVersionModal.versionLabel}`?
                </p>
                {serverOpenVpnClientDeleteVersionModal.error ? (
                  <div className="auth-alert auth-alert--error" role="alert">
                    {serverOpenVpnClientDeleteVersionModal.error}
                  </div>
                ) : null}
                <div className="row-inline" style={{ justifyContent: "flex-end", gap: 8, marginTop: 16 }}>
                  <button
                    type="button"
                    className="btn-secondary"
                    disabled={serverOpenVpnClientDeleteVersionModal.busy}
                    onClick={() =>
                      setServerOpenVpnClientDeleteVersionModal({
                        open: false,
                        versionId: "",
                        versionLabel: "",
                        busy: false,
                        error: "",
                      })
                    }
                  >
                    Отмена
                  </button>
                  <button
                    type="button"
                    className="btn-danger"
                    disabled={serverOpenVpnClientDeleteVersionModal.busy}
                    onClick={() => void deleteServerOpenVpnClientVersion()}
                  >
                    {serverOpenVpnClientDeleteVersionModal.busy ? "Удаление..." : "Удалить"}
                  </button>
                </div>
              </div>
            </div>
          ) : null}
          {serverOpenVpnClientApplyConfirmModal.open ? (
            <div
              className="modal-backdrop"
              role="presentation"
              onClick={(e) => {
                if (e.target === e.currentTarget && !serverOpenVpnClientApplyConfirmModal.busy) {
                  setServerOpenVpnClientApplyConfirmModal({ open: false, busy: false, error: "" });
                }
              }}
            >
              <div
                className="modal-dialog"
                role="dialog"
                aria-modal="true"
                aria-labelledby="openvpn-client-apply-confirm-title"
                onClick={(e) => e.stopPropagation()}
              >
                <div className="modal-dialog-header">
                  <h2 id="openvpn-client-apply-confirm-title" className="modal-dialog-title">
                    Применить конфигурацию клиента
                  </h2>
                  <button
                    type="button"
                    className="modal-close"
                    aria-label="Закрыть"
                    disabled={serverOpenVpnClientApplyConfirmModal.busy}
                    onClick={() => setServerOpenVpnClientApplyConfirmModal({ open: false, busy: false, error: "" })}
                  >
                    ×
                  </button>
                </div>
                <p className="modal-dialog-body-text" style={{ marginTop: 0 }}>
                  Подтвердите применение новой конфигурации клиента.
                </p>
                <p className="modal-dialog-body-text">
                  Изменения затронут только новых клиентов и новые генерации конфигурационных файлов для клиентов.
                </p>
                {serverOpenVpnClientApplyConfirmModal.error ? (
                  <div className="auth-alert auth-alert--error" role="alert">
                    {serverOpenVpnClientApplyConfirmModal.error}
                  </div>
                ) : null}
                <div className="row-inline" style={{ justifyContent: "flex-end", gap: 8, marginTop: 16 }}>
                  <button
                    type="button"
                    className="btn-secondary"
                    disabled={serverOpenVpnClientApplyConfirmModal.busy}
                    onClick={() => setServerOpenVpnClientApplyConfirmModal({ open: false, busy: false, error: "" })}
                  >
                    Отмена
                  </button>
                  <button
                    type="button"
                    disabled={serverOpenVpnClientApplyConfirmModal.busy}
                    onClick={() => void applyServerOpenVpnClientSettings()}
                  >
                    {serverOpenVpnClientApplyConfirmModal.busy ? "Применение..." : "Применить"}
                  </button>
                </div>
              </div>
            </div>
          ) : null}
          {serverOpenVpnApplyConfirmModal.open ? (
            <div
              className="modal-backdrop"
              role="presentation"
              onClick={(e) => {
                if (e.target === e.currentTarget && !serverOpenVpnApplying) {
                  setServerOpenVpnApplyConfirmModal({ open: false, done: false });
                }
              }}
            >
              <div
                className="modal-dialog"
                role="dialog"
                aria-modal="true"
                aria-labelledby="openvpn-apply-confirm-title"
                onClick={(e) => e.stopPropagation()}
              >
                <div className="modal-dialog-header">
                  <h2 id="openvpn-apply-confirm-title" className="modal-dialog-title">
                    Подтверждение применения
                  </h2>
                  <button
                    type="button"
                    className="modal-close"
                    aria-label="Закрыть"
                    disabled={serverOpenVpnApplying}
                    onClick={() => setServerOpenVpnApplyConfirmModal({ open: false, done: false })}
                  >
                    ×
                  </button>
                </div>
                <p className="modal-dialog-body-text" style={{ marginTop: 0 }}>
                  Применение конфигурации перезапустит службу OpenVPN. Продолжить?
                </p>
                {serverOpenVpnApplyResult.status === "success" ? (
                  <div className="auth-alert auth-alert--success" role="status">
                    {serverOpenVpnApplyResult.message}
                  </div>
                ) : null}
                {serverOpenVpnApplyResult.status === "error" ? (
                  <div className="auth-alert auth-alert--error" role="alert">
                    {serverOpenVpnApplyResult.message}
                  </div>
                ) : null}
                {serverOpenVpnApplyLogVisible ? (
                  <pre className="openvpn-check-error-box server-openvpn-apply-log-box">
                    {String(serverOpenVpnApplyLog || "").trim() || "(нет вывода)"}
                  </pre>
                ) : null}
                {serverOpenVpnApplyConfirmModal.done ? (
                  <div className="row-inline" style={{ justifyContent: "flex-end", gap: 8, marginTop: 16 }}>
                    <button
                      type="button"
                      onClick={() => setServerOpenVpnApplyConfirmModal({ open: false, done: false })}
                    >
                      Закрыть
                    </button>
                  </div>
                ) : (
                  <div className="row-inline" style={{ justifyContent: "flex-end", gap: 8, marginTop: 16 }}>
                    <button
                      type="button"
                      className="btn-secondary"
                      disabled={serverOpenVpnApplying}
                      onClick={() => setServerOpenVpnApplyConfirmModal({ open: false, done: false })}
                    >
                      Отмена
                    </button>
                    <button
                      type="button"
                      disabled={serverOpenVpnApplying}
                      onClick={async () => {
                        try {
                          await applyServerOpenVpnSettings();
                          setServerOpenVpnApplyConfirmModal((prev) => ({ ...prev, done: true }));
                        } catch {
                          /* error state already shown in modal */
                        }
                      }}
                    >
                      {serverOpenVpnApplying ? "Применение..." : "Подтвердить"}
                    </button>
                  </div>
                )}
              </div>
            </div>
          ) : null}
          {serverOpenVpnSaveModal.open ? (
            <div
              className="modal-backdrop"
              role="presentation"
              onClick={(e) => {
                if (e.target === e.currentTarget) {
                  setServerOpenVpnSaveModal({ open: false, text: "" });
                }
              }}
            >
              <div
                className="modal-dialog"
                role="dialog"
                aria-modal="true"
                aria-labelledby="openvpn-save-modal-title"
                onClick={(e) => e.stopPropagation()}
              >
                <div className="modal-dialog-header">
                  <h2 id="openvpn-save-modal-title" className="modal-dialog-title">
                    Сохранение настроек
                  </h2>
                  <button
                    type="button"
                    className="modal-close"
                    aria-label="Закрыть"
                    onClick={() => setServerOpenVpnSaveModal({ open: false, text: "" })}
                  >
                    ×
                  </button>
                </div>
                <div className="auth-alert auth-alert--success" role="status">
                  {serverOpenVpnSaveModal.text || "Настройки сохранены на панели."}
                </div>
                <div className="row-inline" style={{ justifyContent: "flex-end", gap: 8, marginTop: 16 }}>
                  <button type="button" onClick={() => setServerOpenVpnSaveModal({ open: false, text: "" })}>
                    OK
                  </button>
                </div>
              </div>
            </div>
          ) : null}
          {srvCertCreateModal.open && selectedServerId ? (
            <div
              className="modal-backdrop"
              role="presentation"
              onClick={(e) => {
                if (e.target === e.currentTarget && !srvCertCreateModal.busy) {
                  setSrvCertCreateModal({
                    open: false,
                    cn: "",
                    validityDays: 825,
                    keySize: "2048",
                    signatureAlgorithm: "sha256",
                    busy: false,
                    error: "",
                  });
                }
              }}
            >
              <div
                className="modal-dialog modal-dialog--wide"
                role="dialog"
                aria-modal="true"
                aria-labelledby="srv-cert-create-title"
                onClick={(e) => e.stopPropagation()}
              >
                <div className="modal-dialog-header">
                  <h2 id="srv-cert-create-title" className="modal-dialog-title">
                    Новый сертификат сервера
                  </h2>
                  <button
                    type="button"
                    className="modal-close"
                    aria-label="Закрыть"
                    disabled={srvCertCreateModal.busy}
                    onClick={() =>
                      setSrvCertCreateModal({
                        open: false,
                        cn: "",
                        validityDays: 825,
                        keySize: "2048",
                        signatureAlgorithm: "sha256",
                        busy: false,
                        error: "",
                      })
                    }
                  >
                    ×
                  </button>
                </div>
                <p className="modal-dialog-body-text" style={{ marginTop: 0 }}>
                  Корневой сертификат: {serverPanelRootCa?.name || serverPanelRootCa?.commonName || "—"}. Срок не может
                  превышать оставшееся время действия корневого сертификата: не более {keysMaxServerCertValidityDays}{" "}
                  сут.
                </p>
                <div className="user-profile-field-block" style={{ marginTop: 12 }}>
                  <div className="user-profile-field-label">Subject CN</div>
                  <input
                    type="text"
                    value={srvCertCreateModal.cn}
                    onChange={(e) => setSrvCertCreateModal((prev) => ({ ...prev, cn: e.target.value }))}
                    style={{ width: "100%", maxWidth: "100%", minWidth: 0 }}
                    disabled={srvCertCreateModal.busy}
                  />
                </div>
                <div className="user-profile-field-block" style={{ marginTop: 12 }}>
                  <div className="user-profile-field-label">Длина ключа RSA, бит</div>
                  <select
                    value={srvCertCreateModal.keySize}
                    onChange={(e) => setSrvCertCreateModal((prev) => ({ ...prev, keySize: e.target.value }))}
                    style={{ width: "100%", maxWidth: "100%", minWidth: 0 }}
                    disabled={srvCertCreateModal.busy}
                  >
                    <option value="2048">2048</option>
                    <option value="3072">3072</option>
                    <option value="4096">4096</option>
                  </select>
                </div>
                <div className="user-profile-field-block" style={{ marginTop: 12 }}>
                  <div className="user-profile-field-label">Алгоритм подписи сертификата</div>
                  <select
                    value={srvCertCreateModal.signatureAlgorithm}
                    onChange={(e) =>
                      setSrvCertCreateModal((prev) => ({ ...prev, signatureAlgorithm: e.target.value }))
                    }
                    style={{ width: "100%", maxWidth: "100%", minWidth: 0 }}
                    disabled={srvCertCreateModal.busy}
                  >
                    <option value="sha256">SHA-256</option>
                    <option value="sha384">SHA-384</option>
                    <option value="sha512">SHA-512</option>
                  </select>
                </div>
                <div className="user-profile-field-block" style={{ marginTop: 12 }}>
                  <div className="user-profile-field-label">Срок действия, суток</div>
                  <input
                    type="number"
                    min={1}
                    max={Math.max(1, keysMaxServerCertValidityDays)}
                    value={srvCertCreateModal.validityDays}
                    onChange={(e) => {
                      const raw = Math.floor(Number(e.target.value) || 0);
                      const cap = Math.max(1, keysMaxServerCertValidityDays);
                      setSrvCertCreateModal((prev) => ({
                        ...prev,
                        validityDays: Math.min(cap, Math.max(1, raw || 1)),
                      }));
                    }}
                    style={{ width: "100%", maxWidth: "100%", minWidth: 0 }}
                    disabled={srvCertCreateModal.busy}
                  />
                </div>
                {srvCertCreateModal.error ? (
                  <div className="auth-alert auth-alert--error" role="alert">
                    {srvCertCreateModal.error}
                  </div>
                ) : null}
                <div className="row-inline" style={{ justifyContent: "flex-end", gap: 8, marginTop: 16 }}>
                  <button
                    type="button"
                    className="btn-secondary"
                    disabled={srvCertCreateModal.busy}
                    onClick={() =>
                      setSrvCertCreateModal({
                        open: false,
                        cn: "",
                        validityDays: 825,
                        keySize: "2048",
                        signatureAlgorithm: "sha256",
                        busy: false,
                        error: "",
                      })
                    }
                  >
                    Отмена
                  </button>
                  <button type="button" disabled={srvCertCreateModal.busy} onClick={() => void submitSrvCertCreate()}>
                    {srvCertCreateModal.busy ? "Выпуск…" : "Выпустить"}
                  </button>
                </div>
              </div>
            </div>
          ) : null}
          {serverCaIssueModal.open && selectedServerId ? (
            <div
              className="modal-backdrop"
              role="presentation"
              onClick={(e) => {
                if (e.target === e.currentTarget && !serverCaIssueModal.busy) {
                  setServerCaIssueModal({
                    open: false,
                    commonName: "",
                    validityDays: "365",
                    busy: false,
                    error: "",
                  });
                }
              }}
            >
              <div
                className="modal-dialog modal-dialog--wide"
                role="dialog"
                aria-modal="true"
                aria-labelledby="server-ca-issue-title"
                onClick={(e) => e.stopPropagation()}
              >
                <div className="modal-dialog-header">
                  <h2 id="server-ca-issue-title" className="modal-dialog-title">
                    Выпустить сертификат
                  </h2>
                  <button
                    type="button"
                    className="modal-close"
                    aria-label="Закрыть"
                    disabled={serverCaIssueModal.busy}
                    onClick={() =>
                      setServerCaIssueModal({
                        open: false,
                        commonName: "",
                        validityDays: "365",
                        busy: false,
                        error: "",
                      })
                    }
                  >
                    ×
                  </button>
                </div>
                <p className="modal-dialog-body-text" style={{ marginTop: 0 }}>
                  Корневой сертификат: {serverPanelRootCa?.name || serverPanelRootCa?.commonName || "—"}.
                </p>
                <div className="user-profile-field-block" style={{ marginTop: 12 }}>
                  <div className="user-profile-field-label">Subject CN</div>
                  <input
                    value={serverCaIssueModal.commonName}
                    onChange={(e) => setServerCaIssueModal((prev) => ({ ...prev, commonName: e.target.value }))}
                    disabled={serverCaIssueModal.busy}
                    style={{ width: "100%", maxWidth: "100%", minWidth: 0 }}
                  />
                </div>
                <div className="user-profile-field-block" style={{ marginTop: 12 }}>
                  <div className="user-profile-field-label">Срок действия, суток</div>
                  <input
                    type="number"
                    min={1}
                    max={36500}
                    value={serverCaIssueModal.validityDays}
                    onChange={(e) => setServerCaIssueModal((prev) => ({ ...prev, validityDays: e.target.value }))}
                    disabled={serverCaIssueModal.busy}
                    style={{ width: "100%", maxWidth: "100%", minWidth: 0 }}
                  />
                </div>
                {serverCaIssueModal.error ? <p>{serverCaIssueModal.error}</p> : null}
                <div className="row-inline" style={{ justifyContent: "flex-end", gap: 8, marginTop: 16 }}>
                  <button
                    type="button"
                    className="btn-secondary"
                    disabled={serverCaIssueModal.busy}
                    onClick={() =>
                      setServerCaIssueModal({
                        open: false,
                        commonName: "",
                        validityDays: "365",
                        busy: false,
                        error: "",
                      })
                    }
                  >
                    Отмена
                  </button>
                  <button type="button" disabled={serverCaIssueModal.busy} onClick={() => void submitServerCaIssueCertificate()}>
                    {serverCaIssueModal.busy ? "Выпуск..." : "Выпустить"}
                  </button>
                </div>
              </div>
            </div>
          ) : null}
          {serverCaImportModal.open && selectedServerId ? (
            <div
              className="modal-backdrop"
              role="presentation"
              onClick={(e) => {
                if (e.target === e.currentTarget && !serverCaImportModal.busy) {
                  setServerCaImportModal({
                    open: false,
                    certPem: "",
                    keyPem: "",
                    busy: false,
                    error: "",
                  });
                }
              }}
            >
              <div
                className="modal-dialog modal-dialog--wide"
                role="dialog"
                aria-modal="true"
                aria-labelledby="server-ca-import-title"
                onClick={(e) => e.stopPropagation()}
              >
                <div className="modal-dialog-header">
                  <h2 id="server-ca-import-title" className="modal-dialog-title">
                    Импортировать сертификат
                  </h2>
                  <button
                    type="button"
                    className="modal-close"
                    aria-label="Закрыть"
                    disabled={serverCaImportModal.busy}
                    onClick={() =>
                      setServerCaImportModal({
                        open: false,
                        certPem: "",
                        keyPem: "",
                        busy: false,
                        error: "",
                      })
                    }
                  >
                    ×
                  </button>
                </div>
                <p className="modal-dialog-body-text" style={{ marginTop: 0 }}>
                  Корневой сертификат: {serverPanelRootCa?.name || serverPanelRootCa?.commonName || "—"}.
                  Будет проверено, что импортируемый сертификат подписан именно этим корневым.
                </p>
                <div className="user-profile-field-block" style={{ marginTop: 12 }}>
                  <div className="user-profile-field-label">Сертификат (PEM)</div>
                  <textarea
                    rows={8}
                    value={serverCaImportModal.certPem}
                    onChange={(e) => setServerCaImportModal((prev) => ({ ...prev, certPem: e.target.value, error: "" }))}
                    disabled={serverCaImportModal.busy}
                    style={{ width: "100%", maxWidth: "100%", minWidth: 0 }}
                    placeholder="-----BEGIN CERTIFICATE-----"
                  />
                </div>
                <div className="user-profile-field-block" style={{ marginTop: 12 }}>
                  <div className="user-profile-field-label">Приватный ключ (PEM)</div>
                  <textarea
                    rows={8}
                    value={serverCaImportModal.keyPem}
                    onChange={(e) => setServerCaImportModal((prev) => ({ ...prev, keyPem: e.target.value, error: "" }))}
                    disabled={serverCaImportModal.busy}
                    style={{ width: "100%", maxWidth: "100%", minWidth: 0 }}
                    placeholder="-----BEGIN PRIVATE KEY-----"
                  />
                </div>
                {serverCaImportModal.error ? <p>{serverCaImportModal.error}</p> : null}
                <div className="row-inline" style={{ justifyContent: "flex-end", gap: 8, marginTop: 16 }}>
                  <button
                    type="button"
                    className="btn-secondary"
                    disabled={serverCaImportModal.busy}
                    onClick={() =>
                      setServerCaImportModal({
                        open: false,
                        certPem: "",
                        keyPem: "",
                        busy: false,
                        error: "",
                      })
                    }
                  >
                    Отмена
                  </button>
                  <button type="button" disabled={serverCaImportModal.busy} onClick={() => void submitServerCaImportCertificate()}>
                    {serverCaImportModal.busy ? "Импорт..." : "Импортировать"}
                  </button>
                </div>
              </div>
            </div>
          ) : null}
          {serverCaIndexImportModal.open && selectedServerId ? (
            <div
              className="modal-backdrop"
              role="presentation"
              onClick={(e) => {
                if (e.target === e.currentTarget && !serverCaIndexImportModal.busy) {
                  setServerCaIndexImportModal({
                    open: false,
                    indexText: "",
                    busy: false,
                    error: "",
                  });
                }
              }}
            >
              <div
                className="modal-dialog modal-dialog--wide"
                role="dialog"
                aria-modal="true"
                aria-labelledby="server-ca-index-import-title"
                onClick={(e) => e.stopPropagation()}
              >
                <div className="modal-dialog-header">
                  <h2 id="server-ca-index-import-title" className="modal-dialog-title">
                    Загрузить индекс сертификатов
                  </h2>
                  <button
                    type="button"
                    className="modal-close"
                    aria-label="Закрыть"
                    disabled={serverCaIndexImportModal.busy}
                    onClick={() =>
                      setServerCaIndexImportModal({
                        open: false,
                        indexText: "",
                        busy: false,
                        error: "",
                      })
                    }
                  >
                    ×
                  </button>
                </div>
                <p className="modal-dialog-body-text" style={{ marginTop: 0 }}>
                  Вставьте содержимое файла index.txt. Будут импортированы выпущенные сертификаты для корневого
                  сертификата текущего сервера.
                </p>
                <div className="user-profile-field-block" style={{ marginTop: 12 }}>
                  <div className="user-profile-field-label">Файл index.txt</div>
                  <div className="row-inline" style={{ gap: 8, flexWrap: "wrap" }}>
                    <input
                      ref={serverCaIndexFileRef}
                      type="file"
                      accept=".txt,text/plain"
                      disabled={serverCaIndexImportModal.busy}
                      onChange={(e) => onServerCaIndexFileChange(e.target.files?.[0] || null)}
                    />
                    <button
                      type="button"
                      className="btn-secondary"
                      disabled={serverCaIndexImportModal.busy}
                      onClick={() => {
                        if (serverCaIndexFileRef.current) {
                          serverCaIndexFileRef.current.value = "";
                        }
                        setServerCaIndexImportModal((prev) => ({ ...prev, indexText: "", error: "" }));
                      }}
                    >
                      Очистить
                    </button>
                  </div>
                  <p className="user-profile-field-hint">
                    Можно выбрать файл или вставить содержимое вручную ниже.
                  </p>
                </div>
                <div className="user-profile-field-block" style={{ marginTop: 12 }}>
                  <div className="user-profile-field-label">index.txt</div>
                  <textarea
                    rows={12}
                    value={serverCaIndexImportModal.indexText}
                    onChange={(e) =>
                      setServerCaIndexImportModal((prev) => ({ ...prev, indexText: e.target.value, error: "" }))
                    }
                    disabled={serverCaIndexImportModal.busy}
                    style={{ width: "100%", maxWidth: "100%", minWidth: 0 }}
                    placeholder="V\t...\t...\tSERIAL\tunknown\t/CN=client-name"
                  />
                </div>
                {serverCaIndexImportModal.error ? <p>{serverCaIndexImportModal.error}</p> : null}
                <div className="row-inline" style={{ justifyContent: "flex-end", gap: 8, marginTop: 16 }}>
                  <button
                    type="button"
                    className="btn-secondary"
                    disabled={serverCaIndexImportModal.busy}
                    onClick={() =>
                      setServerCaIndexImportModal({
                        open: false,
                        indexText: "",
                        busy: false,
                        error: "",
                      })
                    }
                  >
                    Отмена
                  </button>
                  <button type="button" disabled={serverCaIndexImportModal.busy} onClick={() => void submitServerCaImportIndex()}>
                    {serverCaIndexImportModal.busy ? "Загрузка..." : "Загрузить"}
                  </button>
                </div>
              </div>
            </div>
          ) : null}
          {serverServerCertDeleteModal.open && selectedServerId ? (
            <div
              className="modal-backdrop"
              role="presentation"
              onClick={(e) => {
                if (e.target === e.currentTarget && !serverServerCertDeleteModal.busy) {
                  setServerServerCertDeleteModal({ open: false, busy: false, error: "" });
                }
              }}
            >
              <div
                className="modal-dialog modal-dialog--wide"
                role="dialog"
                aria-modal="true"
                aria-labelledby="server-server-cert-delete-title"
                onClick={(e) => e.stopPropagation()}
              >
                <div className="modal-dialog-header">
                  <h2 id="server-server-cert-delete-title" className="modal-dialog-title">
                    Удаление сертификата сервера
                  </h2>
                  <button
                    type="button"
                    className="modal-close"
                    aria-label="Закрыть"
                    disabled={serverServerCertDeleteModal.busy}
                    onClick={() => setServerServerCertDeleteModal({ open: false, busy: false, error: "" })}
                  >
                    ×
                  </button>
                </div>
                <p className="modal-dialog-body-text" style={{ marginTop: 0 }}>
                  Сертификат сервера и закрытый ключ будут безвозвратно удалены на панели; в настройках узла сбросится
                  привязка сертификата сервера. Продолжайте только если осознаёте последствия.
                </p>
                {serverServerCertDeleteModal.error ? (
                  <div className="auth-alert auth-alert--error" role="alert">
                    {serverServerCertDeleteModal.error}
                  </div>
                ) : null}
                <div className="row-inline" style={{ justifyContent: "flex-end", gap: 8, marginTop: 16 }}>
                  <button
                    type="button"
                    className="btn-secondary"
                    disabled={serverServerCertDeleteModal.busy}
                    onClick={() => setServerServerCertDeleteModal({ open: false, busy: false, error: "" })}
                  >
                    Отмена
                  </button>
                  <button
                    type="button"
                    className="btn-danger"
                    disabled={serverServerCertDeleteModal.busy}
                    onClick={() => void submitDeleteServerServerCert()}
                  >
                    {serverServerCertDeleteModal.busy ? "Удаление…" : "Удалить безвозвратно"}
                  </button>
                </div>
              </div>
            </div>
          ) : null}
          {srvCertImportModal.open && selectedServerId ? (
            <div
              className="modal-backdrop"
              role="presentation"
              onClick={(e) => {
                if (e.target === e.currentTarget && !srvCertImportModal.busy) {
                  setSrvCertImportModal({ open: false, certPem: "", keyPem: "", busy: false, error: "" });
                }
              }}
            >
              <div
                className="modal-dialog"
                role="dialog"
                aria-modal="true"
                aria-labelledby="srv-cert-import-title"
                onClick={(e) => e.stopPropagation()}
              >
                <div className="modal-dialog-header">
                  <h2 id="srv-cert-import-title" className="modal-dialog-title">
                    Импорт сертификата и ключа сервера
                  </h2>
                  <button
                    type="button"
                    className="modal-close"
                    aria-label="Закрыть"
                    disabled={srvCertImportModal.busy}
                    onClick={() =>
                      setSrvCertImportModal({ open: false, certPem: "", keyPem: "", busy: false, error: "" })
                    }
                  >
                    ×
                  </button>
                </div>
                <input
                  ref={srvCertImportCertFileRef}
                  type="file"
                  accept=".pem,.crt,.cer,.txt,text/*,*/*"
                  style={{ display: "none" }}
                  onChange={(e) => {
                    const f = e.target.files?.[0];
                    e.target.value = "";
                    if (!f) return;
                    const reader = new FileReader();
                    reader.onload = () =>
                      setSrvCertImportModal((prev) => ({
                        ...prev,
                        certPem: String(reader.result ?? ""),
                      }));
                    reader.readAsText(f);
                  }}
                />
                <input
                  ref={srvCertImportKeyFileRef}
                  type="file"
                  accept=".pem,.key,.txt,text/*,*/*"
                  style={{ display: "none" }}
                  onChange={(e) => {
                    const f = e.target.files?.[0];
                    e.target.value = "";
                    if (!f) return;
                    const reader = new FileReader();
                    reader.onload = () =>
                      setSrvCertImportModal((prev) => ({
                        ...prev,
                        keyPem: String(reader.result ?? ""),
                      }));
                    reader.readAsText(f);
                  }}
                />
                <div className="row-inline" style={{ gap: 8, marginBottom: 8, flexWrap: "wrap" }}>
                  <button
                    type="button"
                    className="btn-secondary"
                    disabled={srvCertImportModal.busy}
                    onClick={() => srvCertImportCertFileRef.current?.click()}
                  >
                    Файл сертификата
                  </button>
                  <button
                    type="button"
                    className="btn-secondary"
                    disabled={srvCertImportModal.busy}
                    onClick={() => srvCertImportKeyFileRef.current?.click()}
                  >
                    Файл ключа
                  </button>
                </div>
                <div className="user-profile-field-block" style={{ marginTop: 8 }}>
                  <div className="user-profile-field-label">Сертификат (PEM)</div>
                  <textarea
                    value={srvCertImportModal.certPem}
                    onChange={(e) => setSrvCertImportModal((prev) => ({ ...prev, certPem: e.target.value }))}
                    rows={8}
                    style={{ width: "100%", fontFamily: "monospace", fontSize: 12 }}
                    disabled={srvCertImportModal.busy}
                  />
                </div>
                <div className="user-profile-field-block" style={{ marginTop: 8 }}>
                  <div className="user-profile-field-label">Закрытый ключ (PEM)</div>
                  <textarea
                    value={srvCertImportModal.keyPem}
                    onChange={(e) => setSrvCertImportModal((prev) => ({ ...prev, keyPem: e.target.value }))}
                    rows={8}
                    style={{ width: "100%", fontFamily: "monospace", fontSize: 12 }}
                    disabled={srvCertImportModal.busy}
                  />
                </div>
                {srvCertImportModal.error ? (
                  <div className="auth-alert auth-alert--error" role="alert">
                    {srvCertImportModal.error}
                  </div>
                ) : null}
                <div className="row-inline" style={{ justifyContent: "flex-end", gap: 8, marginTop: 16 }}>
                  <button
                    type="button"
                    className="btn-secondary"
                    disabled={srvCertImportModal.busy}
                    onClick={() =>
                      setSrvCertImportModal({ open: false, certPem: "", keyPem: "", busy: false, error: "" })
                    }
                  >
                    Отмена
                  </button>
                  <button type="button" disabled={srvCertImportModal.busy} onClick={() => void submitSrvCertImport()}>
                    {srvCertImportModal.busy ? "Импорт…" : "Импортировать"}
                  </button>
                </div>
              </div>
            </div>
          ) : null}
          {serverRootCaCreateModalOpen ? (
            <div
              className="modal-backdrop"
              role="presentation"
              onClick={(e) => {
                if (e.target === e.currentTarget) setServerRootCaCreateModalOpen(false);
              }}
            >
              <div
                className="modal-dialog modal-dialog--wide"
                role="dialog"
                aria-modal="true"
                aria-labelledby="server-root-ca-create-title"
              >
                <div className="modal-dialog-header">
                  <h2 id="server-root-ca-create-title" className="modal-dialog-title">
                    Создание корневого сертификата
                  </h2>
                  <button
                    type="button"
                    className="modal-close"
                    aria-label="Закрыть"
                    onClick={() => setServerRootCaCreateModalOpen(false)}
                  >
                    ×
                  </button>
                </div>
                <form className="user-profile-blocks--stack modal-field-block" onSubmit={createRootCAForServer}>
                  <div className="user-profile-field-block" style={{ marginTop: 0 }}>
                    <div className="user-profile-field-label">
                      Common Name (CN) корневого сертификата <span className="error">*</span>
                    </div>
                    <input
                      required
                      value={newRootCA.commonName}
                      onChange={(e) => setNewRootCA((prev) => ({ ...prev, commonName: e.target.value }))}
                      style={{ width: "100%" }}
                    />
                  </div>
                  <div className="user-profile-field-block">
                    <div className="user-profile-field-label">Длина ключа RSA, бит</div>
                    <select
                      value={newRootCA.keySize}
                      onChange={(e) => setNewRootCA((prev) => ({ ...prev, keySize: e.target.value }))}
                      style={{ width: "100%" }}
                    >
                      <option value="2048">2048</option>
                      <option value="3072">3072</option>
                      <option value="4096">4096</option>
                    </select>
                  </div>
                  <div className="user-profile-field-block">
                    <div className="user-profile-field-label">Алгоритм подписи (хеш)</div>
                    <select
                      value={newRootCA.signatureAlgorithm}
                      onChange={(e) =>
                        setNewRootCA((prev) => ({ ...prev, signatureAlgorithm: e.target.value }))
                      }
                      style={{ width: "100%" }}
                    >
                      <option value="sha256">SHA-256</option>
                      <option value="sha384">SHA-384</option>
                      <option value="sha512">SHA-512</option>
                    </select>
                  </div>
                  <div className="user-profile-field-block">
                    <div className="user-profile-field-label">
                      Срок действия, суток <span className="error">*</span>
                    </div>
                    <input
                      required
                      type="number"
                      min={1}
                      max={3650}
                      value={newRootCA.days}
                      onChange={(e) => setNewRootCA((prev) => ({ ...prev, days: e.target.value }))}
                      style={{ width: "100%" }}
                    />
                  </div>
                  <div className="row-inline" style={{ justifyContent: "flex-end", gap: 8, marginTop: 8 }}>
                    <button type="button" className="btn-secondary" onClick={() => setServerRootCaCreateModalOpen(false)}>
                      Отмена
                    </button>
                    <button type="submit">Создать</button>
                  </div>
                </form>
              </div>
            </div>
          ) : null}
          {serverRootCaImportModalOpen ? (
            <div
              className="modal-backdrop"
              role="presentation"
              onClick={(e) => {
                if (e.target === e.currentTarget) {
                  setServerPanelRootCaImport({ certPem: "", keyPem: "" });
                  setServerRootCaImportModalOpen(false);
                }
              }}
            >
              <div className="modal-dialog" role="dialog" aria-modal="true" aria-labelledby="server-root-ca-import-title">
                <div className="modal-dialog-header">
                  <h2 id="server-root-ca-import-title" className="modal-dialog-title">
                    Импорт корневого сертификата
                  </h2>
                  <button
                    type="button"
                    className="modal-close"
                    aria-label="Закрыть"
                    onClick={() => {
                      setServerPanelRootCaImport({ certPem: "", keyPem: "" });
                      setServerRootCaImportModalOpen(false);
                    }}
                  >
                    ×
                  </button>
                </div>
                <form className="user-profile-blocks--stack modal-field-block" onSubmit={importRootCaForServer}>
                  <div className="user-profile-field-block" style={{ marginTop: 0 }}>
                    <div className="user-profile-field-label">
                      Корневой сертификат (PEM) <span className="error">*</span>
                    </div>
                    <textarea
                      required
                      rows={8}
                      value={serverPanelRootCaImport.certPem}
                      onChange={(e) =>
                        setServerPanelRootCaImport((prev) => ({ ...prev, certPem: e.target.value }))
                      }
                      style={{ width: "100%", fontFamily: "monospace", fontSize: 12 }}
                    />
                  </div>
                  <div className="user-profile-field-block">
                    <div className="user-profile-field-label">
                      Закрытый ключ (PEM) <span className="error">*</span>
                    </div>
                    <textarea
                      required
                      rows={8}
                      value={serverPanelRootCaImport.keyPem}
                      onChange={(e) =>
                        setServerPanelRootCaImport((prev) => ({ ...prev, keyPem: e.target.value }))
                      }
                      style={{ width: "100%", fontFamily: "monospace", fontSize: 12 }}
                    />
                  </div>
                  <p className="user-profile-field-hint muted" style={{ marginTop: 0 }}>
                    Имя и CN записи корневого сертификата на панели подставляются из поля Subject сертификата (при
                    отсутствии CN в
                    Subject используется значение по умолчанию).
                  </p>
                  <div className="row-inline" style={{ justifyContent: "flex-end", gap: 8, marginTop: 8 }}>
                    <button
                      type="button"
                      className="btn-secondary"
                      onClick={() => {
                        setServerPanelRootCaImport({ certPem: "", keyPem: "" });
                        setServerRootCaImportModalOpen(false);
                      }}
                    >
                      Отмена
                    </button>
                    <button type="submit">Импортировать</button>
                  </div>
                </form>
              </div>
            </div>
          ) : null}
          {serverRootCaDeleteModal.open && selectedServerId ? (
            <div
              className="modal-backdrop"
              role="presentation"
              onClick={(e) => {
                if (e.target === e.currentTarget && !serverRootCaDeleteModal.busy) {
                  setServerRootCaDeleteModal({ open: false, step: 1, confirmCommonName: "", busy: false, error: "" });
                }
              }}
            >
              <div
                className="modal-dialog modal-dialog--wide"
                role="dialog"
                aria-modal="true"
                aria-labelledby="server-root-ca-delete-title"
                onClick={(ev) => ev.stopPropagation()}
              >
                <div className="modal-dialog-header">
                  <h2 id="server-root-ca-delete-title" className="modal-dialog-title">
                    Удаление корневого сертификата
                  </h2>
                  <button
                    type="button"
                    className="modal-close"
                    aria-label="Закрыть"
                    disabled={serverRootCaDeleteModal.busy}
                    onClick={() =>
                      setServerRootCaDeleteModal({
                        open: false,
                        step: 1,
                        confirmCommonName: "",
                        busy: false,
                        error: "",
                      })
                    }
                  >
                    ×
                  </button>
                </div>
                {serverRootCaDeleteModal.step === 1 ? (
                  <>
                    <p className="modal-dialog-body-text" style={{ marginTop: 0 }}>
                      Будет удалён корневой сертификат, привязанный к этому серверу на панели. Также безвозвратно
                      удаляются все выпущенные для этого узла сертификаты, выданные этим корневым сертификатом, учёт
                      сессий и
                      идентификаторов на узле, привязка сертификата сервера и связанные данные. Продолжить только если
                      вы осознаёте последствия.
                    </p>
                    <div className="row-inline" style={{ justifyContent: "flex-end", gap: 8, marginTop: 16 }}>
                      <button
                        type="button"
                        className="btn-secondary"
                        onClick={() =>
                          setServerRootCaDeleteModal({
                            open: false,
                            step: 1,
                            confirmCommonName: "",
                            busy: false,
                            error: "",
                          })
                        }
                      >
                        Отмена
                      </button>
                      <button
                        type="button"
                        className="btn-danger"
                        onClick={() =>
                          setServerRootCaDeleteModal((m) => ({
                            ...m,
                            step: 2,
                            confirmCommonName: "",
                            error: "",
                          }))
                        }
                      >
                        Продолжить
                      </button>
                    </div>
                  </>
                ) : (
                  <>
                    <p className="modal-dialog-body-text" style={{ marginTop: 0 }}>
                      Для окончательного удаления введите точный{" "}
                      <strong>Common Name (CN)</strong> этого корневого сертификата (как в таблице выше).
                    </p>
                    <div className="user-profile-field-block" style={{ marginTop: 12 }}>
                      <div className="user-profile-field-label">Common Name (CN)</div>
                      <input
                        type="text"
                        autoComplete="off"
                        value={serverRootCaDeleteModal.confirmCommonName}
                        onChange={(e) =>
                          setServerRootCaDeleteModal((m) => ({
                            ...m,
                            confirmCommonName: e.target.value,
                            error: "",
                          }))
                        }
                        disabled={serverRootCaDeleteModal.busy}
                        style={{ width: "100%" }}
                      />
                    </div>
                    {serverRootCaDeleteModal.error ? (
                      <div className="auth-alert auth-alert--error" role="alert">
                        {serverRootCaDeleteModal.error}
                      </div>
                    ) : null}
                    <div className="row-inline" style={{ justifyContent: "flex-end", gap: 8, marginTop: 16 }}>
                      <button
                        type="button"
                        className="btn-secondary"
                        disabled={serverRootCaDeleteModal.busy}
                        onClick={() =>
                          setServerRootCaDeleteModal((m) => ({
                            ...m,
                            step: 1,
                            confirmCommonName: "",
                            error: "",
                          }))
                        }
                      >
                        Назад
                      </button>
                      <button
                        type="button"
                        className="btn-danger"
                        disabled={serverRootCaDeleteModal.busy}
                        onClick={() => void submitRemoveServerPanelRootCa()}
                      >
                        {serverRootCaDeleteModal.busy ? "Удаление…" : "Удалить безвозвратно"}
                      </button>
                    </div>
                  </>
                )}
              </div>
            </div>
          ) : null}
          {certMaterialUploadModal.open ? (
            <div
              className="modal-backdrop"
              role="presentation"
              onClick={(e) => {
                if (e.target === e.currentTarget && !certMaterialUploadModal.busy) {
                  setCertMaterialUploadModal({ open: false, certId: "", kind: "cert", pem: "", busy: false, error: "" });
                }
              }}
            >
              <div className="modal-dialog modal-dialog--wide" role="dialog" aria-modal="true" onClick={(e) => e.stopPropagation()}>
                <div className="modal-dialog-header">
                  <h2 className="modal-dialog-title">
                    {certMaterialUploadModal.kind === "key" ? "Добавить приватный ключ" : "Добавить сертификат"}
                  </h2>
                  <button
                    type="button"
                    className="modal-close"
                    aria-label="Закрыть"
                    disabled={certMaterialUploadModal.busy}
                    onClick={() =>
                      setCertMaterialUploadModal({ open: false, certId: "", kind: "cert", pem: "", busy: false, error: "" })
                    }
                  >
                    ×
                  </button>
                </div>
                <div className="user-profile-field-block" style={{ marginTop: 0 }}>
                  <div className="user-profile-field-label">PEM содержимое</div>
                  <textarea
                    rows={12}
                    value={certMaterialUploadModal.pem}
                    onChange={(e) => setCertMaterialUploadModal((prev) => ({ ...prev, pem: e.target.value, error: "" }))}
                    disabled={certMaterialUploadModal.busy}
                    placeholder={
                      certMaterialUploadModal.kind === "key"
                        ? "-----BEGIN PRIVATE KEY-----"
                        : "-----BEGIN CERTIFICATE-----"
                    }
                    style={{ width: "100%" }}
                  />
                </div>
                {certMaterialUploadModal.error ? <p className="modal-dialog-body-text" style={{ color: "#b91c1c" }}>{certMaterialUploadModal.error}</p> : null}
                <div className="row-inline" style={{ justifyContent: "flex-end", gap: 8, marginTop: 12 }}>
                  <button
                    type="button"
                    className="btn-secondary"
                    disabled={certMaterialUploadModal.busy}
                    onClick={() =>
                      setCertMaterialUploadModal({ open: false, certId: "", kind: "cert", pem: "", busy: false, error: "" })
                    }
                  >
                    Отмена
                  </button>
                  <button type="button" disabled={certMaterialUploadModal.busy} onClick={() => void submitCertMaterialUpload()}>
                    {certMaterialUploadModal.busy ? "Загрузка..." : "Загрузить"}
                  </button>
                </div>
              </div>
            </div>
          ) : null}
          {userCertRevokeModal.open && !(primaryNav === "users" && usersSub === "profile") ? (
            <div
              className="modal-backdrop"
              role="presentation"
              onClick={(e) => {
                if (e.target === e.currentTarget && !userCertRevokeModal.busy) {
                  setUserCertRevokeModal({ open: false, certId: null, commonName: "", busy: false, error: "" });
                }
              }}
            >
              <div
                className="modal-dialog"
                role="dialog"
                aria-modal="true"
                aria-labelledby="user-cert-revoke-modal-title-global"
                onClick={(e) => e.stopPropagation()}
              >
                <div className="modal-dialog-header">
                  <h2 id="user-cert-revoke-modal-title-global" className="modal-dialog-title">
                    Отзыв сертификата
                  </h2>
                  <button
                    type="button"
                    className="modal-close"
                    aria-label="Закрыть"
                    disabled={userCertRevokeModal.busy}
                    onClick={() =>
                      setUserCertRevokeModal({ open: false, certId: null, commonName: "", busy: false, error: "" })
                    }
                  >
                    ×
                  </button>
                </div>
                <p className="user-cert-modal-intro">
                  Отозвать сертификат <span className="user-cert-modal-cn">{userCertRevokeModal.commonName || "—"}</span>?
                  После отзыва подключение по нему будет невозможно.
                </p>
                {userCertRevokeModal.error ? (
                  <div className="auth-alert auth-alert--error" role="alert">
                    {userCertRevokeModal.error}
                  </div>
                ) : null}
                <div className="row-inline" style={{ justifyContent: "flex-end", gap: 8, marginTop: 16 }}>
                  <button
                    type="button"
                    className="btn-secondary"
                    disabled={userCertRevokeModal.busy}
                    onClick={() =>
                      setUserCertRevokeModal({ open: false, certId: null, commonName: "", busy: false, error: "" })
                    }
                  >
                    Отмена
                  </button>
                  <button
                    type="button"
                    className="btn-danger"
                    disabled={userCertRevokeModal.busy}
                    onClick={confirmUserCertRevoke}
                  >
                    {userCertRevokeModal.busy ? "Отзыв…" : "Отозвать"}
                  </button>
                </div>
              </div>
            </div>
          ) : null}
          {openvpnCheckModal.open ? (
            <div
              className="modal-backdrop"
              role="presentation"
              onClick={(e) => {
                if (e.target === e.currentTarget) {
                  setOpenvpnCheckModal((m) => ({ ...m, open: false }));
                }
              }}
            >
              <div
                className="modal-dialog"
                role="dialog"
                aria-modal="true"
                aria-labelledby="openvpn-check-modal-title"
              >
                <div className="modal-dialog-header">
                  <h2 id="openvpn-check-modal-title" className="modal-dialog-title">
                    {openvpnCheckModal.title}
                  </h2>
                  <button
                    type="button"
                    className="modal-close"
                    aria-label="Закрыть"
                    onClick={() => setOpenvpnCheckModal((m) => ({ ...m, open: false }))}
                  >
                    ×
                  </button>
                </div>
                <p className={`modal-dialog-body-text${openvpnCheckModal.success ? "" : " error"}`} style={{ marginTop: 0 }}>
                  {openvpnCheckModal.message}
                </p>
                <pre className="openvpn-check-error-box">
                  {String(openvpnCheckModal.details || openvpnCheckModal.message || "").trim() || "(нет вывода)"}
                </pre>
                {openvpnCheckModal.hints
                  .filter(
                    (h) =>
                      String(h || "").trim() !==
                      "Сохраните вывод журнала OpenVPN и сверьте последнюю добавленную директиву с документацией.",
                  ).length > 0 ? (
                  <ul className="server-openvpn-hints modal-dialog-body-text">
                    {openvpnCheckModal.hints
                      .filter(
                        (h) =>
                          String(h || "").trim() !==
                          "Сохраните вывод журнала OpenVPN и сверьте последнюю добавленную директиву с документацией.",
                      )
                      .map((h, i) => (
                      <li key={i}>{h}</li>
                      ))}
                  </ul>
                ) : null}
                <div className="row-inline" style={{ justifyContent: "flex-end", gap: 8 }}>
                  <button
                    type="button"
                    onClick={() => setOpenvpnCheckModal((m) => ({ ...m, open: false }))}
                  >
                    Закрыть
                  </button>
                </div>
              </div>
            </div>
          ) : null}
          {userSessionDisconnectModal.open ? (
            <div
              className="modal-backdrop"
              role="presentation"
              onClick={(e) => {
                if (e.target === e.currentTarget && !userSessionDisconnectModal.busy) {
                  userSessionDisconnectTargetRef.current = { nodeId: "", sessionId: "" };
                  setUserSessionDisconnectModal({
                    open: false,
                    nodeName: "",
                    sessionNumber: "",
                    profileName: "",
                    busy: false,
                    error: "",
                  });
                }
              }}
            >
              <div
                className="modal-dialog"
                role="dialog"
                aria-modal="true"
                aria-labelledby="user-session-disconnect-modal-title"
              >
                <div className="modal-dialog-header">
                  <h2 id="user-session-disconnect-modal-title" className="modal-dialog-title">
                    Завершить сессию
                  </h2>
                  <button
                    type="button"
                    className="modal-close"
                    aria-label="Закрыть"
                    disabled={userSessionDisconnectModal.busy}
                    onClick={() => {
                      userSessionDisconnectTargetRef.current = { nodeId: "", sessionId: "" };
                      setUserSessionDisconnectModal({
                        open: false,
                        nodeName: "",
                        sessionNumber: "",
                        profileName: "",
                        busy: false,
                        error: "",
                      });
                    }}
                  >
                    ×
                  </button>
                </div>
                <p className="modal-dialog-body-text">
                  Завершить сессию <strong>{userSessionDisconnectModal.sessionNumber || "—"}</strong> пользователя{" "}
                  <strong>{userSessionDisconnectModal.profileName || "—"}</strong> на узле{" "}
                  <strong>{userSessionDisconnectModal.nodeName || "—"}</strong>?
                </p>
                {userSessionDisconnectModal.error ? (
                  <div className="auth-alert auth-alert--error" role="alert">
                    {userSessionDisconnectModal.error}
                  </div>
                ) : null}
                <div className="row-inline" style={{ justifyContent: "flex-end", gap: 8 }}>
                  <button
                    type="button"
                    className="btn-secondary"
                    disabled={userSessionDisconnectModal.busy}
                    onClick={() => {
                      userSessionDisconnectTargetRef.current = { nodeId: "", sessionId: "" };
                      setUserSessionDisconnectModal({
                        open: false,
                        nodeName: "",
                        sessionNumber: "",
                        profileName: "",
                        busy: false,
                        error: "",
                      });
                    }}
                  >
                    Отмена
                  </button>
                  <button
                    type="button"
                    className="btn-danger"
                    disabled={userSessionDisconnectModal.busy}
                    onClick={submitUserSessionDisconnect}
                  >
                    {userSessionDisconnectModal.busy ? "Выполняется…" : "Завершить"}
                  </button>
                </div>
              </div>
            </div>
          ) : null}
          </div>
          </main>
        </div>
      </div>
    </div>
  );
}
