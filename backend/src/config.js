import dotenv from "dotenv";
import path from "node:path";

dotenv.config();

function parseCorsOrigins(raw) {
  const text = String(raw || "").trim();
  if (!text) return [];
  return text
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function parseBool(value, fallback = false) {
  const normalized = String(value ?? "").trim().toLowerCase();
  if (!normalized) return fallback;
  return !["0", "false", "no", "off"].includes(normalized);
}

function parseAllowedHosts(raw, fallbackOrigins = []) {
  const explicit = parseCorsOrigins(raw);
  if (explicit.length > 0) return explicit.map((x) => x.toLowerCase());
  const derived = fallbackOrigins
    .map((origin) => {
      try {
        return new URL(origin).host.toLowerCase();
      } catch {
        return "";
      }
    })
    .filter(Boolean);
  return [...new Set(derived)];
}

export const config = {
  port: Number(process.env.PORT || 8080),
  /** Max JSON body size (e.g. импорт корневого сертификата: cert, key, index.txt, crl.pem). */
  bodyJsonLimit: process.env.BODY_JSON_LIMIT || "50mb",
  jwtSecret: process.env.JWT_SECRET || "dev_secret_change_me",
  /** Срок действия access-токена (логин и refresh). */
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || "15m",
  /** Время жизни промежуточного JWT после верного пароля, до ввода TOTP (например 5m, 300s). */
  mfaPendingTokenExpiresIn: process.env.MFA_PENDING_TOKEN_EXPIRES_IN || "5m",
  agentSyncIntervalMs: Number(process.env.AGENT_SYNC_INTERVAL_MS || 2000),
  openvpnInfoSyncIntervalMs: Number(process.env.OPENVPN_INFO_SYNC_INTERVAL_MS || 5000),
  clientSyncIntervalMs: Number(process.env.CLIENT_SYNC_INTERVAL_MS || 2000),
  clientSessionFreshnessSeconds: Number(process.env.CLIENT_SESSION_FRESHNESS_SECONDS || 15),
  clientTrafficHistoryMinutes: Number(process.env.CLIENT_TRAFFIC_HISTORY_MINUTES || 15),
  /** How long agent metric snapshots are kept (dashboard charts). */
  agentMetricHistoryMinutes: Number(process.env.AGENT_METRIC_HISTORY_MINUTES || 15),
  openvpnLogRetentionDays: Number(process.env.OPENVPN_LOG_RETENTION_DAYS || 10),
  /** Устарело: push firewall с панели по синку клиентов отключён; агент применяет iptables из локального снимка. Оставлено для совместимости. */
  firewallRuntimeApplyEnabled: process.env.PANEL_FIREWALL_RUNTIME_ENABLED !== "0",
  /**
   * Сколько подряд успешных синков с пустым списком клиентов нужно, чтобы снять runtime firewall.
   * Защита от кратковременных пустых ответов /clients (иначе правила «мигают» в iptables-save).
   * 0 = никогда не снимать автоматически при пустом списке. По умолчанию 25 (при интервале 2 с ≈ 50 с).
   */
  firewallRuntimeEmptyTeardownStreak: (() => {
    const raw = process.env.PANEL_FIREWALL_RUNTIME_EMPTY_TEARDOWN_STREAK;
    if (raw === undefined || raw === "") return 25;
    const n = Number(raw);
    if (!Number.isFinite(n) || n < 0) return 25;
    return Math.floor(n);
  })(),
  /** Каталог ZIP-резервных копий панели (создаётся автоматически). */
  panelBackupDir: process.env.PANEL_BACKUP_DIR || path.join(process.cwd(), "data", "panel-backups"),
  /** Разрешенные Origin для CORS, CSV (например: https://panel.example.com,https://admin.example.com). */
  corsOrigins: parseCorsOrigins(process.env.CORS_ORIGIN || "http://localhost:5173"),
  /** Допустимые Origin для CSRF-проверки state-changing запросов. По умолчанию = CORS_ORIGIN. */
  csrfTrustedOrigins: parseCorsOrigins(process.env.CSRF_TRUSTED_ORIGINS || process.env.CORS_ORIGIN || "http://localhost:5173"),
  csrfProtectionEnabled: parseBool(process.env.CSRF_PROTECTION_ENABLED, true),
  allowedHosts: parseAllowedHosts(process.env.ALLOWED_HOSTS, parseCorsOrigins(process.env.CORS_ORIGIN || "http://localhost:5173")),
  /** Лимит неудачных попыток входа (пароль / 2FA) до блокировки по IP+логин. */
  loginMaxAttempts: (() => {
    const n = Number(process.env.LOGIN_MAX_ATTEMPTS);
    if (!Number.isFinite(n) || n < 3) return 8;
    return Math.min(50, Math.floor(n));
  })(),
  /** Длительность блокировки после превышения лимита, мс. */
  loginLockoutMs: (() => {
    const n = Number(process.env.LOGIN_LOCKOUT_MINUTES);
    const minutes = !Number.isFinite(n) || n < 1 ? 15 : Math.min(1440, Math.floor(n));
    return minutes * 60 * 1000;
  })(),
};
