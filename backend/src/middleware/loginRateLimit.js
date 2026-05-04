import { config } from "../config.js";

/** @type {Map<string, { failures: number; lockedUntil: number }>} */
const stateByKey = new Map();

export function getClientIp(req) {
  const fwd = req.headers["x-forwarded-for"];
  if (fwd) return String(fwd).split(",")[0].trim();
  return req.socket?.remoteAddress || "";
}

export function loginRateLimitKey(req, username) {
  const ip = getClientIp(req);
  const u = String(username ?? "").trim().toLowerCase();
  return `${ip}:${u}`;
}

/**
 * @returns {{ ok: true, key: string } | { ok: false, message: string, retryAfterSeconds: number, key: string }}
 */
export function checkLoginRateLimit(req, username) {
  const key = loginRateLimitKey(req, username);
  const now = Date.now();
  let s = stateByKey.get(key);
  if (!s) {
    return { ok: true, key };
  }
  if (s.lockedUntil > now) {
    const retryAfterSeconds = Math.max(1, Math.ceil((s.lockedUntil - now) / 1000));
    return {
      ok: false,
      key,
      message: "Слишком много неудачных попыток входа. Подождите и попробуйте снова.",
      retryAfterSeconds,
    };
  }
  if (s.lockedUntil && s.lockedUntil <= now) {
    stateByKey.delete(key);
    s = undefined;
  }
  return { ok: true, key };
}

export function recordLoginFailure(key) {
  const now = Date.now();
  const max = config.loginMaxAttempts;
  const lockMs = config.loginLockoutMs;
  const prev = stateByKey.get(key);
  const base = prev && prev.lockedUntil > now ? prev.failures : prev?.failures || 0;
  const failures = base + 1;
  const lockedUntil = failures >= max ? now + lockMs : 0;
  stateByKey.set(key, { failures, lockedUntil });
  if (stateByKey.size > 50_000) {
    for (const k of stateByKey.keys()) {
      stateByKey.delete(k);
      if (stateByKey.size < 40_000) break;
    }
  }
}

export function recordLoginSuccess(key) {
  stateByKey.delete(key);
}
