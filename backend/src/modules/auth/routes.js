import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { Router } from "express";
import { config } from "../../config.js";
import { checkLoginRateLimit, recordLoginFailure, recordLoginSuccess } from "../../middleware/loginRateLimit.js";
import { requireAuth } from "../../middleware.js";
import { prisma } from "../../prisma.js";
import { verifyAndConsumeRecoveryCode } from "../../security/recoveryCodes.js";
import { decryptSecret, verifyTotpToken } from "../../security/totp.js";

const router = Router();

/** Шаг 1: только логин и пароль. При включённом TOTP токен сессии не выдаётся — только mfaPendingToken. */
router.post("/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: "username and password are required" });
  }

  const limit = checkLoginRateLimit(req, username);
  if (!limit.ok) {
    res.setHeader("Retry-After", String(limit.retryAfterSeconds));
    return res.status(429).json({
      error: limit.message,
      retryAfterSeconds: limit.retryAfterSeconds,
    });
  }
  const rateKey = limit.key;

  const admin = await prisma.admin.findUnique({ where: { username } });
  if (!admin || !admin.isActive) {
    recordLoginFailure(rateKey);
    return res.status(401).json({ error: "Invalid credentials" });
  }

  if (admin.inviteToken) {
    recordLoginFailure(rateKey);
    return res.status(401).json({
      error: "Завершите регистрацию по ссылке-приглашению, которую вам отправил администратор панели.",
    });
  }

  const isValid = await bcrypt.compare(password, admin.passwordHash);
  if (!isValid) {
    recordLoginFailure(rateKey);
    return res.status(401).json({ error: "Invalid credentials" });
  }

  if (admin.totpEnabled) {
    const mfaPendingToken = jwt.sign(
      {
        sub: admin.id,
        username: admin.username,
        purpose: "mfa_pending",
      },
      config.jwtSecret,
      { expiresIn: config.mfaPendingTokenExpiresIn },
    );
    return res.json({ mfaRequired: true, mfaPendingToken });
  }

  recordLoginSuccess(rateKey);

  const token = jwt.sign(
    { sub: admin.id, username: admin.username },
    config.jwtSecret,
    { expiresIn: config.jwtExpiresIn },
  );

  return res.json({ token });
});

/** Шаг 2: TOTP или резервный код; выдаётся только полноценный access-токен. */
router.post("/login/mfa", async (req, res) => {
  const { mfaPendingToken, totpCode, recoveryCode } = req.body || {};
  if (!mfaPendingToken) {
    return res.status(400).json({ error: "Требуется токен подтверждения 2FA" });
  }

  let payload;
  try {
    payload = jwt.verify(mfaPendingToken, config.jwtSecret);
  } catch {
    return res.status(401).json({ error: "Сессия подтверждения 2FA истекла. Войдите снова." });
  }

  if (payload.purpose !== "mfa_pending" || !payload.sub || !payload.username) {
    return res.status(401).json({ error: "Недействительный токен подтверждения" });
  }

  const limit = checkLoginRateLimit(req, payload.username);
  if (!limit.ok) {
    res.setHeader("Retry-After", String(limit.retryAfterSeconds));
    return res.status(429).json({
      error: limit.message,
      retryAfterSeconds: limit.retryAfterSeconds,
    });
  }
  const rateKey = limit.key;

  const admin = await prisma.admin.findUnique({ where: { id: payload.sub } });
  if (!admin || !admin.isActive || admin.username !== payload.username) {
    recordLoginFailure(rateKey);
    return res.status(401).json({ error: "Invalid credentials" });
  }

  if (!admin.totpEnabled) {
    return res.status(400).json({
      error: "Двухфакторная аутентификация отключена. Войдите снова, указав только логин и пароль.",
    });
  }

  const secret = admin.totpSecretEnc ? decryptSecret(admin.totpSecretEnc) : "";
  const totpOk = Boolean(secret && verifyTotpToken(secret, totpCode));
  const recoveryOk = await verifyAndConsumeRecoveryCode(admin.id, recoveryCode);

  if (!totpOk && !recoveryOk) {
    recordLoginFailure(rateKey);
    return res.status(401).json({
      error: "Неверный код двухфакторной аутентификации или резервный код",
    });
  }

  recordLoginSuccess(rateKey);

  const token = jwt.sign(
    { sub: admin.id, username: admin.username },
    config.jwtSecret,
    { expiresIn: config.jwtExpiresIn },
  );

  return res.json({ token });
});

/** Продление сессии при активности (новый тот же срок с момента ответа). */
router.post("/refresh", requireAuth, (req, res) => {
  const token = jwt.sign(
    { sub: req.user.sub, username: req.user.username },
    config.jwtSecret,
    { expiresIn: config.jwtExpiresIn },
  );
  return res.json({ token });
});

export default router;
