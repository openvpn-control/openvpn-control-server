import bcrypt from "bcryptjs";
import crypto from "node:crypto";
import { Router } from "express";
import { prisma } from "../../prisma.js";
import { replaceRecoveryCodesForAdmin } from "../../security/recoveryCodes.js";
import {
  decryptSecret,
  encryptSecret,
  generatePendingTotpSetup,
  generateTotpQrDataUrl,
  verifyTotpToken,
} from "../../security/totp.js";

const router = Router();

const INVITE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

function normalizeEmail(email) {
  const s = String(email ?? "").trim().toLowerCase();
  return s || null;
}

function newInviteToken() {
  return crypto.randomBytes(32).toString("hex");
}

function normalizeTotpCode(value) {
  return String(value ?? "").replace(/\s+/g, "");
}

router.get("/me", async (req, res) => {
  const adminId = String(req.user?.sub || "");
  if (!adminId) return res.status(401).json({ error: "Unauthorized" });
  const me = await prisma.admin.findUnique({
    where: { id: adminId },
    select: {
      id: true,
      fullName: true,
      username: true,
      email: true,
      isActive: true,
      totpEnabled: true,
      createdAt: true,
      updatedAt: true,
      _count: {
        select: {
          totpRecoveryCodes: { where: { usedAt: null } },
        },
      },
    },
  });
  if (!me || !me.isActive) return res.status(401).json({ error: "Unauthorized" });
  const { _count, ...rest } = me;
  return res.json({
    ...rest,
    totpRecoveryCodesRemaining: _count.totpRecoveryCodes,
  });
});

router.post("/me/change-password", async (req, res) => {
  const adminId = String(req.user?.sub || "");
  if (!adminId) return res.status(401).json({ error: "Unauthorized" });
  const { currentPassword, newPassword } = req.body || {};
  const current = String(currentPassword || "");
  const next = String(newPassword || "");
  if (!current || !next) {
    return res.status(400).json({ error: "Текущий и новый пароль обязательны" });
  }
  if (next.length < 10) {
    return res.status(400).json({ error: "Новый пароль должен быть не короче 10 символов" });
  }

  const admin = await prisma.admin.findUnique({ where: { id: adminId } });
  if (!admin || !admin.isActive) return res.status(401).json({ error: "Unauthorized" });
  const ok = await bcrypt.compare(current, admin.passwordHash);
  if (!ok) return res.status(400).json({ error: "Текущий пароль указан неверно" });

  await prisma.admin.update({
    where: { id: adminId },
    data: {
      passwordHash: await bcrypt.hash(next, 10),
      passwordResetToken: null,
      passwordResetExpiresAt: null,
    },
  });
  return res.json({ ok: true });
});

router.post("/me/totp/setup/start", async (req, res) => {
  const adminId = String(req.user?.sub || "");
  if (!adminId) return res.status(401).json({ error: "Unauthorized" });
  const admin = await prisma.admin.findUnique({
    where: { id: adminId },
    select: { id: true, username: true, email: true, totpEnabled: true, isActive: true },
  });
  if (!admin || !admin.isActive) return res.status(401).json({ error: "Unauthorized" });

  const account = admin.email || admin.username || admin.id;
  const setup = generatePendingTotpSetup({ accountName: account, issuer: "OpenVPN Control" });
  await prisma.admin.update({
    where: { id: adminId },
    data: {
      totpPendingSecretEnc: setup.encryptedSecret,
      totpPendingExpiresAt: setup.expiresAt,
    },
  });
  const qrDataUrl = await generateTotpQrDataUrl(setup.otpAuthUrl);
  return res.json({
    qrDataUrl,
    manualSecret: setup.secret,
    expiresAt: setup.expiresAt,
  });
});

router.post("/me/totp/setup/confirm", async (req, res) => {
  const adminId = String(req.user?.sub || "");
  if (!adminId) return res.status(401).json({ error: "Unauthorized" });
  const code = normalizeTotpCode(req.body?.totpCode);
  if (!code) return res.status(400).json({ error: "Введите код из приложения" });
  const admin = await prisma.admin.findUnique({
    where: { id: adminId },
    select: {
      id: true,
      isActive: true,
      totpPendingSecretEnc: true,
      totpPendingExpiresAt: true,
    },
  });
  if (!admin || !admin.isActive) return res.status(401).json({ error: "Unauthorized" });
  if (!admin.totpPendingSecretEnc || !admin.totpPendingExpiresAt || admin.totpPendingExpiresAt.getTime() < Date.now()) {
    return res.status(400).json({ error: "Сессия подключения 2FA истекла. Начните заново." });
  }
  const secret = decryptSecret(admin.totpPendingSecretEnc);
  if (!secret || !verifyTotpToken(secret, code)) {
    return res.status(400).json({ error: "Неверный код подтверждения" });
  }

  const recoveryCodes = await prisma.$transaction(async (tx) => {
    await tx.admin.update({
      where: { id: adminId },
      data: {
        totpEnabled: true,
        totpSecretEnc: encryptSecret(secret),
        totpPendingSecretEnc: null,
        totpPendingExpiresAt: null,
      },
    });
    return replaceRecoveryCodesForAdmin(adminId, tx);
  });
  return res.json({ ok: true, recoveryCodes });
});

router.post("/me/totp/recovery-codes/regenerate", async (req, res) => {
  const adminId = String(req.user?.sub || "");
  if (!adminId) return res.status(401).json({ error: "Unauthorized" });
  const code = normalizeTotpCode(req.body?.totpCode);
  if (!code) return res.status(400).json({ error: "Введите код из приложения-аутентификатора" });

  const admin = await prisma.admin.findUnique({
    where: { id: adminId },
    select: { id: true, isActive: true, totpEnabled: true, totpSecretEnc: true },
  });
  if (!admin || !admin.isActive) return res.status(401).json({ error: "Unauthorized" });
  if (!admin.totpEnabled || !admin.totpSecretEnc) {
    return res.status(400).json({ error: "Сначала включите двухфакторную аутентификацию" });
  }
  const secret = decryptSecret(admin.totpSecretEnc);
  if (!secret || !verifyTotpToken(secret, code)) {
    return res.status(400).json({ error: "Неверный код 2FA" });
  }

  const recoveryCodes = await prisma.$transaction(async (tx) => replaceRecoveryCodesForAdmin(adminId, tx));
  return res.json({ recoveryCodes });
});

router.post("/me/totp/disable", async (req, res) => {
  const adminId = String(req.user?.sub || "");
  if (!adminId) return res.status(401).json({ error: "Unauthorized" });
  const code = normalizeTotpCode(req.body?.totpCode);
  if (!code) return res.status(400).json({ error: "Введите текущий код 2FA для отключения" });

  const admin = await prisma.admin.findUnique({
    where: { id: adminId },
    select: { id: true, isActive: true, totpEnabled: true, totpSecretEnc: true },
  });
  if (!admin || !admin.isActive) return res.status(401).json({ error: "Unauthorized" });
  if (!admin.totpEnabled || !admin.totpSecretEnc) {
    return res.status(400).json({ error: "2FA уже отключена" });
  }
  const secret = decryptSecret(admin.totpSecretEnc);
  if (!secret || !verifyTotpToken(secret, code)) {
    return res.status(400).json({ error: "Неверный код 2FA" });
  }

  await prisma.admin.update({
    where: { id: adminId },
    data: {
      totpEnabled: false,
      totpSecretEnc: null,
      totpPendingSecretEnc: null,
      totpPendingExpiresAt: null,
    },
  });
  return res.json({ ok: true });
});

router.get("/", async (_req, res) => {
  const admins = await prisma.admin.findMany({
    orderBy: { createdAt: "desc" },
    select: {
      id: true,
      fullName: true,
      username: true,
      email: true,
      isActive: true,
      inviteToken: true,
      createdAt: true,
      updatedAt: true,
    },
  });
  const payload = admins.map((a) => ({
    id: a.id,
    fullName: a.fullName,
    username: a.username,
    email: a.email,
    isActive: a.isActive,
    invitePending: a.inviteToken != null,
    createdAt: a.createdAt,
    updatedAt: a.updatedAt,
  }));
  res.json(payload);
});

router.post("/", async (req, res) => {
  const body = req.body || {};
  const fullName = String(body.fullName ?? "").trim();
  const username = String(body.username ?? "").trim();
  const emailRaw = normalizeEmail(body.email);

  if (!fullName) {
    return res.status(400).json({ error: "ФИО обязательно" });
  }
  if (!username) {
    return res.status(400).json({ error: "Аккаунт (логин) обязателен" });
  }
  if (!emailRaw) {
    return res.status(400).json({ error: "Электронная почта обязательна" });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailRaw)) {
    return res.status(400).json({ error: "Некорректный адрес электронной почты" });
  }

  const existsUser = await prisma.admin.findUnique({ where: { username } });
  if (existsUser) {
    return res.status(409).json({ error: "Администратор с таким аккаунтом уже есть" });
  }
  const existsEmail = await prisma.admin.findUnique({ where: { email: emailRaw } });
  if (existsEmail) {
    return res.status(409).json({ error: "Администратор с такой почтой уже есть" });
  }

  const inviteToken = newInviteToken();
  const inviteExpiresAt = new Date(Date.now() + INVITE_TTL_MS);
  const placeholderPassword = crypto.randomBytes(48).toString("hex");
  const passwordHash = await bcrypt.hash(placeholderPassword, 10);

  const admin = await prisma.admin.create({
    data: {
      fullName,
      username,
      email: emailRaw,
      passwordHash,
      inviteToken,
      inviteExpiresAt,
    },
    select: {
      id: true,
      fullName: true,
      username: true,
      email: true,
      isActive: true,
      createdAt: true,
      updatedAt: true,
    },
  });

  const invitePath = `/invite-admin?token=${encodeURIComponent(inviteToken)}`;

  return res.status(201).json({
    ...admin,
    invitePending: true,
    invitePath,
  });
});

const PASSWORD_RESET_TTL_MS = 24 * 60 * 60 * 1000;

router.post("/:id/password-reset-link", async (req, res) => {
  const { id } = req.params;
  const admin = await prisma.admin.findUnique({
    where: { id },
    select: { id: true, inviteToken: true },
  });
  if (!admin) {
    return res.status(404).json({ error: "Администратор не найден" });
  }
  if (admin.inviteToken) {
    return res.status(400).json({
      error: "Для этой учётной записи ещё не завершена регистрация по приглашению.",
    });
  }

  const token = newInviteToken();
  const passwordResetExpiresAt = new Date(Date.now() + PASSWORD_RESET_TTL_MS);
  await prisma.admin.update({
    where: { id },
    data: { passwordResetToken: token, passwordResetExpiresAt },
  });

  const resetPath = `/reset-admin-password?token=${encodeURIComponent(token)}`;
  return res.json({ resetPath });
});

router.patch("/:id", async (req, res) => {
  const { id } = req.params;
  const body = req.body || {};
  const { isActive, password, fullName, username, email } = body;

  const updateData = {};
  if (typeof isActive === "boolean") {
    updateData.isActive = isActive;
  }
  if (password) {
    updateData.passwordHash = await bcrypt.hash(password, 10);
    updateData.inviteToken = null;
    updateData.inviteExpiresAt = null;
    updateData.passwordResetToken = null;
    updateData.passwordResetExpiresAt = null;
  }

  if (fullName !== undefined) {
    const fn = String(fullName ?? "").trim();
    if (!fn) {
      return res.status(400).json({ error: "ФИО обязательно" });
    }
    updateData.fullName = fn;
  }
  if (username !== undefined) {
    const u = String(username ?? "").trim();
    if (!u) {
      return res.status(400).json({ error: "Аккаунт (логин) обязателен" });
    }
    const exists = await prisma.admin.findUnique({ where: { username: u }, select: { id: true } });
    if (exists && exists.id !== id) {
      return res.status(409).json({ error: "Администратор с таким аккаунтом уже есть" });
    }
    updateData.username = u;
  }
  if (email !== undefined) {
    const emailRaw = normalizeEmail(email);
    if (!emailRaw) {
      return res.status(400).json({ error: "Электронная почта обязательна" });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailRaw)) {
      return res.status(400).json({ error: "Некорректный адрес электронной почты" });
    }
    const existsEmail = await prisma.admin.findFirst({
      where: { email: emailRaw, NOT: { id } },
      select: { id: true },
    });
    if (existsEmail) {
      return res.status(409).json({ error: "Администратор с такой почтой уже есть" });
    }
    updateData.email = emailRaw;
  }

  if (Object.keys(updateData).length === 0) {
    return res.status(400).json({ error: "Нет данных для обновления" });
  }

  const row = await prisma.admin.update({
    where: { id },
    data: updateData,
    select: {
      id: true,
      fullName: true,
      username: true,
      email: true,
      isActive: true,
      inviteToken: true,
      createdAt: true,
      updatedAt: true,
    },
  });

  return res.json({
    id: row.id,
    fullName: row.fullName,
    username: row.username,
    email: row.email,
    isActive: row.isActive,
    invitePending: row.inviteToken != null,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  });
});

export default router;
