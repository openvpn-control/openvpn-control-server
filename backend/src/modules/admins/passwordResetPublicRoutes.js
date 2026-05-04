import bcrypt from "bcryptjs";
import { Router } from "express";
import { prisma } from "../../prisma.js";

const router = Router();

/** @param {string} token */
async function findAdminByPasswordResetToken(token) {
  const t = String(token || "").trim();
  if (!t || t.length < 16) return null;
  return prisma.admin.findFirst({
    where: { passwordResetToken: t },
    select: {
      id: true,
      fullName: true,
      username: true,
      email: true,
      passwordResetExpiresAt: true,
      passwordResetToken: true,
    },
  });
}

router.get("/", async (req, res) => {
  try {
    const token = String(req.query?.token || "").trim();
    const row = await findAdminByPasswordResetToken(token);
    if (!row || !row.passwordResetToken) {
      return res.status(404).json({ error: "Ссылка сброса пароля недействительна или уже использована" });
    }
    const exp = row.passwordResetExpiresAt ? new Date(row.passwordResetExpiresAt).getTime() : 0;
    if (exp && Date.now() > exp) {
      return res.status(410).json({ error: "Срок действия ссылки истёк. Запросите новую у администратора панели." });
    }
    return res.json({
      fullName: row.fullName || "",
      username: row.username,
      email: row.email || "",
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: e.message || "Ошибка" });
  }
});

router.post("/complete", async (req, res) => {
  try {
    const token = String(req.body?.token || "").trim();
    const password = String(req.body?.password || "");
    if (!token || password.length < 8) {
      return res.status(400).json({ error: "Укажите токен и пароль не короче 8 символов" });
    }

    const row = await findAdminByPasswordResetToken(token);
    if (!row || !row.passwordResetToken) {
      return res.status(404).json({ error: "Ссылка сброса пароля недействительна или уже использована" });
    }
    const exp = row.passwordResetExpiresAt ? new Date(row.passwordResetExpiresAt).getTime() : 0;
    if (exp && Date.now() > exp) {
      return res.status(410).json({ error: "Срок действия ссылки истёк" });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    await prisma.admin.update({
      where: { id: row.id },
      data: {
        passwordHash,
        passwordResetToken: null,
        passwordResetExpiresAt: null,
        inviteToken: null,
        inviteExpiresAt: null,
      },
    });

    return res.json({ ok: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: e.message || "Ошибка" });
  }
});

export default router;
