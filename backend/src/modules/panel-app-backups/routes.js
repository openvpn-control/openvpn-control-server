import { Router } from "express";
import multer from "multer";
import { readFile, unlink } from "node:fs/promises";
import path from "node:path";
import { config } from "../../config.js";
import { prisma } from "../../prisma.js";
import {
  createPanelBackupZip,
  ensureBackupSettingsRow,
  pruneOldBackups,
  restorePanelFromZipBuffer,
} from "../../services/panelBackupService.js";

const router = Router();

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 500 * 1024 * 1024 },
});

const C0_STRIP_CODEPOINTS = [1, 2, 3, 4, 5, 6, 7, 8, 11, 12, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31];
function pgStripC0Controls(colExpr) {
  let out = colExpr;
  for (const c of C0_STRIP_CODEPOINTS) out = `replace(${out}, CHR(${c}), '')`;
  return out;
}

router.get("/", async (_req, res) => {
  try {
    const settings = await ensureBackupSettingsRow();
    const backups = await prisma.$queryRawUnsafe(`
      SELECT
        b.id,
        ${pgStripC0Controls('b."fileName"')} AS "fileName",
        b."sizeBytes",
        ${pgStripC0Controls('b."trigger"')} AS trigger,
        b."createdAt"
      FROM "PanelAppBackup" b
      ORDER BY b."createdAt" DESC
    `);
    return res.json({
      settings: {
        intervalMinutes: settings.intervalMinutes,
        retainCount: settings.retainCount,
        lastScheduledAt: settings.lastScheduledAt,
      },
      backups,
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: e.message || "Ошибка загрузки настроек резервного копирования" });
  }
});

router.put("/settings", async (req, res) => {
  try {
    await ensureBackupSettingsRow();
    const intervalMinutes = Math.max(0, Math.min(10080, Number(req.body?.intervalMinutes ?? 0)));
    const retainCount = Math.max(1, Math.min(500, Number(req.body?.retainCount ?? 10)));
    const prev = await prisma.panelAppBackupSettings.findUnique({ where: { id: 1 } });
    const data = { intervalMinutes, retainCount };
    if (prev && prev.intervalMinutes === 0 && intervalMinutes > 0) {
      data.lastScheduledAt = new Date();
    }
    const updated = await prisma.panelAppBackupSettings.update({
      where: { id: 1 },
      data,
    });
    await pruneOldBackups(config.panelBackupDir);
    return res.json({
      settings: {
        intervalMinutes: updated.intervalMinutes,
        retainCount: updated.retainCount,
        lastScheduledAt: updated.lastScheduledAt,
      },
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: e.message || "Не удалось сохранить настройки" });
  }
});

router.post("/run", async (_req, res) => {
  try {
    const created = await createPanelBackupZip(config.panelBackupDir, "manual");
    return res.status(201).json({
      backup: {
        id: created.id,
        fileName: created.fileName,
        sizeBytes: created.sizeBytes,
        trigger: created.trigger,
        createdAt: created.createdAt,
      },
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: e.message || "Не удалось создать резервную копию" });
  }
});

router.get("/archives/:id/download", async (req, res) => {
  try {
    const row = await prisma.panelAppBackup.findUnique({ where: { id: req.params.id } });
    if (!row) return res.status(404).json({ error: "Копия не найдена" });
    const abs = path.join(config.panelBackupDir, `${row.id}.zip`);
    const buf = await readFile(abs);
    res.setHeader("Content-Type", "application/zip");
    res.setHeader("Content-Disposition", `attachment; filename="${encodeURIComponent(row.fileName)}"`);
    res.setHeader("Content-Length", String(buf.length));
    return res.send(buf);
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: e.message || "Ошибка чтения архива" });
  }
});

router.delete("/archives/:id", async (req, res) => {
  try {
    const row = await prisma.panelAppBackup.findUnique({ where: { id: req.params.id } });
    if (!row) return res.status(404).json({ error: "Копия не найдена" });
    try {
      await unlink(path.join(config.panelBackupDir, `${row.id}.zip`));
    } catch {
      /* file missing */
    }
    await prisma.panelAppBackup.delete({ where: { id: row.id } });
    return res.status(204).send();
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: e.message || "Не удалось удалить копию" });
  }
});

router.post("/restore", upload.single("file"), async (req, res) => {
  try {
    if (!req.file?.buffer?.length) {
      return res.status(400).json({ error: "Файл не передан" });
    }
    await restorePanelFromZipBuffer(config.panelBackupDir, req.file.buffer);
    return res.json({ ok: true, message: "Данные восстановлены из архива. Войдите заново при необходимости." });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: e.message || "Восстановление не удалось" });
  }
});

export default router;
