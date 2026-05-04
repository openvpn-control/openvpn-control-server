import { config } from "../config.js";
import { prisma } from "../prisma.js";
import { createPanelBackupZip, ensureBackupSettingsRow } from "./panelBackupService.js";

let timer = null;
let running = false;

async function tick() {
  if (running) return;
  try {
    const s = await ensureBackupSettingsRow();
    const min = Number(s.intervalMinutes || 0);
    if (min <= 0) return;
    const last = s.lastScheduledAt ? new Date(s.lastScheduledAt).getTime() : 0;
    if (!last) return;
    const due = last + min * 60_000 <= Date.now();
    if (!due) return;
    running = true;
    await createPanelBackupZip(config.panelBackupDir, "scheduled");
    await prisma.panelAppBackupSettings.update({
      where: { id: 1 },
      data: { lastScheduledAt: new Date() },
    });
  } catch (e) {
    console.error("[panel-backup-scheduler]", e?.message || e);
  } finally {
    running = false;
  }
}

export function startPanelBackupScheduler() {
  if (timer) return;
  timer = setInterval(tick, 60_000);
}
