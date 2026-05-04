import AdmZip from "adm-zip";
import { mkdir, readdir, unlink, writeFile } from "node:fs/promises";
import path from "node:path";
import { prisma } from "../prisma.js";
import { exportAllTablesJsonFromRawQueries } from "./panelBackupExportRaw.js";

export const PANEL_BACKUP_FORMAT = "ovpn-control-panel-backup";
export const PANEL_BACKUP_VERSION = 1;

/** @param {import("@prisma/client").Prisma.TransactionClient} tx */
async function wipeApplicationData(tx) {
  await tx.panelAppBackup.deleteMany();
  await tx.adminTotpRecoveryCode.deleteMany();
  await tx.adminActionLog.deleteMany();
  await tx.openvpnServerLog.deleteMany();
  await tx.panelAsyncTask.deleteMany();
  await tx.agentMetricSnapshot.deleteMany();
  await tx.clientTrafficSample.deleteMany();
  await tx.clientSourceIpHistory.deleteMany();
  await tx.clientIpAssignment.deleteMany();
  await tx.agentNodeOpenvpnConfigVersion.deleteMany();
  await tx.agentNodeOpenvpnMaterial.deleteMany();
  await tx.agentNodeOpenvpnSettings.deleteMany();
  await tx.certificate.deleteMany();
  await tx.vpnUser.deleteMany();
  await tx.agentNode.deleteMany();
  await tx.rootCertificateAuthority.deleteMany();
  await tx.organization.deleteMany();
  await tx.admin.deleteMany();
  await tx.panelAppBackupSettings.deleteMany();
}

/** NUL и прочие C0 (кроме tab/LF/CR): ломают Prisma/PostgreSQL и JSON-обработчики. */
const BACKUP_CONTROL_CHARS_RE = /[\0\u0001-\u0008\u000b\u000c\u000e-\u001f]/g;

function stripBackupControlChars(s) {
  return typeof s === "string" ? s.replace(BACKUP_CONTROL_CHARS_RE, "") : s;
}

/**
 * Рекурсивно чистит все строки (в т.ч. внутри JSON-полей), чтобы в архиве и при импорте не было NUL.
 * @param {unknown} x
 * @returns {unknown}
 */
function deepSanitizeForBackup(x) {
  if (x === null || x === undefined) return x;
  if (typeof x === "bigint") return x;
  if (typeof x === "string") return stripBackupControlChars(x);
  if (typeof x === "number" || typeof x === "boolean") return x;
  if (x instanceof Date) return x.toISOString();
  if (Array.isArray(x)) return x.map(deepSanitizeForBackup);
  if (typeof x === "object") {
    /** @type {Record<string, unknown>} */
    const o = {};
    for (const [k, v] of Object.entries(x)) {
      o[k] = deepSanitizeForBackup(v);
    }
    return o;
  }
  return x;
}

function jsonReplacer(_k, v) {
  if (typeof v === "bigint") return v.toString();
  if (typeof v === "string") return stripBackupControlChars(v);
  if (v instanceof Date) return v.toISOString();
  return v;
}

/**
 * @returns {Promise<Record<string, unknown[]>>}
 */
export async function exportAllTablesJson() {
  return exportAllTablesJsonFromRawQueries(prisma);
}

function mapTrafficSample(row) {
  const { rxBytes, txBytes, ...rest } = row;
  return {
    ...rest,
    rxBytes: BigInt(rxBytes),
    txBytes: BigInt(txBytes),
  };
}

/** @param {import("@prisma/client").Prisma.TransactionClient} tx @param {Record<string, unknown[]>} data */
async function importAllFromJson(tx, data) {
  const org = data.Organization || [];
  const adm = data.Admin || [];
  const roots = data.RootCertificateAuthority || [];
  const nodes = data.AgentNode || [];
  const users = data.VpnUser || [];
  const certs = data.Certificate || [];
  const ovs = data.AgentNodeOpenvpnSettings || [];
  const ovc = data.AgentNodeOpenvpnConfigVersion || [];
  const mats = data.AgentNodeOpenvpnMaterial || [];
  const ipA = data.ClientIpAssignment || [];
  const srcH = data.ClientSourceIpHistory || [];
  const traf = data.ClientTrafficSample || [];
  const metrics = data.AgentMetricSnapshot || [];
  const logs = data.OpenvpnServerLog || [];
  const tasks = data.PanelAsyncTask || [];
  const aLogs = data.AdminActionLog || [];
  const totpRec = data.AdminTotpRecoveryCode || [];
  const bset = data.PanelAppBackupSettings || [];

  if (org.length) await tx.organization.createMany({ data: org.map((r) => ({ ...r })) });
  if (roots.length) await tx.rootCertificateAuthority.createMany({ data: roots.map((r) => ({ ...r })) });
  if (nodes.length) await tx.agentNode.createMany({ data: nodes.map((r) => ({ ...r })) });
  if (adm.length) {
    await tx.admin.createMany({
      data: adm.map((r) => {
        const row = { ...r };
        delete row.inviteToken;
        delete row.inviteExpiresAt;
        delete row.passwordResetToken;
        delete row.passwordResetExpiresAt;
        return {
          ...row,
          fullName: row.fullName != null && String(row.fullName).trim() !== "" ? String(row.fullName).trim() : "",
          email: row.email != null && String(row.email).trim() !== "" ? String(row.email).trim().toLowerCase() : null,
          inviteToken: null,
          inviteExpiresAt: null,
          passwordResetToken: null,
          passwordResetExpiresAt: null,
          totpEnabled: row.totpEnabled === true,
          totpSecretEnc: row.totpSecretEnc ?? null,
          totpPendingSecretEnc: row.totpPendingSecretEnc ?? null,
          totpPendingExpiresAt: row.totpPendingExpiresAt ?? null,
        };
      }),
    });
  }
  if (totpRec.length) await tx.adminTotpRecoveryCode.createMany({ data: totpRec.map((r) => ({ ...r })) });
  if (users.length) await tx.vpnUser.createMany({ data: users.map((r) => ({ ...r })) });
  if (certs.length) await tx.certificate.createMany({ data: certs.map((r) => ({ ...r })) });
  if (ovs.length) await tx.agentNodeOpenvpnSettings.createMany({ data: ovs.map((r) => ({ ...r })) });
  if (ovc.length) await tx.agentNodeOpenvpnConfigVersion.createMany({ data: ovc.map((r) => ({ ...r })) });
  if (mats.length) await tx.agentNodeOpenvpnMaterial.createMany({ data: mats.map((r) => ({ ...r })) });
  if (ipA.length) await tx.clientIpAssignment.createMany({ data: ipA.map((r) => ({ ...r })) });
  if (srcH.length) await tx.clientSourceIpHistory.createMany({ data: srcH.map((r) => ({ ...r })) });
  if (traf.length) await tx.clientTrafficSample.createMany({ data: traf.map((r) => mapTrafficSample(r)) });
  if (metrics.length) await tx.agentMetricSnapshot.createMany({ data: metrics.map((r) => ({ ...r })) });
  if (logs.length) await tx.openvpnServerLog.createMany({ data: logs.map((r) => ({ ...r })) });
  if (tasks.length) await tx.panelAsyncTask.createMany({ data: tasks.map((r) => ({ ...r })) });
  if (aLogs.length) await tx.adminActionLog.createMany({ data: aLogs.map((r) => ({ ...r })) });

  if (bset.length) {
    await tx.panelAppBackupSettings.createMany({ data: bset.map((r) => ({ ...r })) });
  } else {
    await tx.panelAppBackupSettings.create({
      data: { id: 1, intervalMinutes: 0, retainCount: 10, lastScheduledAt: new Date() },
    });
  }
}

/**
 * @param {string} backupDir
 * @param {"manual"|"scheduled"} trigger
 */
export async function createPanelBackupZip(backupDir, trigger = "manual") {
  await mkdir(backupDir, { recursive: true });
  const tablesRaw = await exportAllTablesJson();
  const tables = /** @type {Record<string, unknown[]>} */ (deepSanitizeForBackup(tablesRaw));
  const manifest = {
    format: PANEL_BACKUP_FORMAT,
    version: PANEL_BACKUP_VERSION,
    createdAt: new Date().toISOString(),
    tables: Object.keys(tables),
  };

  const zip = new AdmZip();
  zip.addFile("manifest.json", Buffer.from(JSON.stringify(manifest, null, 2), "utf8"));
  for (const [name, rows] of Object.entries(tables)) {
    zip.addFile(`tables/${name}.json`, Buffer.from(JSON.stringify(rows, jsonReplacer, 2), "utf8"));
  }
  const buffer = zip.toBuffer();

  const created = await prisma.panelAppBackup.create({
    data: {
      fileName: `panel-backup-${new Date().toISOString().replace(/[:.]/g, "-")}.zip`,
      sizeBytes: buffer.length,
      trigger,
    },
  });

  const absPath = path.join(backupDir, `${created.id}.zip`);
  await writeFile(absPath, buffer);

  await pruneOldBackups(backupDir);

  return created;
}

/**
 * @param {string} backupDir
 */
export async function pruneOldBackups(backupDir) {
  const settings = await prisma.panelAppBackupSettings.findUnique({ where: { id: 1 } });
  const retain = Math.max(1, Math.min(500, settings?.retainCount ?? 10));
  const rows = await prisma.$queryRawUnsafe(`
    SELECT b.id, b."createdAt"
    FROM "PanelAppBackup" b
    ORDER BY b."createdAt" DESC
  `);
  const drop = rows.slice(retain);
  for (const r of drop) {
    try {
      await unlink(path.join(backupDir, `${r.id}.zip`));
    } catch {
      /* ignore */
    }
    await prisma.panelAppBackup.delete({ where: { id: r.id } }).catch(() => {});
  }
}

/**
 * @param {string} backupDir
 * @param {Buffer} zipBuffer
 */
export async function restorePanelFromZipBuffer(backupDir, zipBuffer) {
  const zip = new AdmZip(zipBuffer);
  const manifestEntry = zip.getEntry("manifest.json");
  if (!manifestEntry) throw new Error("В архиве нет manifest.json");
  const manifest = JSON.parse(manifestEntry.getData().toString("utf8"));
  if (manifest.format !== PANEL_BACKUP_FORMAT) {
    throw new Error("Неизвестный формат резервной копии");
  }
  if (Number(manifest.version) !== PANEL_BACKUP_VERSION) {
    throw new Error(`Версия архива ${manifest.version} не поддерживается (ожидается ${PANEL_BACKUP_VERSION})`);
  }

  /** @type {Record<string, unknown[]>} */
  const data = {};
  const names = Array.isArray(manifest.tables) ? manifest.tables : [];
  for (const name of names) {
    const e = zip.getEntry(`tables/${name}.json`);
    if (!e) continue;
    data[name] = JSON.parse(e.getData().toString("utf8"));
  }

  const dataSafe = /** @type {Record<string, unknown[]>} */ (deepSanitizeForBackup(data));

  await mkdir(backupDir, { recursive: true });

  await prisma.$transaction(
    async (tx) => {
      await wipeApplicationData(tx);
      await importAllFromJson(tx, dataSafe);
    },
    { timeout: 300_000 },
  );

  try {
    const files = await readdir(backupDir);
    for (const f of files) {
      if (!f.endsWith(".zip")) continue;
      await unlink(path.join(backupDir, f));
    }
  } catch {
    /* ignore */
  }
  await prisma.panelAppBackup.deleteMany();
}

export async function ensureBackupSettingsRow() {
  const row = await prisma.panelAppBackupSettings.findUnique({ where: { id: 1 } });
  if (row) return row;
  return prisma.panelAppBackupSettings.create({
    data: { id: 1, intervalMinutes: 0, retainCount: 10, lastScheduledAt: new Date() },
  });
}
