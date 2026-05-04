import bcrypt from "bcryptjs";
import crypto from "node:crypto";
import { prisma } from "../prisma.js";

const RECOVERY_CODE_COUNT = 10;

export function normalizeRecoveryCodeInput(raw) {
  return String(raw ?? "")
    .replace(/[\s-]/g, "")
    .toLowerCase();
}

function formatRecoveryCode(bytes) {
  const h = Buffer.from(bytes).toString("hex");
  return `${h.slice(0, 4)}-${h.slice(4, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}`;
}

/**
 * @param {import("@prisma/client").Prisma.TransactionClient} [tx]
 */
export async function replaceRecoveryCodesForAdmin(adminId, tx = prisma) {
  await tx.adminTotpRecoveryCode.deleteMany({ where: { adminId } });
  const plainCodes = [];
  const rows = [];
  for (let i = 0; i < RECOVERY_CODE_COUNT; i++) {
    const plain = formatRecoveryCode(crypto.randomBytes(8));
    plainCodes.push(plain);
    const normalized = normalizeRecoveryCodeInput(plain);
    const codeHash = await bcrypt.hash(normalized, 10);
    rows.push({ adminId, codeHash });
  }
  await tx.adminTotpRecoveryCode.createMany({ data: rows });
  return plainCodes;
}

/**
 * @returns {Promise<boolean>}
 */
export async function verifyAndConsumeRecoveryCode(adminId, rawCode) {
  const normalized = normalizeRecoveryCodeInput(rawCode);
  if (normalized.length < 16) return false;

  return prisma.$transaction(async (tx) => {
    const rows = await tx.adminTotpRecoveryCode.findMany({
      where: { adminId, usedAt: null },
      select: { id: true, codeHash: true },
    });
    for (const row of rows) {
      const ok = await bcrypt.compare(normalized, row.codeHash);
      if (ok) {
        const updated = await tx.adminTotpRecoveryCode.updateMany({
          where: { id: row.id, usedAt: null },
          data: { usedAt: new Date() },
        });
        if (updated.count === 1) return true;
      }
    }
    return false;
  });
}
