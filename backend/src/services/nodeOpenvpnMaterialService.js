import crypto from "crypto";
import { prisma } from "../prisma.js";
import { generateDhPem2048, generateTlsAuthKeyPem } from "./openvpnPemGenerators.js";

function materialPemFingerprintSha256(pem) {
  try {
    const hex = crypto.createHash("sha256").update(String(pem || ""), "utf8").digest("hex");
    return hex.toUpperCase().match(/.{1,2}/g)?.join(":") || "";
  } catch {
    return "";
  }
}

export function validateMaterialPem(kind, rawPem) {
  const k = String(kind || "").trim();
  const t = String(rawPem || "").trim();
  if (!t.includes("BEGIN")) {
    throw new Error("Ожидается текст в формате PEM");
  }
  if (k === "dh") {
    if (!/BEGIN (DH PARAMETERS|X9\.42 DH PARAMETERS)/i.test(t)) {
      throw new Error("Для DH нужен PEM с BEGIN DH PARAMETERS (openssl dhparam)");
    }
  } else if (k === "tls_auth") {
    if (!/BEGIN OpenVPN Static key V1/i.test(t)) {
      throw new Error("Для tls-auth нужен файл ключа OpenVPN (ta.key)");
    }
  } else {
    throw new Error("kind должен быть dh или tls_auth");
  }
  return t.endsWith("\n") ? t : `${t}\n`;
}

export async function listNodeOpenvpnMaterials(agentNodeId, kindFilter) {
  const node = await prisma.agentNode.findUnique({ where: { id: agentNodeId }, select: { id: true } });
  if (!node) return null;
  const rows = await prisma.agentNodeOpenvpnMaterial.findMany({
    where: {
      agentNodeId,
      ...(kindFilter ? { kind: kindFilter } : {}),
    },
    orderBy: { createdAt: "desc" },
    select: { id: true, kind: true, label: true, createdAt: true, pem: true },
  });
  return rows.map(({ pem, ...rest }) => ({
    ...rest,
    sizeBytes: Buffer.byteLength(String(pem || ""), "utf8"),
    fingerprintSha256: materialPemFingerprintSha256(pem),
  }));
}

export async function createNodeOpenvpnMaterial(agentNodeId, kind, label, pemFromUpload) {
  const k = String(kind || "").trim();
  if (k !== "dh" && k !== "tls_auth") {
    throw new Error("kind должен быть dh или tls_auth");
  }
  const node = await prisma.agentNode.findUnique({ where: { id: agentNodeId }, select: { id: true } });
  if (!node) {
    throw new Error("Узел не найден");
  }
  const pem =
    pemFromUpload !== undefined && pemFromUpload !== null && String(pemFromUpload).trim()
      ? validateMaterialPem(k, pemFromUpload)
      : k === "dh"
        ? generateDhPem2048()
        : generateTlsAuthKeyPem();
  return prisma.agentNodeOpenvpnMaterial.create({
    data: {
      agentNodeId,
      kind: k,
      label: label ? String(label).trim() || null : null,
      pem,
    },
    select: { id: true, kind: true, label: true, createdAt: true },
  });
}

export async function deleteNodeOpenvpnMaterial(agentNodeId, materialId) {
  const mat = await prisma.agentNodeOpenvpnMaterial.findFirst({
    where: { id: materialId, agentNodeId },
  });
  if (!mat) return null;

  await prisma.agentNodeOpenvpnMaterial.delete({ where: { id: materialId } });

  const row = await prisma.agentNodeOpenvpnSettings.findUnique({ where: { agentNodeId } });
  if (row?.settings && typeof row.settings === "object" && !Array.isArray(row.settings)) {
    const s = { ...row.settings };
    let changed = false;
    if (String(s.panelDhMaterialId || "") === materialId) {
      s.panelDhMaterialId = "";
      changed = true;
    }
    if (String(s.panelTlsAuthMaterialId || "") === materialId) {
      s.panelTlsAuthMaterialId = "";
      changed = true;
    }
    if (changed) {
      await prisma.agentNodeOpenvpnSettings.update({
        where: { agentNodeId },
        data: { settings: s },
      });
    }
  }

  return { ok: true };
}
