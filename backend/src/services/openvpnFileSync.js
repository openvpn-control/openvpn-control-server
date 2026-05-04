import crypto from "node:crypto";
import { prisma } from "../prisma.js";
import { postAgentOpenvpnFileSha256, postAgentWriteOpenvpnFile } from "./agentChannel.js";
import { firstTlsAuthPath } from "./openvpnPemGenerators.js";

export function sha256HexUtf8(content) {
  return crypto.createHash("sha256").update(content, "utf8").digest("hex");
}

/** Убрать метаданные панели (в т.ч. firewall в JSON) — не являются директивами OpenVPN и не должны уходить в server.conf. */
export function stripPanelOnlyOpenvpnSettings(settings) {
  if (!settings || typeof settings !== "object") return {};
  const out = { ...settings };
  const panelOnlyKeys = new Set(["remote", "resolv-retry", "nobind", "key-direction", "client-verb"]);
  for (const k of Object.keys(out)) {
    if (String(k).startsWith("panel") || panelOnlyKeys.has(String(k))) delete out[k];
  }
  return out;
}

async function remoteSha256(node, pathStr) {
  try {
    const data = await postAgentOpenvpnFileSha256(node, pathStr);
    if (data && data.exists && typeof data.sha256 === "string") {
      return { exists: true, sha256: data.sha256.toLowerCase() };
    }
    return { exists: false, sha256: "" };
  } catch {
    return { exists: false, sha256: "" };
  }
}

export async function writeOpenvpnFileIfDigestDiffers(node, absPath, utf8Content) {
  const local = sha256HexUtf8(utf8Content);
  const remote = await remoteSha256(node, absPath);
  if (!remote.exists || remote.sha256 !== local) {
    await postAgentWriteOpenvpnFile(node, absPath, Buffer.from(utf8Content, "utf8"));
  }
}

/**
 * Перед записью server.conf: синхронизировать CA, cert/key, DH, tls-auth по SHA-256 с панелью.
 */
export async function syncOpenvpnFilesBeforeApply(node, settings) {
  if (!settings || typeof settings !== "object" || Array.isArray(settings)) return;

  const rootId = String(settings.panelRootCaId || "").trim();
  const caPath = String(settings.ca || "").trim();
  if (rootId && caPath) {
    const root = await prisma.rootCertificateAuthority.findUnique({ where: { id: rootId } });
    if (root?.certPem) {
      await writeOpenvpnFileIfDigestDiffers(node, caPath, root.certPem);
    }
  }

  const certId = String(settings.panelServerCertId || "").trim();
  const certPath = String(settings.cert || "").trim();
  const keyPath = String(settings.key || "").trim();
  if (certId && certPath && keyPath) {
    const certRow = await prisma.certificate.findUnique({
      where: { id: certId },
      select: { certPem: true, keyPem: true, agentNodeId: true },
    });
    if (!certRow?.certPem || !certRow?.keyPem) {
      throw new Error(
        "У выбранного сертификата нет PEM в базе данных. Выпустите новый сертификат для этого пользователя и узла.",
      );
    }
    if (certRow.agentNodeId && certRow.agentNodeId !== node.id) {
      throw new Error("Выбранный сертификат привязан к другому узлу.");
    }
    await writeOpenvpnFileIfDigestDiffers(node, certPath, certRow.certPem);
    await writeOpenvpnFileIfDigestDiffers(node, keyPath, certRow.keyPem);
  }

  const dhMatId = String(settings.panelDhMaterialId || "").trim();
  const dhPath = String(settings.dh || "").trim();
  if (dhMatId && dhPath) {
    const mat = await prisma.agentNodeOpenvpnMaterial.findFirst({
      where: { id: dhMatId, agentNodeId: node.id, kind: "dh" },
    });
    if (!mat) {
      throw new Error("Некорректный выбор файла DH.");
    }
    await writeOpenvpnFileIfDigestDiffers(node, dhPath, mat.pem);
  }

  const tlsMatId = String(settings.panelTlsAuthMaterialId || "").trim();
  const tlsPath = firstTlsAuthPath(settings["tls-auth"]);
  if (tlsMatId && tlsPath) {
    const mat = await prisma.agentNodeOpenvpnMaterial.findFirst({
      where: { id: tlsMatId, agentNodeId: node.id, kind: "tls_auth" },
    });
    if (!mat) {
      throw new Error("Некорректный выбор ключа tls-auth.");
    }
    await writeOpenvpnFileIfDigestDiffers(node, tlsPath, mat.pem);
  }
}
