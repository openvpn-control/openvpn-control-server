import crypto from "crypto";
import forge from "node-forge";
import { prisma } from "../prisma.js";
import { enqueueOpenvpnMaterialSyncTasks } from "./panelTasks.js";

export function rootCaRemainingValidityDays(certPem) {
  try {
    const x = new crypto.X509Certificate(String(certPem || "").trim());
    const exp = new Date(x.validTo).getTime();
    const ms = exp - Date.now();
    return Math.max(0, Math.ceil(ms / 86400000));
  } catch {
    return 0;
  }
}

function assertPrivateKeyMatchesCertificate(certPem, keyPem) {
  const certPub = crypto.createPublicKey(certPem);
  const priv = crypto.createPrivateKey(keyPem);
  const fromPriv = crypto.createPublicKey(priv);
  const a = certPub.export({ type: "spki", format: "pem" }).toString();
  const b = fromPriv.export({ type: "spki", format: "pem" }).toString();
  if (a !== b) {
    throw new Error("Закрытый ключ не соответствует сертификату");
  }
}

function normalizeSerialHex(hex) {
  const digits = String(hex || "").replace(/[^0-9a-f]/gi, "");
  if (!digits) return "";
  const n = BigInt(`0x${digits}`);
  return n.toString(16).toUpperCase();
}

function toPositiveHexSerial(hexString) {
  const hex = String(hexString || "");
  if (!hex) return "";
  const mostSig = parseInt(hex[0], 16);
  if (mostSig < 8) return hex;
  return (mostSig - 8).toString(16) + hex.substring(1);
}

function assertNonNegativeSerial(certPem, label = "Сертификат") {
  const x509 = new crypto.X509Certificate(String(certPem || "").trim());
  const serial = String(x509.serialNumber || "").trim();
  if (serial.startsWith("-")) {
    throw new Error(
      `${label} отклонён: отрицательный serialNumber (${serial}). Используйте сертификат с положительным serialNumber.`,
    );
  }
  return x509;
}

function normalizeCertPemForCompare(pem) {
  return String(pem || "")
    .replace(/\r\n/g, "\n")
    .replace(/\r/g, "\n")
    .trim();
}

function forgeMdForSignature(algorithm) {
  const a = String(algorithm || "sha256").toLowerCase();
  if (a === "sha512") return forge.md.sha512.create();
  if (a === "sha384") return forge.md.sha384.create();
  if (a === "sha1") return forge.md.sha1.create();
  return forge.md.sha256.create();
}

function issueSignedCertificatePem(rootCa, commonName, validityDays, { keySize, signatureAlgorithm } = {}) {
  const caCert = forge.pki.certificateFromPem(rootCa.certPem);
  const caKey = forge.pki.privateKeyFromPem(rootCa.keyPem);
  const bitsRaw = Number(keySize) || 2048;
  const bits = Math.min(8192, Math.max(2048, bitsRaw));
  const keys = forge.pki.rsa.generateKeyPair({ bits });
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = toPositiveHexSerial(forge.util.bytesToHex(forge.random.getBytesSync(9)));
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  const days = Math.max(1, Math.min(Number(validityDays) || 825, 3650));
  cert.validity.notAfter.setTime(cert.validity.notBefore.getTime() + days * 86400000);
  cert.version = 2;
  cert.setSubject([{ name: "commonName", value: commonName }]);
  cert.setIssuer(caCert.subject.attributes);
  cert.setExtensions([
    { name: "basicConstraints", cA: false },
    { name: "keyUsage", digitalSignature: true, keyEncipherment: true },
    { name: "extKeyUsage", serverAuth: true, clientAuth: true },
  ]);
  cert.sign(caKey, forgeMdForSignature(signatureAlgorithm));
  return {
    certPem: forge.pki.certificateToPem(cert),
    keyPem: forge.pki.privateKeyToPem(keys.privateKey),
  };
}

/**
 * Сертификат OpenVPN-сервера узла (без vpnUser), подписанный выбранным корневым сертификатом.
 * Появляется в списке сертификатов корневого сертификата вместе с пользовательскими.
 */
export async function issueServerCertificateForAgentNode({
  agentNodeId,
  rootCaId,
  commonName,
  validityDays,
  keySize,
  signatureAlgorithm,
}) {
  const node = await prisma.agentNode.findUnique({ where: { id: agentNodeId } });
  if (!node) {
    throw new Error("Узел не найден");
  }
  const rid = String(rootCaId || "").trim();
  if (!rid) {
    throw new Error("Выберите корневой сертификат");
  }
  const rootCa = await prisma.rootCertificateAuthority.findUnique({ where: { id: rid } });
  if (!rootCa) {
    throw new Error("Корневой сертификат не найден");
  }

  const existingActive = await prisma.certificate.findFirst({
    where: { agentNodeId, rootCaId: rootCa.id, vpnUserId: null, revokedAt: null },
  });
  if (existingActive) {
    throw new Error("На узле уже есть сертификат сервера. Удалите его перед выпуском нового.");
  }

  let cn = typeof commonName === "string" && commonName.trim() ? commonName.trim() : `server:${node.name}`;
  cn = cn.replace(/[^\w.\-:@]/g, "_").slice(0, 64);
  if (!cn) cn = `server-${agentNodeId.slice(0, 8)}`;

  const maxByRoot = rootCaRemainingValidityDays(rootCa.certPem);
  if (maxByRoot < 1) {
    throw new Error("Срок действия корневого сертификата истёк или истекает сегодня");
  }
  const requested = Math.max(1, Math.min(Number(validityDays) || 825, 3650));
  const days = Math.min(requested, maxByRoot, 3650);
  const { certPem, keyPem } = issueSignedCertificatePem(rootCa, cn, days, {
    keySize,
    signatureAlgorithm,
  });
  const x509 = new crypto.X509Certificate(certPem);
  const serialNumber = normalizeSerialHex(x509.serialNumber) || forge.util.bytesToHex(forge.random.getBytesSync(16));

  const cert = await prisma.certificate.create({
    data: {
      commonName: cn,
      issuedBy: rootCa.name,
      rootCaId: rootCa.id,
      agentNodeId: node.id,
      vpnUserId: null,
      certPem,
      keyPem,
      expiresAt: new Date(x509.validTo),
      serialNumber,
    },
    include: {
      rootCa: { select: { id: true, name: true, commonName: true } },
      agentNode: { select: { id: true, name: true } },
    },
  });

  const { certPem: _c, keyPem: _k, ...rest } = cert;
  return { ...rest, hasKeyMaterial: Boolean(cert.certPem && cert.keyPem) };
}

/**
 * Импорт PEM сертификата и ключа для узла; цепочка до указанного корневого сертификата.
 */
export async function importServerCertificateForAgentNode({ agentNodeId, rootCaId, certPem, keyPem }) {
  const node = await prisma.agentNode.findUnique({ where: { id: agentNodeId } });
  if (!node) {
    throw new Error("Узел не найден");
  }
  const rid = String(rootCaId || "").trim();
  if (!rid) {
    throw new Error("Выберите корневой сертификат");
  }
  const rootCa = await prisma.rootCertificateAuthority.findUnique({ where: { id: rid } });
  if (!rootCa) {
    throw new Error("Корневой сертификат не найден");
  }

  const certPemTrim = String(certPem || "").trim();
  const keyPemTrim = String(keyPem || "").trim();
  if (!certPemTrim.includes("BEGIN CERTIFICATE")) {
    throw new Error("Ожидается PEM сертификата");
  }
  if (!keyPemTrim.includes("BEGIN")) {
    throw new Error("Ожидается PEM закрытого ключа");
  }

  assertPrivateKeyMatchesCertificate(certPemTrim, keyPemTrim);

  const leaf = assertNonNegativeSerial(certPemTrim, "Импортируемый сертификат сервера");
  const ca = new crypto.X509Certificate(rootCa.certPem);
  if (!leaf.checkIssued(ca)) {
    throw new Error("Сертификат не выпущен выбранным корневым сертификатом");
  }
  if (!leaf.verify(ca.publicKey)) {
    throw new Error("Не удалось проверить подпись сертификата корневым сертификатом");
  }

  const cnRaw = leaf.subject
    .split("\n")
    .map((l) => l.trim())
    .find((l) => l.startsWith("CN="));
  const cn = (cnRaw ? cnRaw.replace(/^CN=/i, "").trim() : "") || `server:${node.name}`;
  const cnNorm = cn.replace(/[^\w.\-:@]/g, "_").slice(0, 64) || `server-${agentNodeId.slice(0, 8)}`;

  const serialNumber =
    normalizeSerialHex(leaf.serialNumber) || forge.util.bytesToHex(forge.random.getBytesSync(16));
  const pemNorm = normalizeCertPemForCompare(certPemTrim);
  const keyNorm = keyPemTrim.endsWith("\n") ? keyPemTrim : `${keyPemTrim}\n`;
  const certNorm = certPemTrim.endsWith("\n") ? certPemTrim : `${certPemTrim}\n`;

  const certInclude = {
    rootCa: { select: { id: true, name: true, commonName: true } },
    agentNode: { select: { id: true, name: true } },
  };

  const existingBySerial = await prisma.certificate.findUnique({
    where: { serialNumber },
    include: certInclude,
  });

  if (existingBySerial) {
    const samePem = normalizeCertPemForCompare(existingBySerial.certPem) === pemNorm;
    if (!samePem) {
      throw new Error(
        "В базе уже есть другой сертификат с тем же серийным номером. Отзовите или удалите старую запись либо используйте другой файл.",
      );
    }
    if (existingBySerial.agentNodeId !== node.id) {
      throw new Error("Сертификат с этим серийным номером уже привязан к другому узлу");
    }
    if (existingBySerial.vpnUserId) {
      throw new Error("Сертификат с этим серийным номером зарегистрирован как пользовательский");
    }
    const updated = await prisma.certificate.update({
      where: { id: existingBySerial.id },
      data: {
        certPem: certNorm,
        keyPem: keyNorm,
        expiresAt: new Date(leaf.validTo),
        commonName: cnNorm,
        issuedBy: rootCa.name,
        rootCaId: rootCa.id,
        revokedAt: null,
        revokedReason: null,
      },
      include: certInclude,
    });
    const { certPem: _c, keyPem: _k, ...rest } = updated;
    return { ...rest, hasKeyMaterial: Boolean(updated.certPem && updated.keyPem) };
  }

  const existingByCn = await prisma.certificate.findFirst({
    where: { commonName: cnNorm, agentNodeId: node.id, vpnUserId: null },
    include: certInclude,
  });
  if (existingByCn) {
    const samePem = normalizeCertPemForCompare(existingByCn.certPem) === pemNorm;
    if (samePem) {
      if (existingByCn.vpnUserId) {
        throw new Error("Сертификат с таким CN зарегистрирован как пользовательский");
      }
      const serialTaken = await prisma.certificate.findFirst({
        where: { serialNumber, NOT: { id: existingByCn.id } },
      });
      if (serialTaken) {
        throw new Error(
          "Серийный номер уже занят другой записью в базе. Обратитесь к администратору или удалите конфликтующую запись.",
        );
      }
      const updated = await prisma.certificate.update({
        where: { id: existingByCn.id },
        data: {
          serialNumber,
          certPem: certNorm,
          keyPem: keyNorm,
          expiresAt: new Date(leaf.validTo),
          issuedBy: rootCa.name,
          rootCaId: rootCa.id,
          revokedAt: null,
          revokedReason: null,
          vpnUserId: null,
        },
        include: certInclude,
      });
      const { certPem: _c, keyPem: _k, ...rest } = updated;
      return { ...rest, hasKeyMaterial: Boolean(updated.certPem && updated.keyPem) };
    }
    if (!existingByCn.revokedAt) {
      throw new Error("На этом узле уже есть активный сертификат с таким CN.");
    }
    const serialTaken = await prisma.certificate.findFirst({
      where: { serialNumber, NOT: { id: existingByCn.id } },
    });
    if (serialTaken) {
      throw new Error(
        "Серийный номер уже занят другой записью. Отзовите или удалите конфликтующий сертификат.",
      );
    }
    const updated = await prisma.certificate.update({
      where: { id: existingByCn.id },
      data: {
        serialNumber,
        certPem: certNorm,
        keyPem: keyNorm,
        expiresAt: new Date(leaf.validTo),
        issuedBy: rootCa.name,
        rootCaId: rootCa.id,
        vpnUserId: null,
        revokedAt: null,
        revokedReason: null,
      },
      include: certInclude,
    });
    const { certPem: _c, keyPem: _k, ...rest } = updated;
    return { ...rest, hasKeyMaterial: Boolean(updated.certPem && updated.keyPem) };
  }

  const otherActive = await prisma.certificate.findFirst({
    where: {
      agentNodeId: node.id,
      rootCaId: rootCa.id,
      vpnUserId: null,
      revokedAt: null,
    },
  });
  if (otherActive) {
    throw new Error("На узле уже есть сертификат сервера. Удалите его перед импортом нового.");
  }

  const cert = await prisma.certificate.create({
    data: {
      commonName: cnNorm,
      issuedBy: rootCa.name,
      rootCaId: rootCa.id,
      agentNodeId: node.id,
      vpnUserId: null,
      certPem: certNorm,
      keyPem: keyNorm,
      expiresAt: new Date(leaf.validTo),
      serialNumber,
    },
    include: {
      rootCa: { select: { id: true, name: true, commonName: true } },
      agentNode: { select: { id: true, name: true } },
    },
  });

  const { certPem: _c, keyPem: _k, ...rest } = cert;
  return { ...rest, hasKeyMaterial: Boolean(cert.certPem && cert.keyPem) };
}

/** Удаляет все сертификаты OpenVPN-сервера узла для текущего корневого сертификата панели и сбрасывает panelServerCertId. */
export async function deleteServerCertificateForAgentNode(agentNodeId) {
  const id = String(agentNodeId || "").trim();
  const node = await prisma.agentNode.findUnique({ where: { id } });
  if (!node) {
    throw new Error("Узел не найден");
  }

  const row = await prisma.agentNodeOpenvpnSettings.findUnique({ where: { agentNodeId: id } });
  const prev =
    row?.settings && typeof row.settings === "object" && !Array.isArray(row.settings) ? row.settings : {};
  const rootId = String(prev.panelRootCaId || "").trim();
  if (!rootId) {
    throw new Error("Для этого сервера не задан корневой сертификат");
  }

  await prisma.$transaction(async (tx) => {
    await tx.certificate.deleteMany({
      where: { agentNodeId: id, rootCaId: rootId, vpnUserId: null },
    });
    const next = { ...prev, panelServerCertId: "" };
    await tx.agentNodeOpenvpnSettings.upsert({
      where: { agentNodeId: id },
      create: { agentNodeId: id, settings: next },
      update: { settings: next },
    });
  });

  const row2 = await prisma.agentNodeOpenvpnSettings.findUnique({ where: { agentNodeId: id } });
  const settings =
    row2?.settings && typeof row2.settings === "object" && !Array.isArray(row2.settings) ? row2.settings : {};
  await enqueueOpenvpnMaterialSyncTasks(node, settings);
  return { ok: true };
}
