import crypto from "crypto";
import { Router } from "express";
import forge from "node-forge";
import { prisma } from "../../prisma.js";
import { enqueueCrlDeployTasksForRootCa, enqueuePanelAgentSnapshotForNode } from "../../services/panelTasks.js";
import { generateCrlPem } from "../../services/crlService.js";

const router = Router();

/** OpenSSL-style non-negative serial (RFC 5280). */
function toPositiveHexRootCa(hexString) {
  const hex = String(hexString || "");
  if (!hex) return "";
  const mostSig = parseInt(hex[0], 16);
  if (mostSig < 8) return hex;
  return (mostSig - 8).toString(16) + hex.substring(1);
}

/** OpenSSL-style non-negative serial for leaf certificates as well. */
function toPositiveHexSerial(hexString) {
  return toPositiveHexRootCa(hexString);
}

function hasNegativeSerial(certPem) {
  if (!certPem || typeof certPem !== "string") return false;
  try {
    const x509 = new crypto.X509Certificate(certPem);
    return String(x509.serialNumber || "").trim().startsWith("-");
  } catch {
    return false;
  }
}

function assertPrivateKeyMatchesCertificate(certPem, keyPem) {
  const certPub = crypto.createPublicKey(certPem);
  const priv = crypto.createPrivateKey(keyPem);
  const fromPriv = crypto.createPublicKey(priv);
  const certPubPem = certPub.export({ type: "spki", format: "pem" }).toString();
  const keyPubPem = fromPriv.export({ type: "spki", format: "pem" }).toString();
  if (certPubPem !== keyPubPem) {
    throw new Error("Закрытый ключ не соответствует сертификату");
  }
}

function forgeMessageDigestForRootSignature(algorithm) {
  const a = String(algorithm || "sha256").toLowerCase();
  if (a === "sha512") return forge.md.sha512.create();
  if (a === "sha384") return forge.md.sha384.create();
  if (a === "sha1") return forge.md.sha1.create();
  return forge.md.sha256.create();
}

/** Самоподписанный корневой сертификат (RSA), параметры как у пакета selfsigned по умолчанию. */
function generateRootCaSelfSignedPem({ commonName, days, keySize, signatureAlgorithm }) {
  const bitsRaw = Number(keySize) || 4096;
  const bits = Math.min(8192, Math.max(2048, bitsRaw));
  const daysNum = Math.max(1, Math.min(3650, Number(days) || 3650));
  const keyPair = forge.pki.rsa.generateKeyPair({ bits });
  const cert = forge.pki.createCertificate();
  cert.serialNumber = toPositiveHexRootCa(forge.util.bytesToHex(forge.random.getBytesSync(9)));
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setDate(cert.validity.notBefore.getDate() + daysNum);
  const attrs = [{ name: "commonName", value: String(commonName) }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.publicKey = keyPair.publicKey;
  cert.setExtensions([
    { name: "basicConstraints", cA: true },
    {
      name: "keyUsage",
      keyCertSign: true,
      cRLSign: true,
      digitalSignature: true,
      nonRepudiation: true,
      keyEncipherment: true,
      dataEncipherment: true,
    },
    {
      name: "subjectAltName",
      altNames: [{ type: 6, value: "http://example.org/webid#me" }],
    },
  ]);
  cert.sign(keyPair.privateKey, forgeMessageDigestForRootSignature(signatureAlgorithm));
  return {
    cert: forge.pki.certificateToPem(cert),
    private: forge.pki.privateKeyToPem(keyPair.privateKey),
  };
}

function pemExpiryISO(certPem) {
  if (!certPem || typeof certPem !== "string") return null;
  try {
    const x509 = new crypto.X509Certificate(certPem);
    const d = new Date(x509.validTo);
    return Number.isNaN(d.getTime()) ? null : d.toISOString();
  } catch {
    return null;
  }
}

function isCaOrSelfSignedCertificate(certPem) {
  if (!certPem || typeof certPem !== "string") return false;
  try {
    const x509 = new crypto.X509Certificate(certPem);
    if (x509.ca) return true;
    const subject = String(x509.subject || "").trim();
    const issuer = String(x509.issuer || "").trim();
    return Boolean(subject && issuer && subject === issuer);
  } catch {
    return false;
  }
}

function withRootCaExpiry(row) {
  if (!row) return row;
  return { ...row, expiresAt: pemExpiryISO(row.certPem) };
}

function normalizeFingerprint(value) {
  const raw = String(value || "").trim();
  if (!raw) return "";
  return raw.replace(/:/g, "").toUpperCase().match(/.{1,2}/g)?.join(":") || raw;
}

function detectEncryptedPrivateKeyPem(keyPem) {
  const text = String(keyPem || "");
  return /BEGIN ENCRYPTED PRIVATE KEY/.test(text) || /Proc-Type:\s*4,ENCRYPTED/i.test(text);
}

/** Отпечаток DER-сертификата (hex без двоеточий → с двоеточиями). */
function fingerprintFromDer(der, algo) {
  try {
    const hex = crypto.createHash(algo).update(der).digest("hex");
    return normalizeFingerprint(hex);
  } catch {
    return "";
  }
}

/** Алгоритм хеша подписи по OID подписи сертификата (RSA / частые варианты). */
function digestFromCertificateSignatureOid(oid) {
  const id = String(oid || "");
  const map = {
    "1.2.840.113549.1.1.13": "sha512",
    "1.2.840.113549.1.1.12": "sha384",
    "1.2.840.113549.1.1.11": "sha256",
    "1.2.840.113549.1.1.5": "sha1",
  };
  return map[id] || "";
}

function buildCertificateMaterialSummary(certPem, keyPem) {
  const summary = {
    pairMatches: null,
    fingerprintSha1: "",
    fingerprintSha256: "",
    fingerprintSha384: "",
    fingerprintSha512: "",
    certificateSignatureHash: "",
    serialNumber: "",
    algorithm: "",
    keySize: null,
    validTo: null,
    eku: [],
    encryptedPrivateKey: null,
  };
  if (!certPem) {
    summary.encryptedPrivateKey = keyPem ? detectEncryptedPrivateKeyPem(keyPem) : null;
    return summary;
  }
  try {
    const x509 = new crypto.X509Certificate(certPem);
    const certPublicKey = x509.publicKey;
    const certDetails = certPublicKey?.asymmetricKeyDetails || {};
    const der = x509.raw;
    summary.fingerprintSha1 = fingerprintFromDer(der, "sha1");
    summary.fingerprintSha256 = fingerprintFromDer(der, "sha256");
    summary.fingerprintSha384 = fingerprintFromDer(der, "sha384");
    summary.fingerprintSha512 = fingerprintFromDer(der, "sha512");
    try {
      const fc = forge.pki.certificateFromPem(certPem);
      const inferred = digestFromCertificateSignatureOid(fc.signatureOid);
      summary.certificateSignatureHash = inferred || "sha256";
    } catch {
      summary.certificateSignatureHash = "sha256";
    }
    summary.serialNumber = String(x509.serialNumber || "");
    summary.algorithm = String(certPublicKey?.asymmetricKeyType || "");
    summary.keySize = certDetails.modulusLength ? Number(certDetails.modulusLength) : null;
    summary.validTo = x509.validTo ? new Date(x509.validTo).toISOString() : null;
    summary.eku = Array.isArray(x509.extKeyUsage) ? x509.extKeyUsage : [];
    if (!keyPem) return summary;
    summary.encryptedPrivateKey = detectEncryptedPrivateKeyPem(keyPem);
    if (summary.encryptedPrivateKey) {
      summary.pairMatches = null;
      return summary;
    }
    const privateKey = crypto.createPrivateKey(keyPem);
    const privatePublicKey = crypto.createPublicKey(privateKey);
    const certSpki = certPublicKey.export({ type: "spki", format: "der" });
    const keySpki = privatePublicKey.export({ type: "spki", format: "der" });
    summary.pairMatches = Buffer.compare(certSpki, keySpki) === 0;
    if (!summary.algorithm) summary.algorithm = String(privateKey.asymmetricKeyType || "");
    if (!summary.keySize) {
      const privateDetails = privateKey.asymmetricKeyDetails || {};
      summary.keySize = Number(privateDetails.modulusLength || null);
    }
    return summary;
  } catch {
    summary.encryptedPrivateKey = keyPem ? detectEncryptedPrivateKeyPem(keyPem) : null;
    return summary;
  }
}

/** Подпись конечного сертификата корневым сертификатом (RSA 2048, SHA-256). */
function issueSignedCertificatePem(rootCa, commonName, validityDays) {
  const caCert = forge.pki.certificateFromPem(rootCa.certPem);
  const caKey = forge.pki.privateKeyFromPem(rootCa.keyPem);
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = toPositiveHexSerial(forge.util.bytesToHex(forge.random.getBytesSync(9)));
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  const days = Math.max(1, Math.min(Number(validityDays) || 365, 3650));
  cert.validity.notAfter.setTime(cert.validity.notBefore.getTime() + days * 86400000);
  cert.version = 2;
  cert.setSubject([{ name: "commonName", value: commonName }]);
  cert.setIssuer(caCert.subject.attributes);
  cert.setExtensions([
    { name: "basicConstraints", cA: false },
    { name: "keyUsage", digitalSignature: true, keyEncipherment: true },
    { name: "extKeyUsage", serverAuth: true, clientAuth: true },
  ]);
  cert.sign(caKey, forge.md.sha256.create());
  return {
    certPem: forge.pki.certificateToPem(cert),
    keyPem: forge.pki.privateKeyToPem(keys.privateKey),
  };
}

/** Canonical hex serial for matching index.txt ↔ CRL (leading zeros normalized). */
function normalizeSerialHex(hex) {
  const digits = String(hex || "").replace(/[^0-9a-f]/gi, "");
  if (!digits) return "";
  const n = BigInt(`0x${digits}`);
  return n.toString(16).toUpperCase();
}

/** OpenSSL Easy-RSA / pki.index.txt: V/R/E, dates, serial (hex), subject DN */
function parseEasyRsaIndexLine(raw) {
  const line = String(raw || "").replace(/\r$/, "").trim();
  if (!line || line.startsWith("#")) return null;

  const m = line.match(/^([VRE])\s+(\d{12}Z)(?:\s+(\d{12}Z))?\s+([0-9A-Fa-f]+)\s+/i);
  if (!m) return null;

  const status = m[1].toUpperCase();
  const serialHex = normalizeSerialHex(m[4]);
  if (!serialHex) return null;

  const rest = line.slice(m[0].length);
  const cnMatch = rest.match(/\/CN=([^/\n,]+)/i) || rest.match(/\bCN=([^/\n,]+)/i);
  if (!cnMatch) return null;
  const cn = cnMatch[1].trim();
  if (!cn) return null;

  return {
    status: /** @type {"V" | "R" | "E"} */ (status),
    expiryUtc: m[2],
    revocationUtc: m[3] || null,
    serialHex,
    cn,
  };
}

function opensslUtcTimeToDate(utc) {
  if (!utc || utc.length < 12) return null;
  const yy = parseInt(utc.slice(0, 2), 10);
  const year = yy >= 50 ? 1900 + yy : 2000 + yy;
  const mon = parseInt(utc.slice(2, 4), 10) - 1;
  const day = parseInt(utc.slice(4, 6), 10);
  const hh = parseInt(utc.slice(6, 8), 10);
  const mm = parseInt(utc.slice(8, 10), 10);
  const ss = parseInt(utc.slice(10, 12), 10);
  const d = new Date(Date.UTC(year, mon, day, hh, mm, ss));
  return Number.isNaN(d.getTime()) ? null : d;
}

/** Legacy: tab-separated index, или строка с CN (без разбора serial); не дублирует easy-rsa в syncIssued. */
function parseInventoryLine(line) {
  const t = String(line || "").trim();
  if (!t || t.startsWith("#")) return null;

  if (t.includes("\t")) {
    const parts = t.split("\t");
    const status = parts[0];
    if (!/^[VRE]$/i.test(status)) return null;
    const dn = parts[parts.length - 1] || "";
    const cnMatch = dn.match(/\/CN=([^/\n]+)/) || dn.match(/CN=([^/\n]+)/);
    const cn = cnMatch ? cnMatch[1].trim() : null;
    if (!cn) return null;
    return { status: status.toUpperCase(), cn, serialHex: null, expiryUtc: null };
  }

  const cnFromDn = t.match(/\/CN=([^/\n]+)/) || t.match(/CN=([^/\n]+)/);
  if (cnFromDn) return { status: null, cn: cnFromDn[1].trim(), serialHex: null, expiryUtc: null };

  return { status: null, cn: t, serialHex: null, expiryUtc: null };
}

function toOpensslUtc(d) {
  const x = new Date(d);
  if (Number.isNaN(x.getTime())) return "00000000000000Z";
  const p = (n) => String(n).padStart(2, "0");
  const y = String(x.getUTCFullYear()).slice(-2);
  return `${y}${p(x.getUTCMonth() + 1)}${p(x.getUTCDate())}${p(x.getUTCHours())}${p(x.getUTCMinutes())}${p(x.getUTCSeconds())}Z`;
}

function buildIndexTxtForRootCertificates(rows) {
  const out = [];
  for (const row of rows) {
    const serialHex = normalizeSerialHex(row.serialNumber) || "01";
    const exp = toOpensslUtc(row.expiresAt);
    const cn = String(row.commonName || "unknown").replace(/[\t\n\r]/g, " ");
    if (row.revokedAt) {
      const rev = toOpensslUtc(row.revokedAt);
      out.push(`R\t${exp}\t${rev}\t${serialHex}\tunknown\t/CN=${cn}`);
    } else {
      out.push(`V\t${exp}\t\t${serialHex}\tunknown\t/CN=${cn}`);
    }
  }
  return out.length ? `${out.join("\n")}\n` : "";
}

function isProbablyCrlPem(text) {
  const t = String(text || "").trim();
  return /BEGIN\s+X509\s+CRL/i.test(t) || /BEGIN\s+CERTIFICATE\s+REVOCATION\s+LIST/i.test(t);
}

function revokedSerialSetFromCrlPem(pem) {
  const crl = forge.pki.crlFromPem(String(pem).trim());
  const set = new Set();
  const list = crl.revokedCertificates || [];
  for (const rev of list) {
    const sn = rev.serialNumber;
    let hex = "";
    if (typeof sn === "string") {
      hex = forge.util.bytesToHex(sn);
    } else if (sn != null && typeof sn.toString === "function") {
      hex = sn.toString(16);
    }
    const norm = normalizeSerialHex(hex);
    if (norm) set.add(norm);
  }
  return set;
}

const DEFAULT_IMPORTED_EXPIRY_MS = 10 * 365 * 24 * 60 * 60 * 1000;

async function syncIssuedInventory(prisma, rootCaId, issuedByName, text, agentNodeId = null) {
  const stats = { created: 0, skipped: 0, reactivated: 0, updated: 0 };
  if (!text || !String(text).trim()) return stats;

  /** @type {Map<string, { serialHex: string, expiresAt: Date }>} */
  const byCn = new Map();

  for (const raw of String(text).split(/\r?\n/)) {
    const easy = parseEasyRsaIndexLine(raw);
    if (easy) {
      if (easy.status === "R") continue;
      if (easy.status !== "V" && easy.status !== "E") continue;
      const exp = opensslUtcTimeToDate(easy.expiryUtc) || new Date(Date.now() + DEFAULT_IMPORTED_EXPIRY_MS);
      byCn.set(easy.cn, { serialHex: easy.serialHex, expiresAt: exp });
      continue;
    }

    const p = parseInventoryLine(raw);
    if (!p || !p.cn) continue;
    if (p.status === "R") continue;
    if (p.status && p.status !== "V" && p.status !== "E") continue;

    if (!byCn.has(p.cn)) {
      byCn.set(p.cn, {
        serialHex: null,
        expiresAt: new Date(Date.now() + DEFAULT_IMPORTED_EXPIRY_MS),
      });
    }
  }

  for (const [cn, meta] of byCn) {
    const serialNumber = meta.serialHex || crypto.randomUUID();

    const existing = await prisma.certificate.findFirst({
      where: { commonName: cn, agentNodeId: agentNodeId || null },
    });

    if (existing) {
      if (existing.rootCaId !== rootCaId) {
        stats.skipped += 1;
        continue;
      }

      const data = {
        serialNumber,
        expiresAt: meta.expiresAt,
        issuedBy: issuedByName,
      };
      if (existing.revokedAt) {
        await prisma.certificate.update({
          where: { id: existing.id },
          data: { ...data, revokedAt: null, revokedReason: null },
        });
        stats.reactivated += 1;
        continue;
      }

      const serialChanged = normalizeSerialHex(existing.serialNumber) !== normalizeSerialHex(serialNumber);
      const expChanged = existing.expiresAt.getTime() !== meta.expiresAt.getTime();
      if (serialChanged || expChanged) {
        try {
          await prisma.certificate.update({
            where: { id: existing.id },
            data,
          });
          stats.updated += 1;
        } catch {
          stats.skipped += 1;
        }
        continue;
      }

      stats.skipped += 1;
      continue;
    }

    try {
      await prisma.certificate.create({
        data: {
          commonName: cn,
          serialNumber,
          issuedBy: issuedByName,
          rootCaId,
          agentNodeId: agentNodeId || null,
          expiresAt: meta.expiresAt,
        },
      });
      stats.created += 1;
    } catch {
      stats.skipped += 1;
    }
  }

  return stats;
}

async function syncRevokedInventory(prisma, rootCaId, issuedByName, text) {
  const stats = { updated: 0, created: 0, skipped: 0 };
  if (!text || !String(text).trim()) return stats;

  const seen = new Set();
  for (const raw of String(text).split(/\r?\n/)) {
    const p = parseInventoryLine(raw);
    if (!p) continue;

    const { cn } = p;
    if (!cn || seen.has(cn)) continue;
    seen.add(cn);

    const existing = await prisma.certificate.findFirst({
      where: { commonName: cn, agentNodeId: null },
    });

    if (existing) {
      if (existing.rootCaId !== rootCaId) {
        stats.skipped += 1;
        continue;
      }
      if (!existing.revokedAt) {
        await prisma.certificate.update({
          where: { id: existing.id },
          data: { revokedAt: new Date(), revokedReason: "imported revoke list" },
        });
        stats.updated += 1;
      }
      continue;
    }

    await prisma.certificate.create({
      data: {
        commonName: cn,
        serialNumber: crypto.randomUUID(),
        issuedBy: issuedByName,
        rootCaId,
        agentNodeId: null,
        expiresAt: new Date(Date.now() + DEFAULT_IMPORTED_EXPIRY_MS),
        revokedAt: new Date(),
        revokedReason: "imported revoke list",
      },
    });
    stats.created += 1;
  }

  return stats;
}

/** Отзыв по serial из crl.pem (формат PEM X.509 CRL). */
async function syncRevokedFromCrl(prisma, rootCaId, pem) {
  const stats = { revoked: 0, skipped: 0, notInDb: 0 };
  let serials;
  try {
    serials = revokedSerialSetFromCrlPem(pem);
  } catch {
    throw new Error("Не удалось разобрать CRL (ожидается PEM crl.pem)");
  }
  if (serials.size === 0) return stats;

  const certs = await prisma.certificate.findMany({
    where: { rootCaId, agentNodeId: null },
  });
  const bySerial = new Map(certs.map((c) => [normalizeSerialHex(c.serialNumber), c]));

  const now = new Date();
  for (const serial of serials) {
    const existing = bySerial.get(serial);
    if (!existing) {
      stats.notInDb += 1;
      continue;
    }
    if (existing.rootCaId !== rootCaId) {
      stats.skipped += 1;
      continue;
    }
    if (!existing.revokedAt) {
      await prisma.certificate.update({
        where: { id: existing.id },
        data: { revokedAt: now, revokedReason: "CRL (crl.pem)" },
      });
      stats.revoked += 1;
    }
  }

  return stats;
}

const certInclude = {
  rootCa: {
    select: { id: true, name: true, commonName: true },
  },
  agentNode: {
    select: { id: true, name: true, protocol: true, host: true, port: true },
  },
  vpnUser: {
    select: { id: true, fullName: true, email: true },
  },
};

router.get("/", async (_req, res) => {
  const certs = await prisma.certificate.findMany({
    orderBy: { createdAt: "desc" },
    include: certInclude,
  });
  res.json(
    certs.map((c) => {
      const { certPem, keyPem, ...rest } = c;
      return {
        ...rest,
        hasCertPem: Boolean(certPem),
        hasKeyPem: Boolean(keyPem),
        hasKeyMaterial: Boolean(certPem && keyPem),
      };
    }),
  );
});

router.get("/revoked", async (_req, res) => {
  const certs = await prisma.certificate.findMany({
    where: { revokedAt: { not: null } },
    orderBy: { revokedAt: "desc" },
  });
  res.json(certs);
});

router.post("/", async (req, res) => {
  const {
    commonName: rawCommonName,
    vpnUserId: rawVpnUserId,
    issuedBy,
    expiresAt,
    rootCaId: rawRootCaId,
    agentNodeId: rawAgentNodeId,
  } = req.body || {};

  const vpnUserId = typeof rawVpnUserId === "string" ? rawVpnUserId.trim() : "";
  let vpnUser = null;
  if (vpnUserId) {
    vpnUser = await prisma.vpnUser.findUnique({ where: { id: vpnUserId } });
    if (!vpnUser) {
      return res.status(404).json({ error: "VPN user not found" });
    }
  }

  const commonName = typeof rawCommonName === "string" ? rawCommonName.trim() : "";
  if (!commonName) {
    return res.status(400).json({ error: "commonName (subject CN сертификата) обязателен" });
  }

  const rootCaId = typeof rawRootCaId === "string" ? rawRootCaId.trim() : "";
  if (!rootCaId) {
    return res.status(400).json({ error: "rootCaId is required" });
  }

  const rootCa = await prisma.rootCertificateAuthority.findUnique({ where: { id: rootCaId } });
  if (!rootCa) {
    return res.status(404).json({ error: "Корневой сертификат не найден" });
  }

  let agentNodeId = rawAgentNodeId || null;
  if (agentNodeId === "") agentNodeId = null;
  if (agentNodeId) {
    const node = await prisma.agentNode.findUnique({ where: { id: agentNodeId } });
    if (!node) {
      return res.status(404).json({ error: "Agent node not found" });
    }
  }

  const activeSameCnNode = await prisma.certificate.findFirst({
    where: { commonName, agentNodeId, revokedAt: null },
  });
  if (activeSameCnNode) {
    return res.status(409).json({
      error: "Сертификат с таким subject CN для этого сервера уже есть и не отозван.",
    });
  }

  const issuedByLabel = issuedBy && String(issuedBy).trim() ? String(issuedBy).trim() : rootCa.name;

  const expiresAtDate = expiresAt ? new Date(expiresAt) : new Date(Date.now() + 31536000000);
  const validityDays = Math.max(
    1,
    Math.ceil((expiresAtDate.getTime() - Date.now()) / 86400000),
  );
  const { certPem, keyPem } = issueSignedCertificatePem(rootCa, commonName, validityDays);
  const x509 = new crypto.X509Certificate(certPem);
  const serialNumber = normalizeSerialHex(x509.serialNumber) || forge.util.bytesToHex(forge.random.getBytesSync(16));

  const cert = await prisma.certificate.create({
    data: {
      commonName,
      issuedBy: issuedByLabel,
      rootCaId: rootCa.id,
      agentNodeId,
      vpnUserId: vpnUser?.id || null,
      certPem,
      keyPem,
      expiresAt: new Date(x509.validTo),
      serialNumber,
    },
    include: certInclude,
  });

  if (agentNodeId) {
    enqueuePanelAgentSnapshotForNode(agentNodeId).catch((e) => console.error("enqueuePanelAgentSnapshotForNode:", e.message));
  }

  return res.status(201).json(cert);
});

router.post("/import", async (req, res) => {
  const {
    certPem: rawCertPem,
    keyPem: rawKeyPem,
    rootCaId: rawRootCaId,
    agentNodeId: rawAgentNodeId,
    vpnUserId: rawVpnUserId,
  } = req.body || {};

  const certPem = String(rawCertPem || "").trim();
  const keyPem = String(rawKeyPem || "").trim();
  const rootCaId = String(rawRootCaId || "").trim();
  const agentNodeId = String(rawAgentNodeId || "").trim();
  const vpnUserId = String(rawVpnUserId || "").trim();

  if (!rootCaId) return res.status(400).json({ error: "rootCaId is required" });
  if (!agentNodeId) return res.status(400).json({ error: "agentNodeId is required" });
  if (!certPem) return res.status(400).json({ error: "certPem is required" });
  if (!keyPem) return res.status(400).json({ error: "keyPem is required" });
  if (!certPem.includes("BEGIN CERTIFICATE")) {
    return res.status(400).json({ error: "certPem должен быть сертификатом в PEM-формате" });
  }
  if (!keyPem.includes("PRIVATE KEY")) {
    return res.status(400).json({ error: "keyPem должен быть приватным ключом в PEM-формате" });
  }
  if (hasNegativeSerial(certPem)) {
    return res.status(422).json({
      error:
        "Сертификат отклонён: отрицательный serialNumber (например -ABCD...). Выпустите/импортируйте сертификат с положительным serialNumber.",
    });
  }

  const rootCa = await prisma.rootCertificateAuthority.findUnique({ where: { id: rootCaId } });
  if (!rootCa) return res.status(404).json({ error: "Корневой сертификат не найден" });

  const node = await prisma.agentNode.findUnique({ where: { id: agentNodeId } });
  if (!node) return res.status(404).json({ error: "Agent node not found" });

  let vpnUser = null;
  if (vpnUserId) {
    vpnUser = await prisma.vpnUser.findUnique({ where: { id: vpnUserId } });
    if (!vpnUser) return res.status(404).json({ error: "VPN user not found" });
  }

  let leaf;
  let ca;
  try {
    assertPrivateKeyMatchesCertificate(certPem, keyPem);
    leaf = new crypto.X509Certificate(certPem);
    ca = new crypto.X509Certificate(rootCa.certPem);
  } catch (err) {
    return res.status(422).json({ error: err?.message || "Не удалось разобрать сертификат/ключ" });
  }

  if (!leaf.checkIssued(ca) || !leaf.verify(ca.publicKey)) {
    return res.status(422).json({
      error: "Импорт невозможен: сертификат подписан не корневым сертификатом этого сервера.",
    });
  }

  const commonName =
    leaf.subject
      .split("\n")
      .map((line) => line.trim())
      .find((line) => line.startsWith("CN="))
      ?.replace(/^CN=/i, "")
      .trim() || "";
  if (!commonName) {
    return res.status(422).json({ error: "Не удалось определить Subject CN импортируемого сертификата" });
  }

  const activeSameCnNode = await prisma.certificate.findFirst({
    where: { commonName, agentNodeId, revokedAt: null },
  });
  if (activeSameCnNode) {
    return res.status(409).json({
      error: "Сертификат с таким subject CN для этого сервера уже есть и не отозван.",
    });
  }

  const serialNumber = normalizeSerialHex(leaf.serialNumber) || forge.util.bytesToHex(forge.random.getBytesSync(16));
  const existingBySerial = await prisma.certificate.findUnique({ where: { serialNumber } });
  if (existingBySerial) {
    return res.status(409).json({ error: "Сертификат с таким серийным номером уже существует" });
  }

  const cert = await prisma.certificate.create({
    data: {
      commonName,
      issuedBy: rootCa.name,
      rootCaId: rootCa.id,
      agentNodeId,
      vpnUserId: vpnUser?.id || null,
      certPem: certPem.endsWith("\n") ? certPem : `${certPem}\n`,
      keyPem: keyPem.endsWith("\n") ? keyPem : `${keyPem}\n`,
      expiresAt: new Date(leaf.validTo),
      serialNumber,
    },
    include: certInclude,
  });

  enqueuePanelAgentSnapshotForNode(agentNodeId).catch((e) => console.error("enqueuePanelAgentSnapshotForNode:", e.message));
  return res.status(201).json(cert);
});

router.patch("/:id", async (req, res) => {
  const { id } = req.params;
  const body = req.body || {};
  const hasAgent = "agentNodeId" in body;
  const hasVpnUser = "vpnUserId" in body;
  const hasCertPem = "certPem" in body;
  const hasKeyPem = "keyPem" in body;
  if (!hasAgent && !hasVpnUser && !hasCertPem && !hasKeyPem) {
    return res.status(400).json({ error: "Укажите agentNodeId, vpnUserId, certPem и/или keyPem" });
  }

  const existing = await prisma.certificate.findUnique({ where: { id } });
  if (!existing) {
    return res.status(404).json({ error: "Certificate not found" });
  }

  let agentNodeId = existing.agentNodeId;
  if (hasAgent) {
    agentNodeId = body.agentNodeId === "" || body.agentNodeId == null ? null : body.agentNodeId;
    if (agentNodeId) {
      const node = await prisma.agentNode.findUnique({ where: { id: agentNodeId } });
      if (!node) {
        return res.status(404).json({ error: "Agent node not found" });
      }
    }
    const conflict = await prisma.certificate.findFirst({
      where: {
        commonName: existing.commonName,
        agentNodeId,
        revokedAt: null,
        NOT: { id },
      },
    });
    if (conflict) {
      return res.status(409).json({ error: "Another certificate already uses this user and server pair" });
    }
  }

  let vpnUserId = existing.vpnUserId;
  if (hasVpnUser) {
    if (body.vpnUserId === "" || body.vpnUserId == null) {
      vpnUserId = null;
    } else {
      const u = await prisma.vpnUser.findUnique({ where: { id: body.vpnUserId } });
      if (!u) {
        return res.status(404).json({ error: "VPN user not found" });
      }
      vpnUserId = u.id;
    }
  }

  let certPem = existing.certPem;
  if (hasCertPem) {
    certPem = body.certPem == null || String(body.certPem).trim() === "" ? null : String(body.certPem);
    if (certPem && !certPem.includes("BEGIN CERTIFICATE")) {
      return res.status(400).json({ error: "certPem должен быть сертификатом в PEM-формате" });
    }
    if (certPem && hasNegativeSerial(certPem)) {
      return res.status(422).json({
        error:
          "Сертификат отклонён: отрицательный serialNumber (например -ABCD...). Выпустите/импортируйте сертификат с положительным serialNumber.",
      });
    }
  }

  let keyPem = existing.keyPem;
  if (hasKeyPem) {
    keyPem = body.keyPem == null || String(body.keyPem).trim() === "" ? null : String(body.keyPem);
    if (keyPem && !String(keyPem).includes("PRIVATE KEY")) {
      return res.status(400).json({ error: "keyPem должен быть приватным ключом в PEM-формате" });
    }
  }

  if (hasVpnUser && vpnUserId && isCaOrSelfSignedCertificate(certPem || existing.certPem)) {
    return res.status(422).json({
      error: "К пользователю можно привязать только клиентский сертификат. Корневой сертификат привязывать нельзя.",
    });
  }

  const cert = await prisma.certificate.update({
    where: { id },
    data: {
      ...(hasAgent ? { agentNodeId } : {}),
      ...(hasVpnUser ? { vpnUserId } : {}),
      ...(hasCertPem ? { certPem } : {}),
      ...(hasKeyPem ? { keyPem } : {}),
    },
    include: certInclude,
  });

  const nodes = new Set();
  if (existing.agentNodeId) nodes.add(existing.agentNodeId);
  if (cert.agentNodeId) nodes.add(cert.agentNodeId);
  for (const nid of nodes) {
    if (nid) enqueuePanelAgentSnapshotForNode(nid).catch((e) => console.error("enqueuePanelAgentSnapshotForNode:", e.message));
  }

  return res.json(cert);
});

router.post("/:id/view-material", async (req, res) => {
  const { id } = req.params;
  const kind = String(req.body?.kind || "").trim().toLowerCase();
  if (kind !== "public" && kind !== "private") {
    return res.status(400).json({ error: "kind must be public or private" });
  }
  const cert = await prisma.certificate.findUnique({
    where: { id },
    select: {
      id: true,
      commonName: true,
      certPem: true,
      keyPem: true,
      createdAt: true,
      expiresAt: true,
    },
  });
  if (!cert) {
    return res.status(404).json({ error: "Certificate not found" });
  }
  const value = kind === "public" ? cert.certPem : cert.keyPem;
  if (!value) {
    return res.status(404).json({ error: "Материал недоступен" });
  }
  return res.json({
    kind,
    label: kind === "public" ? "Открытый ключ" : "Закрытый ключ",
    pem: value,
    commonName: cert.commonName,
    updatedAt: cert.expiresAt || cert.createdAt || null,
  });
});

router.get("/:id/material-summary", async (req, res) => {
  const { id } = req.params;
  const cert = await prisma.certificate.findUnique({
    where: { id },
    select: {
      id: true,
      certPem: true,
      keyPem: true,
      expiresAt: true,
      serialNumber: true,
    },
  });
  if (!cert) {
    return res.status(404).json({ error: "Certificate not found" });
  }
  const summary = buildCertificateMaterialSummary(cert.certPem, cert.keyPem);
  if (!summary.serialNumber && cert.serialNumber) {
    summary.serialNumber = cert.serialNumber;
  }
  if (!summary.validTo && cert.expiresAt) {
    summary.validTo = cert.expiresAt.toISOString();
  }
  return res.json(summary);
});

router.post("/:id/revoke", async (req, res) => {
  const { id } = req.params;
  const { reason } = req.body || {};

  const before = await prisma.certificate.findUnique({
    where: { id },
    select: { rootCaId: true, agentNodeId: true },
  });
  const cert = await prisma.certificate.update({
    where: { id },
    data: { revokedAt: new Date(), revokedReason: reason || "manual revoke" },
  });
  if (before?.rootCaId) {
    enqueueCrlDeployTasksForRootCa(before.rootCaId).catch((err) =>
      console.error("enqueueCrlDeployTasksForRootCa:", err),
    );
  }
  if (before?.agentNodeId) {
    enqueuePanelAgentSnapshotForNode(before.agentNodeId).catch((e) =>
      console.error("enqueuePanelAgentSnapshotForNode:", e.message),
    );
  }

  return res.json(cert);
});

router.get("/root-ca", async (_req, res) => {
  const authorities = await prisma.rootCertificateAuthority.findMany({
    orderBy: { createdAt: "desc" },
    select: {
      id: true,
      name: true,
      commonName: true,
      isActive: true,
      createdAt: true,
      updatedAt: true,
      certPem: true,
    },
  });
  res.json(authorities.map(withRootCaExpiry));
});

router.get("/root-ca/:rootCaId/summary", async (req, res) => {
  const rootCaId = String(req.params.rootCaId || "").trim();
  const root = await prisma.rootCertificateAuthority.findUnique({
    where: { id: rootCaId },
    select: { id: true, name: true, commonName: true, certPem: true, createdAt: true },
  });
  if (!root?.certPem) {
    return res.status(404).json({ error: "Корневой сертификат не найден" });
  }
  const summary = buildCertificateMaterialSummary(root.certPem, null);
  return res.json({
    id: root.id,
    name: root.name,
    commonName: root.commonName,
    createdAt: root.createdAt,
    ...summary,
  });
});

router.get("/root-ca/:rootCaId/export", async (req, res) => {
  const rootCaId = String(req.params.rootCaId || "").trim();
  const kind = String(req.query?.kind || "").trim().toLowerCase();
  const root = await prisma.rootCertificateAuthority.findUnique({
    where: { id: rootCaId },
    select: { id: true, certPem: true, keyPem: true },
  });
  if (!root) return res.status(404).json({ error: "Корневой сертификат не найден" });

  if (kind === "root_crt") {
    return res.json({
      fileName: "root.crt",
      contentBase64: Buffer.from(String(root.certPem || ""), "utf8").toString("base64"),
    });
  }
  if (kind === "root_key") {
    return res.json({
      fileName: "root.key",
      contentBase64: Buffer.from(String(root.keyPem || ""), "utf8").toString("base64"),
    });
  }
  if (kind === "index") {
    const rows = await prisma.certificate.findMany({
      where: { rootCaId },
      orderBy: [{ createdAt: "asc" }],
      select: { commonName: true, serialNumber: true, expiresAt: true, revokedAt: true },
    });
    const content = buildIndexTxtForRootCertificates(rows);
    return res.json({
      fileName: "index.txt",
      contentBase64: Buffer.from(content, "utf8").toString("base64"),
    });
  }
  if (kind === "crl") {
    const revoked = await prisma.certificate.findMany({
      where: { rootCaId, revokedAt: { not: null } },
      select: { serialNumber: true, commonName: true, expiresAt: true, revokedAt: true },
    });
    let pem = "";
    try {
      pem = generateCrlPem({ certPem: root.certPem, keyPem: root.keyPem }, revoked);
    } catch (err) {
      return res.status(422).json({
        error:
          "Невозможно сформировать CRL: корневой сертификат и приватный ключ не совпадают или повреждены.",
        details: err instanceof Error ? err.message : String(err),
      });
    }
    return res.json({
      fileName: "crl.pem",
      contentBase64: Buffer.from(String(pem || ""), "utf8").toString("base64"),
    });
  }
  return res.status(400).json({ error: "kind должен быть root_crt, root_key, index или crl" });
});

router.post("/root-ca/import", async (req, res) => {
  const { name, commonName, certPem, keyPem, issuedList, revokedList } = req.body || {};
  if (!certPem || !keyPem) {
    return res.status(400).json({ error: "certPem and keyPem are required" });
  }
  if (!certPem.includes("BEGIN CERTIFICATE") || !keyPem.includes("BEGIN")) {
    return res.status(400).json({ error: "Invalid PEM payload" });
  }
  try {
    assertPrivateKeyMatchesCertificate(certPem, keyPem);
  } catch (err) {
    return res.status(422).json({
      error: "Импорт невозможен: корневой сертификат и приватный ключ не совпадают.",
      details: err instanceof Error ? err.message : String(err),
    });
  }
  let resolvedName = String(name || "").trim();
  let resolvedCommonName = String(commonName || "").trim();
  if (!resolvedName || !resolvedCommonName) {
    let fromCertCn = "";
    try {
      const x509 = new crypto.X509Certificate(certPem);
      const subj = String(x509.subject || "");
      const m = subj.match(/CN=([^,\n/]+)/i);
      fromCertCn = m ? m[1].trim() : "";
    } catch {
      fromCertCn = "";
    }
    if (!resolvedCommonName) resolvedCommonName = fromCertCn || "Импортированный корневой сертификат";
    if (!resolvedName) resolvedName = resolvedCommonName;
  }
  const created = await prisma.rootCertificateAuthority.create({
    data: {
      name: resolvedName,
      commonName: resolvedCommonName,
      certPem,
      keyPem,
      isActive: true,
    },
    select: {
      id: true,
      name: true,
      commonName: true,
      isActive: true,
      createdAt: true,
      updatedAt: true,
      certPem: true,
    },
  });

  const inventory = {};
  const issuedText = typeof issuedList === "string" ? issuedList : "";
  const revokedText = typeof revokedList === "string" ? revokedList : "";

  if (issuedText.trim()) {
    inventory.issued = await syncIssuedInventory(prisma, created.id, created.name, issuedText);
  }
  if (revokedText.trim()) {
    if (isProbablyCrlPem(revokedText)) {
      try {
        inventory.revoked = await syncRevokedFromCrl(prisma, created.id, revokedText);
      } catch (err) {
        const msg = err instanceof Error ? err.message : "CRL parse error";
        return res.status(400).json({ error: msg });
      }
    } else {
      inventory.revoked = await syncRevokedInventory(prisma, created.id, created.name, revokedText);
    }
  }

  await enqueueCrlDeployTasksForRootCa(created.id);

  res.status(201).json({ ...withRootCaExpiry(created), inventory });
});

router.post("/root-ca/:rootCaId/import-index", async (req, res) => {
  const rootCaId = String(req.params.rootCaId || "").trim();
  const issuedList = typeof req.body?.issuedList === "string" ? req.body.issuedList : "";
  const agentNodeId = String(req.body?.agentNodeId || "").trim();
  if (!rootCaId) return res.status(400).json({ error: "rootCaId is required" });
  if (!issuedList.trim()) {
    return res.status(400).json({ error: "Требуется содержимое index.txt (issuedList)" });
  }
  const root = await prisma.rootCertificateAuthority.findUnique({
    where: { id: rootCaId },
    select: { id: true, name: true },
  });
  if (!root) return res.status(404).json({ error: "Корневой сертификат не найден" });
  if (agentNodeId) {
    const node = await prisma.agentNode.findUnique({ where: { id: agentNodeId }, select: { id: true } });
    if (!node) return res.status(404).json({ error: "Сервер не найден" });
  }
  const issued = await syncIssuedInventory(prisma, root.id, root.name, issuedList, agentNodeId || null);
  return res.json({ ok: true, issued });
});

router.post("/root-ca/generate", async (req, res) => {
  const { name, commonName, days, keySize, signatureAlgorithm } = req.body || {};
  if (!name || !commonName) {
    return res.status(400).json({ error: "name and commonName are required" });
  }

  const allowedSig = new Set(["sha256", "sha384", "sha512"]);
  const sig = allowedSig.has(String(signatureAlgorithm || "").toLowerCase())
    ? String(signatureAlgorithm).toLowerCase()
    : "sha256";

  const pems = generateRootCaSelfSignedPem({
    commonName,
    days: Number(days || 3650),
    keySize: Number(keySize) || 4096,
    signatureAlgorithm: sig,
  });

  const created = await prisma.rootCertificateAuthority.create({
    data: {
      name,
      commonName,
      certPem: pems.cert,
      keyPem: pems.private,
      isActive: true,
    },
    select: {
      id: true,
      name: true,
      commonName: true,
      isActive: true,
      createdAt: true,
      updatedAt: true,
      certPem: true,
    },
  });

  await enqueueCrlDeployTasksForRootCa(created.id);

  res.status(201).json(withRootCaExpiry(created));
});

export default router;
