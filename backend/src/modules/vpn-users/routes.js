import { Router } from "express";
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import { config } from "../../config.js";
import { prisma } from "../../prisma.js";
import { parseUserFirewallStored, serializeUserFirewallForDb } from "../../services/firewallUserRules.js";
import { normalizeUserCcdSettings } from "../../services/userCcd.js";
import { enqueuePanelAgentSnapshotForVpnUser } from "../../services/panelTasks.js";
import { remoteAddrHostOnly } from "../../utils/remoteAddr.js";

const router = Router();

function optionalTrim(value) {
  if (value == null) return null;
  const s = String(value).trim();
  return s || null;
}

function requiredTrim(value, label) {
  const s = value == null ? "" : String(value).trim();
  if (!s) {
    const err = new Error(`REQUIRED:${label}`);
    err.code = "REQUIRED";
    throw err;
  }
  return s;
}

const userInclude = {
  organization: { select: { id: true, name: true } },
};

function parseTlsAuthDirection(raw) {
  const text = Array.isArray(raw) ? String(raw[0] || "") : String(raw || "");
  const parts = text.trim().split(/\s+/).filter(Boolean);
  if (parts.length < 2) return "1";
  const dir = String(parts[1] || "").trim();
  return dir || "1";
}

function invertDirection(value) {
  const v = String(value || "").trim();
  if (v === "0") return "1";
  if (v === "1") return "0";
  return "1";
}

function deriveClientRemoteCertTls(serverValue) {
  const v = String(serverValue || "").trim().toLowerCase();
  if (v === "client") return "server";
  if (v === "server") return "client";
  return "server";
}

function normalizeClientDevFromServer(raw) {
  const v = String(raw || "").trim().toLowerCase();
  if (!v) return "tun";
  if (v.startsWith("tap")) return "tap";
  return "tun";
}

function renderClientSettingLine(key, raw) {
  const k = String(key || "").trim();
  const v = raw;
  if (!k) return null;
  if (typeof v === "boolean") return v ? k : null;
  const text = String(v == null ? "" : v).trim();
  if (!text) return null;
  return `${k} ${text}`;
}

function isClientLeafCertificate(certPem) {
  try {
    const x509 = new crypto.X509Certificate(String(certPem || ""));
    if (x509.ca) return false;
    if (String(x509.subject || "").trim() === String(x509.issuer || "").trim()) return false;
    return true;
  } catch {
    return false;
  }
}

function buildClientOvpn({ node, settings, cert, rootCa, tlsAuthPem }) {
  const proto = String(settings?.proto || "udp").trim() || "udp";
  const port = Number(settings?.port) > 0 ? Number(settings.port) : 1194;
  const host = String(node.host || "").trim();
  const serviceSettings = settings && typeof settings === "object" && !Array.isArray(settings) ? settings : {};
  const keyDirection = String(settings?.["key-direction"] || "{{key_direction}}");
  const clientDev = normalizeClientDevFromServer(settings?.dev);
  const remoteValue = String(settings?.remote || "{{host}} {{port}}")
    .replace(/\{\{\s*host\s*\}\}/g, host)
    .replace(/\{\{\s*port\s*\}\}/g, String(port));
  const resolvRetryValue = String(settings?.["resolv-retry"] || "infinite").trim() || "infinite";
  const noBindEnabled = Boolean(settings?.nobind ?? true);
  const serverTlsAuthDirection = parseTlsAuthDirection(settings?.["tls-auth"]);
  const resolvedServerKeyDirection = keyDirection.replace(
    /\{\{\s*key_direction\s*\}\}/g,
    serverTlsAuthDirection,
  );
  const clientKeyDirection = invertDirection(resolvedServerKeyDirection);
  const clientVerb = Number(settings?.["client-verb"]);
  const clientVerbValue = Number.isFinite(clientVerb) ? Math.max(0, Math.min(11, clientVerb)) : 3;
  const lines = [];
  const pushLine = (key) => {
    const line = renderClientSettingLine(key, serviceSettings[key]);
    if (line) lines.push(line);
  };
  lines.push("client");
  lines.push(`dev ${clientDev}`);
  lines.push(`proto ${proto}`);
  lines.push(`remote ${remoteValue}`);
  lines.push(`resolv-retry ${resolvRetryValue}`);
  if (noBindEnabled) lines.push("nobind");
  pushLine("persist-key");
  pushLine("persist-tun");
  lines.push(`remote-cert-tls ${deriveClientRemoteCertTls(serviceSettings["remote-cert-tls"])}`);
  if (tlsAuthPem) {
    lines.push(`key-direction ${clientKeyDirection}`);
  }
  pushLine("comp-lzo");
  lines.push(`verb ${clientVerbValue}`);
  pushLine("mute");
  const caPem = String(rootCa.certPem || "").trim();
  const certPem = String(cert.certPem || "").trim();
  const keyPem = String(cert.keyPem || "").trim();
  lines.push("", "<ca>", caPem, "</ca>", "");
  lines.push("<cert>", certPem, "</cert>", "");
  lines.push("<key>", keyPem, "</key>");
  if (tlsAuthPem) {
    lines.push("", "<tls-auth>", String(tlsAuthPem || "").trim(), "</tls-auth>");
  }
  lines.push("");
  return lines.join("\n");
}

async function sendProfileByEmail(to, subject, fileName, contentUtf8) {
  const boundary = `ovpn-${Date.now().toString(16)}`;
  const attachmentB64 = Buffer.from(contentUtf8, "utf8").toString("base64");
  const message = [
    `To: ${to}`,
    `Subject: ${subject}`,
    "MIME-Version: 1.0",
    `Content-Type: multipart/mixed; boundary="${boundary}"`,
    "",
    `--${boundary}`,
    "Content-Type: text/plain; charset=UTF-8",
    "",
    "Во вложении конфигурация OpenVPN.",
    "",
    `--${boundary}`,
    `Content-Type: application/octet-stream; name="${fileName}"`,
    "Content-Transfer-Encoding: base64",
    `Content-Disposition: attachment; filename="${fileName}"`,
    "",
    attachmentB64,
    `--${boundary}--`,
    "",
  ].join("\n");
  await new Promise((resolve, reject) => {
    const p = spawn("sendmail", ["-t", "-oi"], { stdio: ["pipe", "pipe", "pipe"] });
    let stderr = "";
    p.stderr.on("data", (d) => {
      stderr += String(d || "");
    });
    p.on("error", reject);
    p.on("close", (code) => {
      if (code === 0) resolve();
      else reject(new Error(stderr.trim() || `sendmail exited with code ${code}`));
    });
    p.stdin.write(message);
    p.stdin.end();
  });
}

router.get("/", async (_req, res) => {
  const users = await prisma.vpnUser.findMany({
    orderBy: { createdAt: "desc" },
    include: userInclude,
  });
  res.json(users);
});

router.post("/", async (req, res) => {
  const { fullName, position, email, phone, organizationId, notes } = req.body || {};
  try {
    let orgIdFinal = null;
    const orgRaw = organizationId == null ? "" : String(organizationId).trim();
    if (orgRaw) {
      const org = await prisma.organization.findUnique({ where: { id: orgRaw } });
      if (!org) {
        return res.status(404).json({ error: "Организация не найдена" });
      }
      orgIdFinal = org.id;
    }

    const created = await prisma.vpnUser.create({
      data: {
        fullName: requiredTrim(fullName, "fullName"),
        position: optionalTrim(position),
        email: requiredTrim(email, "email").toLowerCase(),
        phone: optionalTrim(phone),
        organizationId: orgIdFinal,
        notes: optionalTrim(notes),
      },
      include: userInclude,
    });
    res.status(201).json(created);
  } catch (err) {
    if (err.code === "REQUIRED") {
      return res.status(400).json({ error: `Обязательное поле: ${String(err.message).replace("REQUIRED:", "")}` });
    }
    if (err.code === "P2002") {
      return res.status(409).json({ error: "Пользователь с таким email уже существует" });
    }
    throw err;
  }
});

async function listServersWithPanelRootForCertificateIssue() {
  const settingsRows = await prisma.agentNodeOpenvpnSettings.findMany({
    include: {
      agentNode: {
        select: { id: true, name: true, host: true, port: true, protocol: true, status: true },
      },
    },
  });
  return settingsRows.map((row) => {
    const st = row.settings && typeof row.settings === "object" ? row.settings : {};
    return {
      id: row.agentNodeId,
      name: row.agentNode?.name || row.agentNodeId,
      host: row.agentNode?.host || "",
      apiPort: row.agentNode?.port || null,
      protocol: row.agentNode?.protocol || "http",
      status: row.agentNode?.status || "UNKNOWN",
      panelRootCaId: String(st.panelRootCaId || ""),
      openvpnPort: Number(st.port || 0) || 1194,
      openvpnProto: String(st.proto || "udp"),
    };
  });
}

/** Список серверов с привязанным корневым сертификатом панели (для выпуска/привязки сертификата пользователя). */
router.get("/issue-certificate/servers", async (_req, res) => {
  try {
    const servers = await listServersWithPanelRootForCertificateIssue();
    res.json({ servers });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message || "Ошибка" });
  }
});

router.get("/:id/firewall", async (req, res) => {
  const user = await prisma.vpnUser.findUnique({
    where: { id: req.params.id },
    select: { id: true, firewallRules: true },
  });
  if (!user) return res.status(404).json({ error: "Пользователь не найден" });
  const parsed = parseUserFirewallStored(user.firewallRules);
  return res.json({ mode: parsed.mode, rules: parsed.rules, natRules: parsed.natRules });
});

router.post("/:id/firewall", async (req, res) => {
  const user = await prisma.vpnUser.findUnique({ where: { id: req.params.id }, select: { id: true } });
  if (!user) return res.status(404).json({ error: "Пользователь не найден" });
  const stored = serializeUserFirewallForDb(req.body?.mode, req.body?.rules, req.body?.natRules);
  const updated = await prisma.vpnUser.update({
    where: { id: user.id },
    data: { firewallRules: stored },
    select: { firewallRules: true },
  });
  const parsed = parseUserFirewallStored(updated.firewallRules);
  enqueuePanelAgentSnapshotForVpnUser(user.id).catch((e) => console.error("enqueuePanelAgentSnapshotForVpnUser:", e.message));
  return res.json({
    ok: true,
    message: "Firewall-правила пользователя сохранены.",
    mode: parsed.mode,
    rules: parsed.rules,
    natRules: parsed.natRules,
  });
});

router.post("/:id/firewall-check", async (req, res) => {
  const user = await prisma.vpnUser.findUnique({ where: { id: req.params.id }, select: { id: true } });
  if (!user) return res.status(404).json({ error: "Пользователь не найден" });
  const parsed = serializeUserFirewallForDb(req.body?.mode, req.body?.rules, req.body?.natRules);
  return res.json({
    ok: true,
    message: "Конфиг пользователя валиден.",
    mode: parsed.mode,
    rules: parsed.rules,
    natRules: parsed.natRules,
  });
});

router.get("/:id/ccd", async (req, res) => {
  const user = await prisma.vpnUser.findUnique({
    where: { id: req.params.id },
    select: { id: true, ccdSettings: true },
  });
  if (!user) return res.status(404).json({ error: "Пользователь не найден" });
  return res.json(normalizeUserCcdSettings(user.ccdSettings));
});

router.post("/:id/ccd", async (req, res) => {
  const user = await prisma.vpnUser.findUnique({ where: { id: req.params.id }, select: { id: true } });
  if (!user) return res.status(404).json({ error: "Пользователь не найден" });
  const stored = normalizeUserCcdSettings(req.body);
  await prisma.vpnUser.update({
    where: { id: user.id },
    data: { ccdSettings: stored },
  });
  enqueuePanelAgentSnapshotForVpnUser(user.id).catch((e) => console.error("enqueuePanelAgentSnapshotForVpnUser:", e.message));
  return res.json({
    ok: true,
    message: "CCD сохранён; поставлена задача доставки на серверы OpenVPN.",
    ...stored,
  });
});

function trafficKey(agentNodeId, sessionId) {
  return `${agentNodeId}\t${sessionId}`;
}

router.get("/:id/vpn-sessions", async (req, res) => {
  const { id } = req.params;
  const user = await prisma.vpnUser.findUnique({ where: { id } });
  if (!user) {
    return res.status(404).json({ error: "Пользователь не найден" });
  }

  const certs = await prisma.certificate.findMany({
    where: { vpnUserId: id },
    select: { commonName: true },
  });
  const cnList = [...new Set(certs.map((c) => String(c.commonName || "").trim()).filter(Boolean))];
  if (cnList.length === 0) {
    return res.json([]);
  }

  const rows = await prisma.clientIpAssignment.findMany({
    where: { commonName: { in: cnList } },
    orderBy: { lastSeenAt: "desc" },
    include: { agentNode: { select: { id: true, name: true } } },
  });

  const seenPairs = new Set();
  const pairList = [];
  for (const r of rows) {
    const k = trafficKey(r.agentNodeId, r.sessionId);
    if (seenPairs.has(k)) continue;
    seenPairs.add(k);
    pairList.push({ agentNodeId: r.agentNodeId, sessionId: r.sessionId });
  }

  const trafficByKey = new Map();
  await Promise.all(
    pairList.map(async ({ agentNodeId, sessionId }) => {
      const sample = await prisma.clientTrafficSample.findFirst({
        where: { agentNodeId, sessionId },
        orderBy: { sampledAt: "desc" },
      });
      trafficByKey.set(trafficKey(agentNodeId, sessionId), sample);
    }),
  );

  const sessionCutoff = new Date(Date.now() - config.clientSessionFreshnessSeconds * 1000);
  const payload = rows.map((r) => {
    const sample = trafficByKey.get(trafficKey(r.agentNodeId, r.sessionId));
    const lastSeen = new Date(r.lastSeenAt);
    const activeByTime = lastSeen >= sessionCutoff;
    const isActive = !r.endedAt && activeByTime;
    return {
      nodeId: r.agentNodeId,
      nodeName: r.agentNode?.name || r.agentNodeId,
      sessionId: r.sessionId,
      commonName: r.commonName,
      remoteIp: remoteAddrHostOnly(r.realIp),
      virtualIp: r.virtualIp,
      connectedAt: r.connectedAt,
      firstSeenAt: r.firstSeenAt,
      lastSeenAt: r.lastSeenAt,
      endedAt: r.endedAt,
      isActive,
      inBps: sample?.inBps ?? 0,
      outBps: sample?.outBps ?? 0,
    };
  });

  res.json(payload);
});

router.patch("/:id", async (req, res) => {
  const { id } = req.params;
  const body = req.body || {};
  const existing = await prisma.vpnUser.findUnique({ where: { id } });
  if (!existing) {
    return res.status(404).json({ error: "Пользователь не найден" });
  }

  const data = {};
  try {
    if ("fullName" in body) data.fullName = requiredTrim(body.fullName, "fullName");
    if ("position" in body) data.position = optionalTrim(body.position);
    if ("email" in body) data.email = requiredTrim(body.email, "email").toLowerCase();
    if ("phone" in body) data.phone = optionalTrim(body.phone);
    if ("notes" in body) data.notes = optionalTrim(body.notes);
    if ("organizationId" in body) {
      const raw = body.organizationId;
      if (raw == null || String(raw).trim() === "") {
        data.organizationId = null;
      } else {
        const orgId = String(raw).trim();
        const org = await prisma.organization.findUnique({ where: { id: orgId } });
        if (!org) {
          return res.status(404).json({ error: "Организация не найдена" });
        }
        data.organizationId = org.id;
      }
    }
  } catch (err) {
    if (err.code === "REQUIRED") {
      return res.status(400).json({ error: `Обязательное поле: ${String(err.message).replace("REQUIRED:", "")}` });
    }
    throw err;
  }

  if (Object.keys(data).length === 0) {
    return res.status(400).json({ error: "Нет полей для обновления" });
  }

  try {
    const updated = await prisma.vpnUser.update({
      where: { id },
      data,
      include: userInclude,
    });
    res.json(updated);
  } catch (err) {
    if (err.code === "P2002") {
      return res.status(409).json({ error: "Пользователь с таким email уже существует" });
    }
    throw err;
  }
});

router.get("/:id/connection-profile/options", async (req, res) => {
  const userId = req.params.id;
  const user = await prisma.vpnUser.findUnique({ where: { id: userId } });
  if (!user) return res.status(404).json({ error: "Пользователь не найден" });
  const certs = await prisma.certificate.findMany({
    where: {
      vpnUserId: userId,
      revokedAt: null,
      certPem: { not: null },
      keyPem: { not: null },
    },
    orderBy: { createdAt: "desc" },
    select: {
      id: true,
      commonName: true,
      rootCaId: true,
      expiresAt: true,
      certPem: true,
    },
  });
  const safeCerts = certs
    .filter((c) => isClientLeafCertificate(c.certPem))
    .map(({ certPem, ...rest }) => rest);
  const servers = await listServersWithPanelRootForCertificateIssue();
  return res.json({ certificates: safeCerts, servers, defaultEmail: user.email || "" });
});

router.post("/:id/connection-profile", async (req, res) => {
  const userId = req.params.id;
  const action = String(req.body?.action || "").trim().toLowerCase();
  const certificateId = String(req.body?.certificateId || "").trim();
  const serverId = String(req.body?.serverId || "").trim();
  const email = String(req.body?.email || "").trim();
  if (!["download", "email"].includes(action)) return res.status(400).json({ error: "action должен быть download или email" });
  if (!certificateId || !serverId) return res.status(400).json({ error: "certificateId и serverId обязательны" });
  const user = await prisma.vpnUser.findUnique({ where: { id: userId } });
  if (!user) return res.status(404).json({ error: "Пользователь не найден" });
  const cert = await prisma.certificate.findFirst({
    where: { id: certificateId, vpnUserId: userId, revokedAt: null },
    select: { id: true, commonName: true, rootCaId: true, certPem: true, keyPem: true },
  });
  if (!cert) return res.status(404).json({ error: "Сертификат пользователя не найден" });
  if (!cert.certPem || !cert.keyPem) return res.status(422).json({ error: "У сертификата нет cert/key материала" });
  if (!isClientLeafCertificate(cert.certPem)) {
    return res.status(422).json({ error: "Выбран корневой сертификат или некорректный certPem. Нужен клиентский сертификат." });
  }
  const node = await prisma.agentNode.findUnique({ where: { id: serverId } });
  if (!node) return res.status(404).json({ error: "Сервер не найден" });
  const row = await prisma.agentNodeOpenvpnSettings.findUnique({ where: { agentNodeId: serverId } });
  const settings = row?.settings && typeof row.settings === "object" && !Array.isArray(row.settings) ? row.settings : {};
  const panelRootCaId = String(settings.panelRootCaId || "").trim();
  if (!panelRootCaId || panelRootCaId !== String(cert.rootCaId || "").trim()) {
    return res.status(409).json({
      error: "Сертификат не соответствует корневому сертификату выбранного сервера",
    });
  }
  const rootCa = await prisma.rootCertificateAuthority.findUnique({ where: { id: panelRootCaId } });
  if (!rootCa?.certPem) {
    return res.status(422).json({ error: "Для выбранного корневого сертификата отсутствует certPem" });
  }
  let tlsAuthPem = "";
  const tlsAuthId = String(settings.panelTlsAuthMaterialId || "").trim();
  if (tlsAuthId) {
    const tlsMat = await prisma.agentNodeOpenvpnMaterial.findFirst({
      where: { id: tlsAuthId, agentNodeId: serverId, kind: "tls_auth" },
      select: { pem: true },
    });
    tlsAuthPem = String(tlsMat?.pem || "").trim();
  }
  const profile = buildClientOvpn({
    node,
    settings,
    cert,
    rootCa,
    tlsAuthPem,
  });
  const safeServer = String(node.name || "server").replace(/[^a-zA-Z0-9._-]+/g, "-");
  const safeCn = String(cert.commonName || "user").replace(/[^a-zA-Z0-9._-]+/g, "-");
  const fileName = `${safeServer}-${safeCn}.ovpn`;
  if (action === "download") {
    return res.json({ fileName, contentBase64: Buffer.from(profile, "utf8").toString("base64") });
  }
  if (!email) return res.status(400).json({ error: "email обязателен для отправки" });
  try {
    await sendProfileByEmail(email, "OpenVPN connection profile", fileName, profile);
    return res.json({ ok: true, message: `Конфигурация отправлена на ${email}` });
  } catch (err) {
    return res.status(502).json({
      error: "Не удалось отправить email через sendmail на сервере панели",
      details: err instanceof Error ? err.message : String(err),
    });
  }
});

export default router;
