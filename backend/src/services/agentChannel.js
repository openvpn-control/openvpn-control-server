import http from "http";
import https from "https";
import crypto from "crypto";
import zlib from "zlib";
import { config } from "../config.js";
import { prisma } from "../prisma.js";

function doRequest(node, path, method = "GET", body = null, timeoutMs = 8000) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const protocol = (node.protocol || "http").toLowerCase();
    const transport = protocol === "https" ? https : http;
    const req = transport.request(
      {
        host: node.host,
        port: node.port,
        path,
        method,
        timeout: timeoutMs,
        headers: {
          "Content-Type": "application/json",
          "X-Agent-Token": node.authToken,
          ...(payload ? { "Content-Length": Buffer.byteLength(payload) } : {}),
        },
      },
      (res) => {
        let data = "";
        res.on("data", (chunk) => {
          data += chunk;
        });
        res.on("end", () => {
          if (res.statusCode >= 400) {
            let parsed = null;
            try {
              parsed = data ? JSON.parse(data) : null;
            } catch {
              /* ignore */
            }
            const msg = parsed?.error || data || `Agent ${node.name} returned ${res.statusCode}`;
            const err = new Error(msg);
            err.statusCode = res.statusCode;
            err.hints = Array.isArray(parsed?.hints) ? parsed.hints : [];
            err.agentBody = parsed;
            reject(err);
            return;
          }
          try {
            resolve(data ? JSON.parse(data) : {});
          } catch {
            reject(new Error(`Invalid JSON from agent ${node.name}`));
          }
        });
      },
    );

    req.on("error", reject);
    req.on("timeout", () => req.destroy(new Error("Agent request timeout")));
    if (payload) req.write(payload);
    req.end();
  });
}

function parseOpenVpnLogLine(line) {
  const raw = String(line || "").trim();
  if (!raw) return null;
  const m = raw.match(
    /^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+\-]\d{2}:?\d{2})?|\w{3}\s+\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+(.*)$/,
  );
  const occurredRaw = m ? m[1] : null;
  const event = m ? m[2] : raw;
  const userMatch =
    event.match(/common name[:=]\s*([A-Za-z0-9._-]+)/i) ||
    event.match(/\bCN=([A-Za-z0-9._-]+)/) ||
    event.match(/peer info:\s*IV_CLIUSER=([^\s,]+)/i) ||
    event.match(/\b([A-Za-z0-9._-]+)\/\d{1,3}(?:\.\d{1,3}){3}:\d+\b/);
  const ipMatch = event.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/);
  const parsedAt = occurredRaw ? new Date(occurredRaw.replace(",", ".")) : null;
  const occurredAt = parsedAt && Number.isFinite(parsedAt.getTime()) ? parsedAt : new Date();
  const upperEvent = String(event || "").toUpperCase();
  if (upperEvent.startsWith("MANAGEMENT:")) {
    return null;
  }
  return {
    occurredAt,
    occurredRaw,
    event,
    username: userMatch ? userMatch[1] : null,
    ipAddress: ipMatch ? ipMatch[1] : null,
    rawLine: raw,
  };
}

async function persistOpenvpnLogs(nodeId, lines) {
  if (!Array.isArray(lines) || lines.length === 0) return;
  const prepared = lines
    .map((line) => parseOpenVpnLogLine(line))
    .filter(Boolean)
    .map((row) => ({
      ...row,
      agentNodeId: nodeId,
      fingerprint: crypto.createHash("sha1").update(`${nodeId}|${row.occurredRaw || ""}|${row.rawLine}`).digest("hex"),
    }));
  if (prepared.length === 0) return;
  await prisma.openvpnServerLog.createMany({
    data: prepared,
    skipDuplicates: true,
  });
}

async function cleanupOldOpenvpnLogs() {
  const retentionDays = Number(config.openvpnLogRetentionDays || 10);
  const cutoff = new Date(Date.now() - Math.max(1, retentionDays) * 24 * 60 * 60 * 1000);
  await prisma.openvpnServerLog.deleteMany({
    where: {
      occurredAt: { lt: cutoff },
    },
  });
}

export async function syncNodeMetrics(node) {
  try {
    const metrics = await doRequest(node, "/metrics");
    const updated = await prisma.agentNode.update({
      where: { id: node.id },
      data: {
        status: metrics.status || "ONLINE",
        cpuPercent: Number(metrics.cpuPercent || 0),
        memoryPercent: Number(metrics.memoryPercent || 0),
        diskPercent: Number(metrics.diskPercent || 0),
        diskReadBps: Number(metrics.diskReadBps || 0),
        diskWriteBps: Number(metrics.diskWriteBps || 0),
        networkInBps: Number(metrics.networkInBps || 0),
        networkOutBps: Number(metrics.networkOutBps || 0),
        activeClients: Number(metrics.activeClients || 0),
        lastSeenAt: new Date(),
      },
    });

    await prisma.agentMetricSnapshot.create({
      data: {
        agentNodeId: node.id,
        cpuPercent: Number(metrics.cpuPercent || 0),
        memoryPercent: Number(metrics.memoryPercent || 0),
        diskPercent: Number(metrics.diskPercent || 0),
        diskReadBps: Number(metrics.diskReadBps || 0),
        diskWriteBps: Number(metrics.diskWriteBps || 0),
        networkInBps: Number(metrics.networkInBps || 0),
        networkOutBps: Number(metrics.networkOutBps || 0),
        activeClients: Number(metrics.activeClients || 0),
      },
    });

    const cutoff = new Date(Date.now() - config.agentMetricHistoryMinutes * 60 * 1000);
    await prisma.agentMetricSnapshot.deleteMany({
      where: { createdAt: { lt: cutoff } },
    });

    return { node: node.name, ok: true, data: updated };
  } catch (error) {
    await prisma.agentNode.update({
      where: { id: node.id },
      data: {
        status: "UNKNOWN",
        activeClients: 0,
      },
    });
    return { node: node.name, ok: false, error: error.message };
  }
}

export async function syncAllNodes() {
  const nodes = await prisma.agentNode.findMany();
  const results = await Promise.all(nodes.map((node) => syncNodeMetrics(node)));
  return results.map((result) =>
    result.ok
      ? { node: result.node, ok: true }
      : { node: result.node, ok: false, error: result.error },
  );
}

export async function syncNodeOpenVPNInfo(node) {
  try {
    const info = await doRequest(node, "/openvpn/info", "GET", null, 10000);
    let logs = Array.isArray(info.recentLogs) ? info.recentLogs : [];
    if ((!logs || logs.length === 0) && typeof info.compressedLogsB64 === "string" && info.compressedLogsB64) {
      try {
        const gz = Buffer.from(info.compressedLogsB64, "base64");
        const text = zlib.gunzipSync(gz).toString("utf8");
        logs = text
          .split(/\r?\n/)
          .map((x) => x.trim())
          .filter(Boolean);
      } catch {
        logs = [];
      }
    }
    await prisma.agentNode.update({
      where: { id: node.id },
      data: {
        agentVersion: typeof info.agentVersion === "string" ? info.agentVersion : null,
        openvpnBinaryPath: info.binaryPath || null,
        openvpnVersion: info.version || null,
        openvpnBuild: info.build || null,
        openvpnConfigPath: info.configPath || null,
        openvpnServerLogPath: info.serverLogPath || null,
        openvpnManagementAddr: info.managementAddr || null,
        openvpnRunning: Boolean(info.running),
        openvpnServiceUnit: info.serviceUnit || null,
        openvpnServiceActiveState: info.activeState || null,
        openvpnServiceSubState: info.subState || null,
        openvpnServiceMainPid: Number.isFinite(Number(info.mainPid)) ? Number(info.mainPid) : null,
        openvpnServiceActiveSince: info.activeSince || null,
        openvpnServiceRecentLogs: logs.slice(-1000),
        openvpnLogsEnabled: Boolean(info.logsEnabled),
        openvpnLogsNote: info.logsNote || null,
        openvpnInfoError: info.lastError || null,
        openvpnInfoSeenAt: new Date(),
      },
    });
    await persistOpenvpnLogs(node.id, logs);
    await cleanupOldOpenvpnLogs();
    return { node: node.name, ok: true };
  } catch (error) {
    await prisma.agentNode.update({
      where: { id: node.id },
      data: {
        openvpnRunning: false,
        openvpnServiceRecentLogs: [],
        openvpnLogsEnabled: false,
        openvpnLogsNote: null,
        openvpnInfoError: error.message || "OpenVPN info poll failed",
      },
    });
    return { node: node.name, ok: false, error: error.message };
  }
}

export async function syncAllOpenVPNInfo() {
  const nodes = await prisma.agentNode.findMany();
  const results = await Promise.all(nodes.map((node) => syncNodeOpenVPNInfo(node)));
  return results.map((result) =>
    result.ok
      ? { node: result.node, ok: true }
      : { node: result.node, ok: false, error: result.error },
  );
}

/**
 * @returns {Promise<Array<{ nodeId: string, ok: boolean, clients: any[] }>>}
 */
export async function collectClientsFromAgentsDetailed() {
  const nodes = await prisma.agentNode.findMany();
  return Promise.all(
    nodes.map(async (node) => {
      try {
        const clients = await doRequest(node, "/clients");
        const list = Array.isArray(clients) ? clients : [];
        return {
          nodeId: node.id,
          ok: true,
          clients: list.map((client) => ({ ...client, nodeId: node.id, nodeName: node.name })),
        };
      } catch {
        return { nodeId: node.id, ok: false, clients: [] };
      }
    }),
  );
}

export async function collectClientsFromAgents() {
  const rows = await collectClientsFromAgentsDetailed();
  return rows.flatMap((r) => r.clients);
}

export async function disconnectClientOnAgent(nodeId, clientId) {
  const node = await prisma.agentNode.findUnique({ where: { id: nodeId } });
  if (!node) throw new Error("Agent node not found");
  return doRequest(node, "/clients/disconnect", "POST", { id: clientId });
}

/** Чтение настроек OpenVPN (server.conf) с агента. */
export async function getAgentOpenVPNSettings(node) {
  return doRequest(node, "/openvpn/settings", "GET", null, 30000);
}

export async function getAgentOpenVPNRawConfig(node) {
  return doRequest(node, "/openvpn/raw-config", "GET", null, 30000);
}

export async function getAgentSystemNetwork(node) {
  return doRequest(node, "/system/network", "GET", null, 30000);
}

export async function getAgentSystemServices(node) {
  return doRequest(node, "/system/services", "GET", null, 30000);
}

/** systemctl start|stop|restart для указанного .service unit (агент проверяет имя). */
export async function postAgentSystemServiceUnitAction(node, body) {
  return doRequest(node, "/system/service-unit", "POST", body || {}, 90000);
}

export async function getAgentDnsmasq(node) {
  return doRequest(node, "/dnsmasq", "GET", null, 30000);
}

export async function postAgentDnsmasq(node, body) {
  return doRequest(node, "/dnsmasq", "POST", body || {}, 60000);
}

/** Сохранение настроек: агент проверяет конфиг и пишет файл. */
export async function postAgentOpenVPNSettings(node, settings) {
  return doRequest(node, "/openvpn/settings", "POST", { settings }, 120000);
}

export async function postAgentOpenVPNApplyConfig(node) {
  return doRequest(node, "/openvpn/apply-config", "POST", {}, 120000);
}

export async function postAgentOpenVPNServiceAction(node, action) {
  return doRequest(node, "/openvpn/service", "POST", { action }, 30000);
}

export async function postAgentOpenVPNCheckConfig(node) {
  return doRequest(node, "/openvpn/check-config", "POST", {}, 30000);
}

export async function postAgentBinaryUpdate(node, fileName, binaryBase64, checksumSha256) {
  return doRequest(
    node,
    "/agent/update",
    "POST",
    { fileName, binaryBase64, checksumSha256 },
    180000,
  );
}

/** Запись файла на узел (путь должен быть в каталоге конфига OpenVPN на агенте). */
export async function postAgentWriteOpenvpnFile(node, pathStr, buffer) {
  const contentBase64 = Buffer.isBuffer(buffer) ? buffer.toString("base64") : Buffer.from(buffer).toString("base64");
  return doRequest(node, "/openvpn/write-file", "POST", { path: pathStr, contentBase64 }, 120000);
}

/** Runtime iptables: пустой script — снять цепочки панели на агенте. */
export async function postAgentFirewallRuntimeApply(node, body) {
  return doRequest(node, "/firewall/apply-runtime", "POST", body, 60000);
}

/** Полный снимок панели (CCD + firewall + контекст туннеля) для локального кэша на агенте. */
export async function postAgentPanelSnapshot(node, snapshot) {
  return doRequest(node, "/panel/snapshot", "POST", snapshot, 120000);
}

/** SHA-256 файла на узле (путь в каталоге конфига OpenVPN). */
export async function postAgentOpenvpnFileSha256(node, pathStr) {
  return doRequest(node, "/openvpn/file-sha256", "POST", { path: pathStr }, 30000);
}
