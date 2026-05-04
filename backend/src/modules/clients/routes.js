import { Router } from "express";
import { disconnectClientOnAgent } from "../../services/agentChannel.js";
import { prisma } from "../../prisma.js";
import { config } from "../../config.js";
import { remoteAddrHostOnly } from "../../utils/remoteAddr.js";

const router = Router();

/** CN сертификата → пользователь VPN (если есть неотозванный или любой привязанный сертификат с этим CN). */
async function buildCommonNameVpnUserLookup() {
  const certs = await prisma.certificate.findMany({
    where: { vpnUserId: { not: null } },
    select: {
      commonName: true,
      vpnUserId: true,
      revokedAt: true,
      vpnUser: { select: { id: true, fullName: true, email: true } },
    },
  });
  const map = new Map();
  for (const c of certs) {
    const cn = String(c.commonName || "").trim();
    if (!cn) continue;
    const prev = map.get(cn);
    const active = !c.revokedAt;
    if (!prev || (active && !prev.fromActiveCert)) {
      map.set(cn, {
        fromActiveCert: active,
        vpnUserId: c.vpnUserId,
        vpnUserFullName: c.vpnUser?.fullName || "",
        vpnUserEmail: c.vpnUser?.email || "",
      });
    }
  }
  return map;
}

function attachVpnUserByCommonName(row, lookup) {
  const cn = String(row.commonName || "").trim();
  const hit = cn ? lookup.get(cn) : null;
  return {
    ...row,
    vpnUserId: hit?.vpnUserId ?? null,
    vpnUserFullName: hit?.vpnUserFullName ?? null,
    vpnUserEmail: hit?.vpnUserEmail ?? null,
  };
}

router.get("/", async (_req, res) => {
  const freshnessCutoff = new Date(Date.now() - config.clientSessionFreshnessSeconds * 1000);
  const historyTake = Math.min(Math.floor((config.clientTrafficHistoryMinutes * 60) / 2), 300);

  const [nodes, sessions, recentSamples] = await Promise.all([
    prisma.agentNode.findMany({ select: { id: true, name: true } }),
    prisma.clientIpAssignment.findMany({
      where: { lastSeenAt: { gte: freshnessCutoff }, virtualIp: { not: "" } },
      orderBy: { lastSeenAt: "desc" },
    }),
    prisma.clientTrafficSample.findMany({
      where: { sampledAt: { gte: freshnessCutoff } },
      orderBy: { sampledAt: "desc" },
      take: 10000,
    }),
  ]);

  const nodeNameById = new Map(nodes.map((n) => [n.id, n.name]));
  const trafficBySession = new Map();
  for (const sample of recentSamples) {
    const key = `${sample.agentNodeId}:${sample.sessionId}`;
    const entry = trafficBySession.get(key) || { latest: null, history: [] };
    if (!entry.latest) {
      entry.latest = sample;
    }
    if (entry.history.length < historyTake) {
      entry.history.push({
        sampledAt: sample.sampledAt,
        inBps: sample.inBps,
        outBps: sample.outBps,
      });
    }
    trafficBySession.set(key, entry);
  }

  res.json(
    sessions.map((session) => {
      const key = `${session.agentNodeId}:${session.sessionId}`;
      const traffic = trafficBySession.get(key);
      return {
        id: session.sessionId,
        commonName: session.commonName,
        remoteIp: remoteAddrHostOnly(session.realIp),
        virtualIp: session.virtualIp,
        connectedAt: session.connectedAt,
        nodeId: session.agentNodeId,
        nodeName: nodeNameById.get(session.agentNodeId) || "",
        inBps: traffic?.latest?.inBps || 0,
        outBps: traffic?.latest?.outBps || 0,
        trafficHistory: traffic ? [...traffic.history].reverse() : [],
      };
    }),
  );
});

router.get("/history", async (_req, res) => {
  const [rows, lookup] = await Promise.all([
    prisma.clientIpAssignment.findMany({
      where: { virtualIp: { not: "" } },
      include: {
        agentNode: { select: { id: true, name: true, host: true, port: true } },
      },
      orderBy: { lastSeenAt: "desc" },
      take: 1000,
    }),
    buildCommonNameVpnUserLookup(),
  ]);
  res.json(rows.map((r) => attachVpnUserByCommonName(r, lookup)));
});

router.get("/source-history", async (_req, res) => {
  const [rows, lookup] = await Promise.all([
    prisma.clientSourceIpHistory.findMany({
      include: {
        agentNode: { select: { id: true, name: true, host: true, port: true } },
      },
      orderBy: { lastSeenAt: "desc" },
      take: 1000,
    }),
    buildCommonNameVpnUserLookup(),
  ]);
  res.json(rows.map((r) => attachVpnUserByCommonName(r, lookup)));
});

router.post("/:nodeId/:id/disconnect", async (req, res) => {
  try {
    const result = await disconnectClientOnAgent(req.params.nodeId, req.params.id);
    return res.json(result);
  } catch (error) {
    return res.status(502).json({ error: `Failed to disconnect client: ${error.message}` });
  }
});

export default router;
