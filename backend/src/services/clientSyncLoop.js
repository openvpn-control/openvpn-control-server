import { config } from "../config.js";
import { prisma } from "../prisma.js";
import { collectClientsFromAgentsDetailed } from "./agentChannel.js";
import { remoteAddrHostOnly } from "../utils/remoteAddr.js";

export async function syncClientsSnapshot() {
  const clientRows = await collectClientsFromAgentsDetailed();
  const clients = clientRows.flatMap((r) => r.clients);
  const now = new Date();
  const trafficCutoff = new Date(Date.now() - config.clientTrafficHistoryMinutes * 60 * 1000);
  const sessionCutoff = new Date(Date.now() - config.clientSessionFreshnessSeconds * 1000);
  /** Узлы, с которых успешно получен список клиентов — только для них закрываем «исходные IP». */
  const activeSessionsByNode = new Map();
  for (const row of clientRows) {
    if (!row.ok) continue;
    const ids = new Set(row.clients.map((c) => c.id));
    activeSessionsByNode.set(row.nodeId, ids);
  }

  await prisma.clientTrafficSample.deleteMany({
    where: { sampledAt: { lt: trafficCutoff } },
  });

  await Promise.all(
    clients.map(async (client) => {
      const hostIp = remoteAddrHostOnly(client.remoteIp || "");
      const rxBytes = BigInt(client.rxBytes || 0);
      const txBytes = BigInt(client.txBytes || 0);
      const lastSample = await prisma.clientTrafficSample.findFirst({
        where: { agentNodeId: client.nodeId, sessionId: client.id },
        orderBy: { sampledAt: "desc" },
      });
      let inBps = 0;
      let outBps = 0;
      if (lastSample) {
        const seconds = (now.getTime() - new Date(lastSample.sampledAt).getTime()) / 1000;
        if (seconds > 0) {
          const rxDelta = Number(rxBytes - lastSample.rxBytes);
          const txDelta = Number(txBytes - lastSample.txBytes);
          inBps = rxDelta > 0 ? rxDelta / seconds : 0;
          outBps = txDelta > 0 ? txDelta / seconds : 0;
        }
      }

      await prisma.clientTrafficSample.create({
        data: {
          agentNodeId: client.nodeId,
          sessionId: client.id,
          commonName: client.commonName || "",
          virtualIp: client.virtualIp || "",
          realIp: hostIp,
          rxBytes,
          txBytes,
          inBps,
          outBps,
          sampledAt: now,
        },
      });

      await prisma.clientSourceIpHistory.upsert({
        where: {
          agentNodeId_sessionId_realIp: {
            agentNodeId: client.nodeId,
            sessionId: client.id,
            realIp: hostIp,
          },
        },
        update: {
          commonName: client.commonName || "",
          connectedAt: client.connectedAt || "",
          lastSeenAt: now,
          endedAt: null,
          durationSeconds: null,
        },
        create: {
          agentNodeId: client.nodeId,
          sessionId: client.id,
          commonName: client.commonName || "",
          realIp: hostIp,
          connectedAt: client.connectedAt || "",
          lastSeenAt: now,
        },
      });

      if (client.virtualIp) {
        await prisma.clientIpAssignment.upsert({
          where: {
            agentNodeId_sessionId: {
              agentNodeId: client.nodeId,
              sessionId: client.id,
            },
          },
          update: {
            commonName: client.commonName || "",
            realIp: hostIp,
            virtualIp: client.virtualIp || "",
            connectedAt: client.connectedAt || "",
            lastSeenAt: now,
            endedAt: null,
          },
          create: {
            agentNodeId: client.nodeId,
            sessionId: client.id,
            commonName: client.commonName || "",
            realIp: hostIp,
            virtualIp: client.virtualIp || "",
            connectedAt: client.connectedAt || "",
            lastSeenAt: now,
          },
        });
      }
    }),
  );

  const openSourceRows = await prisma.clientSourceIpHistory.findMany({
    where: { endedAt: null },
    select: { id: true, agentNodeId: true, sessionId: true, firstSeenAt: true },
  });
  const toCloseSource = [];
  for (const row of openSourceRows) {
    const activeSet = activeSessionsByNode.get(row.agentNodeId);
    if (activeSet === undefined) continue;
    if (!activeSet.has(row.sessionId)) {
      toCloseSource.push(row);
    }
  }
  if (toCloseSource.length > 0) {
    await Promise.all(
      toCloseSource.map((row) =>
        prisma.clientSourceIpHistory.update({
          where: { id: row.id },
          data: {
            endedAt: now,
            durationSeconds: Math.max(
              0,
              Math.round((now.getTime() - new Date(row.firstSeenAt).getTime()) / 1000),
            ),
          },
        }),
      ),
    );
  }

  const sourceHistoryEndedRetention = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);
  await prisma.clientSourceIpHistory.deleteMany({
    where: { endedAt: { lt: sourceHistoryEndedRetention } },
  });

  const activeCn = new Set();
  for (const client of clients) {
    const cn = String(client.commonName || "").trim();
    if (cn) activeCn.add(cn);
  }
  if (activeCn.size > 0) {
    const linked = await prisma.certificate.findMany({
      where: {
        commonName: { in: [...activeCn] },
        vpnUserId: { not: null },
      },
      select: { vpnUserId: true },
    });
    const userIds = [...new Set(linked.map((r) => r.vpnUserId).filter(Boolean))];
    if (userIds.length > 0) {
      await prisma.vpnUser.updateMany({
        where: { id: { in: userIds } },
        data: { lastVpnActivityAt: now },
      });
    }
  }

  await prisma.clientIpAssignment.updateMany({
    where: {
      endedAt: null,
      lastSeenAt: { lt: sessionCutoff },
    },
    data: { endedAt: now },
  });

  const endedRetention = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
  await prisma.clientIpAssignment.deleteMany({
    where: { endedAt: { lt: endedRetention } },
  });

}

export function startClientSyncLoop() {
  let inFlight = false;
  const sync = async () => {
    if (inFlight) return;
    inFlight = true;
    try {
      await syncClientsSnapshot();
    } catch (error) {
      console.error("Client sync failed:", error.message);
    } finally {
      inFlight = false;
    }
  };

  sync();
  return setInterval(sync, config.clientSyncIntervalMs);
}
