import { Router } from "express";
import { config } from "../../config.js";
import { prisma } from "../../prisma.js";

const router = Router();

router.get("/overview", async (_req, res) => {
  const agents = await prisma.agentNode.findMany({
    orderBy: { updatedAt: "desc" },
  });
  const agentIds = agents.map((item) => item.id);
  const since = new Date(Date.now() - config.agentMetricHistoryMinutes * 60 * 1000);
  const historyRows =
    agentIds.length === 0
      ? []
      : await prisma.agentMetricSnapshot.findMany({
          where: { agentNodeId: { in: agentIds }, createdAt: { gte: since } },
          orderBy: { createdAt: "asc" },
        });
  const historyByNode = historyRows.reduce((acc, row) => {
    if (!acc[row.agentNodeId]) acc[row.agentNodeId] = [];
    acc[row.agentNodeId].push(row);
    return acc;
  }, {});

  const totalClients = agents.reduce((acc, item) => acc + item.activeClients, 0);
  const avgCpu = agents.length
    ? agents.reduce((acc, item) => acc + item.cpuPercent, 0) / agents.length
    : 0;
  const avgMem = agents.length
    ? agents.reduce((acc, item) => acc + item.memoryPercent, 0) / agents.length
    : 0;
  const totalNetIn = agents.reduce((acc, item) => acc + Number(item.networkInBps || 0), 0);
  const totalNetOut = agents.reduce((acc, item) => acc + Number(item.networkOutBps || 0), 0);

  res.json({
    totalServers: agents.length,
    totalClients,
    avgCpuPercent: Number(avgCpu.toFixed(2)),
    avgMemoryPercent: Number(avgMem.toFixed(2)),
    totalNetworkInBps: totalNetIn,
    totalNetworkOutBps: totalNetOut,
    metricHistoryMinutes: config.agentMetricHistoryMinutes,
    servers: agents.map((item) => ({
      ...item,
      recentMetrics: historyByNode[item.id] || [],
    })),
  });
});

router.get("/admin-actions", async (req, res) => {
  const limitRaw = Number(req.query.limit || 200);
  const limit = Number.isFinite(limitRaw) ? Math.min(Math.max(limitRaw, 1), 1000) : 200;
  const nodeId = req.query.nodeId ? String(req.query.nodeId) : null;

  const rows = await prisma.adminActionLog.findMany({
    where: nodeId ? { targetType: "agent-node", targetId: nodeId } : undefined,
    include: {
      admin: { select: { id: true, username: true } },
    },
    orderBy: { createdAt: "desc" },
    take: limit,
  });

  res.json(rows);
});

export default router;
