import { Router } from "express";
import { prisma } from "../../prisma.js";
import { syncAllNodes } from "../../services/agentChannel.js";

const router = Router();

router.get("/nodes", async (_req, res) => {
  const nodes = await prisma.agentNode.findMany({
    orderBy: { createdAt: "desc" },
    select: {
      id: true,
      name: true,
      protocol: true,
      host: true,
      port: true,
      agentVersion: true,
      status: true,
      cpuPercent: true,
      memoryPercent: true,
      diskPercent: true,
      diskReadBps: true,
      diskWriteBps: true,
      networkInBps: true,
      networkOutBps: true,
      activeClients: true,
      lastSeenAt: true,
      openvpnBinaryPath: true,
      openvpnVersion: true,
      openvpnBuild: true,
      openvpnConfigPath: true,
      openvpnServerLogPath: true,
      openvpnManagementAddr: true,
      openvpnRunning: true,
      openvpnServiceUnit: true,
      openvpnServiceActiveState: true,
      openvpnServiceSubState: true,
      openvpnServiceMainPid: true,
      openvpnServiceActiveSince: true,
      openvpnServiceRecentLogs: true,
      openvpnLogsEnabled: true,
      openvpnLogsNote: true,
      openvpnInfoSeenAt: true,
      openvpnInfoError: true,
      createdAt: true,
      updatedAt: true,
    },
  });
  res.json(nodes);
});

router.post("/nodes", async (req, res) => {
  const { name, protocol, host, port, authToken } = req.body || {};
  if (!name || !host || !port || !authToken) {
    return res.status(400).json({ error: "name, host, port and authToken are required" });
  }

  const agent = await prisma.agentNode.create({
    data: {
      name,
      protocol: protocol || "http",
      host,
      port: Number(port),
      authToken,
      status: "UNKNOWN",
    },
  });

  return res.status(201).json(agent);
});

router.patch("/nodes/:id", async (req, res) => {
  const id = req.params.id;
  const existing = await prisma.agentNode.findUnique({ where: { id } });
  if (!existing) {
    return res.status(404).json({ error: "Узел не найден" });
  }
  const body = req.body || {};
  const data = {};
  if ("name" in body) {
    const name = body.name == null ? "" : String(body.name).trim();
    if (!name) {
      return res.status(400).json({ error: "Имя узла обязательно" });
    }
    data.name = name;
  }
  if ("protocol" in body) {
    const p = String(body.protocol || "http").trim() || "http";
    data.protocol = p;
  }
  if ("host" in body) {
    const host = body.host == null ? "" : String(body.host).trim();
    if (!host) {
      return res.status(400).json({ error: "Хост обязателен" });
    }
    data.host = host;
  }
  if ("port" in body) {
    const port = Number(body.port);
    if (!Number.isFinite(port) || port < 1 || port > 65535) {
      return res.status(400).json({ error: "Некорректный порт" });
    }
    data.port = port;
  }
  if ("authToken" in body) {
    const token = body.authToken == null ? "" : String(body.authToken).trim();
    if (token) {
      data.authToken = token;
    }
  }
  if (Object.keys(data).length === 0) {
    return res.status(400).json({ error: "Нет полей для обновления" });
  }
  const updated = await prisma.agentNode.update({
    where: { id },
    data,
    select: {
      id: true,
      name: true,
      protocol: true,
      host: true,
      port: true,
      agentVersion: true,
      status: true,
      cpuPercent: true,
      memoryPercent: true,
      diskPercent: true,
      diskReadBps: true,
      diskWriteBps: true,
      networkInBps: true,
      networkOutBps: true,
      activeClients: true,
      lastSeenAt: true,
      openvpnBinaryPath: true,
      openvpnVersion: true,
      openvpnBuild: true,
      openvpnConfigPath: true,
      openvpnServerLogPath: true,
      openvpnManagementAddr: true,
      openvpnRunning: true,
      openvpnServiceUnit: true,
      openvpnServiceActiveState: true,
      openvpnServiceSubState: true,
      openvpnServiceMainPid: true,
      openvpnServiceActiveSince: true,
      openvpnServiceRecentLogs: true,
      openvpnLogsEnabled: true,
      openvpnLogsNote: true,
      openvpnInfoSeenAt: true,
      openvpnInfoError: true,
      createdAt: true,
      updatedAt: true,
    },
  });
  return res.json(updated);
});

router.delete("/nodes/:id", async (req, res) => {
  await prisma.agentNode.delete({ where: { id: req.params.id } });
  res.status(204).end();
});

router.post("/sync", async (_req, res) => {
  const results = await syncAllNodes();
  res.json(results);
});

export default router;
