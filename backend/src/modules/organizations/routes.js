import { Router } from "express";
import { prisma } from "../../prisma.js";
import { parseUserFirewallStored, serializeUserFirewallForDb } from "../../services/firewallUserRules.js";
import { enqueuePanelAgentSnapshotForNode } from "../../services/panelTasks.js";

const router = Router();

function optionalTrim(value) {
  if (value == null) return null;
  const s = String(value).trim();
  return s || null;
}

router.get("/", async (_req, res) => {
  const rows = await prisma.organization.findMany({
    orderBy: { name: "asc" },
  });
  res.json(rows);
});

router.post("/", async (req, res) => {
  const { name, inn, legalAddress, generalDirector, phone, email } = req.body || {};
  if (!name || !String(name).trim()) {
    return res.status(400).json({ error: "Название организации обязательно" });
  }
  const created = await prisma.organization.create({
    data: {
      name: String(name).trim(),
      inn: optionalTrim(inn),
      legalAddress: optionalTrim(legalAddress),
      generalDirector: optionalTrim(generalDirector),
      phone: optionalTrim(phone),
      email: optionalTrim(email),
    },
  });
  res.status(201).json(created);
});

router.patch("/:id", async (req, res) => {
  const { id } = req.params;
  const { name, inn, legalAddress, generalDirector, phone, email } = req.body || {};
  if (!name || !String(name).trim()) {
    return res.status(400).json({ error: "Название организации обязательно" });
  }
  try {
    const updated = await prisma.organization.update({
      where: { id },
      data: {
        name: String(name).trim(),
        inn: optionalTrim(inn),
        legalAddress: optionalTrim(legalAddress),
        generalDirector: optionalTrim(generalDirector),
        phone: optionalTrim(phone),
        email: optionalTrim(email),
      },
    });
    res.json(updated);
  } catch {
    res.status(404).json({ error: "Организация не найдена" });
  }
});

router.get("/:id/firewall", async (req, res) => {
  const org = await prisma.organization.findUnique({
    where: { id: req.params.id },
    select: { id: true, firewallRules: true },
  });
  if (!org) return res.status(404).json({ error: "Организация не найдена" });
  const parsed = parseUserFirewallStored(org.firewallRules);
  return res.json({ mode: parsed.mode, rules: parsed.rules, natRules: parsed.natRules });
});

router.post("/:id/firewall", async (req, res) => {
  const org = await prisma.organization.findUnique({ where: { id: req.params.id }, select: { id: true } });
  if (!org) return res.status(404).json({ error: "Организация не найдена" });
  const stored = serializeUserFirewallForDb(req.body?.mode, req.body?.rules, req.body?.natRules);
  const updated = await prisma.organization.update({
    where: { id: org.id },
    data: { firewallRules: stored },
    select: { firewallRules: true },
  });
  const parsed = parseUserFirewallStored(updated.firewallRules);
  // Организационные правила попадают в snapshot; переочередим доставку на узлы этой организации.
  const certRows = await prisma.certificate.findMany({
    where: {
      revokedAt: null,
      agentNodeId: { not: null },
      vpnUser: { organizationId: org.id },
    },
    select: { agentNodeId: true },
  });
  const nodeIds = [...new Set(certRows.map((r) => String(r.agentNodeId || "").trim()).filter(Boolean))];
  for (const nodeId of nodeIds) {
    await enqueuePanelAgentSnapshotForNode(nodeId);
  }
  return res.json({
    ok: true,
    message: "Firewall-правила организации сохранены.",
    mode: parsed.mode,
    rules: parsed.rules,
    natRules: parsed.natRules,
  });
});

router.post("/:id/firewall-check", async (req, res) => {
  const org = await prisma.organization.findUnique({ where: { id: req.params.id }, select: { id: true } });
  if (!org) return res.status(404).json({ error: "Организация не найдена" });
  const parsed = serializeUserFirewallForDb(req.body?.mode, req.body?.rules, req.body?.natRules);
  return res.json({
    ok: true,
    message: "Конфиг организации валиден.",
    mode: parsed.mode,
    rules: parsed.rules,
    natRules: parsed.natRules,
  });
});

export default router;
