import { Router } from "express";
import {
  applyFirewallConfigForPanel,
  applyOpenvpnSettingsForPanel,
  checkFirewallConfigForPanel,
  getFirewallConfigForPanel,
  getOpenvpnRawConfigForPanel,
  getNodeNetworkInfoForPanel,
  getNodeSystemServicesForPanel,
  postNodeSystemServiceUnitActionForPanel,
  getOpenvpnLogsForPanel,
  getDnsmasqForPanel,
  postAgentUpdateForPanel,
  enqueueDnsmasqApplyTaskForPanel,
  postDnsmasqForPanel,
  postOpenvpnCheckConfigForPanel,
  getOpenvpnSettingsForPanel,
  removeRootCaForPanel,
  postOpenvpnServiceActionForPanel,
  postOpenvpnSettingsForPanel,
} from "../../services/openvpnPanelSettings.js";
import {
  createNodeOpenvpnMaterial,
  deleteNodeOpenvpnMaterial,
  listNodeOpenvpnMaterials,
} from "../../services/nodeOpenvpnMaterialService.js";
import {
  deleteServerCertificateForAgentNode,
  importServerCertificateForAgentNode,
  issueServerCertificateForAgentNode,
} from "../../services/serverNodeCertificateService.js";

const router = Router();

/** Эталон настроек на сервере панели; синхронизация с агентом только на бэкенде. */
router.get("/:id/openvpn-settings", async (req, res) => {
  const r = await getOpenvpnSettingsForPanel(req.params.id);
  return res.status(r.status).json(r.body);
});

router.post("/:id/openvpn-settings", async (req, res) => {
  const r = await postOpenvpnSettingsForPanel(req.params.id, req.body);
  return res.status(r.status).json(r.body);
});

router.get("/:id/firewall", async (req, res) => {
  const r = await getFirewallConfigForPanel(req.params.id);
  return res.status(r.status).json(r.body);
});

router.post("/:id/firewall-apply", async (req, res) => {
  const r = await applyFirewallConfigForPanel(req.params.id, req.body);
  return res.status(r.status).json(r.body);
});

router.post("/:id/firewall-check", async (req, res) => {
  const r = await checkFirewallConfigForPanel(req.params.id, req.body);
  return res.status(r.status).json(r.body);
});

router.post("/:id/root-ca/remove", async (req, res) => {
  const r = await removeRootCaForPanel(req.params.id, req.body);
  return res.status(r.status).json(r.body);
});

router.post("/:id/openvpn-settings-apply", async (req, res) => {
  const r = await applyOpenvpnSettingsForPanel(req.params.id, req.body);
  return res.status(r.status).json(r.body);
});

router.post("/:id/openvpn-service", async (req, res) => {
  const r = await postOpenvpnServiceActionForPanel(req.params.id, req.body);
  return res.status(r.status).json(r.body);
});

router.post("/:id/openvpn-check-config", async (req, res) => {
  const r = await postOpenvpnCheckConfigForPanel(req.params.id);
  return res.status(r.status).json(r.body);
});

router.post("/:id/agent-update", async (req, res) => {
  const r = await postAgentUpdateForPanel(req.params.id, req.body);
  return res.status(r.status).json(r.body);
});

router.get("/:id/openvpn-logs", async (req, res) => {
  const r = await getOpenvpnLogsForPanel(req.params.id, req.query || {});
  return res.status(r.status).json(r.body);
});

router.get("/:id/openvpn-raw-config", async (req, res) => {
  const r = await getOpenvpnRawConfigForPanel(req.params.id);
  return res.status(r.status).json(r.body);
});

router.get("/:id/network-info", async (req, res) => {
  const r = await getNodeNetworkInfoForPanel(req.params.id);
  return res.status(r.status).json(r.body);
});

router.get("/:id/system-services", async (req, res) => {
  const r = await getNodeSystemServicesForPanel(req.params.id);
  return res.status(r.status).json(r.body);
});

router.post("/:id/system-service-unit", async (req, res) => {
  const r = await postNodeSystemServiceUnitActionForPanel(req.params.id, req.body);
  return res.status(r.status).json(r.body);
});

router.post("/:id/dnsmasq/apply-task", async (req, res) => {
  const r = await enqueueDnsmasqApplyTaskForPanel(req.params.id, req.body);
  return res.status(r.status).json(r.body);
});

router.get("/:id/dnsmasq", async (req, res) => {
  const r = await getDnsmasqForPanel(req.params.id);
  return res.status(r.status).json(r.body);
});

router.post("/:id/dnsmasq", async (req, res) => {
  const r = await postDnsmasqForPanel(req.params.id, req.body);
  return res.status(r.status).json(r.body);
});

router.get("/:id/openvpn-materials", async (req, res) => {
  const kind = req.query?.kind ? String(req.query.kind).trim() : undefined;
  const k = kind === "dh" || kind === "tls_auth" ? kind : undefined;
  const rows = await listNodeOpenvpnMaterials(req.params.id, k);
  if (rows === null) return res.status(404).json({ error: "Node not found" });
  res.json(rows);
});

router.post("/:id/openvpn-materials", async (req, res) => {
  try {
    const row = await createNodeOpenvpnMaterial(
      req.params.id,
      req.body?.kind,
      req.body?.label,
      req.body?.pem,
    );
    res.status(201).json(row);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    res.status(400).json({ error: msg });
  }
});

router.delete("/:id/openvpn-materials/:materialId", async (req, res) => {
  const r = await deleteNodeOpenvpnMaterial(req.params.id, req.params.materialId);
  if (r === null) return res.status(404).json({ error: "Материал не найден" });
  res.status(204).end();
});

router.post("/:id/server-certificate", async (req, res) => {
  try {
    const cert = await issueServerCertificateForAgentNode({
      agentNodeId: req.params.id,
      rootCaId: req.body?.rootCaId,
      commonName: req.body?.commonName,
      validityDays: req.body?.validityDays,
      keySize: req.body?.keySize,
      signatureAlgorithm: req.body?.signatureAlgorithm,
    });
    res.status(201).json(cert);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    const code = msg.includes("уже есть") ? 409 : 400;
    res.status(code).json({ error: msg });
  }
});

router.delete("/:id/server-certificate", async (req, res) => {
  try {
    await deleteServerCertificateForAgentNode(req.params.id);
    res.status(204).end();
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    res.status(400).json({ error: msg });
  }
});

router.post("/:id/server-certificate-import", async (req, res) => {
  try {
    const cert = await importServerCertificateForAgentNode({
      agentNodeId: req.params.id,
      rootCaId: req.body?.rootCaId,
      certPem: req.body?.certPem,
      keyPem: req.body?.keyPem,
    });
    res.status(201).json(cert);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    const code = msg.includes("уже есть") ? 409 : 400;
    res.status(code).json({ error: msg });
  }
});

export default router;
