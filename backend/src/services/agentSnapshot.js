import crypto from "node:crypto";
import { prisma } from "../prisma.js";
import { getFirewallConfigForPanel } from "./openvpnPanelSettings.js";
import { parseUserFirewallStored } from "./firewallUserRules.js";
import { composeFirewallLevels } from "./firewallComposition.js";
import { renderUserCcdText, normalizeUserCcdSettings } from "./userCcd.js";

/**
 * Снимок состояния для агента: туннельный firewall, пер-пользовательские правила и CCD.
 * revision — sha256 от канонического JSON (без полей revision/updatedAt).
 */
export async function buildAgentSnapshotForNode(agentNodeId) {
  const id = String(agentNodeId || "").trim();
  if (!id) return null;
  const node = await prisma.agentNode.findUnique({ where: { id }, select: { id: true, name: true } });
  if (!node) return null;

  const cfg = await getFirewallConfigForPanel(id);
  if (cfg.status !== 200) return null;

  const tunnel = cfg.body.tunnel;
  const tunnelContext = cfg.body.tunnelContext || {};

  const certs = await prisma.certificate.findMany({
    where: { agentNodeId: id, revokedAt: null },
    select: {
      commonName: true,
      vpnUserId: true,
      vpnUser: {
        select: {
          id: true,
          fullName: true,
          firewallRules: true,
          ccdSettings: true,
          organization: { select: { firewallRules: true } },
        },
      },
    },
  });

  const usersByCn = {};
  for (const c of certs) {
    const cn = String(c.commonName || "").trim();
    if (!cn) continue;
    const u = c.vpnUser;
    const userFw = u ? parseUserFirewallStored(u.firewallRules) : { mode: "merge", rules: [], natRules: [] };
    const orgFw = u?.organization ? parseUserFirewallStored(u.organization.firewallRules) : { mode: "merge", rules: [], natRules: [] };
    const effective = composeFirewallLevels(orgFw, userFw);
    const ccdNorm = u ? normalizeUserCcdSettings(u.ccdSettings) : normalizeUserCcdSettings({});
    const ccdText = u ? renderUserCcdText(u.fullName, u.ccdSettings) : "";
    usersByCn[cn] = {
      vpnUserId: u?.id || null,
      firewallMode: effective.mode,
      firewallRules: effective.rules,
      firewallNatRules: effective.natRules,
      ccdSettings: ccdNorm,
      ccdText,
    };
  }

  const sortedCn = Object.keys(usersByCn).sort();
  const usersOrdered = {};
  for (const k of sortedCn) usersOrdered[k] = usersByCn[k];

  const bodyForHash = {
    schemaVersion: 1,
    agentNodeId: node.id,
    tunnelContext: {
      tunnelInterface: tunnelContext.tunnelInterface || "tun0",
      vpnSubnet: tunnelContext.vpnSubnet || "",
      vpnSubnetCidr: tunnelContext.vpnSubnetCidr || "",
    },
    tunnelFirewall: {
      defaultPolicy: tunnel.defaultPolicy,
      rules: tunnel.rules || [],
      natRules: tunnel.natRules || [],
    },
    usersByCn: usersOrdered,
  };
  const revision = crypto.createHash("sha256").update(JSON.stringify(bodyForHash), "utf8").digest("hex");

  return {
    ...bodyForHash,
    revision,
    updatedAt: new Date().toISOString(),
    nodeName: node.name,
  };
}
