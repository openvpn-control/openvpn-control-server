import crypto from "node:crypto";
import { prisma } from "../prisma.js";
import { config } from "../config.js";
import { postAgentFirewallRuntimeApply } from "./agentChannel.js";
import { getFirewallConfigForPanel } from "./openvpnPanelSettings.js";
import { renderFirewallRuntimeIptablesScript } from "./firewallIptablesRuntime.js";
import { parseUserFirewallStored } from "./firewallUserRules.js";
import { composeFirewallLevels, deriveSessionNatRules } from "./firewallComposition.js";

/** nodeId -> { streak: number, tornDown: boolean } — устойчивость к ложным пустым /clients */
const firewallRuntimeEmptyState = new Map();

/** SHA-256 последнего успешно применённого скрипта; не дёргаем агента, если набор правил не изменился (меньше разрывов и потерь пакетов). */
const lastFirewallRuntimeScriptHashByNodeId = new Map();

function firewallRuntimeScriptHash(script) {
  return crypto.createHash("sha256").update(String(script || ""), "utf8").digest("hex");
}

function normalizeVirtIp(raw) {
  const s = String(raw || "").trim();
  if (!s) return "";
  const base = s.split(",")[0].trim();
  const ip = base.split(":")[0].trim();
  return ip;
}

/**
 * Сессии, которым нужны отдельные цепочки: replace (всегда) или merge с непустыми rules.
 */
async function buildFirewallRuntimeSessions(agentNodeId, liveClients) {
  const cns = [...new Set(liveClients.map((c) => String(c.commonName || "").trim()).filter(Boolean))];
  if (cns.length === 0) return [];

  const certs = await prisma.certificate.findMany({
    where: {
      agentNodeId,
      commonName: { in: cns },
      revokedAt: null,
      vpnUserId: { not: null },
    },
    select: { commonName: true, vpnUserId: true },
  });
  const cnToUser = new Map();
  for (const row of certs) {
    if (!cnToUser.has(row.commonName)) cnToUser.set(row.commonName, row.vpnUserId);
  }
  const userIds = [...new Set([...cnToUser.values()].filter(Boolean))];
  const users =
    userIds.length > 0
      ? await prisma.vpnUser.findMany({
          where: { id: { in: userIds } },
          select: { id: true, firewallRules: true, organization: { select: { firewallRules: true } } },
        })
      : [];
  const userFirewallById = new Map(users.map((u) => {
    const userFw = parseUserFirewallStored(u.firewallRules);
    const orgFw = u.organization ? parseUserFirewallStored(u.organization.firewallRules) : { mode: "merge", rules: [], natRules: [] };
    return [u.id, composeFirewallLevels(orgFw, userFw)];
  }));

  const sessions = [];
  for (const c of liveClients) {
    const cn = String(c.commonName || "").trim();
    const vip = normalizeVirtIp(c.virtualIp);
    if (!cn || !vip) continue;
    const uid = cnToUser.get(cn);
    const parsed = uid ? userFirewallById.get(uid) : { mode: "merge", rules: [], natRules: [] };
    const mode = parsed?.mode || "merge";
    const rules = parsed?.rules || [];
    const natRules = parsed?.natRules || [];
    if (mode === "replace" || rules.length > 0 || natRules.length > 0) {
      sessions.push({ commonName: cn, virtualIp: vip, mode, rules, natRules });
    }
  }
  return sessions;
}

/**
 * @param {Array<{ nodeId: string, ok: boolean, clients: Array<{ commonName?: string, virtualIp?: string, nodeId?: string }> }>} clientRows — collectClientsFromAgentsDetailed
 */
export async function syncFirewallRuntimeAfterClientSync(clientRows) {
  if (!config.firewallRuntimeApplyEnabled) return;

  const onlineNodes = await prisma.agentNode.findMany({
    where: { status: "ONLINE" },
  });
  const onlineById = new Map(onlineNodes.map((n) => [n.id, n]));

  for (const row of clientRows || []) {
    if (!row.ok) continue;
    const node = onlineById.get(row.nodeId);
    if (!node) continue;
    const list = row.clients || [];
    try {
      const cfg = await getFirewallConfigForPanel(node.id);
      const tunnelContext = cfg.status === 200 ? cfg.body.tunnelContext : {};
      if (list.length === 0) {
        const need = config.firewallRuntimeEmptyTeardownStreak;
        if (need === 0) {
          continue;
        }
        let st = firewallRuntimeEmptyState.get(row.nodeId);
        if (!st) st = { streak: 0, tornDown: false };
        if (st.tornDown) {
          continue;
        }
        st = { ...st, streak: st.streak + 1 };
        if (st.streak < need) {
          firewallRuntimeEmptyState.set(row.nodeId, st);
          continue;
        }
        await postAgentFirewallRuntimeApply(node, {
          script: "",
          tunnelInterface: tunnelContext?.tunnelInterface || "tun0",
          vpnSubnetCidr: tunnelContext?.vpnSubnetCidr || "",
        });
        firewallRuntimeEmptyState.set(row.nodeId, { streak: st.streak, tornDown: true });
        lastFirewallRuntimeScriptHashByNodeId.delete(row.nodeId);
        continue;
      }
      firewallRuntimeEmptyState.delete(row.nodeId);
      if (cfg.status !== 200) continue;
      const { tunnel } = cfg.body;
      const sessions = await buildFirewallRuntimeSessions(node.id, list);
      const sessionNatRules = deriveSessionNatRules(sessions);
      const script = renderFirewallRuntimeIptablesScript({
        nodeLabel: node.name || node.id,
        tunnelInterface: tunnelContext?.tunnelInterface || "tun0",
        vpnSubnetCidr: tunnelContext?.vpnSubnetCidr || "",
        tunnelDefaultPolicy: tunnel.defaultPolicy,
        tunnelRules: tunnel.rules || [],
        natRules: [...(tunnel.natRules || []), ...sessionNatRules],
        sessions,
      });
      const scriptHash = firewallRuntimeScriptHash(script);
      if (lastFirewallRuntimeScriptHashByNodeId.get(row.nodeId) === scriptHash) {
        continue;
      }
      await postAgentFirewallRuntimeApply(node, {
        script,
        tunnelInterface: tunnelContext?.tunnelInterface || "tun0",
        vpnSubnetCidr: tunnelContext?.vpnSubnetCidr || "",
      });
      lastFirewallRuntimeScriptHashByNodeId.set(row.nodeId, scriptHash);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      console.error(`Firewall runtime sync (${node.name}):`, msg);
    }
  }
}
