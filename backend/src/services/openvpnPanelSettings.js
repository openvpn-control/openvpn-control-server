import { prisma } from "../prisma.js";
import { getInitialOpenVpnServerSettings } from "../openvpnDefaults.js";
import {
  getAgentDnsmasq,
  getAgentSystemNetwork,
  getAgentSystemServices,
  postAgentSystemServiceUnitAction,
  getAgentOpenVPNRawConfig,
  getAgentOpenVPNSettings,
  postAgentDnsmasq,
  postAgentBinaryUpdate,
  postAgentOpenVPNApplyConfig,
  postAgentOpenVPNCheckConfig,
  postAgentOpenVPNServiceAction,
  postAgentOpenVPNSettings,
} from "./agentChannel.js";
import {
  stripPanelOnlyOpenvpnSettings,
} from "./openvpnFileSync.js";
import {
  enqueueDnsmasqApplyTask,
  enqueueOpenvpnMaterialSyncTasks,
  enqueuePanelAgentSnapshotForNode,
  processPendingTasksForNode,
} from "./panelTasks.js";

const fallbackHints = [
  "Проверьте, что агент доступен по host/port и токену.",
  "Задайте на агенте OPENVPN_SERVER_CONF к пути server.conf.",
];

const PANEL_FIREWALL_DEFAULT_POLICY_KEY = "panelFirewallDefaultPolicy";
const PANEL_FIREWALL_BASE_RULES_KEY = "panelFirewallBaseRules";
const PANEL_FIREWALL_HOST_DEFAULT_POLICY_KEY = "panelFirewallHostDefaultPolicy";
const PANEL_FIREWALL_HOST_RULES_KEY = "panelFirewallHostRules";
const PANEL_FIREWALL_TUNNEL_DEFAULT_POLICY_KEY = "panelFirewallTunnelDefaultPolicy";
const PANEL_FIREWALL_TUNNEL_RULES_KEY = "panelFirewallTunnelRules";
const PANEL_FIREWALL_TUNNEL_NAT_RULES_KEY = "panelFirewallTunnelNatRules";

function ipv4OctetsToInt(s) {
  const p = String(s)
    .split(".")
    .map((x) => parseInt(x, 10));
  if (p.length !== 4 || p.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return null;
  return ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
}

function netmaskDottedToPrefix(maskStr) {
  const n = ipv4OctetsToInt(maskStr);
  if (n == null) return null;
  let prefix = 0;
  let v = n;
  while (v & 0x80000000) {
    prefix++;
    v = (v << 1) >>> 0;
  }
  if (v !== 0) return null;
  return prefix;
}

/** Директива server в OpenVPN: «сеть маска» или «сеть /prefix». */
function openvpnServerLineToCidr(serverLine) {
  const m = String(serverLine || "").trim().match(/^(\S+)\s+(\S+)$/);
  if (!m) return "";
  const ip = m[1];
  const second = m[2];
  if (/^\d+$/.test(second)) {
    const pl = parseInt(second, 10);
    if (pl >= 0 && pl <= 32) return `${ip}/${pl}`;
  }
  if (second.includes(".")) {
    const pref = netmaskDottedToPrefix(second);
    if (pref == null) return "";
    return `${ip}/${pref}`;
  }
  return "";
}

/**
 * В server.conf часто `dev tun` / `dev tap` без номера — в Linux это обычно tun0/tap0.
 * Для iptables/nft нужно реальное имя интерфейса.
 */
function linuxIfaceFromOpenvpnDev(dev) {
  const s = String(dev || "").trim();
  if (!s) return "";
  const l = s.toLowerCase();
  if (l === "tun") return "tun0";
  if (l === "tap") return "tap0";
  return s;
}

function parseTunnelContext(openvpnSettings) {
  const src = openvpnSettings && typeof openvpnSettings === "object" && !Array.isArray(openvpnSettings)
    ? openvpnSettings
    : {};
  const rawDev = String(src.dev || "").trim();
  const tunnelInterface = rawDev ? linuxIfaceFromOpenvpnDev(rawDev) : "tun0";
  const serverDirective = String(src.server || "").trim();
  const subnetMatch = serverDirective.match(/^(\S+)\s+(\S+)$/);
  const vpnSubnet = subnetMatch ? `${subnetMatch[1]} ${subnetMatch[2]}` : "";
  const vpnSubnetCidr = openvpnServerLineToCidr(serverDirective);
  return { tunnelInterface, vpnSubnet, vpnSubnetCidr };
}

function normalizeFirewallRule(rule, idx = 0) {
  const src = rule && typeof rule === "object" && !Array.isArray(rule) ? rule : {};
  return {
    id: String(src.id || `rule-${idx + 1}`),
    action: String(src.action || "allow").toLowerCase() === "deny" ? "deny" : "allow",
    proto: ["tcp", "udp", "icmp", "any"].includes(String(src.proto || "").toLowerCase())
      ? String(src.proto).toLowerCase()
      : "tcp",
    destination: String(src.destination || "").trim(),
    ports: String(src.ports || "").trim(),
    note: String(src.note || "").trim(),
  };
}

function normalizeFirewallBaseRules(raw) {
  const rows = Array.isArray(raw) ? raw : [];
  return rows.map((r, i) => normalizeFirewallRule(r, i));
}

function normalizeFirewallNatRule(rule, idx = 0) {
  const src = rule && typeof rule === "object" && !Array.isArray(rule) ? rule : {};
  const type = String(src.type || "masquerade").toLowerCase();
  const rawOut = String(src.outInterface || "").trim();
  return {
    id: String(src.id || `nat-${idx + 1}`),
    type: ["masquerade", "snat", "dnat"].includes(type) ? type : "masquerade",
    src: String(src.src || "").trim(),
    dst: String(src.dst || "").trim(),
    outInterface: rawOut ? linuxIfaceFromOpenvpnDev(rawOut) : "",
    toAddress: String(src.toAddress || "").trim(),
    note: String(src.note || "").trim(),
  };
}

function normalizeFirewallNatRules(raw) {
  const rows = Array.isArray(raw) ? raw : [];
  return rows.map((r, i) => normalizeFirewallNatRule(r, i));
}

function normalizeFirewallDefaultPolicy(raw) {
  return String(raw || "").toLowerCase() === "allow" ? "allow" : "deny";
}

function renderFirewallScriptPreview({ node, defaultPolicy, baseRules, tunnelInterface, vpnSubnet, vpnSubnetCidr }) {
  const chainPolicy = defaultPolicy === "allow" ? "accept" : "drop";
  const cidr = String(vpnSubnetCidr || "").trim();
  const lines = [
    `# firewall preview for node: ${node?.name || node?.id || "unknown"}`,
    `# scope: tunnel interface "${tunnelInterface || "tun0"}" + VPN subnet "${cidr || vpnSubnet || "n/a"}"`,
    "table inet ovpn_clients {",
    "  chain forward {",
    "    type filter hook forward priority 0;",
    `    policy ${chainPolicy};`,
  ];
  for (const r of baseRules) {
    const intf = tunnelInterface ? `iifname "${tunnelInterface}" ` : "";
    const subnet = cidr ? `ip saddr ${cidr} ` : "";
    const proto = r.proto === "any" ? "" : `${r.proto} `;
    const dst = r.destination ? `ip daddr ${r.destination} ` : "";
    const ports = r.ports ? `dport { ${r.ports} } ` : "";
    const verdict = r.action === "deny" ? "drop" : "accept";
    lines.push(`    ${intf}${subnet}${proto}${dst}${ports}${verdict}`.replace(/\s+/g, " ").trim() + ";");
  }
  lines.push("  }", "}");
  return lines.join("\n");
}

function renderFirewallDualScriptPreview({ node, tunnelDefaultPolicy, tunnelRules, natRules, tunnelContext }) {
  const tunnel = renderFirewallScriptPreview({
    node,
    defaultPolicy: tunnelDefaultPolicy,
    baseRules: tunnelRules,
    tunnelInterface: tunnelContext?.tunnelInterface,
    vpnSubnet: tunnelContext?.vpnSubnet,
    vpnSubnetCidr: tunnelContext?.vpnSubnetCidr,
  });
  const nat = ["table ip ovpn_nat {"];
  const post = [
    "  chain postrouting {",
    "    type nat hook postrouting priority 100;",
  ];
  const pre = [
    "  chain prerouting {",
    "    type nat hook prerouting priority -100;",
  ];
  for (const r of natRules) {
    if (r.type === "dnat") {
      const src = r.src ? `ip saddr ${r.src} ` : "";
      const dst = r.dst ? `ip daddr ${r.dst} ` : "";
      const inIface = r.outInterface ? `iifname "${r.outInterface}" ` : "";
      const to = r.toAddress ? `to ${r.toAddress}` : "";
      pre.push(`    ${src}${dst}${inIface}dnat ${to}`.replace(/\s+/g, " ").trim() + ";");
      continue;
    }
    if (r.type === "snat") {
      const src = r.src ? `ip saddr ${r.src} ` : "";
      const dst = r.dst ? `ip daddr ${r.dst} ` : "";
      const out = r.outInterface ? `oifname "${r.outInterface}" ` : "";
      const to = r.toAddress ? `to ${r.toAddress}` : "";
      post.push(`    ${src}${dst}${out}snat ${to}`.replace(/\s+/g, " ").trim() + ";");
      continue;
    }
    const src = r.src ? `ip saddr ${r.src} ` : "";
    const dst = r.dst ? `ip daddr ${r.dst} ` : "";
    const out = r.outInterface ? `oifname "${r.outInterface}" ` : "";
    post.push(`    ${src}${dst}${out}masquerade`.replace(/\s+/g, " ").trim() + ";");
  }
  post.push("  }");
  pre.push("  }");
  nat.push(...post, ...pre, "}");
  return [tunnel, "", "# --- tunnel nat ---", ...nat].join("\n");
}

export async function getFirewallConfigForPanel(nodeId) {
  const node = await prisma.agentNode.findUnique({ where: { id: nodeId }, select: { id: true, name: true } });
  if (!node) return { status: 404, body: { error: "Узел не найден" } };
  const row = await prisma.agentNodeOpenvpnSettings.findUnique({ where: { agentNodeId: node.id }, select: { settings: true } });
  const settings = row?.settings && typeof row.settings === "object" && !Array.isArray(row.settings) ? row.settings : {};
  const fallbackDefault = normalizeFirewallDefaultPolicy(settings[PANEL_FIREWALL_DEFAULT_POLICY_KEY]);
  const fallbackRules = normalizeFirewallBaseRules(settings[PANEL_FIREWALL_BASE_RULES_KEY]);
  const tunnelDefaultPolicy = normalizeFirewallDefaultPolicy(settings[PANEL_FIREWALL_TUNNEL_DEFAULT_POLICY_KEY] || fallbackDefault);
  const tunnelRules = normalizeFirewallBaseRules(settings[PANEL_FIREWALL_TUNNEL_RULES_KEY] || fallbackRules);
  const natRules = normalizeFirewallNatRules(settings[PANEL_FIREWALL_TUNNEL_NAT_RULES_KEY]);
  const tunnelContext = parseTunnelContext(settings);
  return {
    status: 200,
    body: {
      tunnel: { defaultPolicy: tunnelDefaultPolicy, rules: tunnelRules, natRules },
      tunnelContext,
      preview: renderFirewallDualScriptPreview({
        node,
        tunnelDefaultPolicy,
        tunnelRules,
        natRules,
        tunnelContext,
      }),
    },
  };
}

export async function applyFirewallConfigForPanel(nodeId, reqBody) {
  const node = await prisma.agentNode.findUnique({ where: { id: nodeId }, select: { id: true, name: true } });
  if (!node) return { status: 404, body: { error: "Узел не найден" } };
  const tunnelDefaultPolicy = normalizeFirewallDefaultPolicy(reqBody?.tunnel?.defaultPolicy);
  const tunnelRules = normalizeFirewallBaseRules(reqBody?.tunnel?.rules);
  const natRules = normalizeFirewallNatRules(reqBody?.tunnel?.natRules);
  const row = await prisma.agentNodeOpenvpnSettings.findUnique({ where: { agentNodeId: node.id }, select: { settings: true } });
  const prev = row?.settings && typeof row.settings === "object" && !Array.isArray(row.settings) ? row.settings : {};
  const tunnelContext = parseTunnelContext(prev);
  const next = {
    ...prev,
    [PANEL_FIREWALL_TUNNEL_DEFAULT_POLICY_KEY]: tunnelDefaultPolicy,
    [PANEL_FIREWALL_TUNNEL_RULES_KEY]: tunnelRules,
    [PANEL_FIREWALL_TUNNEL_NAT_RULES_KEY]: natRules,
  };
  await prisma.agentNodeOpenvpnSettings.upsert({
    where: { agentNodeId: node.id },
    create: { agentNodeId: node.id, settings: next },
    update: { settings: next },
  });
  enqueuePanelAgentSnapshotForNode(node.id).catch((e) => console.error("enqueuePanelAgentSnapshotForNode:", e.message));
  return {
    status: 200,
    body: {
      ok: true,
      message: "Конфигурация tunnel firewall сохранена.",
      tunnel: { defaultPolicy: tunnelDefaultPolicy, rules: tunnelRules, natRules },
      tunnelContext,
      preview: renderFirewallDualScriptPreview({
        node,
        tunnelDefaultPolicy,
        tunnelRules,
        natRules,
        tunnelContext,
      }),
    },
  };
}

export async function checkFirewallConfigForPanel(nodeId, reqBody) {
  const node = await prisma.agentNode.findUnique({ where: { id: nodeId }, select: { id: true, name: true } });
  if (!node) return { status: 404, body: { error: "Узел не найден" } };
  const tunnelDefaultPolicy = normalizeFirewallDefaultPolicy(reqBody?.tunnel?.defaultPolicy);
  const tunnelRules = normalizeFirewallBaseRules(reqBody?.tunnel?.rules);
  const natRules = normalizeFirewallNatRules(reqBody?.tunnel?.natRules);
  const row = await prisma.agentNodeOpenvpnSettings.findUnique({ where: { agentNodeId: node.id }, select: { settings: true } });
  const settings = row?.settings && typeof row.settings === "object" && !Array.isArray(row.settings) ? row.settings : {};
  const tunnelContext = parseTunnelContext(settings);
  return {
    status: 200,
    body: {
      ok: true,
      message: "Конфигурация tunnel firewall валидна.",
      tunnel: { defaultPolicy: tunnelDefaultPolicy, rules: tunnelRules, natRules },
      tunnelContext,
      preview: renderFirewallDualScriptPreview({
        node,
        tunnelDefaultPolicy,
        tunnelRules,
        natRules,
        tunnelContext,
      }),
    },
  };
}

export async function getOpenvpnSettingsForPanel(nodeId) {
  const node = await prisma.agentNode.findUnique({ where: { id: nodeId } });
  if (!node) {
    return { status: 404, body: { error: "Узел не найден" } };
  }

  try {
    const data = await getAgentOpenVPNSettings(node);
    if (!data || typeof data.settings !== "object" || Array.isArray(data.settings)) {
      throw new Error("Некорректный ответ агента (settings)");
    }
    const agentSettings = data.settings;
    const configPath = typeof data.configPath === "string" ? data.configPath : null;
    const row = await prisma.agentNodeOpenvpnSettings.findUnique({ where: { agentNodeId: node.id } });
    const prev =
      row?.settings && typeof row.settings === "object" && !Array.isArray(row.settings) ? row.settings : {};
    const merged = { ...prev, ...agentSettings };

    await prisma.agentNodeOpenvpnSettings.upsert({
      where: { agentNodeId: node.id },
      create: { agentNodeId: node.id, settings: merged, configPath },
      update: { settings: merged, configPath },
    });

    return {
      status: 200,
      body: { settings: merged, configPath, source: "agent" },
    };
  } catch (err) {
    const hints = Array.isArray(err.hints) && err.hints.length ? err.hints : fallbackHints;

    const row = await prisma.agentNodeOpenvpnSettings.findUnique({ where: { agentNodeId: node.id } });
    if (row) {
      return {
        status: 200,
        body: {
          settings: row.settings,
          configPath: row.configPath ?? null,
          source: "database",
          hints,
        },
      };
    }

    const initial = getInitialOpenVpnServerSettings();
    const created = await prisma.agentNodeOpenvpnSettings.create({
      data: { agentNodeId: node.id, settings: initial, configPath: null },
    });

    return {
      status: 200,
      body: {
        settings: created.settings,
        configPath: null,
        source: "seed",
        hints,
      },
    };
  }
}

export async function postOpenvpnSettingsForPanel(nodeId, reqBody) {
  const node = await prisma.agentNode.findUnique({ where: { id: nodeId } });
  if (!node) {
    return { status: 404, body: { error: "Узел не найден" } };
  }
  const { settings } = reqBody || {};
  if (!settings || typeof settings !== "object") {
    return { status: 400, body: { error: "Требуется объект settings" } };
  }
  const row = await prisma.agentNodeOpenvpnSettings.findUnique({ where: { agentNodeId: node.id } });
  const prev = row?.settings && typeof row.settings === "object" && !Array.isArray(row.settings) ? row.settings : {};
  const merged = { ...prev, ...settings };
  try {
    await postAgentOpenVPNSettings(node, stripPanelOnlyOpenvpnSettings(merged));
    await enqueueOpenvpnMaterialSyncTasks(node, merged);
    await prisma.agentNodeOpenvpnSettings.upsert({
      where: { agentNodeId: node.id },
      create: { agentNodeId: node.id, settings: merged },
      update: { settings: merged },
    });
    enqueuePanelAgentSnapshotForNode(node.id).catch((e) => console.error("enqueuePanelAgentSnapshotForNode:", e.message));
    return { status: 200, body: { ok: true } };
  } catch (err) {
    let status = 502;
    if (err.statusCode === 422) status = 422;
    else if (typeof err.statusCode === "number" && err.statusCode >= 400 && err.statusCode < 500) {
      status = err.statusCode;
    } else if (!err.statusCode) status = 400;
    return {
      status,
      body: {
        error: err.message || "Ошибка применения настроек",
        hints: Array.isArray(err.hints) ? err.hints : [],
        output: typeof err.agentBody?.output === "string" ? err.agentBody.output : "",
        serviceLog: typeof err.agentBody?.serviceLog === "string" ? err.agentBody.serviceLog : "",
        backupPath: typeof err.agentBody?.backupPath === "string" ? err.agentBody.backupPath : "",
        rolledBack: Boolean(err.agentBody?.rolledBack),
      },
    };
  }
}

/**
 * Полное снятие корневого сертификата с узла: удаляет все сертификаты этого узла, выданные этим корневым сертификатом,
 * очищает привязку сертификата сервера, удаляет учёт сессий/трафика на узле.
 * Запись RootCertificateAuthority удаляется, если на неё больше нет ссылок в настройках и в таблице Certificate.
 */
export async function removeRootCaForPanel(nodeId, reqBody) {
  const agentNodeId = String(nodeId || "").trim();

  const node = await prisma.agentNode.findUnique({ where: { id: agentNodeId } });
  if (!node) {
    return { status: 404, body: { error: "Узел не найден" } };
  }

  const row = await prisma.agentNodeOpenvpnSettings.findUnique({ where: { agentNodeId } });
  const prev = row?.settings && typeof row.settings === "object" && !Array.isArray(row.settings) ? row.settings : {};
  const rootId = String(prev.panelRootCaId || "").trim();
  if (!rootId) {
    return { status: 400, body: { error: "Для этого сервера не задан корневой сертификат" } };
  }

  const rootRow = await prisma.rootCertificateAuthority.findUnique({
    where: { id: rootId },
    select: { commonName: true },
  });
  const expectedCn = String(rootRow?.commonName || "").trim();
  const providedCn = String(reqBody?.confirmCommonName || "").trim();
  if (!expectedCn || providedCn !== expectedCn) {
    return {
      status: 400,
      body: { error: "Подтвердите удаление: введите точный Common Name (CN) корневого сертификата." },
    };
  }

  const nextSettings = { ...prev, panelRootCaId: "", panelServerCertId: "" };

  await prisma.$transaction(async (tx) => {
    await tx.certificate.deleteMany({ where: { agentNodeId, rootCaId: rootId } });
    await tx.clientIpAssignment.deleteMany({ where: { agentNodeId } });
    await tx.clientSourceIpHistory.deleteMany({ where: { agentNodeId } });
    await tx.clientTrafficSample.deleteMany({ where: { agentNodeId } });
    await tx.openvpnServerLog.deleteMany({ where: { agentNodeId } });

    await tx.agentNodeOpenvpnSettings.upsert({
      where: { agentNodeId },
      create: { agentNodeId, settings: nextSettings },
      update: { settings: nextSettings },
    });
  });

  const allRows = await prisma.agentNodeOpenvpnSettings.findMany({ select: { settings: true } });
  let settingsRefs = 0;
  for (const r of allRows) {
    const s = r.settings && typeof r.settings === "object" && !Array.isArray(r.settings) ? r.settings : {};
    if (String(s.panelRootCaId || "").trim() === rootId) settingsRefs += 1;
  }
  const certRefs = await prisma.certificate.count({ where: { rootCaId: rootId } });
  if (settingsRefs === 0 && certRefs === 0) {
    try {
      await prisma.rootCertificateAuthority.delete({ where: { id: rootId } });
    } catch {
      /* FK или гонка — оставляем запись */
    }
  }

  const mergedRow = await prisma.agentNodeOpenvpnSettings.findUnique({ where: { agentNodeId } });
  const merged =
    mergedRow?.settings && typeof mergedRow.settings === "object" && !Array.isArray(mergedRow.settings)
      ? mergedRow.settings
      : nextSettings;

  try {
    await enqueueOpenvpnMaterialSyncTasks(node, merged);
  } catch (e) {
    console.error("enqueueOpenvpnMaterialSyncTasks after root remove:", e);
  }

  return { status: 200, body: { ok: true, settings: merged } };
}

export async function applyOpenvpnSettingsForPanel(nodeId, reqBody) {
  const node = await prisma.agentNode.findUnique({ where: { id: nodeId } });
  if (!node) {
    return { status: 404, body: { error: "Узел не найден" } };
  }
  const row = await prisma.agentNodeOpenvpnSettings.findUnique({ where: { agentNodeId: node.id } });
  const prev = row?.settings && typeof row.settings === "object" && !Array.isArray(row.settings) ? row.settings : {};
  const incoming = reqBody?.settings && typeof reqBody.settings === "object" && !Array.isArray(reqBody.settings)
    ? reqBody.settings
    : {};
  const settings = { ...prev, ...incoming };
  try {
    await enqueueOpenvpnMaterialSyncTasks(node, settings);
    await processPendingTasksForNode(node, 50);
    // Re-stage current panel draft before apply to avoid missing staged file.
    await postAgentOpenVPNSettings(node, stripPanelOnlyOpenvpnSettings(settings));
    const applyData = await postAgentOpenVPNApplyConfig(node);
    await prisma.agentNodeOpenvpnSettings.upsert({
      where: { agentNodeId: node.id },
      create: { agentNodeId: node.id, settings },
      update: { settings },
    });
    enqueuePanelAgentSnapshotForNode(node.id).catch((e) => console.error("enqueuePanelAgentSnapshotForNode:", e.message));
    return {
      status: 200,
      body: {
        ok: true,
        message: "Настройки применены на агенте.",
        output: typeof applyData?.output === "string" ? applyData.output : "",
        serviceLog: typeof applyData?.serviceLog === "string" ? applyData.serviceLog : "",
      },
    };
  } catch (err) {
    let status = 502;
    if (err.statusCode === 422) status = 422;
    else if (typeof err.statusCode === "number" && err.statusCode >= 400 && err.statusCode < 500) {
      status = err.statusCode;
    } else if (!err.statusCode) status = 400;
    return {
      status,
      body: {
        error: err.message || "Ошибка применения настроек",
        hints: Array.isArray(err.hints) ? err.hints : [],
        output: typeof err.agentBody?.output === "string" ? err.agentBody.output : "",
        serviceLog: typeof err.agentBody?.serviceLog === "string" ? err.agentBody.serviceLog : "",
        backupPath: typeof err.agentBody?.backupPath === "string" ? err.agentBody.backupPath : "",
        rolledBack: Boolean(err.agentBody?.rolledBack),
      },
    };
  }
}

export async function getOpenvpnRawConfigForPanel(nodeId) {
  const node = await prisma.agentNode.findUnique({ where: { id: nodeId } });
  if (!node) {
    return { status: 404, body: { error: "Узел не найден" } };
  }
  try {
    const data = await getAgentOpenVPNRawConfig(node);
    return {
      status: 200,
      body: {
        configPath: typeof data?.configPath === "string" ? data.configPath : null,
        rawConfig: typeof data?.rawConfig === "string" ? data.rawConfig : "",
      },
    };
  } catch (err) {
    return {
      status: 502,
      body: {
        error: err.message || "Не удалось прочитать raw-конфиг с агента",
      },
    };
  }
}

export async function getNodeNetworkInfoForPanel(nodeId) {
  const node = await prisma.agentNode.findUnique({ where: { id: nodeId } });
  if (!node) {
    return { status: 404, body: { error: "Узел не найден" } };
  }
  try {
    const data = await getAgentSystemNetwork(node);
    const interfaces = Array.isArray(data?.interfaces) ? data.interfaces : [];
    const addresses = Array.isArray(data?.addresses) ? data.addresses : [];
    return {
      status: 200,
      body: {
        interfaces: interfaces.map((it) => ({
          name: String(it?.name || ""),
          addresses: Array.isArray(it?.addresses) ? it.addresses.map((x) => String(x || "")).filter(Boolean) : [],
        })),
        addresses: addresses.map((x) => String(x || "")).filter(Boolean),
      },
    };
  } catch (err) {
    return {
      status: 502,
      body: { error: err.message || "Не удалось получить интерфейсы/адреса с агента" },
    };
  }
}

export async function getNodeSystemServicesForPanel(nodeId) {
  const node = await prisma.agentNode.findUnique({ where: { id: nodeId } });
  if (!node) {
    return { status: 404, body: { error: "Узел не найден" } };
  }
  try {
    const data = await getAgentSystemServices(node);
    const rows = Array.isArray(data?.services) ? data.services : [];
    return {
      status: 200,
      body: {
        services: rows.map((r) => ({
          unit: String(r?.unit || ""),
          loadState: String(r?.loadState || ""),
          activeState: String(r?.activeState || ""),
          subState: String(r?.subState || ""),
          description: String(r?.description || ""),
          mainPid: typeof r?.mainPid === "number" && Number.isFinite(r.mainPid) ? r.mainPid : undefined,
          uptimeSeconds:
            typeof r?.uptimeSeconds === "number" && Number.isFinite(r.uptimeSeconds) ? r.uptimeSeconds : undefined,
        })),
      },
    };
  } catch (err) {
    return {
      status: 502,
      body: { error: err.message || "Не удалось получить список служб с агента" },
    };
  }
}

function isAllowedSystemdServiceUnitName(unit) {
  const u = String(unit || "").trim();
  if (!u || u.length > 256 || !u.endsWith(".service")) return false;
  const base = u.slice(0, -".service".length);
  if (!base) return false;
  return /^[a-zA-Z0-9@._-]+$/.test(base);
}

export async function postNodeSystemServiceUnitActionForPanel(nodeId, reqBody) {
  const node = await prisma.agentNode.findUnique({ where: { id: nodeId } });
  if (!node) {
    return { status: 404, body: { error: "Узел не найден" } };
  }
  const unit = String(reqBody?.unit || "").trim();
  const action = String(reqBody?.action || "").trim().toLowerCase();
  if (!isAllowedSystemdServiceUnitName(unit)) {
    return { status: 400, body: { error: "Недопустимое имя unit (ожидается *.service)" } };
  }
  if (!["start", "stop", "restart"].includes(action)) {
    return { status: 400, body: { error: "action должен быть start|stop|restart" } };
  }
  try {
    const data = await postAgentSystemServiceUnitAction(node, { unit, action });
    return { status: 200, body: data };
  } catch (err) {
    const rawOutput = typeof err.agentBody?.output === "string" ? err.agentBody.output.trim() : "";
    return {
      status: 502,
      body: {
        error: rawOutput
          ? `${err.message || "Не удалось выполнить systemctl"}: ${rawOutput}`
          : err.message || "Не удалось выполнить systemctl",
        output: rawOutput || null,
      },
    };
  }
}

export async function getDnsmasqForPanel(nodeId) {
  const node = await prisma.agentNode.findUnique({ where: { id: nodeId } });
  if (!node) {
    return { status: 404, body: { error: "Узел не найден" } };
  }
  try {
    const data = await getAgentDnsmasq(node);
    return {
      status: 200,
      body: {
        service: data?.service || {},
        configPath: String(data?.configPath || ""),
        config: String(data?.config || ""),
      },
    };
  } catch (err) {
    return {
      status: 502,
      body: { error: err.message || "Не удалось получить состояние DNSMasq" },
    };
  }
}

export async function postDnsmasqForPanel(nodeId, reqBody) {
  const node = await prisma.agentNode.findUnique({ where: { id: nodeId } });
  if (!node) {
    return { status: 404, body: { error: "Узел не найден" } };
  }
  const action = String(reqBody?.action || "").trim().toLowerCase() || "save";
  if (!["save", "apply", "start", "stop", "restart"].includes(action)) {
    return { status: 400, body: { error: "action должен быть save|apply|start|stop|restart" } };
  }
  try {
    const data = await postAgentDnsmasq(node, {
      action,
      config: String(reqBody?.config || ""),
    });
    return { status: 200, body: data };
  } catch (err) {
    return {
      status: 502,
      body: {
        error: err.message || "Не удалось выполнить операцию DNSMasq",
        output: typeof err.agentBody?.output === "string" ? err.agentBody.output : "",
      },
    };
  }
}

/** Поставить в очередь задачу применения конфига DNSMasq (как action=apply на агенте). */
export async function enqueueDnsmasqApplyTaskForPanel(nodeId, reqBody) {
  const node = await prisma.agentNode.findUnique({ where: { id: nodeId } });
  if (!node) {
    return { status: 404, body: { error: "Узел не найден" } };
  }
  const config = String(reqBody?.config ?? "");
  await enqueueDnsmasqApplyTask(node.id, config);
  return {
    status: 202,
    body: {
      ok: true,
      message:
        "Задача применения DNSMasq поставлена в очередь. Статус выполнения — в разделе «Задачи» (тип dnsmasq_apply).",
    },
  };
}

export async function postOpenvpnServiceActionForPanel(nodeId, reqBody) {
  const node = await prisma.agentNode.findUnique({ where: { id: nodeId } });
  if (!node) {
    return { status: 404, body: { error: "Узел не найден" } };
  }
  const action = String(reqBody?.action || "").toLowerCase();
  if (!["start", "stop", "restart"].includes(action)) {
    return { status: 400, body: { error: "action должен быть start|stop|restart" } };
  }
  try {
    const data = await postAgentOpenVPNServiceAction(node, action);
    return { status: 200, body: data };
  } catch (err) {
    const rawOutput = typeof err.agentBody?.output === "string" ? err.agentBody.output.trim() : "";
    const hintUnit = node.openvpnServiceUnit || "openvpn.service";
    return {
      status: 502,
      body: {
        error: rawOutput
          ? `${err.message || "Не удалось выполнить команду OpenVPN service"}: ${rawOutput}`
          : err.message || "Не удалось выполнить команду OpenVPN service",
        output: rawOutput || null,
        hints: [
          `Проверьте unit OpenVPN: ${hintUnit}.`,
          "При необходимости задайте OPENVPN_SERVICE_UNIT или OPENVPN_SERVICE_*_CMD на агенте.",
          "Проверьте права пользователя агента на выполнение systemctl.",
        ],
      },
    };
  }
}

export async function postOpenvpnCheckConfigForPanel(nodeId) {
  const node = await prisma.agentNode.findUnique({ where: { id: nodeId } });
  if (!node) {
    return { status: 404, body: { error: "Узел не найден" } };
  }
  try {
    const row = await prisma.agentNodeOpenvpnSettings.findUnique({ where: { agentNodeId: node.id } });
    const saved =
      row?.settings && typeof row.settings === "object" && !Array.isArray(row.settings) ? row.settings : null;
    if (saved) {
      await postAgentOpenVPNSettings(node, stripPanelOnlyOpenvpnSettings(saved));
    }
    const data = await postAgentOpenVPNCheckConfig(node);
    return { status: 200, body: data };
  } catch (err) {
    const status = err.statusCode === 422 ? 422 : 502;
    return {
      status,
      body: {
        error: err.message || "Проверка конфига не выполнена",
        hints: Array.isArray(err.hints) ? err.hints : [],
        output: typeof err.agentBody?.output === "string" ? err.agentBody.output : "",
        command: typeof err.agentBody?.command === "string" ? err.agentBody.command : "",
        configPath: typeof err.agentBody?.configPath === "string" ? err.agentBody.configPath : "",
      },
    };
  }
}

export async function postAgentUpdateForPanel(nodeId, reqBody) {
  const node = await prisma.agentNode.findUnique({ where: { id: nodeId } });
  if (!node) {
    return { status: 404, body: { error: "Узел не найден" } };
  }
  const fileName = String(reqBody?.fileName || "").trim();
  const binaryBase64 = String(reqBody?.binaryBase64 || "").trim();
  const checksumSha256 = String(reqBody?.checksumSha256 || "").trim();
  if (!binaryBase64) {
    return { status: 400, body: { error: "Требуется binaryBase64" } };
  }
  try {
    const data = await postAgentBinaryUpdate(node, fileName, binaryBase64, checksumSha256);
    return { status: 200, body: data };
  } catch (err) {
    return {
      status: 502,
      body: {
        error: err.message || "Обновление агента не выполнено",
        output: err.agentBody?.output || null,
      },
    };
  }
}

export async function getOpenvpnLogsForPanel(nodeId, query) {
  const node = await prisma.agentNode.findUnique({ where: { id: nodeId }, select: { id: true } });
  if (!node) {
    return { status: 404, body: { error: "Узел не найден" } };
  }
  const page = Math.max(1, Number(query?.page) || 1);
  const pageSize = Math.min(200, Math.max(10, Number(query?.pageSize) || 50));
  const q = String(query?.q || "").trim();
  const where = {
    agentNodeId: node.id,
    ...(q
      ? {
          OR: [
            { username: { contains: q, mode: "insensitive" } },
            { event: { contains: q, mode: "insensitive" } },
            { occurredRaw: { contains: q, mode: "insensitive" } },
            { ipAddress: { contains: q, mode: "insensitive" } },
            { rawLine: { contains: q, mode: "insensitive" } },
          ],
        }
      : {}),
  };
  const [total, rows] = await Promise.all([
    prisma.openvpnServerLog.count({ where }),
    prisma.openvpnServerLog.findMany({
      where,
      orderBy: [{ occurredAt: "desc" }, { id: "desc" }],
      skip: (page - 1) * pageSize,
      take: pageSize,
      select: {
        id: true,
        occurredAt: true,
        occurredRaw: true,
        event: true,
        username: true,
        ipAddress: true,
      },
    }),
  ]);
  return {
    status: 200,
    body: {
      page,
      pageSize,
      total,
      totalPages: Math.max(1, Math.ceil(total / pageSize)),
      rows,
    },
  };
}
