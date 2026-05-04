/**
 * Bash-скрипт с командами iptables для агента (правила видны в iptables-save).
 * FORWARD: прямые переходы в OPENVPN_PANEL_BASE и в OVPN_MRG_* / OVPN_REP_* (без лишней цепочки-диспетчера).
 * nat: OPENVPN_PANEL_NAT.
 */

const CHAIN_BASE = "OPENVPN_PANEL_BASE";
const CHAIN_NAT = "OPENVPN_PANEL_NAT";
const CHAIN_NAT_POST = "OPENVPN_PANEL_NAT_POST";
const CHAIN_NAT_PRE = "OPENVPN_PANEL_NAT_PRE";
/** Старые выкладки; только снятие */
const LEGACY_DISPATCH = "OPENVPN_PANEL_FWD";

function chainSuffixFromVirtIp(ip) {
  return String(ip || "")
    .trim()
    .split("/")[0]
    .replace(/\./g, "_")
    .replace(/:/g, "_");
}

function shQuote(s) {
  return `'${String(s).replace(/'/g, `'\"'\"'`)}'`;
}

function normalizeTunnelIfName(raw) {
  const s = String(raw || "").trim() || "tun0";
  const l = s.toLowerCase();
  if (l === "tun") return "tun0";
  if (l === "tap") return "tap0";
  return s;
}

function orderedRulesForIptables(baseRules, userRules, mode) {
  const combined = mode === "replace" ? [...(userRules || [])] : [...(baseRules || []), ...(userRules || [])];
  return combined.slice().reverse();
}

function portMatchArgs(r) {
  const ports = String(r.ports || "").trim().replace(/\s+/g, "");
  if (!ports) return "";
  if (ports.includes(",") || ports.includes(":")) {
    return `-m multiport --dports ${ports}`;
  }
  return `--dport ${ports}`;
}

/** @returns {string[]} */
function emitFilterAppends(chain, r) {
  const tgt = r.action === "deny" ? "DROP" : "ACCEPT";
  if (r.proto === "icmp") {
    const dst = r.destination ? `-d ${shQuote(r.destination)} ` : "";
    return [`iptables -t filter -A ${chain} -p icmp ${dst}-j ${tgt}`.replace(/\s+/g, " ").trim()];
  }
  const dst = r.destination ? `-d ${shQuote(r.destination)} ` : "";
  const pm = portMatchArgs(r);
  if (r.proto === "any") {
    if (pm) {
      return [
        `iptables -t filter -A ${chain} -p tcp ${dst}${pm} -j ${tgt}`.replace(/\s+/g, " ").trim(),
        `iptables -t filter -A ${chain} -p udp ${dst}${pm} -j ${tgt}`.replace(/\s+/g, " ").trim(),
      ];
    }
    return [
      `iptables -t filter -A ${chain} -p tcp ${dst}-j ${tgt}`.replace(/\s+/g, " ").trim(),
      `iptables -t filter -A ${chain} -p udp ${dst}-j ${tgt}`.replace(/\s+/g, " ").trim(),
    ];
  }
  const proto = r.proto === "udp" ? "udp" : "tcp";
  const portPart = pm ? ` ${pm}` : "";
  return [`iptables -t filter -A ${chain} -p ${proto} ${dst}${portPart} -j ${tgt}`.replace(/\s+/g, " ").trim()];
}

function appendDefaultEnd(chain, defaultPolicy) {
  if (defaultPolicy === "allow") {
    return [`iptables -t filter -A ${chain} -j RETURN`];
  }
  return [`iptables -t filter -A ${chain} -j DROP`];
}

function buildFilterChainContent(chainName, defaultPolicy, orderedRules) {
  const lines = [];
  for (const rule of orderedRules) {
    lines.push(...emitFilterAppends(chainName, rule));
  }
  lines.push(...appendDefaultEnd(chainName, defaultPolicy));
  return lines;
}

function natAppendLine(chain, r) {
  if (r.type === "masquerade") {
    const src = r.src ? `-s ${shQuote(r.src)} ` : "";
    const dst = r.dst ? `-d ${shQuote(r.dst)} ` : "";
    const out = r.outInterface ? `-o ${shQuote(r.outInterface)} ` : "";
    return `iptables -t nat -A ${chain} ${src}${dst}${out}-j MASQUERADE`.replace(/\s+/g, " ").trim();
  }
  if (r.type === "snat") {
    const src = r.src ? `-s ${shQuote(r.src)} ` : "";
    const dst = r.dst ? `-d ${shQuote(r.dst)} ` : "";
    const out = r.outInterface ? `-o ${shQuote(r.outInterface)} ` : "";
    const to = r.toAddress ? ` --to-source ${shQuote(r.toAddress)}` : "";
    return `iptables -t nat -A ${chain} ${src}${dst}${out}-j SNAT${to}`.replace(/\s+/g, " ").trim();
  }
  const src = r.src ? `-s ${shQuote(r.src)} ` : "";
  const dst = r.dst ? `-d ${shQuote(r.dst)} ` : "";
  // Для DNAT outInterface трактуем как входящий интерфейс (-i) в PREROUTING.
  const inIface = r.outInterface ? `-i ${shQuote(r.outInterface)} ` : "";
  const to = r.toAddress ? ` --to-destination ${shQuote(r.toAddress)}` : "";
  return `iptables -t nat -A ${chain} ${src}${dst}${inIface}-j DNAT${to}`.replace(/\s+/g, " ").trim();
}

/**
 * Полный bash-скрипт применения.
 */
export function renderFirewallRuntimeIptablesScript(p) {
  const iface = normalizeTunnelIfName(p.tunnelInterface);
  const cidr = String(p.vpnSubnetCidr || "").trim();
  const IF = shQuote(iface);
  const SN = cidr ? shQuote(cidr) : "";
  const sessions = p.sessions || [];

  const lines = [
    "#!/bin/sh",
    "set -e",
    `# openvpn-panel runtime firewall (iptables) — ${p.nodeLabel || "node"}`,
    "set +e",
  ];

  // Все jump панели из FORWARD (в т.ч. /32 от уже отключившихся клиентов; не только «текущий» список сессий)
  lines.push(
    'while iptables -t filter -S FORWARD 2>/dev/null | grep -qE -- \'-j OVPN_| -j OPENVPN_PANEL_\'; do SPEC=$(iptables -t filter -S FORWARD 2>/dev/null | grep -E -- \'-j OVPN_| -j OPENVPN_PANEL_\' | head -n1 | sed \'s/^-A FORWARD //\'); [ -z "$SPEC" ] && break; iptables -t filter -D FORWARD $SPEC 2>/dev/null || break; done',
  );
  // Все цепочки OVPN_* (старые виртуальные IP)
  lines.push(
    'for c in $(iptables -t filter -L 2>/dev/null | sed -n \'s/^Chain \\(OVPN_[^ ]*\\) .*/\\1/p\'); do iptables -t filter -F "$c" 2>/dev/null; iptables -t filter -X "$c" 2>/dev/null; done',
  );
  lines.push(`iptables -t filter -F ${LEGACY_DISPATCH} 2>/dev/null || true`);
  lines.push(`iptables -t filter -X ${LEGACY_DISPATCH} 2>/dev/null || true`);
  lines.push(`iptables -t filter -F ${CHAIN_BASE} 2>/dev/null || true`);
  lines.push(`iptables -t filter -X ${CHAIN_BASE} 2>/dev/null || true`);
  if (cidr) {
    lines.push(
      `while iptables -t nat -C POSTROUTING -s ${SN} -j ${CHAIN_NAT} 2>/dev/null; do iptables -t nat -D POSTROUTING -s ${SN} -j ${CHAIN_NAT}; done`,
      `while iptables -t nat -C POSTROUTING -s ${SN} -j ${CHAIN_NAT_POST} 2>/dev/null; do iptables -t nat -D POSTROUTING -s ${SN} -j ${CHAIN_NAT_POST}; done`,
    );
  }
  lines.push(
    `while iptables -t nat -C POSTROUTING -j ${CHAIN_NAT} 2>/dev/null; do iptables -t nat -D POSTROUTING -j ${CHAIN_NAT}; done`,
    `while iptables -t nat -C POSTROUTING -j ${CHAIN_NAT_POST} 2>/dev/null; do iptables -t nat -D POSTROUTING -j ${CHAIN_NAT_POST}; done`,
    `while iptables -t nat -C PREROUTING -j ${CHAIN_NAT_PRE} 2>/dev/null; do iptables -t nat -D PREROUTING -j ${CHAIN_NAT_PRE}; done`,
    `iptables -t nat -F ${CHAIN_NAT} 2>/dev/null || true`,
    `iptables -t nat -X ${CHAIN_NAT} 2>/dev/null || true`,
    `iptables -t nat -F ${CHAIN_NAT_POST} 2>/dev/null || true`,
    `iptables -t nat -X ${CHAIN_NAT_POST} 2>/dev/null || true`,
    `iptables -t nat -F ${CHAIN_NAT_PRE} 2>/dev/null || true`,
    `iptables -t nat -X ${CHAIN_NAT_PRE} 2>/dev/null || true`,
    "set -e",
  );

  for (const s of sessions) {
    const suf = chainSuffixFromVirtIp(s.virtualIp);
    const vip = String(s.virtualIp || "").trim().split("/")[0];
    if (!vip) continue;
    if (s.mode === "replace") {
      const ord = orderedRulesForIptables([], s.rules || [], "replace");
      lines.push(`iptables -t filter -N OVPN_REP_${suf}`);
      lines.push(...buildFilterChainContent(`OVPN_REP_${suf}`, p.tunnelDefaultPolicy, ord));
    } else if (Array.isArray(s.rules) && s.rules.length > 0) {
      const ord = orderedRulesForIptables(p.tunnelRules || [], s.rules || [], "merge");
      lines.push(`iptables -t filter -N OVPN_MRG_${suf}`);
      lines.push(...buildFilterChainContent(`OVPN_MRG_${suf}`, p.tunnelDefaultPolicy, ord));
    }
  }

  const baseOrdered = orderedRulesForIptables(p.tunnelRules || [], [], "merge");
  lines.push(`iptables -t filter -N ${CHAIN_BASE}`);
  lines.push(...buildFilterChainContent(CHAIN_BASE, p.tunnelDefaultPolicy, baseOrdered));

  if (cidr) {
    lines.push(`iptables -t filter -I FORWARD 1 -i ${IF} -s ${SN} -j ${CHAIN_BASE}`);
  } else {
    lines.push(`iptables -t filter -I FORWARD 1 -i ${IF} -j ${CHAIN_BASE}`);
  }
  for (const s of sessions) {
    const suf = chainSuffixFromVirtIp(s.virtualIp);
    const vip = String(s.virtualIp || "").trim().split("/")[0];
    if (!vip) continue;
    if (s.mode === "replace") {
      lines.push(`iptables -t filter -I FORWARD 1 -i ${IF} -s ${shQuote(`${vip}/32`)} -j OVPN_REP_${suf}`);
    } else if (Array.isArray(s.rules) && s.rules.length > 0) {
      lines.push(`iptables -t filter -I FORWARD 1 -i ${IF} -s ${shQuote(`${vip}/32`)} -j OVPN_MRG_${suf}`);
    }
  }

  const natRules = p.natRules || [];
  if (natRules.length > 0) {
    const postRules = natRules.filter((r) => String(r?.type || "").toLowerCase() !== "dnat");
    const preRules = natRules.filter((r) => String(r?.type || "").toLowerCase() === "dnat");
    if (postRules.length > 0) {
      lines.push(`iptables -t nat -N ${CHAIN_NAT_POST}`);
      for (const r of postRules) {
        lines.push(natAppendLine(CHAIN_NAT_POST, r));
      }
      if (cidr) {
        lines.push(`iptables -t nat -I POSTROUTING 1 -s ${SN} -j ${CHAIN_NAT_POST}`);
      } else {
        lines.push(`iptables -t nat -I POSTROUTING 1 -j ${CHAIN_NAT_POST}`);
      }
    }
    if (preRules.length > 0) {
      lines.push(`iptables -t nat -N ${CHAIN_NAT_PRE}`);
      for (const r of preRules) {
        lines.push(natAppendLine(CHAIN_NAT_PRE, r));
      }
      lines.push(`iptables -t nat -I PREROUTING 1 -j ${CHAIN_NAT_PRE}`);
    }
  }

  return lines.join("\n");
}
