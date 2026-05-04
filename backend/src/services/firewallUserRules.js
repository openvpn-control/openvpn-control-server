/** Парсинг firewallRules у VpnUser: legacy-массив или { mode, rules }. */

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

export function normalizeFirewallRulesArray(raw) {
  const rows = Array.isArray(raw) ? raw : [];
  return rows.map((r, i) => normalizeFirewallRule(r, i));
}

function normalizeFirewallNatRule(rule, idx = 0) {
  const src = rule && typeof rule === "object" && !Array.isArray(rule) ? rule : {};
  const type = String(src.type || "masquerade").toLowerCase();
  return {
    id: String(src.id || `nat-${idx + 1}`),
    type: ["masquerade", "snat", "dnat"].includes(type) ? type : "masquerade",
    src: String(src.src || "").trim(),
    dst: String(src.dst || "").trim(),
    outInterface: String(src.outInterface || "").trim(),
    toAddress: String(src.toAddress || "").trim(),
    note: String(src.note || "").trim(),
  };
}

export function normalizeFirewallNatRulesArray(raw) {
  const rows = Array.isArray(raw) ? raw : [];
  return rows.map((r, i) => normalizeFirewallNatRule(r, i));
}

/**
 * @returns {{ mode: "merge"|"replace", rules: ReturnType<normalizeFirewallRulesArray>, natRules: ReturnType<normalizeFirewallNatRulesArray> }}
 */
export function parseUserFirewallStored(raw) {
  if (raw == null) return { mode: "merge", rules: [], natRules: [] };
  if (Array.isArray(raw)) return { mode: "merge", rules: normalizeFirewallRulesArray(raw), natRules: [] };
  if (typeof raw === "object" && !Array.isArray(raw)) {
    const mode = String(raw.mode || "merge").toLowerCase() === "replace" ? "replace" : "merge";
    const rules = normalizeFirewallRulesArray(raw.rules);
    const natRules = normalizeFirewallNatRulesArray(raw.natRules);
    return { mode, rules, natRules };
  }
  return { mode: "merge", rules: [], natRules: [] };
}

export function serializeUserFirewallForDb(mode, rules, natRules) {
  const m = String(mode || "merge").toLowerCase() === "replace" ? "replace" : "merge";
  return {
    mode: m,
    rules: normalizeFirewallRulesArray(rules),
    natRules: normalizeFirewallNatRulesArray(natRules),
  };
}
