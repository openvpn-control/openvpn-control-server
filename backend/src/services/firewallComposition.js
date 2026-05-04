export function composeFirewallLevels(orgLike, userLike) {
  const orgMode = String(orgLike?.mode || "merge").toLowerCase() === "replace" ? "replace" : "merge";
  const userMode = String(userLike?.mode || "merge").toLowerCase() === "replace" ? "replace" : "merge";
  const orgRules = Array.isArray(orgLike?.rules) ? orgLike.rules : [];
  const userRules = Array.isArray(userLike?.rules) ? userLike.rules : [];
  const orgNatRules = Array.isArray(orgLike?.natRules) ? orgLike.natRules : [];
  const userNatRules = Array.isArray(userLike?.natRules) ? userLike.natRules : [];

  if (userMode === "replace") {
    return { mode: "replace", rules: userRules, natRules: userNatRules };
  }
  if (orgMode === "replace") {
    return { mode: "replace", rules: [...orgRules, ...userRules], natRules: [...orgNatRules, ...userNatRules] };
  }
  return { mode: "merge", rules: [...orgRules, ...userRules], natRules: [...orgNatRules, ...userNatRules] };
}

export function deriveSessionNatRules(sessions) {
  const out = [];
  for (const s of sessions || []) {
    const vip = String(s?.virtualIp || "").trim();
    if (!vip) continue;
    const nat = Array.isArray(s?.natRules) ? s.natRules : [];
    for (const r of nat) {
      const src = String(r?.src || "").trim() || `${vip}/32`;
      out.push({
        type: String(r?.type || "masquerade"),
        src,
        dst: String(r?.dst || "").trim(),
        outInterface: String(r?.outInterface || "").trim(),
        toAddress: String(r?.toAddress || "").trim(),
        note: String(r?.note || "").trim(),
      });
    }
  }
  return out;
}
