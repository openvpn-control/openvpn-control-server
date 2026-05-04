/**
 * Нормализация и рендер текста CCD-файла для пользователя (как в UI предпросмотре).
 */

export function normalizeUserCcdSettings(raw) {
  const src = raw && typeof raw === "object" && !Array.isArray(raw) ? raw : {};
  return {
    ifconfigPushLocal: String(src.ifconfigPushLocal || "").trim(),
    ifconfigPushRemote: String(src.ifconfigPushRemote || "").trim(),
    pushRoutes: String(src.pushRoutes || "").trim(),
    iroutes: String(src.iroutes || "").trim(),
    dnsServers: String(src.dnsServers || "").trim(),
    customDirectives: String(src.customDirectives || "").trim(),
  };
}

function pushLinesFromMultiline(prefix, text) {
  const lines = [];
  for (const line of String(text || "")
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean)) {
    lines.push(`${prefix} ${line}`);
  }
  return lines;
}

export function renderUserCcdText(userDisplayName, settings) {
  const s = normalizeUserCcdSettings(settings);
  const lines = [];
  lines.push(`# ccd for user: ${String(userDisplayName || "unknown-user").trim() || "unknown-user"}`);
  if (s.ifconfigPushLocal && s.ifconfigPushRemote) {
    lines.push(`ifconfig-push ${s.ifconfigPushLocal} ${s.ifconfigPushRemote}`);
  }
  lines.push(...pushLinesFromMultiline("push", s.pushRoutes));
  lines.push(...pushLinesFromMultiline("iroute", s.iroutes));
  for (const dns of String(s.dnsServers || "")
    .split(/[\s,]+/)
    .map((x) => x.trim())
    .filter(Boolean)) {
    lines.push(`push dhcp-option DNS ${dns}`);
  }
  for (const rawLine of String(s.customDirectives || "").split(/\r?\n/)) {
    const t = rawLine.trim();
    if (t) lines.push(t);
  }
  return `${lines.join("\n").trim()}\n`;
}
