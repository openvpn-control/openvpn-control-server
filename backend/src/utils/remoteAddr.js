/**
 * Из адреса клиента OpenVPN (часто IPv4:порт или [IPv6]:порт) оставляет только IP-хост для хранения в БД.
 * IPv6 без скобок с портом не режем (неоднозначно).
 * @param {unknown} addr
 * @returns {string}
 */
export function remoteAddrHostOnly(addr) {
  const s = String(addr ?? "").trim();
  if (!s) return "";
  if (s.startsWith("[")) {
    const end = s.indexOf("]");
    if (end > 1) return s.slice(1, end);
  }
  const lastColon = s.lastIndexOf(":");
  if (lastColon > 0) {
    const tail = s.slice(lastColon + 1);
    if (/^\d{1,5}$/.test(tail)) {
      const host = s.slice(0, lastColon);
      if (host.includes(".")) return host;
    }
  }
  return s;
}
