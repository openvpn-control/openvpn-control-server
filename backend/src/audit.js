import { prisma } from "./prisma.js";

const HIDDEN_KEYS = new Set(["password", "passwordHash", "authToken", "keyPem", "certPem", "token"]);

function sanitizeValue(value) {
  if (value == null) return value;
  if (Array.isArray(value)) return value.slice(0, 20).map((x) => sanitizeValue(x));
  if (typeof value === "object") {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = HIDDEN_KEYS.has(k) ? "[redacted]" : sanitizeValue(v);
    }
    return out;
  }
  if (typeof value === "string" && value.length > 400) return `${value.slice(0, 400)}…`;
  return value;
}

function deriveTarget(path, params = {}) {
  if (path.includes("/agent/nodes/")) {
    return { targetType: "agent-node", targetId: params.id || params.nodeId || null };
  }
  if (path.includes("/vpn-users/")) {
    return { targetType: "vpn-user", targetId: params.id || null };
  }
  if (path.includes("/organizations/")) {
    return { targetType: "organization", targetId: params.id || null };
  }
  if (path.includes("/certificates/")) {
    return { targetType: "certificate", targetId: params.id || null };
  }
  if (path.includes("/admins/")) {
    return { targetType: "admin", targetId: params.id || null };
  }
  return { targetType: null, targetId: null };
}

function pickAction(req) {
  const p = req.path || "";
  if (p.includes("/openvpn/service")) return "openvpn-service-action";
  if (p.includes("/openvpn-settings")) return "openvpn-settings-update";
  if (p.includes("/disconnect")) return "vpn-client-disconnect";
  return `${req.method.toLowerCase()} ${p}`;
}

function clientIp(req) {
  const xff = req.headers["x-forwarded-for"];
  if (typeof xff === "string" && xff) return xff.split(",")[0].trim();
  if (Array.isArray(xff) && xff.length > 0) return String(xff[0]).trim();
  return req.ip || req.socket?.remoteAddress || "";
}

export function auditAdminActions(req, res, next) {
  if (!["POST", "PUT", "PATCH", "DELETE"].includes(req.method)) return next();
  if (!req.user?.sub) return next();

  const startedAt = new Date();
  const action = pickAction(req);
  const body = sanitizeValue(req.body);

  res.on("finish", async () => {
    try {
      const { targetType, targetId } = deriveTarget(req.path, req.params);
      await prisma.adminActionLog.create({
        data: {
          adminId: String(req.user.sub),
          adminUsername: String(req.user.username || ""),
          method: req.method,
          path: req.originalUrl || req.path,
          action,
          targetType,
          targetId,
          ipAddress: clientIp(req),
          userAgent: req.headers["user-agent"] ? String(req.headers["user-agent"]) : null,
          statusCode: Number(res.statusCode || 0),
          details: body || null,
          createdAt: startedAt,
        },
      });
    } catch (error) {
      console.error("Failed to write admin action log:", error.message);
    }
  });

  next();
}
