import cors from "cors";
import express from "express";
import morgan from "morgan";
import { auditAdminActions } from "./audit.js";
import { config } from "./config.js";
import { requireAuth } from "./middleware.js";
import adminsRoutes from "./modules/admins/routes.js";
import adminInvitePublicRoutes from "./modules/admins/invitePublicRoutes.js";
import adminPasswordResetPublicRoutes from "./modules/admins/passwordResetPublicRoutes.js";
import agentsRoutes from "./modules/agents/routes.js";
import authRoutes from "./modules/auth/routes.js";
import certificatesRoutes from "./modules/certificates/routes.js";
import clientsRoutes from "./modules/clients/routes.js";
import monitoringRoutes from "./modules/monitoring/routes.js";
import openvpnPanelRoutes from "./modules/openvpn-panel/routes.js";
import organizationsRoutes from "./modules/organizations/routes.js";
import panelAppBackupsRoutes from "./modules/panel-app-backups/routes.js";
import tasksRoutes from "./modules/tasks/routes.js";
import vpnUsersRoutes from "./modules/vpn-users/routes.js";

export function createApp() {
  const app = express();
  const allowedOrigins = new Set(config.corsOrigins);
  const csrfTrustedOrigins = new Set(config.csrfTrustedOrigins);
  const allowedHosts = new Set(config.allowedHosts);
  app.use(
    cors({
      origin(origin, callback) {
        // Requests without Origin (curl/health checks) are allowed.
        if (!origin) return callback(null, true);
        if (allowedOrigins.has(origin)) return callback(null, true);
        return callback(new Error("CORS: origin is not allowed"));
      },
    }),
  );
  app.use((req, res, next) => {
    if (req.path === "/health") return next();

    const hostHeader = String(req.headers["x-forwarded-host"] || req.headers.host || "").split(",")[0].trim().toLowerCase();
    if (hostHeader && allowedHosts.size > 0 && !allowedHosts.has(hostHeader)) {
      return res.status(403).json({ error: "Host is not allowed" });
    }

    if (!config.csrfProtectionEnabled) return next();
    if (!["POST", "PUT", "PATCH", "DELETE"].includes(req.method)) return next();

    const origin = req.headers.origin;
    if (!origin) return next();
    if (csrfTrustedOrigins.has(origin)) return next();

    return res.status(403).json({ error: "CSRF protection: origin is not allowed" });
  });
  app.use(express.json({ limit: config.bodyJsonLimit }));
  app.use(morgan("dev"));

  app.get("/health", (_req, res) => {
    res.json({ status: "ok" });
  });

  app.get("/", (_req, res) => {
    const panel = config.panelUrl;
    const accept = String(_req.headers.accept || "");
    if (accept.includes("text/html")) {
      res.status(200).type("html").send(
        `<!doctype html><html lang="ru"><head><meta charset="utf-8"><title>OpenVPN Control API</title></head>` +
          `<body style="font-family:system-ui,sans-serif;max-width:40em;margin:2rem auto;line-height:1.5">` +
          `<h1>Это API backend</h1><p>Веб-панель открывайте по адресу: <a href="${panel}">${panel}</a></p>` +
          `<p>Проверка API: <a href="/health">/health</a></p></body></html>`,
      );
      return;
    }
    res.status(200).json({
      service: "openvpn-control-api",
      message: "Web panel is not served on this port. Open the panel URL in a browser.",
      panelUrl: panel,
      health: "/health",
      apiPrefix: "/api",
    });
  });

  app.use("/api/auth", authRoutes);
  app.use("/api/admin-invite", adminInvitePublicRoutes);
  app.use("/api/admin-password-reset", adminPasswordResetPublicRoutes);
  app.use("/api/agent", requireAuth, auditAdminActions, agentsRoutes);
  app.use("/api/panel/nodes", requireAuth, auditAdminActions, openvpnPanelRoutes);
  app.use("/api/tasks", requireAuth, auditAdminActions, tasksRoutes);
  app.use("/api/admins", requireAuth, auditAdminActions, adminsRoutes);
  app.use("/api/monitoring", requireAuth, auditAdminActions, monitoringRoutes);
  app.use("/api/certificates", requireAuth, auditAdminActions, certificatesRoutes);
  app.use("/api/clients", requireAuth, auditAdminActions, clientsRoutes);
  app.use("/api/organizations", requireAuth, auditAdminActions, organizationsRoutes);
  app.use("/api/vpn-users", requireAuth, auditAdminActions, vpnUsersRoutes);
  app.use("/api/panel/app-backups", requireAuth, auditAdminActions, panelAppBackupsRoutes);

  return app;
}
