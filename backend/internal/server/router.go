package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/openvpn-control/openvpn-control-server/backend/internal/audit"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/auth"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/config"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/handlers"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/httpx"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/limiter"
	mw "github.com/openvpn-control/openvpn-control-server/backend/internal/middleware"
)

func NewRouter(cfg config.Config, pool *pgxpool.Pool) http.Handler {
	loginLim := limiter.NewLogin(cfg.LoginMaxAttempts, cfg.LoginLockout)
	authH := &auth.Handler{Cfg: cfg, Pool: pool, Limiter: loginLim}
	agentsH := &handlers.Agents{Cfg: cfg, Pool: pool}
	monH := &handlers.Monitoring{Cfg: cfg, Pool: pool}
	clientsH := &handlers.Clients{Cfg: cfg, Pool: pool}
	orgsH := &handlers.Organizations{Pool: pool}
	tasksH := &handlers.Tasks{Pool: pool}
	adminsH := &handlers.Admins{Cfg: cfg, Pool: pool}
	adminPublicH := &handlers.AdminPublic{Pool: pool}
	panelBackupsH := &handlers.PanelBackups{Cfg: cfg, Pool: pool}
	vpnUsersH := &handlers.VpnUsers{Cfg: cfg, Pool: pool}
	certH := &handlers.Certificates{Pool: pool}
	panelNodesH := &handlers.PanelNodes{Pool: pool}

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(mw.Stack(cfg, loginLim))

	r.Get("/health", handlers.Health)
	r.Get("/", handlers.Root(cfg))

	r.Route("/api", func(api chi.Router) {
		api.Route("/auth", func(ar chi.Router) {
			ar.Post("/login", authH.Login)
			ar.Post("/login/mfa", authH.LoginMFA)
			ar.With(mw.RequireAuth(cfg)).Post("/refresh", authH.Refresh)
		})

		api.Route("/admin-invite", adminPublicH.MountInvite)
		api.Route("/admin-password-reset", adminPublicH.MountPasswordReset)

		api.Group(func(pr chi.Router) {
			pr.Use(mw.RequireAuth(cfg))
			pr.Use(audit.Middleware(pool))
			agentsH.Mount(pr)
			pr.Route("/monitoring", monH.Mount)
			pr.Route("/clients", clientsH.Mount)
			pr.Route("/organizations", orgsH.Mount)
			pr.Route("/tasks", tasksH.Mount)
			pr.Route("/admins", adminsH.Mount)
			pr.Route("/panel/app-backups", panelBackupsH.Mount)
			pr.Route("/vpn-users", vpnUsersH.Mount)
			pr.Route("/certificates", certH.Mount)
			panelNodesH.Mount(pr)
		})

		api.NotFound(func(w http.ResponseWriter, _ *http.Request) {
			httpx.WriteError(w, http.StatusNotFound, "not found")
		})
	})

	return r
}
