package handlers

import (
	"net/http"

	"github.com/openvpn-control/openvpn-control-server/backend/internal/config"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/httpx"
)

func Health(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func Root(cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if acceptHTML(r) {
			panel := cfg.PanelURL
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<!doctype html><html lang="ru"><body><h1>API backend (Go)</h1><p>Панель: <a href="` + panel + `">` + panel + `</a></p></body></html>`))
			return
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"service":   "openvpn-control-api",
			"runtime":   "go",
			"panelUrl":  cfg.PanelURL,
			"health":    "/health",
			"apiPrefix": "/api",
		})
	}
}

func acceptHTML(r *http.Request) bool {
	return contains(r.Header.Get("Accept"), "text/html")
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || indexSub(s, sub))
}

func indexSub(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
