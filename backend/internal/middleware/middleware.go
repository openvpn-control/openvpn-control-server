package middleware

import (
	"net/http"
	"strings"

	"github.com/openvpn-control/openvpn-control-server/backend/internal/auth"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/config"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/httpx"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/limiter"
)

func Stack(cfg config.Config, _ *limiter.Login) func(http.Handler) http.Handler {
	corsSet := map[string]struct{}{}
	for _, o := range cfg.CORSOrigins {
		corsSet[o] = struct{}{}
	}
	csrfSet := map[string]struct{}{}
	for _, o := range cfg.CSRFTrustedOrigins {
		csrfSet[o] = struct{}{}
	}
	hostSet := map[string]struct{}{}
	for _, h := range cfg.AllowedHosts {
		hostSet[h] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if cfg.CORSProtectionEnabled && origin != "" {
				if _, ok := corsSet[origin]; !ok {
					httpx.WriteError(w, http.StatusForbidden, "CORS: origin is not allowed")
					return
				}
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
			}
			if r.Method == http.MethodOptions {
				if cfg.CORSProtectionEnabled && origin != "" {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
					w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Origin")
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}

			if r.URL.Path != "/health" && len(hostSet) > 0 {
				host := strings.ToLower(r.Header.Get("X-Forwarded-Host"))
				if host == "" {
					host = strings.ToLower(r.Host)
				}
				if i := strings.Index(host, ","); i >= 0 {
					host = strings.TrimSpace(host[:i])
				}
				if host != "" {
					if _, ok := hostSet[host]; !ok {
						httpx.WriteError(w, http.StatusForbidden, "Host is not allowed")
						return
					}
				}
			}

			if cfg.CORSProtectionEnabled && cfg.CSRFProtectionEnabled && origin != "" {
				switch r.Method {
				case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
					if _, ok := csrfSet[origin]; !ok {
						httpx.WriteError(w, http.StatusForbidden, "CSRF protection: origin is not allowed")
						return
					}
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

func RequireAuth(cfg config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := r.Header.Get("Authorization")
			if !strings.HasPrefix(h, "Bearer ") {
				httpx.WriteError(w, http.StatusUnauthorized, "Unauthorized")
				return
			}
			claims, err := auth.ParseToken(cfg.JWTSecret, strings.TrimPrefix(h, "Bearer "))
			if err != nil || claims.Purpose == "mfa_pending" {
				httpx.WriteError(w, http.StatusUnauthorized, "Invalid token")
				return
			}
			next.ServeHTTP(w, r.WithContext(auth.WithUser(r.Context(), claims)))
		})
	}
}

func User(r *http.Request) *auth.Claims {
	return auth.UserFromRequest(r)
}
