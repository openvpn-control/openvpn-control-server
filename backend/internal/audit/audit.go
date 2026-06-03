package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/segmentio/ksuid"

	"github.com/openvpn-control/openvpn-control-server/backend/internal/auth"
)

var hiddenKeys = map[string]struct{}{
	"password": {}, "passwordHash": {}, "authToken": {}, "keyPem": {}, "certPem": {}, "token": {},
}

type responseRecorder struct {
	http.ResponseWriter
	status int
}

func (r *responseRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Middleware logs mutating admin API calls to AdminActionLog (Node auditAdminActions).
func Middleware(pool *pgxpool.Pool) func(http.Handler) http.Handler {
	disabled := os.Getenv("AUDIT_ADMIN_ACTIONS_DISABLED") == "1"
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if disabled {
				next.ServeHTTP(w, r)
				return
			}
			switch r.Method {
			case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
			default:
				next.ServeHTTP(w, r)
				return
			}
			claims := auth.UserFromRequest(r)
			if claims == nil || claims.Sub == "" {
				next.ServeHTTP(w, r)
				return
			}

			startedAt := time.Now()
			var bodyCopy []byte
			if r.Body != nil && r.ContentLength != 0 {
				bodyCopy, _ = io.ReadAll(r.Body)
				r.Body = io.NopCloser(bytes.NewReader(bodyCopy))
			}
			details := sanitizeJSON(bodyCopy)

			rec := &responseRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)

			path := r.URL.Path
			if q := r.URL.RawQuery; q != "" {
				path = path + "?" + q
			}
			targetType, targetID := deriveTarget(r)
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				detailsJSON, _ := json.Marshal(details)
				var detailsArg any
				if len(detailsJSON) > 2 {
					detailsArg = detailsJSON
				}
				_, _ = pool.Exec(ctx, `
					INSERT INTO "AdminActionLog" (
						id, "adminId", "adminUsername", method, path, action,
						"targetType", "targetId", "ipAddress", "userAgent", "statusCode", details, "createdAt"
					) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
					ksuid.New().String(),
					claims.Sub,
					claims.Username,
					r.Method,
					path,
					pickAction(r),
					targetType,
					targetID,
					clientIP(r),
					strings.TrimSpace(r.UserAgent()),
					rec.status,
					detailsArg,
					startedAt,
				)
			}()
		})
	}
}

func pickAction(r *http.Request) string {
	p := r.URL.Path
	if strings.Contains(p, "/openvpn/service") {
		return "openvpn-service-action"
	}
	if strings.Contains(p, "/openvpn-settings") {
		return "openvpn-settings-update"
	}
	if strings.Contains(p, "/disconnect") {
		return "vpn-client-disconnect"
	}
	return strings.ToLower(r.Method) + " " + p
}

func deriveTarget(r *http.Request) (*string, *string) {
	p := r.URL.Path
	id := chi.URLParam(r, "id")
	if id == "" {
		id = chi.URLParam(r, "nodeId")
	}
	var tt, tid string
	switch {
	case strings.Contains(p, "/agent/nodes/"), strings.Contains(p, "/panel/nodes/"):
		tt, tid = "agent-node", id
	case strings.Contains(p, "/vpn-users/"):
		tt, tid = "vpn-user", id
	case strings.Contains(p, "/organizations/"):
		tt, tid = "organization", id
	case strings.Contains(p, "/certificates/"):
		tt, tid = "certificate", id
	case strings.Contains(p, "/admins/"):
		tt, tid = "admin", id
	default:
		return nil, nil
	}
	if tid == "" {
		return &tt, nil
	}
	return &tt, &tid
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host, _, _ := strings.Cut(r.RemoteAddr, ":")
	return host
}

func sanitizeJSON(raw []byte) any {
	if len(raw) == 0 {
		return nil
	}
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return nil
	}
	return sanitizeValue(v)
}

func sanitizeValue(v any) any {
	switch t := v.(type) {
	case nil:
		return nil
	case []any:
		if len(t) > 20 {
			t = t[:20]
		}
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = sanitizeValue(x)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if _, hide := hiddenKeys[k]; hide {
				out[k] = "[redacted]"
			} else {
				out[k] = sanitizeValue(val)
			}
		}
		return out
	case string:
		if len(t) > 400 {
			return t[:400] + "…"
		}
		return t
	default:
		return t
	}
}
