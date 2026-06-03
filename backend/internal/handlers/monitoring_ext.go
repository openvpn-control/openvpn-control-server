package handlers

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/openvpn-control/openvpn-control-server/backend/internal/httpx"
)

func (h *Monitoring) Mount(r chi.Router) {
	r.Get("/overview", h.Overview)
	r.Get("/admin-actions", h.AdminActions)
}

func (h *Monitoring) AdminActions(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			if n < 1 {
				n = 1
			}
			if n > 1000 {
				n = 1000
			}
			limit = n
		}
	}
	nodeID := r.URL.Query().Get("nodeId")
	var raw []byte
	var err error
	if nodeID != "" {
		err = h.Pool.QueryRow(r.Context(), `
			SELECT COALESCE(json_agg(row_to_json(x)), '[]'::json)::text FROM (
				SELECT l.*, json_build_object('id', a.id, 'username', a.username) AS admin
				FROM "AdminActionLog" l
				LEFT JOIN "Admin" a ON a.id = l."adminId"
				WHERE l."targetType" = 'agent-node' AND l."targetId" = $1
				ORDER BY l."createdAt" DESC LIMIT $2
			) x`, nodeID, limit).Scan(&raw)
	} else {
		err = h.Pool.QueryRow(r.Context(), `
			SELECT COALESCE(json_agg(row_to_json(x)), '[]'::json)::text FROM (
				SELECT l.*, json_build_object('id', a.id, 'username', a.username) AS admin
				FROM "AdminActionLog" l
				LEFT JOIN "Admin" a ON a.id = l."adminId"
				ORDER BY l."createdAt" DESC LIMIT $1
			) x`, limit).Scan(&raw)
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeRawJSON(w, raw)
}
