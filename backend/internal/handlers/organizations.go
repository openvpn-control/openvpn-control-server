package handlers

import (
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/openvpn-control/openvpn-control-server/backend/internal/httpx"
)

type Organizations struct {
	Pool *pgxpool.Pool
}

func (h *Organizations) List(w http.ResponseWriter, r *http.Request) {
	var raw []byte
	err := h.Pool.QueryRow(r.Context(), `
		SELECT COALESCE(json_agg(row_to_json(o)), '[]'::json)::text FROM (
			SELECT * FROM "Organization" ORDER BY name
		) o`).Scan(&raw)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

