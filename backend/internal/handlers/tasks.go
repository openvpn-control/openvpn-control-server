package handlers

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/openvpn-control/openvpn-control-server/backend/internal/httpx"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/paneltasks"
)

type Tasks struct {
	Pool *pgxpool.Pool
}

func (h *Tasks) Mount(r chi.Router) {
	r.Get("/", h.List)
	r.Post("/{id}/retry", h.Retry)
}

func (h *Tasks) List(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	raw, err := paneltasks.List(r.Context(), h.Pool, limit)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeRawJSON(w, raw)
}

func (h *Tasks) Retry(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	raw, errMsg, notFound, err := paneltasks.Retry(r.Context(), h.Pool, id)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if notFound {
		httpx.WriteError(w, http.StatusNotFound, "Задача не найдена")
		return
	}
	if errMsg != "" {
		httpx.WriteError(w, http.StatusConflict, errMsg)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}
