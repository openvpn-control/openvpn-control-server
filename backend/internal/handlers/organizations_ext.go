package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/openvpn-control/openvpn-control-server/backend/internal/firewall"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/httpx"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/paneltasks"
)

func (h *Organizations) Mount(r chi.Router) {
	r.Get("/", h.List)
	r.Post("/", h.Create)
	r.Patch("/{id}", h.Patch)
	r.Get("/{id}/firewall", h.GetFirewall)
	r.Post("/{id}/firewall", h.SaveFirewall)
	r.Post("/{id}/firewall-check", h.CheckFirewall)
}

func optTrim(v any) *string {
	if v == nil {
		return nil
	}
	s := strings.TrimSpace(strAny(v))
	if s == "" {
		return nil
	}
	return &s
}

func (h *Organizations) Create(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := httpx.DecodeJSONLoose(r, &body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}
	name := strings.TrimSpace(strAny(body["name"]))
	if name == "" {
		httpx.WriteError(w, http.StatusBadRequest, "Название организации обязательно")
		return
	}
	id := newID()
	var row json.RawMessage
	err := h.Pool.QueryRow(r.Context(), `
		INSERT INTO "Organization" (id, name, inn, "legalAddress", "generalDirector", phone, email, "createdAt", "updatedAt")
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
		RETURNING row_to_json("Organization")::text`,
		id, name, optTrim(body["inn"]), optTrim(body["legalAddress"]),
		optTrim(body["generalDirector"]), optTrim(body["phone"]), optTrim(body["email"]),
	).Scan(&row)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write(row)
}

func (h *Organizations) Patch(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var body map[string]any
	if err := httpx.DecodeJSONLoose(r, &body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}
	name := strings.TrimSpace(strAny(body["name"]))
	if name == "" {
		httpx.WriteError(w, http.StatusBadRequest, "Название организации обязательно")
		return
	}
	var row json.RawMessage
	err := h.Pool.QueryRow(r.Context(), `
		UPDATE "Organization" SET name = $2, inn = $3, "legalAddress" = $4, "generalDirector" = $5,
			phone = $6, email = $7, "updatedAt" = NOW()
		WHERE id = $1
		RETURNING row_to_json("Organization")::text`,
		id, name, optTrim(body["inn"]), optTrim(body["legalAddress"]),
		optTrim(body["generalDirector"]), optTrim(body["phone"]), optTrim(body["email"]),
	).Scan(&row)
	if err != nil {
		if err == pgx.ErrNoRows {
			httpx.WriteError(w, http.StatusNotFound, "Организация не найдена")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(row)
}

func (h *Organizations) GetFirewall(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var raw []byte
	err := h.Pool.QueryRow(r.Context(), `SELECT "firewallRules" FROM "Organization" WHERE id = $1`, id).Scan(&raw)
	if err != nil {
		if err == pgx.ErrNoRows {
			httpx.WriteError(w, http.StatusNotFound, "Организация не найдена")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	parsed := firewall.ParseStored(raw)
	httpx.WriteJSON(w, http.StatusOK, parsed)
}

func (h *Organizations) SaveFirewall(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var body map[string]any
	if err := httpx.DecodeJSONLoose(r, &body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}
	stored, err := firewall.SerializeForDB(strAny(body["mode"]), body["rules"], body["natRules"])
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var exists bool
	if err := h.Pool.QueryRow(r.Context(), `SELECT true FROM "Organization" WHERE id = $1`, id).Scan(&exists); err != nil || !exists {
		httpx.WriteError(w, http.StatusNotFound, "Организация не найдена")
		return
	}
	_, err = h.Pool.Exec(r.Context(), `UPDATE "Organization" SET "firewallRules" = $2, "updatedAt" = NOW() WHERE id = $1`, id, stored)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = paneltasks.EnqueueSnapshotForOrgNodes(r.Context(), h.Pool, id)
	parsed := firewall.ParseStored(stored)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok": true, "message": "Firewall-правила организации сохранены.",
		"mode": parsed.Mode, "rules": parsed.Rules, "natRules": parsed.NatRules,
	})
}

func (h *Organizations) CheckFirewall(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var body map[string]any
	if err := httpx.DecodeJSONLoose(r, &body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}
	var exists bool
	if err := h.Pool.QueryRow(r.Context(), `SELECT true FROM "Organization" WHERE id = $1`, id).Scan(&exists); err != nil || !exists {
		httpx.WriteError(w, http.StatusNotFound, "Организация не найдена")
		return
	}
	stored, _ := firewall.SerializeForDB(strAny(body["mode"]), body["rules"], body["natRules"])
	parsed := firewall.ParseStored(stored)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok": true, "message": "Конфиг организации валиден.",
		"mode": parsed.Mode, "rules": parsed.Rules, "natRules": parsed.NatRules,
	})
}
