package handlers

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/openvpn-control/openvpn-control-server/backend/internal/config"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/httpx"
	mw "github.com/openvpn-control/openvpn-control-server/backend/internal/middleware"
)

type Admins struct {
	Cfg  config.Config
	Pool *pgxpool.Pool
}

func (h *Admins) Mount(r chi.Router) {
	r.Get("/me", h.Me)
	r.Post("/me/change-password", h.ChangePassword)
	h.mountExt(r)
}

func (h *Admins) Me(w http.ResponseWriter, r *http.Request) {
	u := mw.User(r)
	if u == nil {
		httpx.WriteError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	var raw []byte
	err := h.Pool.QueryRow(r.Context(), `
		SELECT row_to_json(x)::text FROM (
			SELECT a.id, a."fullName", a.username, a.email, a."isActive", a."totpEnabled",
				a."createdAt", a."updatedAt",
				(SELECT COUNT(*)::int FROM "AdminTotpRecoveryCode" rc
				 WHERE rc."adminId" = a.id AND rc."usedAt" IS NULL) AS "totpRecoveryCodesRemaining"
			FROM "Admin" a WHERE a.id = $1 AND a."isActive" = true
		) x`, u.Sub).Scan(&raw)
	if err != nil {
		if err == pgx.ErrNoRows {
			httpx.WriteError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeRawJSON(w, raw)
}

func (h *Admins) ChangePassword(w http.ResponseWriter, r *http.Request) {
	u := mw.User(r)
	if u == nil {
		httpx.WriteError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	var body struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}
	if err := httpx.DecodeJSON(r, &body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}
	current := strings.TrimSpace(body.CurrentPassword)
	next := body.NewPassword
	if current == "" || next == "" {
		httpx.WriteError(w, http.StatusBadRequest, "Текущий и новый пароль обязательны")
		return
	}
	if len(next) < 10 {
		httpx.WriteError(w, http.StatusBadRequest, "Новый пароль должен быть не короче 10 символов")
		return
	}
	var hash string
	var active bool
	err := h.Pool.QueryRow(r.Context(), `SELECT "passwordHash", "isActive" FROM "Admin" WHERE id = $1`, u.Sub).Scan(&hash, &active)
	if err != nil || !active {
		httpx.WriteError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(current)) != nil {
		httpx.WriteError(w, http.StatusBadRequest, "Текущий пароль указан неверно")
		return
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(next), bcrypt.DefaultCost)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "hash error")
		return
	}
	_, err = h.Pool.Exec(r.Context(), `
		UPDATE "Admin" SET "passwordHash" = $2, "passwordResetToken" = NULL, "passwordResetExpiresAt" = NULL, "updatedAt" = NOW()
		WHERE id = $1`, u.Sub, string(newHash))
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
