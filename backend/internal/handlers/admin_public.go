package handlers

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/openvpn-control/openvpn-control-server/backend/internal/httpx"
)

type AdminPublic struct {
	Pool *pgxpool.Pool
}

func (h *AdminPublic) MountInvite(r chi.Router) {
	r.Get("/", h.InviteGet)
	r.Post("/complete", h.InviteComplete)
}

func (h *AdminPublic) MountPasswordReset(r chi.Router) {
	r.Get("/", h.PasswordResetGet)
	r.Post("/complete", h.PasswordResetComplete)
}

func findAdminByInviteToken(ctx context.Context, pool *pgxpool.Pool, token string) (id, fullName, username string, email *string, inviteExpiresAt *time.Time, inviteToken *string, err error) {
	t := strings.TrimSpace(token)
	if len(t) < 16 {
		return "", "", "", nil, nil, nil, pgx.ErrNoRows
	}
	err = pool.QueryRow(ctx, `
		SELECT id, COALESCE("fullName", ''), username, email, "inviteExpiresAt", "inviteToken"
		FROM "Admin" WHERE "inviteToken" = $1 LIMIT 1`, t).
		Scan(&id, &fullName, &username, &email, &inviteExpiresAt, &inviteToken)
	return
}

func findAdminByPasswordResetToken(ctx context.Context, pool *pgxpool.Pool, token string) (id, fullName, username string, email *string, expiresAt *time.Time, resetToken *string, err error) {
	t := strings.TrimSpace(token)
	if len(t) < 16 {
		return "", "", "", nil, nil, nil, pgx.ErrNoRows
	}
	err = pool.QueryRow(ctx, `
		SELECT id, COALESCE("fullName", ''), username, email, "passwordResetExpiresAt", "passwordResetToken"
		FROM "Admin" WHERE "passwordResetToken" = $1 LIMIT 1`, t).
		Scan(&id, &fullName, &username, &email, &expiresAt, &resetToken)
	return
}

func tokenExpired(exp *time.Time) bool {
	if exp == nil {
		return false
	}
	return time.Now().After(*exp)
}

func (h *AdminPublic) InviteGet(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	id, fullName, username, email, exp, invTok, err := findAdminByInviteToken(r.Context(), h.Pool, token)
	if err != nil || id == "" || invTok == nil || *invTok == "" {
		httpx.WriteError(w, http.StatusNotFound, "Приглашение не найдено или уже использовано")
		return
	}
	if tokenExpired(exp) {
		httpx.WriteError(w, http.StatusGone, "Срок действия приглашения истёк")
		return
	}
	emailStr := ""
	if email != nil {
		emailStr = *email
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{
		"fullName": fullName,
		"username": username,
		"email":    emailStr,
	})
}

func (h *AdminPublic) InviteComplete(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := httpx.DecodeJSONLoose(r, &body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}
	token := strings.TrimSpace(body.Token)
	password := body.Password
	if token == "" || len(password) < 8 {
		httpx.WriteError(w, http.StatusBadRequest, "Укажите токен и пароль не короче 8 символов")
		return
	}
	id, _, _, _, exp, invTok, err := findAdminByInviteToken(r.Context(), h.Pool, token)
	if err != nil || id == "" || invTok == nil || *invTok == "" {
		httpx.WriteError(w, http.StatusNotFound, "Приглашение не найдено или уже использовано")
		return
	}
	if tokenExpired(exp) {
		httpx.WriteError(w, http.StatusGone, "Срок действия приглашения истёк")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "hash error")
		return
	}
	if _, err := h.Pool.Exec(r.Context(), `
		UPDATE "Admin" SET "passwordHash" = $2, "inviteToken" = NULL, "inviteExpiresAt" = NULL, "updatedAt" = NOW()
		WHERE id = $1`, id, string(hash)); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *AdminPublic) PasswordResetGet(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	id, fullName, username, email, exp, resetTok, err := findAdminByPasswordResetToken(r.Context(), h.Pool, token)
	if err != nil || id == "" || resetTok == nil || *resetTok == "" {
		httpx.WriteError(w, http.StatusNotFound, "Ссылка сброса пароля недействительна или уже использована")
		return
	}
	if tokenExpired(exp) {
		httpx.WriteError(w, http.StatusGone, "Срок действия ссылки истёк. Запросите новую у администратора панели.")
		return
	}
	emailStr := ""
	if email != nil {
		emailStr = *email
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{
		"fullName": fullName,
		"username": username,
		"email":    emailStr,
	})
}

func (h *AdminPublic) PasswordResetComplete(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := httpx.DecodeJSONLoose(r, &body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}
	token := strings.TrimSpace(body.Token)
	password := body.Password
	if token == "" || len(password) < 8 {
		httpx.WriteError(w, http.StatusBadRequest, "Укажите токен и пароль не короче 8 символов")
		return
	}
	id, _, _, _, exp, resetTok, err := findAdminByPasswordResetToken(r.Context(), h.Pool, token)
	if err != nil || id == "" || resetTok == nil || *resetTok == "" {
		httpx.WriteError(w, http.StatusNotFound, "Ссылка сброса пароля недействительна или уже использована")
		return
	}
	if tokenExpired(exp) {
		httpx.WriteError(w, http.StatusGone, "Срок действия ссылки истёк")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "hash error")
		return
	}
	if _, err := h.Pool.Exec(r.Context(), `
		UPDATE "Admin" SET "passwordHash" = $2, "passwordResetToken" = NULL, "passwordResetExpiresAt" = NULL,
			"inviteToken" = NULL, "inviteExpiresAt" = NULL, "updatedAt" = NOW()
		WHERE id = $1`, id, string(hash)); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
