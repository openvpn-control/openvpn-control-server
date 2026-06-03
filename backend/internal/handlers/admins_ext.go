package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/openvpn-control/openvpn-control-server/backend/internal/auth"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/httpx"
	mw "github.com/openvpn-control/openvpn-control-server/backend/internal/middleware"
)

const (
	inviteTTL         = 7 * 24 * time.Hour
	passwordResetTTL  = 24 * time.Hour
	totpPendingTTL    = 10 * time.Minute
)

var emailRx = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)

func (h *Admins) mountExt(r chi.Router) {
	r.Get("/", h.List)
	r.Post("/", h.Create)
	r.Post("/{id}/password-reset-link", h.PasswordResetLink)
	r.Patch("/{id}", h.Patch)
	r.Post("/me/totp/setup/start", h.TotpSetupStart)
	r.Post("/me/totp/setup/confirm", h.TotpSetupConfirm)
	r.Post("/me/totp/recovery-codes/regenerate", h.TotpRecoveryRegenerate)
	r.Post("/me/totp/disable", h.TotpDisable)
}

func normalizeAdminEmail(email string) string {
	s := strings.ToLower(strings.TrimSpace(email))
	if s == "" {
		return ""
	}
	return s
}

func newAdminToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func normalizeTotpCode(v string) string {
	return strings.ReplaceAll(strings.TrimSpace(v), " ", "")
}

func (h *Admins) List(w http.ResponseWriter, r *http.Request) {
	rows, err := h.Pool.Query(r.Context(), `
		SELECT a.id, a."fullName", a.username, a.email, a."isActive",
			(a."inviteToken" IS NOT NULL) AS "invitePending",
			a."createdAt", a."updatedAt"
		FROM "Admin" a
		ORDER BY a."createdAt" DESC`)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, fullName, username string
		var email *string
		var isActive, invitePending bool
		var createdAt, updatedAt time.Time
		if err := rows.Scan(&id, &fullName, &username, &email, &isActive, &invitePending, &createdAt, &updatedAt); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		item := map[string]any{
			"id":            id,
			"fullName":      fullName,
			"username":      username,
			"isActive":      isActive,
			"invitePending": invitePending,
			"createdAt":     createdAt,
			"updatedAt":     updatedAt,
		}
		if email != nil {
			item["email"] = *email
		} else {
			item["email"] = nil
		}
		out = append(out, item)
	}
	if out == nil {
		out = []map[string]any{}
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (h *Admins) Create(w http.ResponseWriter, r *http.Request) {
	var body struct {
		FullName string `json:"fullName"`
		Username string `json:"username"`
		Email    string `json:"email"`
	}
	if err := httpx.DecodeJSONLoose(r, &body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}
	fullName := strings.TrimSpace(body.FullName)
	username := strings.TrimSpace(body.Username)
	emailRaw := normalizeAdminEmail(body.Email)
	if fullName == "" {
		httpx.WriteError(w, http.StatusBadRequest, "ФИО обязательно")
		return
	}
	if username == "" {
		httpx.WriteError(w, http.StatusBadRequest, "Аккаунт (логин) обязателен")
		return
	}
	if emailRaw == "" {
		httpx.WriteError(w, http.StatusBadRequest, "Электронная почта обязательна")
		return
	}
	if !emailRx.MatchString(emailRaw) {
		httpx.WriteError(w, http.StatusBadRequest, "Некорректный адрес электронной почты")
		return
	}
	var exists string
	if err := h.Pool.QueryRow(r.Context(), `SELECT id FROM "Admin" WHERE username = $1`, username).Scan(&exists); err == nil {
		httpx.WriteError(w, http.StatusConflict, "Администратор с таким аккаунтом уже есть")
		return
	} else if err != pgx.ErrNoRows {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := h.Pool.QueryRow(r.Context(), `SELECT id FROM "Admin" WHERE email = $1`, emailRaw).Scan(&exists); err == nil {
		httpx.WriteError(w, http.StatusConflict, "Администратор с такой почтой уже есть")
		return
	} else if err != pgx.ErrNoRows {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	inviteToken, err := newAdminToken()
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "token error")
		return
	}
	placeholder := make([]byte, 48)
	if _, err := rand.Read(placeholder); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "random error")
		return
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(hex.EncodeToString(placeholder)), bcrypt.DefaultCost)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "hash error")
		return
	}
	id := newID()
	inviteExpiresAt := time.Now().Add(inviteTTL)
	var raw []byte
	err = h.Pool.QueryRow(r.Context(), `
		INSERT INTO "Admin" (id, "fullName", username, email, "passwordHash", "inviteToken", "inviteExpiresAt", "createdAt", "updatedAt")
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
		RETURNING row_to_json(x)::text FROM (
			SELECT id, "fullName", username, email, "isActive", "createdAt", "updatedAt" FROM "Admin" WHERE id = $1
		) x`, id, fullName, username, emailRaw, string(passwordHash), inviteToken, inviteExpiresAt).Scan(&raw)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var admin map[string]any
	_ = json.Unmarshal(raw, &admin)
	admin["invitePending"] = true
	admin["invitePath"] = "/invite-admin?token=" + url.QueryEscape(inviteToken)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(admin)
}

func (h *Admins) PasswordResetLink(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var inviteToken *string
	err := h.Pool.QueryRow(r.Context(), `SELECT "inviteToken" FROM "Admin" WHERE id = $1`, id).Scan(&inviteToken)
	if err == pgx.ErrNoRows {
		httpx.WriteError(w, http.StatusNotFound, "Администратор не найден")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if inviteToken != nil && *inviteToken != "" {
		httpx.WriteError(w, http.StatusBadRequest, "Для этой учётной записи ещё не завершена регистрация по приглашению.")
		return
	}
	token, err := newAdminToken()
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "token error")
		return
	}
	expiresAt := time.Now().Add(passwordResetTTL)
	if _, err := h.Pool.Exec(r.Context(), `
		UPDATE "Admin" SET "passwordResetToken" = $2, "passwordResetExpiresAt" = $3, "updatedAt" = NOW()
		WHERE id = $1`, id, token, expiresAt); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{
		"resetPath": "/reset-admin-password?token=" + url.QueryEscape(token),
	})
}

func (h *Admins) Patch(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var body map[string]any
	if err := httpx.DecodeJSONLoose(r, &body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}
	sets := []string{}
	args := []any{id}
	argN := 2

	if v, ok := body["isActive"]; ok {
		if b, ok := v.(bool); ok {
			sets = append(sets, `"isActive" = $`+itoa(argN))
			args = append(args, b)
			argN++
		}
	}
	if v, ok := body["password"]; ok {
		pw := strings.TrimSpace(strAny(v))
		if pw != "" {
			hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
			if err != nil {
				httpx.WriteError(w, http.StatusInternalServerError, "hash error")
				return
			}
			sets = append(sets, `"passwordHash" = $`+itoa(argN))
			args = append(args, string(hash))
			argN++
			sets = append(sets, `"inviteToken" = NULL`, `"inviteExpiresAt" = NULL`, `"passwordResetToken" = NULL`, `"passwordResetExpiresAt" = NULL`)
		}
	}
	if v, ok := body["fullName"]; ok {
		fn := strings.TrimSpace(strAny(v))
		if fn == "" {
			httpx.WriteError(w, http.StatusBadRequest, "ФИО обязательно")
			return
		}
		sets = append(sets, `"fullName" = $`+itoa(argN))
		args = append(args, fn)
		argN++
	}
	if v, ok := body["username"]; ok {
		u := strings.TrimSpace(strAny(v))
		if u == "" {
			httpx.WriteError(w, http.StatusBadRequest, "Аккаунт (логин) обязателен")
			return
		}
		var other string
		err := h.Pool.QueryRow(r.Context(), `SELECT id FROM "Admin" WHERE username = $1`, u).Scan(&other)
		if err == nil && other != id {
			httpx.WriteError(w, http.StatusConflict, "Администратор с таким аккаунтом уже есть")
			return
		}
		if err != nil && err != pgx.ErrNoRows {
			httpx.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		sets = append(sets, `username = $`+itoa(argN))
		args = append(args, u)
		argN++
	}
	if v, ok := body["email"]; ok {
		emailRaw := normalizeAdminEmail(strAny(v))
		if emailRaw == "" {
			httpx.WriteError(w, http.StatusBadRequest, "Электронная почта обязательна")
			return
		}
		if !emailRx.MatchString(emailRaw) {
			httpx.WriteError(w, http.StatusBadRequest, "Некорректный адрес электронной почты")
			return
		}
		var other string
		err := h.Pool.QueryRow(r.Context(), `SELECT id FROM "Admin" WHERE email = $1 AND id <> $2`, emailRaw, id).Scan(&other)
		if err == nil {
			httpx.WriteError(w, http.StatusConflict, "Администратор с такой почтой уже есть")
			return
		}
		if err != nil && err != pgx.ErrNoRows {
			httpx.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		sets = append(sets, `email = $`+itoa(argN))
		args = append(args, emailRaw)
		argN++
	}
	if len(sets) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "Нет данных для обновления")
		return
	}
	sets = append(sets, `"updatedAt" = NOW()`)
	q := `UPDATE "Admin" SET ` + strings.Join(sets, ", ") + ` WHERE id = $1
		RETURNING id, "fullName", username, email, "isActive", ("inviteToken" IS NOT NULL) AS "invitePending", "createdAt", "updatedAt"`
	var rowID, fullName, username string
	var email *string
	var isActive, invitePending bool
	var createdAt, updatedAt time.Time
	err := h.Pool.QueryRow(r.Context(), q, args...).Scan(
		&rowID, &fullName, &username, &email, &isActive, &invitePending, &createdAt, &updatedAt)
	if err == pgx.ErrNoRows {
		httpx.WriteError(w, http.StatusNotFound, "Администратор не найден")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp := map[string]any{
		"id": rowID, "fullName": fullName, "username": username, "isActive": isActive,
		"invitePending": invitePending, "createdAt": createdAt, "updatedAt": updatedAt,
	}
	if email != nil {
		resp["email"] = *email
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (h *Admins) requireAdmin(w http.ResponseWriter, r *http.Request) (string, bool) {
	u := mw.User(r)
	if u == nil {
		httpx.WriteError(w, http.StatusUnauthorized, "Unauthorized")
		return "", false
	}
	return u.Sub, true
}

func (h *Admins) TotpSetupStart(w http.ResponseWriter, r *http.Request) {
	adminID, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}
	var username string
	var email *string
	var totpEnabled, isActive bool
	err := h.Pool.QueryRow(r.Context(), `
		SELECT username, email, "totpEnabled", "isActive" FROM "Admin" WHERE id = $1`, adminID).
		Scan(&username, &email, &totpEnabled, &isActive)
	if err != nil || !isActive {
		httpx.WriteError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	account := username
	if email != nil && *email != "" {
		account = *email
	}
	secret, otpauth, err := auth.GenerateTotpKey("OpenVPN Control", account)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	enc, err := auth.EncryptSecret(h.Cfg.JWTSecret, secret)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	expiresAt := time.Now().Add(totpPendingTTL)
	if _, err := h.Pool.Exec(r.Context(), `
		UPDATE "Admin" SET "totpPendingSecretEnc" = $2, "totpPendingExpiresAt" = $3, "updatedAt" = NOW()
		WHERE id = $1`, adminID, enc, expiresAt); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	qrDataURL, err := auth.GenerateTotpQRDataURL(otpauth)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"qrDataUrl":    qrDataURL,
		"manualSecret": secret,
		"expiresAt":    expiresAt,
	})
}

func (h *Admins) TotpSetupConfirm(w http.ResponseWriter, r *http.Request) {
	adminID, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}
	var body struct {
		TotpCode string `json:"totpCode"`
	}
	if err := httpx.DecodeJSONLoose(r, &body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}
	code := normalizeTotpCode(body.TotpCode)
	if code == "" {
		httpx.WriteError(w, http.StatusBadRequest, "Введите код из приложения")
		return
	}
	var pendingEnc *string
	var pendingExp *time.Time
	var isActive bool
	err := h.Pool.QueryRow(r.Context(), `
		SELECT "totpPendingSecretEnc", "totpPendingExpiresAt", "isActive" FROM "Admin" WHERE id = $1`, adminID).
		Scan(&pendingEnc, &pendingExp, &isActive)
	if err != nil || !isActive {
		httpx.WriteError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	if pendingEnc == nil || pendingExp == nil || pendingExp.Before(time.Now()) {
		httpx.WriteError(w, http.StatusBadRequest, "Сессия подключения 2FA истекла. Начните заново.")
		return
	}
	secret, err := auth.DecryptSecret(h.Cfg.JWTSecret, *pendingEnc)
	if err != nil || !auth.VerifyTotp(secret, code) {
		httpx.WriteError(w, http.StatusBadRequest, "Неверный код подтверждения")
		return
	}
	secretEnc, err := auth.EncryptSecret(h.Cfg.JWTSecret, secret)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	tx, err := h.Pool.Begin(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	if _, err := tx.Exec(r.Context(), `
		UPDATE "Admin" SET "totpEnabled" = true, "totpSecretEnc" = $2,
			"totpPendingSecretEnc" = NULL, "totpPendingExpiresAt" = NULL, "updatedAt" = NOW()
		WHERE id = $1`, adminID, secretEnc); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	recoveryCodes, err := auth.ReplaceRecoveryCodesForAdmin(r.Context(), tx, adminID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "recoveryCodes": recoveryCodes})
}

func (h *Admins) TotpRecoveryRegenerate(w http.ResponseWriter, r *http.Request) {
	adminID, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}
	var body struct {
		TotpCode string `json:"totpCode"`
	}
	if err := httpx.DecodeJSONLoose(r, &body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}
	code := normalizeTotpCode(body.TotpCode)
	if code == "" {
		httpx.WriteError(w, http.StatusBadRequest, "Введите код из приложения-аутентификатора")
		return
	}
	if !h.verifyAdminTotp(r, adminID, code, w) {
		return
	}
	tx, err := h.Pool.Begin(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	recoveryCodes, err := auth.ReplaceRecoveryCodesForAdmin(r.Context(), tx, adminID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"recoveryCodes": recoveryCodes})
}

func (h *Admins) TotpDisable(w http.ResponseWriter, r *http.Request) {
	adminID, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}
	var body struct {
		TotpCode string `json:"totpCode"`
	}
	if err := httpx.DecodeJSONLoose(r, &body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}
	code := normalizeTotpCode(body.TotpCode)
	if code == "" {
		httpx.WriteError(w, http.StatusBadRequest, "Введите текущий код 2FA для отключения")
		return
	}
	var totpEnabled bool
	var secretEnc *string
	var isActive bool
	err := h.Pool.QueryRow(r.Context(), `
		SELECT "totpEnabled", "totpSecretEnc", "isActive" FROM "Admin" WHERE id = $1`, adminID).
		Scan(&totpEnabled, &secretEnc, &isActive)
	if err != nil || !isActive {
		httpx.WriteError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	if !totpEnabled || secretEnc == nil {
		httpx.WriteError(w, http.StatusBadRequest, "2FA уже отключена")
		return
	}
	secret, err := auth.DecryptSecret(h.Cfg.JWTSecret, *secretEnc)
	if err != nil || !auth.VerifyTotp(secret, code) {
		httpx.WriteError(w, http.StatusBadRequest, "Неверный код 2FA")
		return
	}
	if _, err := h.Pool.Exec(r.Context(), `
		UPDATE "Admin" SET "totpEnabled" = false, "totpSecretEnc" = NULL,
			"totpPendingSecretEnc" = NULL, "totpPendingExpiresAt" = NULL, "updatedAt" = NOW()
		WHERE id = $1`, adminID); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *Admins) verifyAdminTotp(r *http.Request, adminID, code string, w http.ResponseWriter) bool {
	var totpEnabled bool
	var secretEnc *string
	var isActive bool
	err := h.Pool.QueryRow(r.Context(), `
		SELECT "totpEnabled", "totpSecretEnc", "isActive" FROM "Admin" WHERE id = $1`, adminID).
		Scan(&totpEnabled, &secretEnc, &isActive)
	if err != nil || !isActive {
		httpx.WriteError(w, http.StatusUnauthorized, "Unauthorized")
		return false
	}
	if !totpEnabled || secretEnc == nil {
		httpx.WriteError(w, http.StatusBadRequest, "Сначала включите двухфакторную аутентификацию")
		return false
	}
	secret, err := auth.DecryptSecret(h.Cfg.JWTSecret, *secretEnc)
	if err != nil || !auth.VerifyTotp(secret, code) {
		httpx.WriteError(w, http.StatusBadRequest, "Неверный код 2FA")
		return false
	}
	return true
}
