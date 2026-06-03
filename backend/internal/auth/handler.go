package auth

import (
	"context"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/openvpn-control/openvpn-control-server/backend/internal/config"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/httpx"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/limiter"
)

type Handler struct {
	Cfg     config.Config
	Pool    *pgxpool.Pool
	Limiter *limiter.Login
}

type loginBody struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type mfaBody struct {
	MFAPendingToken string `json:"mfaPendingToken"`
	TotpCode        string `json:"totpCode"`
	RecoveryCode    string `json:"recoveryCode"`
}

type adminRow struct {
	ID           string
	Username     string
	PasswordHash string
	IsActive     bool
	InviteToken  *string
	TotpEnabled  bool
	TotpSecretEnc *string
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var body loginBody
	if err := httpx.DecodeJSON(r, &body); err != nil || body.Username == "" || body.Password == "" {
		httpx.WriteError(w, http.StatusBadRequest, "username and password are required")
		return
	}
	ip := limiter.ClientIP(r)
	if ok, retry := h.Limiter.Check(ip, body.Username); !ok {
		w.Header().Set("Retry-After", itoa(retry))
		httpx.WriteJSON(w, http.StatusTooManyRequests, map[string]any{
			"error":               "Слишком много неудачных попыток входа. Подождите и попробуйте снова.",
			"retryAfterSeconds": retry,
		})
		return
	}
	admin, err := h.loadAdmin(r.Context(), body.Username)
	if err != nil || admin == nil || !admin.IsActive {
		h.Limiter.Fail(ip, body.Username)
		httpx.WriteError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}
	if admin.InviteToken != nil && *admin.InviteToken != "" {
		h.Limiter.Fail(ip, body.Username)
		httpx.WriteError(w, http.StatusUnauthorized, "Завершите регистрацию по ссылке-приглашению, которую вам отправил администратор панели.")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(body.Password)) != nil {
		h.Limiter.Fail(ip, body.Username)
		httpx.WriteError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}
	if admin.TotpEnabled {
		tok, err := SignMFAPending(h.Cfg.JWTSecret, h.Cfg.MFAPendingExpiresIn, admin.ID, admin.Username)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "token error")
			return
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"mfaRequired": true, "mfaPendingToken": tok})
		return
	}
	h.Limiter.Success(ip, body.Username)
	tok, err := SignAccess(h.Cfg.JWTSecret, h.Cfg.JWTExpiresIn, admin.ID, admin.Username)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "token error")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"token": tok})
}

func (h *Handler) LoginMFA(w http.ResponseWriter, r *http.Request) {
	var body mfaBody
	if err := httpx.DecodeJSON(r, &body); err != nil || body.MFAPendingToken == "" {
		httpx.WriteError(w, http.StatusBadRequest, "Требуется токен подтверждения 2FA")
		return
	}
	claims, err := ParseToken(h.Cfg.JWTSecret, body.MFAPendingToken)
	if err != nil || claims.Purpose != "mfa_pending" {
		httpx.WriteError(w, http.StatusUnauthorized, "Сессия подтверждения 2FA истекла. Войдите снова.")
		return
	}
	ip := limiter.ClientIP(r)
	if ok, retry := h.Limiter.Check(ip, claims.Username); !ok {
		w.Header().Set("Retry-After", itoa(retry))
		httpx.WriteJSON(w, http.StatusTooManyRequests, map[string]any{"error": "Слишком много неудачных попыток входа.", "retryAfterSeconds": retry})
		return
	}
	admin, err := h.loadAdminByID(r.Context(), claims.Sub)
	if err != nil || admin == nil || !admin.IsActive || admin.Username != claims.Username || !admin.TotpEnabled {
		h.Limiter.Fail(ip, claims.Username)
		httpx.WriteError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}
	secret := ""
	if admin.TotpSecretEnc != nil {
		secret, _ = DecryptSecret(h.Cfg.JWTSecret, *admin.TotpSecretEnc)
	}
	totpOk := secret != "" && VerifyTotp(secret, body.TotpCode)
	recoveryOk := VerifyAndConsumeRecoveryCode(r.Context(), h.Pool, admin.ID, body.RecoveryCode)
	if !totpOk && !recoveryOk {
		h.Limiter.Fail(ip, claims.Username)
		httpx.WriteError(w, http.StatusUnauthorized, "Неверный код двухфакторной аутентификации или резервный код")
		return
	}
	h.Limiter.Success(ip, claims.Username)
	tok, err := SignAccess(h.Cfg.JWTSecret, h.Cfg.JWTExpiresIn, admin.ID, admin.Username)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "token error")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"token": tok})
}

func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	u := UserFromRequest(r)
	if u == nil {
		httpx.WriteError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	tok, err := SignAccess(h.Cfg.JWTSecret, h.Cfg.JWTExpiresIn, u.Sub, u.Username)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "token error")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"token": tok})
}

func (h *Handler) loadAdmin(ctx context.Context, username string) (*adminRow, error) {
	row := h.Pool.QueryRow(ctx, `
		SELECT id, username, "passwordHash", "isActive", "inviteToken", "totpEnabled", "totpSecretEnc"
		FROM "Admin" WHERE username = $1`, username)
	return scanAdmin(row.Scan)
}

func (h *Handler) loadAdminByID(ctx context.Context, id string) (*adminRow, error) {
	row := h.Pool.QueryRow(ctx, `
		SELECT id, username, "passwordHash", "isActive", "inviteToken", "totpEnabled", "totpSecretEnc"
		FROM "Admin" WHERE id = $1`, id)
	return scanAdmin(row.Scan)
}

func scanAdmin(scan func(dest ...any) error) (*adminRow, error) {
	var a adminRow
	err := scan(&a.ID, &a.Username, &a.PasswordHash, &a.IsActive, &a.InviteToken, &a.TotpEnabled, &a.TotpSecretEnc)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func itoa(n int) string {
	if n <= 0 {
		return "1"
	}
	return strconv.Itoa(n)
}
