package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/openvpn-control/openvpn-control-server/backend/internal/ccd"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/cert"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/config"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/firewall"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/httpx"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/ovpn"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/paneltasks"
)

type VpnUsers struct {
	Cfg  config.Config
	Pool *pgxpool.Pool
}

func (h *VpnUsers) Mount(r chi.Router) {
	r.Get("/", h.List)
	r.Post("/", h.Create)
	r.Get("/issue-certificate/servers", h.IssueCertServers)
	r.Get("/{id}/firewall", h.GetFirewall)
	r.Post("/{id}/firewall", h.SaveFirewall)
	r.Post("/{id}/firewall-check", h.CheckFirewall)
	r.Get("/{id}/ccd", h.GetCCD)
	r.Post("/{id}/ccd", h.SaveCCD)
	r.Get("/{id}/vpn-sessions", h.VPNSessions)
	r.Patch("/{id}", h.Patch)
	r.Get("/{id}/connection-profile/options", h.ProfileOptions)
	r.Post("/{id}/connection-profile", h.Profile)
}

func (h *VpnUsers) List(w http.ResponseWriter, r *http.Request) {
	var raw []byte
	err := h.Pool.QueryRow(r.Context(), `
		SELECT COALESCE(json_agg(row_to_json(u)), '[]'::json)::text FROM (
			SELECT v.*, row_to_json(o) AS organization FROM "VpnUser" v
			LEFT JOIN "Organization" o ON o.id = v."organizationId"
			ORDER BY v."createdAt" DESC
		) u`).Scan(&raw)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeRawJSON(w, raw)
}

func (h *VpnUsers) Create(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := httpx.DecodeJSONLoose(r, &body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}
	fullName, err := reqTrim(body["fullName"], "fullName")
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	email, err := reqTrim(body["email"], "email")
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	email = strings.ToLower(email)
	orgID, err := h.resolveOrgID(r, body["organizationId"])
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "Организация не найдена")
		return
	}
	id := newID()
	_, qerr := h.Pool.Exec(r.Context(), `
		INSERT INTO "VpnUser" (id, "fullName", position, email, phone, "organizationId", notes, "createdAt", "updatedAt")
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())`,
		id, fullName, optStr(body["position"]), email, optStr(body["phone"]), orgID, optStr(body["notes"]),
	)
	if qerr != nil {
		if isUniqueViolation(qerr) {
			httpx.WriteError(w, http.StatusConflict, "Пользователь с таким email уже существует")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, qerr.Error())
		return
	}
	w.WriteHeader(http.StatusCreated)
	h.writeUser(w, r, id)
}

func (h *VpnUsers) Patch(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var exists bool
	if err := h.Pool.QueryRow(r.Context(), `SELECT true FROM "VpnUser" WHERE id = $1`, id).Scan(&exists); err != nil || !exists {
		httpx.WriteError(w, http.StatusNotFound, "Пользователь не найден")
		return
	}
	var body map[string]any
	if err := httpx.DecodeJSONLoose(r, &body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}
	sets := []string{}
	args := []any{}
	n := 1
	if _, ok := body["fullName"]; ok {
		v, err := reqTrim(body["fullName"], "fullName")
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		sets, args, n = addSet(sets, args, n, `"fullName"`, v)
	}
	if _, ok := body["position"]; ok {
		sets, args, n = addSet(sets, args, n, "position", optStr(body["position"]))
	}
	if _, ok := body["email"]; ok {
		v, err := reqTrim(body["email"], "email")
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		sets, args, n = addSet(sets, args, n, "email", strings.ToLower(v))
	}
	if _, ok := body["phone"]; ok {
		sets, args, n = addSet(sets, args, n, "phone", optStr(body["phone"]))
	}
	if _, ok := body["notes"]; ok {
		sets, args, n = addSet(sets, args, n, "notes", optStr(body["notes"]))
	}
	if _, ok := body["organizationId"]; ok {
		orgID, err := h.resolveOrgID(r, body["organizationId"])
		if err != nil {
			httpx.WriteError(w, http.StatusNotFound, "Организация не найдена")
			return
		}
		sets, args, n = addSet(sets, args, n, `"organizationId"`, orgID)
	}
	if len(sets) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "Нет полей для обновления")
		return
	}
	sets = append(sets, `"updatedAt" = NOW()`)
	args = append(args, id)
	q := `UPDATE "VpnUser" SET ` + strings.Join(sets, ", ") + ` WHERE id = $` + itoa(n)
	_, err := h.Pool.Exec(r.Context(), q, args...)
	if err != nil {
		if isUniqueViolation(err) {
			httpx.WriteError(w, http.StatusConflict, "Пользователь с таким email уже существует")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.writeUser(w, r, id)
}

func (h *VpnUsers) IssueCertServers(w http.ResponseWriter, r *http.Request) {
	raw, err := listIssueServers(r.Context(), h.Pool)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"servers": json.RawMessage(raw)})
}

func (h *VpnUsers) GetFirewall(w http.ResponseWriter, r *http.Request) {
	var raw []byte
	err := h.Pool.QueryRow(r.Context(), `SELECT "firewallRules" FROM "VpnUser" WHERE id = $1`, chi.URLParam(r, "id")).Scan(&raw)
	if err == pgx.ErrNoRows {
		httpx.WriteError(w, http.StatusNotFound, "Пользователь не найден")
		return
	}
	parsed := firewall.ParseStored(raw)
	httpx.WriteJSON(w, http.StatusOK, parsed)
}

func (h *VpnUsers) SaveFirewall(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !h.userExists(r, id) {
		httpx.WriteError(w, http.StatusNotFound, "Пользователь не найден")
		return
	}
	var body map[string]any
	_ = httpx.DecodeJSONLoose(r, &body)
	stored, _ := firewall.SerializeForDB(strAny(body["mode"]), body["rules"], body["natRules"])
	_, err := h.Pool.Exec(r.Context(), `UPDATE "VpnUser" SET "firewallRules" = $2, "updatedAt" = NOW() WHERE id = $1`, id, stored)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = paneltasks.EnqueueSnapshotForVpnUser(r.Context(), h.Pool, id)
	parsed := firewall.ParseStored(stored)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok": true, "message": "Firewall-правила пользователя сохранены.",
		"mode": parsed.Mode, "rules": parsed.Rules, "natRules": parsed.NatRules,
	})
}

func (h *VpnUsers) CheckFirewall(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !h.userExists(r, id) {
		httpx.WriteError(w, http.StatusNotFound, "Пользователь не найден")
		return
	}
	var body map[string]any
	_ = httpx.DecodeJSONLoose(r, &body)
	stored, _ := firewall.SerializeForDB(strAny(body["mode"]), body["rules"], body["natRules"])
	parsed := firewall.ParseStored(stored)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok": true, "message": "Конфиг пользователя валиден.",
		"mode": parsed.Mode, "rules": parsed.Rules, "natRules": parsed.NatRules,
	})
}

func (h *VpnUsers) GetCCD(w http.ResponseWriter, r *http.Request) {
	var raw []byte
	err := h.Pool.QueryRow(r.Context(), `SELECT "ccdSettings" FROM "VpnUser" WHERE id = $1`, chi.URLParam(r, "id")).Scan(&raw)
	if err == pgx.ErrNoRows {
		httpx.WriteError(w, http.StatusNotFound, "Пользователь не найден")
		return
	}
	var m any
	_ = json.Unmarshal(raw, &m)
	httpx.WriteJSON(w, http.StatusOK, ccd.Normalize(m))
}

func (h *VpnUsers) SaveCCD(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !h.userExists(r, id) {
		httpx.WriteError(w, http.StatusNotFound, "Пользователь не найден")
		return
	}
	var body map[string]any
	_ = httpx.DecodeJSONLoose(r, &body)
	stored := ccd.Normalize(body)
	b, _ := json.Marshal(stored)
	_, err := h.Pool.Exec(r.Context(), `UPDATE "VpnUser" SET "ccdSettings" = $2, "updatedAt" = NOW() WHERE id = $1`, id, b)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = paneltasks.EnqueueSnapshotForVpnUser(r.Context(), h.Pool, id)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok": true, "message": "CCD сохранён; поставлена задача доставки на серверы OpenVPN.",
		"ifconfigPushLocal": stored.IfconfigPushLocal, "ifconfigPushRemote": stored.IfconfigPushRemote,
		"pushRoutes": stored.PushRoutes, "iroutes": stored.Iroutes, "dnsServers": stored.DNSServers,
		"customDirectives": stored.CustomDirectives,
	})
}

func (h *VpnUsers) VPNSessions(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !h.userExists(r, id) {
		httpx.WriteError(w, http.StatusNotFound, "Пользователь не найден")
		return
	}
	ctx := r.Context()
	now := time.Now().UTC()
	supplementUserVpnSessions(ctx, h.Pool, id, now)

	cutoff := now.Add(-h.Cfg.ClientSessionFreshness)
	rows, err := h.Pool.Query(ctx, `
		SELECT c."agentNodeId", c."sessionId", c."commonName", c."realIp", c."virtualIp",
			c."connectedAt", c."firstSeenAt", c."lastSeenAt", c."endedAt", COALESCE(n.name, c."agentNodeId")
		FROM "ClientIpAssignment" c
		LEFT JOIN "AgentNode" n ON n.id = c."agentNodeId"
		WHERE LOWER(TRIM(c."commonName")) IN (
			SELECT LOWER(TRIM("commonName")) FROM "Certificate" WHERE "vpnUserId" = $1 AND TRIM("commonName") <> ''
		)
		ORDER BY c."lastSeenAt" DESC`, id)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	type pair struct{ nodeID, sessID string }
	seen := map[string]bool{}
	var out []map[string]any
	for rows.Next() {
		var nodeID, sessID, cn, realIP, vip string
		var connectedAt, firstSeen, lastSeen time.Time
		var endedAt *time.Time
		var nodeName string
		if rows.Scan(&nodeID, &sessID, &cn, &realIP, &vip, &connectedAt, &firstSeen, &lastSeen, &endedAt, &nodeName) != nil {
			continue
		}
		key := nodeID + "\t" + sessID
		if seen[key] {
			continue
		}
		seen[key] = true
		var inBps, outBps float64
		_ = h.Pool.QueryRow(r.Context(), `
			SELECT COALESCE("inBps",0), COALESCE("outBps",0) FROM "ClientTrafficSample"
			WHERE "agentNodeId" = $1 AND "sessionId" = $2 ORDER BY "sampledAt" DESC LIMIT 1`,
			nodeID, sessID).Scan(&inBps, &outBps)
		active := endedAt == nil && lastSeen.After(cutoff)
		out = append(out, map[string]any{
			"nodeId": nodeID, "nodeName": nodeName, "sessionId": sessID, "commonName": cn,
			"remoteIp": remoteHost(realIP), "virtualIp": vip, "connectedAt": connectedAt,
			"firstSeenAt": firstSeen, "lastSeenAt": lastSeen, "endedAt": endedAt,
			"isActive": active, "inBps": inBps, "outBps": outBps,
		})
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (h *VpnUsers) ProfileOptions(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var email string
	if err := h.Pool.QueryRow(r.Context(), `SELECT email FROM "VpnUser" WHERE id = $1`, id).Scan(&email); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "Пользователь не найден")
		return
	}
	var certsRaw []byte
	_ = h.Pool.QueryRow(r.Context(), `
		SELECT COALESCE(json_agg(row_to_json(c)), '[]'::json)::text FROM (
			SELECT id, "commonName", "rootCaId", "expiresAt", "certPem"
			FROM "Certificate" WHERE "vpnUserId" = $1 AND "revokedAt" IS NULL
			AND "certPem" IS NOT NULL AND "keyPem" IS NOT NULL ORDER BY "createdAt" DESC
		) c`, id).Scan(&certsRaw)
	var certs []map[string]any
	_ = json.Unmarshal(certsRaw, &certs)
	var safe []map[string]any
	for _, c := range certs {
		pem, _ := c["certPem"].(string)
		if cert.IsClientLeaf(pem) {
			delete(c, "certPem")
			safe = append(safe, c)
		}
	}
	servers, _ := listIssueServers(r.Context(), h.Pool)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"certificates": safe, "servers": json.RawMessage(servers), "defaultEmail": email,
	})
}

func (h *VpnUsers) Profile(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var body struct {
		Action        string `json:"action"`
		CertificateID string `json:"certificateId"`
		ServerID      string `json:"serverId"`
		Email         string `json:"email"`
	}
	if err := httpx.DecodeJSON(r, &body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}
	action := strings.ToLower(strings.TrimSpace(body.Action))
	if action != "download" && action != "email" {
		httpx.WriteError(w, http.StatusBadRequest, "action должен быть download или email")
		return
	}
	if body.CertificateID == "" || body.ServerID == "" {
		httpx.WriteError(w, http.StatusBadRequest, "certificateId и serverId обязательны")
		return
	}
	var certPEM, keyPEM, rootCaID, cn string
	var nodeHost, nodeName string
	err := h.Pool.QueryRow(r.Context(), `
		SELECT c."certPem", c."keyPem", c."rootCaId", c."commonName", n.host, n.name
		FROM "Certificate" c
		INNER JOIN "AgentNode" n ON n.id = $1
		WHERE c.id = $2 AND c."vpnUserId" = $3 AND c."revokedAt" IS NULL`,
		body.ServerID, body.CertificateID, id,
	).Scan(&certPEM, &keyPEM, &rootCaID, &cn, &nodeHost, &nodeName)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "Сертификат или сервер не найден")
		return
	}
	if certPEM == "" || keyPEM == "" {
		httpx.WriteError(w, http.StatusUnprocessableEntity, "У сертификата нет cert/key материала")
		return
	}
	if !cert.IsClientLeaf(certPEM) {
		httpx.WriteError(w, http.StatusUnprocessableEntity, "Нужен клиентский сертификат")
		return
	}
	var settings []byte
	var rootPEM string
	_ = h.Pool.QueryRow(r.Context(), `SELECT settings FROM "AgentNodeOpenvpnSettings" WHERE "agentNodeId" = $1`, body.ServerID).Scan(&settings)
	_ = h.Pool.QueryRow(r.Context(), `SELECT "certPem" FROM "RootCertificateAuthority" WHERE id = $1`, rootCaID).Scan(&rootPEM)
	var st map[string]any
	_ = json.Unmarshal(settings, &st)
	if strings.TrimSpace(strAny(st["panelRootCaId"])) != strings.TrimSpace(rootCaID) {
		httpx.WriteError(w, http.StatusConflict, "Сертификат не соответствует корневому сертификату выбранного сервера")
		return
	}
	tlsPem := ""
	var tlsID string
	if st != nil {
		tlsID = strings.TrimSpace(strAny(st["panelTlsAuthMaterialId"]))
	}
	if tlsID != "" {
		_ = h.Pool.QueryRow(r.Context(), `
			SELECT pem FROM "AgentNodeOpenvpnMaterial"
			WHERE id = $1 AND "agentNodeId" = $2 AND kind = 'tls_auth'`, tlsID, body.ServerID).Scan(&tlsPem)
	}
	profile := ovpn.BuildClientOvpn(ovpn.BuildInput{
		Node: ovpn.Node{Host: nodeHost, Name: nodeName}, Settings: st,
		CertPEM: certPEM, KeyPEM: keyPEM, RootCAPEM: rootPEM, TLSAuthPEM: tlsPem,
	})
	safeName := func(s string) string {
		var b strings.Builder
		for _, r := range s {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
				b.WriteRune(r)
			} else {
				b.WriteRune('-')
			}
		}
		return b.String()
	}
	fileName := safeName(nodeName) + "-" + safeName(cn) + ".ovpn"
	if action == "download" {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"fileName": fileName, "contentBase64": base64.StdEncoding.EncodeToString([]byte(profile)),
		})
		return
	}
	email := strings.TrimSpace(body.Email)
	if email == "" {
		httpx.WriteError(w, http.StatusBadRequest, "email обязателен для отправки")
		return
	}
	if err := sendProfileEmail(email, fileName, profile); err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "Не удалось отправить email через sendmail на сервере панели")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "Конфигурация отправлена на " + email})
}

func (h *VpnUsers) userExists(r *http.Request, id string) bool {
	var ok bool
	_ = h.Pool.QueryRow(r.Context(), `SELECT true FROM "VpnUser" WHERE id = $1`, id).Scan(&ok)
	return ok
}

func (h *VpnUsers) writeUser(w http.ResponseWriter, r *http.Request, id string) {
	var raw []byte
	if err := h.Pool.QueryRow(r.Context(), `
		SELECT row_to_json(x)::text FROM (
			SELECT v.*, row_to_json(o) AS organization FROM "VpnUser" v
			LEFT JOIN "Organization" o ON o.id = v."organizationId" WHERE v.id = $1
		) x`, id).Scan(&raw); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeRawJSON(w, raw)
}

func (h *VpnUsers) resolveOrgID(r *http.Request, raw any) (*string, error) {
	if raw == nil {
		return nil, nil
	}
	s := strings.TrimSpace(strAny(raw))
	if s == "" {
		return nil, nil
	}
	var ok bool
	if err := h.Pool.QueryRow(r.Context(), `SELECT true FROM "Organization" WHERE id = $1`, s).Scan(&ok); err != nil || !ok {
		return nil, pgx.ErrNoRows
	}
	return &s, nil
}

func listIssueServers(ctx context.Context, pool *pgxpool.Pool) ([]byte, error) {
	var raw []byte
	err := pool.QueryRow(ctx, `
		SELECT COALESCE(json_agg(row_to_json(s)), '[]'::json)::text FROM (
			SELECT s."agentNodeId" AS id, COALESCE(n.name, s."agentNodeId") AS name,
				COALESCE(n.host, '') AS host, n.port AS "apiPort", COALESCE(n.protocol, 'http') AS protocol,
				COALESCE(n.status, 'UNKNOWN') AS status,
				COALESCE(s.settings->>'panelRootCaId', '') AS "panelRootCaId",
				COALESCE((s.settings->>'port')::int, 0) AS "openvpnPort",
				COALESCE(s.settings->>'proto', 'udp') AS "openvpnProto"
			FROM "AgentNodeOpenvpnSettings" s
			LEFT JOIN "AgentNode" n ON n.id = s."agentNodeId"
		) s`).Scan(&raw)
	return raw, err
}

func sendProfileEmail(to, fileName, content string) error {
	boundary := "ovpn-" + newID()
	b64 := base64.StdEncoding.EncodeToString([]byte(content))
	msg := strings.Join([]string{
		"To: " + to,
		"Subject: OpenVPN connection profile",
		"MIME-Version: 1.0",
		"Content-Type: multipart/mixed; boundary=\"" + boundary + "\"",
		"", "--" + boundary,
		"Content-Type: text/plain; charset=UTF-8", "",
		"Во вложении конфигурация OpenVPN.", "",
		"--" + boundary,
		"Content-Type: application/octet-stream; name=\"" + fileName + "\"",
		"Content-Transfer-Encoding: base64",
		"Content-Disposition: attachment; filename=\"" + fileName + "\"", "", b64,
		"--" + boundary + "--", "",
	}, "\n")
	cmd := exec.Command("sendmail", "-t", "-oi")
	cmd.Stdin = strings.NewReader(msg)
	return cmd.Run()
}

func reqTrim(v any, label string) (string, error) {
	s := strings.TrimSpace(strAny(v))
	if s == "" {
		return "", errRequired(label)
	}
	return s, nil
}

func errRequired(label string) error { return &requiredErr{label} }

type requiredErr struct{ label string }

func (e *requiredErr) Error() string { return "Обязательное поле: " + e.label }

func optStr(v any) *string {
	s := strings.TrimSpace(strAny(v))
	if s == "" {
		return nil
	}
	return &s
}

func addSet(sets []string, args []any, n int, col string, val any) ([]string, []any, int) {
	sets = append(sets, col+` = $`+itoa(n))
	args = append(args, val)
	return sets, args, n + 1
}

func isUniqueViolation(err error) bool {
	return strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "23505")
}
