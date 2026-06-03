package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/openvpn-control/openvpn-control-server/backend/internal/cert"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/crl"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/httpx"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/paneltasks"
)

type Certificates struct {
	Pool *pgxpool.Pool
}

func (h *Certificates) Mount(r chi.Router) {
	r.Get("/", h.List)
	r.Get("/revoked", h.Revoked)
	r.Get("/root-ca", h.ListRootCA)
	r.Get("/root-ca/{rootCaId}/summary", h.RootCASummary)
	r.Get("/root-ca/{rootCaId}/export", h.RootCAExport)
	r.Post("/root-ca/import", h.RootCAImport)
	r.Post("/root-ca/generate", h.RootCAGenerate)
	r.Post("/root-ca/{rootCaId}/import-index", h.RootCAImportIndex)
	r.Post("/", h.Create)
	r.Post("/import", h.Import)
	r.Patch("/{id}", h.Patch)
	r.Post("/{id}/view-material", h.ViewMaterial)
	r.Get("/{id}/material-summary", h.MaterialSummary)
	r.Post("/{id}/revoke", h.Revoke)
}

func (h *Certificates) List(w http.ResponseWriter, r *http.Request) {
	var raw []byte
	err := h.Pool.QueryRow(r.Context(), `
		SELECT COALESCE(json_agg(row_to_json(x)), '[]'::json)::text FROM (
			SELECT c.*,
				CASE WHEN rc.id IS NOT NULL THEN json_build_object(
					'id', rc.id, 'name', rc.name, 'commonName', rc."commonName"
				) END AS "rootCa",
				CASE WHEN n.id IS NOT NULL THEN json_build_object(
					'id', n.id, 'name', n.name, 'protocol', n.protocol, 'host', n.host, 'port', n.port
				) END AS "agentNode",
				CASE WHEN u.id IS NOT NULL THEN json_build_object(
					'id', u.id, 'fullName', u."fullName", 'email', u.email
				) END AS "vpnUser"
			FROM "Certificate" c
			LEFT JOIN "RootCertificateAuthority" rc ON rc.id = c."rootCaId"
			LEFT JOIN "AgentNode" n ON n.id = c."agentNodeId"
			LEFT JOIN "VpnUser" u ON u.id = c."vpnUserId"
			ORDER BY c."createdAt" DESC
		) x`).Scan(&raw)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var rows []map[string]any
	if err := json.Unmarshal(raw, &rows); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, stripCertListRow(row))
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func stripCertListRow(row map[string]any) map[string]any {
	certPem, _ := row["certPem"].(string)
	keyPem, _ := row["keyPem"].(string)
	delete(row, "certPem")
	delete(row, "keyPem")
	row["hasCertPem"] = certPem != ""
	row["hasKeyPem"] = keyPem != ""
	row["hasKeyMaterial"] = certPem != "" && keyPem != ""
	return row
}

func (h *Certificates) Revoked(w http.ResponseWriter, r *http.Request) {
	var raw []byte
	err := h.Pool.QueryRow(r.Context(), `
		SELECT COALESCE(json_agg(row_to_json(c) ORDER BY c."revokedAt" DESC), '[]'::json)::text
		FROM "Certificate" c WHERE c."revokedAt" IS NOT NULL`).Scan(&raw)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeRawJSON(w, raw)
}

func (h *Certificates) Create(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := httpx.DecodeJSONLoose(r, &body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}

	commonName := strings.TrimSpace(strAny(body["commonName"]))
	if commonName == "" {
		httpx.WriteError(w, http.StatusBadRequest, "commonName (subject CN сертификата) обязателен")
		return
	}
	rootCaID := strings.TrimSpace(strAny(body["rootCaId"]))
	if rootCaID == "" {
		httpx.WriteError(w, http.StatusBadRequest, "rootCaId is required")
		return
	}

	vpnUserID := nullableID(body["vpnUserId"])
	if vpnUserID != nil {
		var exists bool
		if err := h.Pool.QueryRow(r.Context(), `SELECT true FROM "VpnUser" WHERE id = $1`, *vpnUserID).Scan(&exists); err != nil || !exists {
			httpx.WriteError(w, http.StatusNotFound, "VPN user not found")
			return
		}
	}

	var rootName, rootCertPEM, rootKeyPEM string
	err := h.Pool.QueryRow(r.Context(), `
		SELECT name, "certPem", "keyPem" FROM "RootCertificateAuthority" WHERE id = $1`, rootCaID,
	).Scan(&rootName, &rootCertPEM, &rootKeyPEM)
	if err == pgx.ErrNoRows {
		httpx.WriteError(w, http.StatusNotFound, "Корневой сертификат не найден")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	agentNodeID := nullableID(body["agentNodeId"])
	if agentNodeID != nil {
		var exists bool
		if err := h.Pool.QueryRow(r.Context(), `SELECT true FROM "AgentNode" WHERE id = $1`, *agentNodeID).Scan(&exists); err != nil || !exists {
			httpx.WriteError(w, http.StatusNotFound, "Agent node not found")
			return
		}
	}

	if h.activeSameCN(r.Context(), commonName, agentNodeID, "") {
		httpx.WriteError(w, http.StatusConflict, "Сертификат с таким subject CN для этого сервера уже есть и не отозван.")
		return
	}

	issuedBy := strings.TrimSpace(strAny(body["issuedBy"]))
	if issuedBy == "" {
		issuedBy = rootName
	}

	validityDays := 365
	if expiresRaw := strings.TrimSpace(strAny(body["expiresAt"])); expiresRaw != "" {
		if t, parseErr := time.Parse(time.RFC3339, expiresRaw); parseErr == nil {
			days := int(math.Ceil(time.Until(t).Hours() / 24))
			if days < 1 {
				days = 1
			}
			validityDays = days
		}
	}

	certPEM, keyPEM, expiresAt, serial, issueErr := cert.IssueLeaf(rootCertPEM, rootKeyPEM, commonName, validityDays)
	if issueErr != nil {
		httpx.WriteError(w, http.StatusInternalServerError, issueErr.Error())
		return
	}
	if serial == "" {
		serial = newID()
	}

	id := newID()
	_, qerr := h.Pool.Exec(r.Context(), `
		INSERT INTO "Certificate" (
			id, "commonName", "serialNumber", "issuedBy", "rootCaId", "agentNodeId", "vpnUserId",
			"certPem", "keyPem", "expiresAt", "createdAt"
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())`,
		id, commonName, serial, issuedBy, rootCaID, agentNodeID, vpnUserID,
		certPEM, keyPEM, expiresAt,
	)
	if qerr != nil {
		if isUniqueViolation(qerr) {
			httpx.WriteError(w, http.StatusConflict, "Сертификат с таким серийным номером уже существует")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, qerr.Error())
		return
	}

	if agentNodeID != nil {
		_ = paneltasks.EnqueueSnapshotForNode(r.Context(), h.Pool, *agentNodeID)
	}

	w.WriteHeader(http.StatusCreated)
	h.writeCert(w, r, id)
}

func (h *Certificates) Import(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := httpx.DecodeJSONLoose(r, &body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}

	certPEM := strings.TrimSpace(strAny(body["certPem"]))
	keyPEM := strings.TrimSpace(strAny(body["keyPem"]))
	rootCaID := strings.TrimSpace(strAny(body["rootCaId"]))
	agentNodeID := strings.TrimSpace(strAny(body["agentNodeId"]))
	vpnUserID := nullableID(body["vpnUserId"])

	if rootCaID == "" {
		httpx.WriteError(w, http.StatusBadRequest, "rootCaId is required")
		return
	}
	if agentNodeID == "" {
		httpx.WriteError(w, http.StatusBadRequest, "agentNodeId is required")
		return
	}
	if certPEM == "" {
		httpx.WriteError(w, http.StatusBadRequest, "certPem is required")
		return
	}
	if keyPEM == "" {
		httpx.WriteError(w, http.StatusBadRequest, "keyPem is required")
		return
	}
	if !strings.Contains(certPEM, "BEGIN CERTIFICATE") {
		httpx.WriteError(w, http.StatusBadRequest, "certPem должен быть сертификатом в PEM-формате")
		return
	}
	if !strings.Contains(keyPEM, "PRIVATE KEY") {
		httpx.WriteError(w, http.StatusBadRequest, "keyPem должен быть приватным ключом в PEM-формате")
		return
	}
	if cert.HasNegativeSerial(certPEM) {
		httpx.WriteError(w, http.StatusUnprocessableEntity,
			"Сертификат отклонён: отрицательный serialNumber (например -ABCD...). Выпустите/импортируйте сертификат с положительным serialNumber.")
		return
	}

	var rootName, rootCertPEM string
	err := h.Pool.QueryRow(r.Context(), `
		SELECT name, "certPem" FROM "RootCertificateAuthority" WHERE id = $1`, rootCaID,
	).Scan(&rootName, &rootCertPEM)
	if err == pgx.ErrNoRows {
		httpx.WriteError(w, http.StatusNotFound, "Корневой сертификат не найден")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	var nodeExists bool
	if err := h.Pool.QueryRow(r.Context(), `SELECT true FROM "AgentNode" WHERE id = $1`, agentNodeID).Scan(&nodeExists); err != nil || !nodeExists {
		httpx.WriteError(w, http.StatusNotFound, "Agent node not found")
		return
	}
	if vpnUserID != nil {
		var exists bool
		if err := h.Pool.QueryRow(r.Context(), `SELECT true FROM "VpnUser" WHERE id = $1`, *vpnUserID).Scan(&exists); err != nil || !exists {
			httpx.WriteError(w, http.StatusNotFound, "VPN user not found")
			return
		}
	}

	if err := cert.KeysMatch(certPEM, keyPEM); err != nil {
		httpx.WriteError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if err := cert.VerifyIssuedByRoot(certPEM, rootCertPEM); err != nil {
		httpx.WriteError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}

	commonName, err := cert.SubjectCN(certPEM)
	if err != nil || commonName == "" {
		httpx.WriteError(w, http.StatusUnprocessableEntity, "Не удалось определить Subject CN импортируемого сертификата")
		return
	}

	agentPtr := &agentNodeID
	if h.activeSameCN(r.Context(), commonName, agentPtr, "") {
		httpx.WriteError(w, http.StatusConflict, "Сертификат с таким subject CN для этого сервера уже есть и не отозван.")
		return
	}

	leaf, err := cert.ParseCertificate(certPEM)
	if err != nil {
		httpx.WriteError(w, http.StatusUnprocessableEntity, "Не удалось разобрать сертификат/ключ")
		return
	}
	serial := cert.SerialHex(leaf)
	if serial == "" {
		serial = newID()
	}

	var dup bool
	if err := h.Pool.QueryRow(r.Context(), `SELECT true FROM "Certificate" WHERE "serialNumber" = $1`, serial).Scan(&dup); err == nil {
		httpx.WriteError(w, http.StatusConflict, "Сертификат с таким серийным номером уже существует")
		return
	}

	id := newID()
	_, qerr := h.Pool.Exec(r.Context(), `
		INSERT INTO "Certificate" (
			id, "commonName", "serialNumber", "issuedBy", "rootCaId", "agentNodeId", "vpnUserId",
			"certPem", "keyPem", "expiresAt", "createdAt"
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())`,
		id, commonName, serial, rootName, rootCaID, agentNodeID, vpnUserID,
		cert.EnsurePEMNewline(certPEM), cert.EnsurePEMNewline(keyPEM), leaf.NotAfter,
	)
	if qerr != nil {
		if isUniqueViolation(qerr) {
			httpx.WriteError(w, http.StatusConflict, "Сертификат с таким серийным номером уже существует")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, qerr.Error())
		return
	}

	_ = paneltasks.EnqueueSnapshotForNode(r.Context(), h.Pool, agentNodeID)
	w.WriteHeader(http.StatusCreated)
	h.writeCert(w, r, id)
}

func (h *Certificates) Patch(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var existing struct {
		CommonName  string
		AgentNodeID *string
		VpnUserID   *string
		CertPEM     *string
		KeyPEM      *string
	}
	err := h.Pool.QueryRow(r.Context(), `
		SELECT "commonName", "agentNodeId", "vpnUserId", "certPem", "keyPem"
		FROM "Certificate" WHERE id = $1`, id,
	).Scan(&existing.CommonName, &existing.AgentNodeID, &existing.VpnUserID, &existing.CertPEM, &existing.KeyPEM)
	if err == pgx.ErrNoRows {
		httpx.WriteError(w, http.StatusNotFound, "Certificate not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	var body map[string]any
	if err := httpx.DecodeJSONLoose(r, &body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}

	_, hasAgent := body["agentNodeId"]
	_, hasVpnUser := body["vpnUserId"]
	_, hasCertPem := body["certPem"]
	_, hasKeyPem := body["keyPem"]
	if !hasAgent && !hasVpnUser && !hasCertPem && !hasKeyPem {
		httpx.WriteError(w, http.StatusBadRequest, "Укажите agentNodeId, vpnUserId, certPem и/или keyPem")
		return
	}

	agentNodeID := existing.AgentNodeID
	if hasAgent {
		agentNodeID = nullableID(body["agentNodeId"])
		if agentNodeID != nil {
			var exists bool
			if err := h.Pool.QueryRow(r.Context(), `SELECT true FROM "AgentNode" WHERE id = $1`, *agentNodeID).Scan(&exists); err != nil || !exists {
				httpx.WriteError(w, http.StatusNotFound, "Agent node not found")
				return
			}
		}
		if h.activeSameCN(r.Context(), existing.CommonName, agentNodeID, id) {
			httpx.WriteError(w, http.StatusConflict, "Another certificate already uses this user and server pair")
			return
		}
	}

	vpnUserID := existing.VpnUserID
	if hasVpnUser {
		vpnUserID = nullableID(body["vpnUserId"])
		if vpnUserID != nil {
			var exists bool
			if err := h.Pool.QueryRow(r.Context(), `SELECT true FROM "VpnUser" WHERE id = $1`, *vpnUserID).Scan(&exists); err != nil || !exists {
				httpx.WriteError(w, http.StatusNotFound, "VPN user not found")
				return
			}
		}
	}

	certPEM := existing.CertPEM
	if hasCertPem {
		raw := strings.TrimSpace(strAny(body["certPem"]))
		if raw == "" {
			certPEM = nil
		} else {
			if !strings.Contains(raw, "BEGIN CERTIFICATE") {
				httpx.WriteError(w, http.StatusBadRequest, "certPem должен быть сертификатом в PEM-формате")
				return
			}
			if cert.HasNegativeSerial(raw) {
				httpx.WriteError(w, http.StatusUnprocessableEntity,
					"Сертификат отклонён: отрицательный serialNumber (например -ABCD...). Выпустите/импортируйте сертификат с положительным serialNumber.")
				return
			}
			certPEM = &raw
		}
	}

	keyPEM := existing.KeyPEM
	if hasKeyPem {
		raw := strings.TrimSpace(strAny(body["keyPem"]))
		if raw == "" {
			keyPEM = nil
		} else {
			if !strings.Contains(raw, "PRIVATE KEY") {
				httpx.WriteError(w, http.StatusBadRequest, "keyPem должен быть приватным ключом в PEM-формате")
				return
			}
			keyPEM = &raw
		}
	}

	if hasVpnUser && vpnUserID != nil {
		checkPEM := ""
		if certPEM != nil {
			checkPEM = *certPEM
		} else if existing.CertPEM != nil {
			checkPEM = *existing.CertPEM
		}
		if checkPEM != "" && cert.IsCAOrSelfSigned(checkPEM) {
			httpx.WriteError(w, http.StatusUnprocessableEntity,
				"К пользователю можно привязать только клиентский сертификат. Корневой сертификат привязывать нельзя.")
			return
		}
	}

	sets := []string{}
	args := []any{}
	n := 1
	if hasAgent {
		sets, args, n = addSet(sets, args, n, `"agentNodeId"`, agentNodeID)
	}
	if hasVpnUser {
		sets, args, n = addSet(sets, args, n, `"vpnUserId"`, vpnUserID)
	}
	if hasCertPem {
		sets, args, n = addSet(sets, args, n, `"certPem"`, certPEM)
	}
	if hasKeyPem {
		sets, args, n = addSet(sets, args, n, `"keyPem"`, keyPEM)
	}
	args = append(args, id)
	_, err = h.Pool.Exec(r.Context(),
		`UPDATE "Certificate" SET `+strings.Join(sets, ", ")+` WHERE id = $`+itoa(n), args...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	nodes := map[string]struct{}{}
	if existing.AgentNodeID != nil {
		nodes[*existing.AgentNodeID] = struct{}{}
	}
	if agentNodeID != nil {
		nodes[*agentNodeID] = struct{}{}
	}
	for nodeID := range nodes {
		_ = paneltasks.EnqueueSnapshotForNode(r.Context(), h.Pool, nodeID)
	}

	h.writeCert(w, r, id)
}

func (h *Certificates) ViewMaterial(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var body struct {
		Kind string `json:"kind"`
	}
	if err := httpx.DecodeJSONLoose(r, &body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}
	kind := strings.ToLower(strings.TrimSpace(body.Kind))
	if kind != "public" && kind != "private" {
		httpx.WriteError(w, http.StatusBadRequest, "kind must be public or private")
		return
	}

	var commonName string
	var certPEM, keyPEM *string
	var createdAt, expiresAt time.Time
	err := h.Pool.QueryRow(r.Context(), `
		SELECT "commonName", "certPem", "keyPem", "createdAt", "expiresAt"
		FROM "Certificate" WHERE id = $1`, id,
	).Scan(&commonName, &certPEM, &keyPEM, &createdAt, &expiresAt)
	if err == pgx.ErrNoRows {
		httpx.WriteError(w, http.StatusNotFound, "Certificate not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	var value string
	label := "Открытый ключ"
	if kind == "public" {
		if certPEM != nil {
			value = *certPEM
		}
	} else {
		label = "Закрытый ключ"
		if keyPEM != nil {
			value = *keyPEM
		}
	}
	if value == "" {
		httpx.WriteError(w, http.StatusNotFound, "Материал недоступен")
		return
	}

	updatedAt := expiresAt
	if updatedAt.IsZero() {
		updatedAt = createdAt
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"kind":       kind,
		"label":      label,
		"pem":        value,
		"commonName": commonName,
		"updatedAt":  updatedAt,
	})
}

func (h *Certificates) MaterialSummary(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var certPEM, keyPEM *string
	var expiresAt time.Time
	var serialNumber string
	err := h.Pool.QueryRow(r.Context(), `
		SELECT "certPem", "keyPem", "expiresAt", "serialNumber"
		FROM "Certificate" WHERE id = $1`, id,
	).Scan(&certPEM, &keyPEM, &expiresAt, &serialNumber)
	if err == pgx.ErrNoRows {
		httpx.WriteError(w, http.StatusNotFound, "Certificate not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	certStr, keyStr := "", ""
	if certPEM != nil {
		certStr = *certPEM
	}
	if keyPEM != nil {
		keyStr = *keyPEM
	}
	summary := cert.BuildMaterialSummary(certStr, keyStr)
	if summary.SerialNumber == "" && serialNumber != "" {
		summary.SerialNumber = serialNumber
	}
	if summary.ValidTo == nil && !expiresAt.IsZero() {
		v := expiresAt.UTC().Format(time.RFC3339)
		summary.ValidTo = &v
	}
	httpx.WriteJSON(w, http.StatusOK, summary)
}

func (h *Certificates) Revoke(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var body struct {
		Reason string `json:"reason"`
	}
	_ = httpx.DecodeJSONLoose(r, &body)

	var rootCaID, agentNodeID *string
	err := h.Pool.QueryRow(r.Context(), `
		SELECT "rootCaId", "agentNodeId" FROM "Certificate" WHERE id = $1`, id,
	).Scan(&rootCaID, &agentNodeID)
	if err == pgx.ErrNoRows {
		httpx.WriteError(w, http.StatusNotFound, "Certificate not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	reason := strings.TrimSpace(body.Reason)
	if reason == "" {
		reason = "manual revoke"
	}

	tag, err := h.Pool.Exec(r.Context(), `
		UPDATE "Certificate" SET "revokedAt" = NOW(), "revokedReason" = $1 WHERE id = $2`, reason, id)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		httpx.WriteError(w, http.StatusNotFound, "Certificate not found")
		return
	}

	if rootCaID != nil {
		_ = paneltasks.EnqueueCrlDeployForRootCa(r.Context(), h.Pool, *rootCaID)
	}
	if agentNodeID != nil {
		_ = paneltasks.EnqueueSnapshotForNode(r.Context(), h.Pool, *agentNodeID)
	}

	var raw []byte
	err = h.Pool.QueryRow(r.Context(), `SELECT row_to_json(c)::text FROM "Certificate" c WHERE c.id = $1`, id).Scan(&raw)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeRawJSON(w, raw)
}

func (h *Certificates) ListRootCA(w http.ResponseWriter, r *http.Request) {
	rows, err := h.Pool.Query(r.Context(), `
		SELECT id, name, "commonName", "isActive", "createdAt", "updatedAt", "certPem"
		FROM "RootCertificateAuthority" ORDER BY "createdAt" DESC`)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	type rootRow struct {
		ID         string     `json:"id"`
		Name       string     `json:"name"`
		CommonName string     `json:"commonName"`
		IsActive   bool       `json:"isActive"`
		CreatedAt  time.Time  `json:"createdAt"`
		UpdatedAt  time.Time  `json:"updatedAt"`
		ExpiresAt  *time.Time `json:"expiresAt"`
	}
	out := []rootRow{}
	for rows.Next() {
		var id, name, commonName, certPEM string
		var isActive bool
		var createdAt, updatedAt time.Time
		if err := rows.Scan(&id, &name, &commonName, &isActive, &createdAt, &updatedAt, &certPEM); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		out = append(out, rootRow{
			ID: id, Name: name, CommonName: commonName, IsActive: isActive,
			CreatedAt: createdAt, UpdatedAt: updatedAt, ExpiresAt: cert.PemExpiryISO(certPEM),
		})
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (h *Certificates) RootCASummary(w http.ResponseWriter, r *http.Request) {
	rootCaID := strings.TrimSpace(chi.URLParam(r, "rootCaId"))
	var id, name, commonName, certPEM string
	var createdAt time.Time
	err := h.Pool.QueryRow(r.Context(), `
		SELECT id, name, "commonName", "certPem", "createdAt"
		FROM "RootCertificateAuthority" WHERE id = $1`, rootCaID,
	).Scan(&id, &name, &commonName, &certPEM, &createdAt)
	if err == pgx.ErrNoRows || certPEM == "" {
		httpx.WriteError(w, http.StatusNotFound, "Корневой сертификат не найден")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	summary := cert.BuildMaterialSummary(certPEM, "")
	resp := map[string]any{
		"id": id, "name": name, "commonName": commonName, "createdAt": createdAt,
	}
	b, _ := json.Marshal(summary)
	_ = json.Unmarshal(b, &resp)
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (h *Certificates) RootCAExport(w http.ResponseWriter, r *http.Request) {
	rootCaID := strings.TrimSpace(chi.URLParam(r, "rootCaId"))
	kind := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("kind")))

	var certPEM, keyPEM string
	err := h.Pool.QueryRow(r.Context(), `
		SELECT "certPem", "keyPem" FROM "RootCertificateAuthority" WHERE id = $1`, rootCaID,
	).Scan(&certPEM, &keyPEM)
	if err == pgx.ErrNoRows {
		httpx.WriteError(w, http.StatusNotFound, "Корневой сертификат не найден")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	switch kind {
	case "root_crt":
		httpx.WriteJSON(w, http.StatusOK, map[string]string{
			"fileName":        "root.crt",
			"contentBase64": base64.StdEncoding.EncodeToString([]byte(certPEM)),
		})
	case "root_key":
		httpx.WriteJSON(w, http.StatusOK, map[string]string{
			"fileName":        "root.key",
			"contentBase64": base64.StdEncoding.EncodeToString([]byte(keyPEM)),
		})
	case "index":
		indexRows, err := h.fetchIndexRows(r.Context(), rootCaID)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		content := cert.BuildIndexTxt(indexRows)
		httpx.WriteJSON(w, http.StatusOK, map[string]string{
			"fileName":        "index.txt",
			"contentBase64": base64.StdEncoding.EncodeToString([]byte(content)),
		})
	case "crl":
		revoked, err := h.fetchRevokedRows(r.Context(), rootCaID)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		pem, genErr := crl.GeneratePEM(certPEM, keyPEM, revoked)
		if genErr != nil {
			httpx.WriteError(w, http.StatusUnprocessableEntity,
				"Невозможно сформировать CRL: корневой сертификат и приватный ключ не совпадают или повреждены.")
			return
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]string{
			"fileName":        "crl.pem",
			"contentBase64": base64.StdEncoding.EncodeToString([]byte(pem)),
		})
	default:
		httpx.WriteError(w, http.StatusBadRequest, "kind должен быть root_crt, root_key, index или crl")
	}
}

func (h *Certificates) RootCAImport(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := httpx.DecodeJSONLoose(r, &body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}

	certPEM := strings.TrimSpace(strAny(body["certPem"]))
	keyPEM := strings.TrimSpace(strAny(body["keyPem"]))
	if certPEM == "" || keyPEM == "" {
		httpx.WriteError(w, http.StatusBadRequest, "certPem and keyPem are required")
		return
	}
	if !strings.Contains(certPEM, "BEGIN CERTIFICATE") || !strings.Contains(keyPEM, "BEGIN") {
		httpx.WriteError(w, http.StatusBadRequest, "Invalid PEM payload")
		return
	}
	if err := cert.KeysMatch(certPEM, keyPEM); err != nil {
		httpx.WriteError(w, http.StatusUnprocessableEntity, "Импорт невозможен: корневой сертификат и приватный ключ не совпадают.")
		return
	}

	name := strings.TrimSpace(strAny(body["name"]))
	commonName := strings.TrimSpace(strAny(body["commonName"]))
	if commonName == "" {
		if cn, err := cert.SubjectCN(certPEM); err == nil && cn != "" {
			commonName = cn
		} else {
			commonName = "Импортированный корневой сертификат"
		}
	}
	if name == "" {
		name = commonName
	}

	id := newID()
	var isActive bool
	var createdAt, updatedAt time.Time
	err := h.Pool.QueryRow(r.Context(), `
		INSERT INTO "RootCertificateAuthority" (id, name, "commonName", "certPem", "keyPem", "isActive", "createdAt", "updatedAt")
		VALUES ($1, $2, $3, $4, $5, true, NOW(), NOW())
		RETURNING id, name, "commonName", "isActive", "createdAt", "updatedAt", "certPem"`,
		id, name, commonName, certPEM, keyPEM,
	).Scan(&id, &name, &commonName, &isActive, &createdAt, &updatedAt, &certPEM)
	if err != nil {
		if isUniqueViolation(err) {
			httpx.WriteError(w, http.StatusConflict, "Корневой сертификат с таким именем уже существует")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	_ = paneltasks.EnqueueCrlDeployForRootCa(r.Context(), h.Pool, id)

	inventory := map[string]any{}
	issuedText := strings.TrimSpace(strAny(body["issuedList"]))
	if issuedText != "" {
		issued, syncErr := cert.SyncIssuedInventory(r.Context(), h.Pool, id, name, issuedText, nil)
		if syncErr != nil {
			httpx.WriteError(w, http.StatusInternalServerError, syncErr.Error())
			return
		}
		inventory["issued"] = issued
	}
	revokedText := strings.TrimSpace(strAny(body["revokedList"]))
	if revokedText != "" {
		if cert.IsProbablyCrlPem(revokedText) {
			revoked, syncErr := cert.SyncRevokedFromCRL(r.Context(), h.Pool, id, revokedText)
			if syncErr != nil {
				httpx.WriteError(w, http.StatusBadRequest, syncErr.Error())
				return
			}
			inventory["revoked"] = revoked
		} else {
			revoked, syncErr := cert.SyncRevokedInventory(r.Context(), h.Pool, id, name, revokedText)
			if syncErr != nil {
				httpx.WriteError(w, http.StatusInternalServerError, syncErr.Error())
				return
			}
			inventory["revoked"] = revoked
		}
	}

	resp := map[string]any{
		"id": id, "name": name, "commonName": commonName, "isActive": isActive,
		"createdAt": createdAt, "updatedAt": updatedAt,
		"expiresAt": cert.PemExpiryISO(certPEM),
		"inventory": inventory,
	}
	httpx.WriteJSON(w, http.StatusCreated, resp)
}

func (h *Certificates) RootCAGenerate(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := httpx.DecodeJSONLoose(r, &body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}

	name := strings.TrimSpace(strAny(body["name"]))
	commonName := strings.TrimSpace(strAny(body["commonName"]))
	if name == "" || commonName == "" {
		httpx.WriteError(w, http.StatusBadRequest, "name and commonName are required")
		return
	}

	days := 3650
	if v := strAny(body["days"]); v != "" {
		if n, err := parseIntDefault(v, 3650); err == nil {
			days = n
		}
	}
	keySize := 4096
	if v := strAny(body["keySize"]); v != "" {
		if n, err := parseIntDefault(v, 4096); err == nil {
			keySize = n
		}
	}

	certPEM, keyPEM, err := cert.GenerateRootCA(commonName, days, keySize)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	id := newID()
	var isActive bool
	var createdAt, updatedAt time.Time
	err = h.Pool.QueryRow(r.Context(), `
		INSERT INTO "RootCertificateAuthority" (id, name, "commonName", "certPem", "keyPem", "isActive", "createdAt", "updatedAt")
		VALUES ($1, $2, $3, $4, $5, true, NOW(), NOW())
		RETURNING id, name, "commonName", "isActive", "createdAt", "updatedAt", "certPem"`,
		id, name, commonName, certPEM, keyPEM,
	).Scan(&id, &name, &commonName, &isActive, &createdAt, &updatedAt, &certPEM)
	if err != nil {
		if isUniqueViolation(err) {
			err = h.Pool.QueryRow(r.Context(), `
				SELECT id, name, "commonName", "isActive", "createdAt", "updatedAt", "certPem"
				FROM "RootCertificateAuthority" WHERE name = $1`, name,
			).Scan(&id, &name, &commonName, &isActive, &createdAt, &updatedAt, &certPEM)
			if err != nil {
				httpx.WriteError(w, http.StatusConflict, "Корневой сертификат с таким именем уже существует")
				return
			}
			httpx.WriteJSON(w, http.StatusOK, map[string]any{
				"id": id, "name": name, "commonName": commonName, "isActive": isActive,
				"createdAt": createdAt, "updatedAt": updatedAt,
				"expiresAt": cert.PemExpiryISO(certPEM), "existing": true,
			})
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	_ = paneltasks.EnqueueCrlDeployForRootCa(r.Context(), h.Pool, id)

	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"id": id, "name": name, "commonName": commonName, "isActive": isActive,
		"createdAt": createdAt, "updatedAt": updatedAt,
		"expiresAt": cert.PemExpiryISO(certPEM),
	})
}

func (h *Certificates) RootCAImportIndex(w http.ResponseWriter, r *http.Request) {
	rootCaID := strings.TrimSpace(chi.URLParam(r, "rootCaId"))
	if rootCaID == "" {
		httpx.WriteError(w, http.StatusBadRequest, "rootCaId is required")
		return
	}

	var body map[string]any
	if err := httpx.DecodeJSONLoose(r, &body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}
	issuedList := strings.TrimSpace(strAny(body["issuedList"]))
	if issuedList == "" {
		httpx.WriteError(w, http.StatusBadRequest, "Требуется содержимое index.txt (issuedList)")
		return
	}

	var exists bool
	err := h.Pool.QueryRow(r.Context(), `SELECT true FROM "RootCertificateAuthority" WHERE id = $1`, rootCaID).Scan(&exists)
	if err == pgx.ErrNoRows {
		httpx.WriteError(w, http.StatusNotFound, "Корневой сертификат не найден")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !exists {
		httpx.WriteError(w, http.StatusNotFound, "Корневой сертификат не найден")
		return
	}

	var agentNodeID *string
	if s := strings.TrimSpace(strAny(body["agentNodeId"])); s != "" {
		var nodeExists bool
		if err := h.Pool.QueryRow(r.Context(), `SELECT true FROM "AgentNode" WHERE id = $1`, s).Scan(&nodeExists); err != nil || !nodeExists {
			httpx.WriteError(w, http.StatusNotFound, "Сервер не найден")
			return
		}
		agentNodeID = &s
	}

	var rootName string
	if err := h.Pool.QueryRow(r.Context(), `SELECT name FROM "RootCertificateAuthority" WHERE id = $1`, rootCaID).Scan(&rootName); err != nil {
		if err == pgx.ErrNoRows {
			httpx.WriteError(w, http.StatusNotFound, "Корневой сертификат не найден")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	issued, syncErr := cert.SyncIssuedInventory(r.Context(), h.Pool, rootCaID, rootName, issuedList, agentNodeID)
	if syncErr != nil {
		httpx.WriteError(w, http.StatusInternalServerError, syncErr.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "issued": issued})
}

func (h *Certificates) writeCert(w http.ResponseWriter, r *http.Request, id string) {
	raw, err := h.certJSON(r.Context(), id)
	if err == pgx.ErrNoRows {
		httpx.WriteError(w, http.StatusNotFound, "Certificate not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeRawJSON(w, raw)
}

func (h *Certificates) certJSON(ctx context.Context, id string) ([]byte, error) {
	var raw []byte
	err := h.Pool.QueryRow(ctx, `
		SELECT row_to_json(x)::text FROM (
			SELECT c.*,
				CASE WHEN rc.id IS NOT NULL THEN json_build_object(
					'id', rc.id, 'name', rc.name, 'commonName', rc."commonName"
				) END AS "rootCa",
				CASE WHEN n.id IS NOT NULL THEN json_build_object(
					'id', n.id, 'name', n.name, 'protocol', n.protocol, 'host', n.host, 'port', n.port
				) END AS "agentNode",
				CASE WHEN u.id IS NOT NULL THEN json_build_object(
					'id', u.id, 'fullName', u."fullName", 'email', u.email
				) END AS "vpnUser"
			FROM "Certificate" c
			LEFT JOIN "RootCertificateAuthority" rc ON rc.id = c."rootCaId"
			LEFT JOIN "AgentNode" n ON n.id = c."agentNodeId"
			LEFT JOIN "VpnUser" u ON u.id = c."vpnUserId"
			WHERE c.id = $1
		) x`, id).Scan(&raw)
	return raw, err
}

func (h *Certificates) activeSameCN(ctx context.Context, commonName string, agentNodeID *string, excludeID string) bool {
	var id string
	q := `SELECT id FROM "Certificate"
		WHERE "commonName" = $1 AND "agentNodeId" IS NOT DISTINCT FROM $2 AND "revokedAt" IS NULL`
	args := []any{commonName, agentNodeID}
	if excludeID != "" {
		q += ` AND id <> $3`
		args = append(args, excludeID)
	}
	err := h.Pool.QueryRow(ctx, q, args...).Scan(&id)
	return err == nil
}

func (h *Certificates) fetchIndexRows(ctx context.Context, rootCaID string) ([]cert.IndexCertRow, error) {
	rows, err := h.Pool.Query(ctx, `
		SELECT "commonName", "serialNumber", "expiresAt", "revokedAt"
		FROM "Certificate" WHERE "rootCaId" = $1 ORDER BY "createdAt" ASC`, rootCaID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []cert.IndexCertRow{}
	for rows.Next() {
		var row cert.IndexCertRow
		if err := rows.Scan(&row.CommonName, &row.SerialNumber, &row.ExpiresAt, &row.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func (h *Certificates) fetchRevokedRows(ctx context.Context, rootCaID string) ([]crl.RevokedRow, error) {
	rows, err := h.Pool.Query(ctx, `
		SELECT "serialNumber", "commonName", "expiresAt", "revokedAt"
		FROM "Certificate" WHERE "rootCaId" = $1 AND "revokedAt" IS NOT NULL`, rootCaID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []crl.RevokedRow{}
	for rows.Next() {
		var row crl.RevokedRow
		if err := rows.Scan(&row.SerialNumber, &row.CommonName, &row.ExpiresAt, &row.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func nullableID(v any) *string {
	s := strings.TrimSpace(strAny(v))
	if s == "" {
		return nil
	}
	return &s
}

func parseIntDefault(s string, def int) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return def, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def, err
	}
	return n, nil
}
