package panel

import (
	"context"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/segmentio/ksuid"

	"github.com/openvpn-control/openvpn-control-server/backend/internal/cert"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/paneltasks"
)

var cnSanitizeRe = regexp.MustCompile(`[^\w.\-:@]`)

type IssueServerCertInput struct {
	AgentNodeID        string
	RootCaID           string
	CommonName         string
	ValidityDays       int
	KeySize            int
	SignatureAlgorithm string
}

type ServerCertView struct {
	ID             string         `json:"id"`
	CommonName     string         `json:"commonName"`
	IssuedBy       string         `json:"issuedBy"`
	RootCaID       string         `json:"rootCaId"`
	AgentNodeID    string         `json:"agentNodeId"`
	VpnUserID      *string        `json:"vpnUserId"`
	SerialNumber   string         `json:"serialNumber"`
	ExpiresAt      time.Time      `json:"expiresAt"`
	CreatedAt      time.Time      `json:"createdAt"`
	RevokedAt      *time.Time     `json:"revokedAt"`
	RevokedReason  *string        `json:"revokedReason"`
	RootCa         map[string]any `json:"rootCa"`
	AgentNode      map[string]any `json:"agentNode"`
	HasKeyMaterial bool           `json:"hasKeyMaterial"`
}

func rootCaRemainingValidityDays(certPEM string) int {
	c, err := cert.ParseCertificate(certPEM)
	if err != nil {
		return 0
	}
	days := int(math.Ceil(time.Until(c.NotAfter).Hours() / 24))
	if days < 0 {
		return 0
	}
	return days
}

func normalizeServerCN(raw, fallback string) string {
	cn := strings.TrimSpace(raw)
	if cn == "" {
		cn = fallback
	}
	cn = cnSanitizeRe.ReplaceAllString(cn, "_")
	if len(cn) > 64 {
		cn = cn[:64]
	}
	return cn
}

func IssueServerCertificateForAgentNode(ctx context.Context, pool *pgxpool.Pool, in IssueServerCertInput) (*ServerCertView, error) {
	var nodeName string
	err := pool.QueryRow(ctx, `SELECT name FROM "AgentNode" WHERE id = $1`, in.AgentNodeID).Scan(&nodeName)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("Узел не найден")
	}
	if err != nil {
		return nil, err
	}
	rid := strings.TrimSpace(in.RootCaID)
	if rid == "" {
		return nil, fmt.Errorf("Выберите корневой сертификат")
	}
	var rootName, rootCertPEM, rootKeyPEM string
	err = pool.QueryRow(ctx, `
		SELECT name, "certPem", "keyPem" FROM "RootCertificateAuthority" WHERE id = $1`, rid,
	).Scan(&rootName, &rootCertPEM, &rootKeyPEM)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("Корневой сертификат не найден")
	}
	if err != nil {
		return nil, err
	}
	var existingID string
	err = pool.QueryRow(ctx, `
		SELECT id FROM "Certificate"
		WHERE "agentNodeId" = $1 AND "rootCaId" = $2 AND "vpnUserId" IS NULL AND "revokedAt" IS NULL`,
		in.AgentNodeID, rid).Scan(&existingID)
	if err == nil {
		return nil, fmt.Errorf("На узле уже есть сертификат сервера. Удалите его перед выпуском нового.")
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	cn := normalizeServerCN(in.CommonName, fmt.Sprintf("server:%s", nodeName))
	if cn == "" {
		cn = normalizeServerCN("", fmt.Sprintf("server-%s", in.AgentNodeID[:min(8, len(in.AgentNodeID))]))
	}
	maxByRoot := rootCaRemainingValidityDays(rootCertPEM)
	if maxByRoot < 1 {
		return nil, fmt.Errorf("Срок действия корневого сертификата истёк или истекает сегодня")
	}
	requested := in.ValidityDays
	if requested < 1 {
		requested = 825
	}
	if requested > 3650 {
		requested = 3650
	}
	days := requested
	if days > maxByRoot {
		days = maxByRoot
	}
	if days > 3650 {
		days = 3650
	}
	certPEM, keyPEM, expiresAt, serial, err := cert.IssueLeaf(rootCertPEM, rootKeyPEM, cn, days)
	if err != nil {
		return nil, err
	}
	id := ksuid.New().String()
	return insertServerCertView(ctx, pool, id, cn, rootName, rid, in.AgentNodeID, certPEM, keyPEM, expiresAt, serial)
}

type ImportServerCertInput struct {
	AgentNodeID string
	RootCaID    string
	CertPEM     string
	KeyPEM      string
}

func ImportServerCertificateForAgentNode(ctx context.Context, pool *pgxpool.Pool, in ImportServerCertInput) (*ServerCertView, error) {
	var nodeName string
	err := pool.QueryRow(ctx, `SELECT name FROM "AgentNode" WHERE id = $1`, in.AgentNodeID).Scan(&nodeName)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("Узел не найден")
	}
	if err != nil {
		return nil, err
	}
	rid := strings.TrimSpace(in.RootCaID)
	if rid == "" {
		return nil, fmt.Errorf("Выберите корневой сертификат")
	}
	var rootName, rootCertPEM string
	err = pool.QueryRow(ctx, `SELECT name, "certPem" FROM "RootCertificateAuthority" WHERE id = $1`, rid).Scan(&rootName, &rootCertPEM)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("Корневой сертификат не найден")
	}
	if err != nil {
		return nil, err
	}
	certPemTrim := strings.TrimSpace(in.CertPEM)
	keyPemTrim := strings.TrimSpace(in.KeyPEM)
	if !strings.Contains(certPemTrim, "BEGIN CERTIFICATE") {
		return nil, fmt.Errorf("Ожидается PEM сертификата")
	}
	if !strings.Contains(keyPemTrim, "BEGIN") {
		return nil, fmt.Errorf("Ожидается PEM закрытого ключа")
	}
	if err := cert.KeysMatch(certPemTrim, keyPemTrim); err != nil {
		return nil, err
	}
	if cert.HasNegativeSerial(certPemTrim) {
		return nil, fmt.Errorf("Импортируемый сертификат сервера отклонён: отрицательный serialNumber. Используйте сертификат с положительным serialNumber.")
	}
	if err := cert.VerifyIssuedByRoot(certPemTrim, rootCertPEM); err != nil {
		return nil, fmt.Errorf("Сертификат не выпущен выбранным корневым сертификатом")
	}
	leaf, err := cert.ParseCertificate(certPemTrim)
	if err != nil {
		return nil, err
	}
	cn, _ := cert.SubjectCN(certPemTrim)
	cnNorm := normalizeServerCN(cn, fmt.Sprintf("server:%s", nodeName))
	if cnNorm == "" {
		cnNorm = normalizeServerCN("", fmt.Sprintf("server-%s", in.AgentNodeID[:min(8, len(in.AgentNodeID))]))
	}
	serialNumber := cert.SerialHex(leaf)
	if serialNumber == "" {
		serialNumber = ksuid.New().String()
	}
	certNorm := cert.EnsurePEMNewline(certPemTrim)
	keyNorm := cert.EnsurePEMNewline(keyPemTrim)
	pemNorm := normalizeCertPemForCompare(certNorm)

	if view, err := tryImportBySerial(ctx, pool, serialNumber, in.AgentNodeID, pemNorm, certNorm, keyNorm, cnNorm, rootName, rid, leaf.NotAfter); err != nil {
		return nil, err
	} else if view != nil {
		return view, nil
	}
	if view, err := tryImportByCN(ctx, pool, cnNorm, in.AgentNodeID, serialNumber, pemNorm, certNorm, keyNorm, rootName, rid, leaf.NotAfter); err != nil {
		return nil, err
	} else if view != nil {
		return view, nil
	}
	var otherActive string
	err = pool.QueryRow(ctx, `
		SELECT id FROM "Certificate"
		WHERE "agentNodeId" = $1 AND "rootCaId" = $2 AND "vpnUserId" IS NULL AND "revokedAt" IS NULL`,
		in.AgentNodeID, rid).Scan(&otherActive)
	if err == nil {
		return nil, fmt.Errorf("На узле уже есть сертификат сервера. Удалите его перед импортом нового.")
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	id := ksuid.New().String()
	return insertServerCertView(ctx, pool, id, cnNorm, rootName, rid, in.AgentNodeID, certNorm, keyNorm, leaf.NotAfter, serialNumber)
}

func DeleteServerCertificateForAgentNode(ctx context.Context, pool *pgxpool.Pool, agentNodeID string) error {
	id := strings.TrimSpace(agentNodeID)
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT true FROM "AgentNode" WHERE id = $1`, id).Scan(&exists); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("Узел не найден")
		}
		return err
	}
	prev, _, err := loadSettingsRow(ctx, pool, id)
	if errors.Is(err, pgx.ErrNoRows) {
		prev = map[string]any{}
	} else if err != nil {
		return err
	}
	rootID := strings.TrimSpace(asString(prev["panelRootCaId"]))
	if rootID == "" {
		return fmt.Errorf("Для этого сервера не задан корневой сертификат")
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	_, _ = tx.Exec(ctx, `
		DELETE FROM "Certificate" WHERE "agentNodeId" = $1 AND "rootCaId" = $2 AND "vpnUserId" IS NULL`, id, rootID)
	next := mergeSettings(prev, map[string]any{"panelServerCertId": ""})
	if err := upsertSettingsTx(ctx, tx, id, next); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	settings, _, _ := loadSettingsRow(ctx, pool, id)
	if settings == nil {
		settings = next
	}
	return paneltasks.EnqueueOpenvpnMaterialSyncTasks(ctx, pool, id, settings)
}

func normalizeCertPemForCompare(pem string) string {
	s := strings.ReplaceAll(pem, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return strings.TrimSpace(s)
}

func insertServerCertView(ctx context.Context, pool *pgxpool.Pool, id, cn, issuedBy, rootCaID, agentNodeID, certPEM, keyPEM string, expiresAt time.Time, serial string) (*ServerCertView, error) {
	_, err := pool.Exec(ctx, `
		INSERT INTO "Certificate" (
			id, "commonName", "issuedBy", "rootCaId", "agentNodeId", "vpnUserId",
			"certPem", "keyPem", "expiresAt", "serialNumber", "createdAt"
		) VALUES ($1, $2, $3, $4, $5, NULL, $6, $7, $8, $9, NOW())`,
		id, cn, issuedBy, rootCaID, agentNodeID, certPEM, keyPEM, expiresAt, serial)
	if err != nil {
		return nil, err
	}
	return fetchServerCertView(ctx, pool, id)
}

func fetchServerCertView(ctx context.Context, pool *pgxpool.Pool, id string) (*ServerCertView, error) {
	var v ServerCertView
	var rootID, rootName, rootCN, nodeID, nodeName string
	var certPEM, keyPEM string
	err := pool.QueryRow(ctx, `
		SELECT c.id, c."commonName", c."issuedBy", c."rootCaId", c."agentNodeId", c."serialNumber",
			c."expiresAt", c."createdAt", c."revokedAt", c."revokedReason",
			r.id, r.name, r."commonName", n.id, n.name, c."certPem", c."keyPem"
		FROM "Certificate" c
		INNER JOIN "RootCertificateAuthority" r ON r.id = c."rootCaId"
		INNER JOIN "AgentNode" n ON n.id = c."agentNodeId"
		WHERE c.id = $1`, id,
	).Scan(
		&v.ID, &v.CommonName, &v.IssuedBy, &v.RootCaID, &v.AgentNodeID, &v.SerialNumber,
		&v.ExpiresAt, &v.CreatedAt, &v.RevokedAt, &v.RevokedReason,
		&rootID, &rootName, &rootCN, &nodeID, &nodeName, &certPEM, &keyPEM,
	)
	if err != nil {
		return nil, err
	}
	v.RootCa = map[string]any{"id": rootID, "name": rootName, "commonName": rootCN}
	v.AgentNode = map[string]any{"id": nodeID, "name": nodeName}
	v.HasKeyMaterial = certPEM != "" && keyPEM != ""
	return &v, nil
}

func tryImportBySerial(ctx context.Context, pool *pgxpool.Pool, serial, agentNodeID, pemNorm, certNorm, keyNorm, cnNorm, rootName, rootCaID string, expiresAt time.Time) (*ServerCertView, error) {
	var existingID, existingNode, existingCert string
	var vpnUserID *string
	err := pool.QueryRow(ctx, `
		SELECT id, "agentNodeId", "certPem", "vpnUserId" FROM "Certificate" WHERE "serialNumber" = $1`, serial,
	).Scan(&existingID, &existingNode, &existingCert, &vpnUserID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if normalizeCertPemForCompare(existingCert) != pemNorm {
		return nil, fmt.Errorf("В базе уже есть другой сертификат с тем же серийным номером. Отзовите или удалите старую запись либо используйте другой файл.")
	}
	if existingNode != agentNodeID {
		return nil, fmt.Errorf("Сертификат с этим серийным номером уже привязан к другому узлу")
	}
	if vpnUserID != nil {
		return nil, fmt.Errorf("Сертификат с этим серийным номером зарегистрирован как пользовательский")
	}
	_, err = pool.Exec(ctx, `
		UPDATE "Certificate" SET "certPem" = $2, "keyPem" = $3, "expiresAt" = $4, "commonName" = $5,
			"issuedBy" = $6, "rootCaId" = $7, "revokedAt" = NULL, "revokedReason" = NULL
		WHERE id = $1`, existingID, certNorm, keyNorm, expiresAt, cnNorm, rootName, rootCaID)
	if err != nil {
		return nil, err
	}
	return fetchServerCertView(ctx, pool, existingID)
}

func tryImportByCN(ctx context.Context, pool *pgxpool.Pool, cnNorm, agentNodeID, serial, pemNorm, certNorm, keyNorm, rootName, rootCaID string, expiresAt time.Time) (*ServerCertView, error) {
	var existingID, existingCert string
	var revokedAt *time.Time
	var vpnUserID *string
	err := pool.QueryRow(ctx, `
		SELECT id, "certPem", "vpnUserId", "revokedAt" FROM "Certificate"
		WHERE "commonName" = $1 AND "agentNodeId" = $2 AND "vpnUserId" IS NULL`, cnNorm, agentNodeID,
	).Scan(&existingID, &existingCert, &vpnUserID, &revokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	samePem := normalizeCertPemForCompare(existingCert) == pemNorm
	if samePem {
		if vpnUserID != nil {
			return nil, fmt.Errorf("Сертификат с таким CN зарегистрирован как пользовательский")
		}
	} else if revokedAt == nil {
		return nil, fmt.Errorf("На этом узле уже есть активный сертификат с таким CN.")
	}
	var taken string
	err = pool.QueryRow(ctx, `SELECT id FROM "Certificate" WHERE "serialNumber" = $1 AND id <> $2`, serial, existingID).Scan(&taken)
	if err == nil {
		if samePem {
			return nil, fmt.Errorf("Серийный номер уже занят другой записью в базе. Обратитесь к администратору или удалите конфликтующую запись.")
		}
		return nil, fmt.Errorf("Серийный номер уже занят другой записью. Отзовите или удалите конфликтующий сертификат.")
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	_, err = pool.Exec(ctx, `
		UPDATE "Certificate" SET "serialNumber" = $2, "certPem" = $3, "keyPem" = $4, "expiresAt" = $5,
			"issuedBy" = $6, "rootCaId" = $7, "vpnUserId" = NULL, "revokedAt" = NULL, "revokedReason" = NULL
		WHERE id = $1`, existingID, serial, certNorm, keyNorm, expiresAt, rootName, rootCaID)
	if err != nil {
		return nil, err
	}
	return fetchServerCertView(ctx, pool, existingID)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
