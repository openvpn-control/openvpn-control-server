package panel

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/segmentio/ksuid"
)

var (
	dhPemRe     = regexp.MustCompile(`(?i)BEGIN (DH PARAMETERS|X9\.42 DH PARAMETERS)`)
	tlsAuthPemRe = regexp.MustCompile(`(?i)BEGIN OpenVPN Static key V1`)
)

func materialPemFingerprintSha256(pem string) string {
	sum := sha256.Sum256([]byte(pem))
	hexStr := strings.ToUpper(hex.EncodeToString(sum[:]))
	var parts []string
	for i := 0; i < len(hexStr); i += 2 {
		parts = append(parts, hexStr[i:i+2])
	}
	return strings.Join(parts, ":")
}

func ValidateMaterialPem(kind, rawPem string) (string, error) {
	k := strings.TrimSpace(kind)
	t := strings.TrimSpace(rawPem)
	if !strings.Contains(t, "BEGIN") {
		return "", fmt.Errorf("Ожидается текст в формате PEM")
	}
	switch k {
	case "dh":
		if !dhPemRe.MatchString(t) {
			return "", fmt.Errorf("Для DH нужен PEM с BEGIN DH PARAMETERS (openssl dhparam)")
		}
	case "tls_auth":
		if !tlsAuthPemRe.MatchString(t) {
			return "", fmt.Errorf("Для tls-auth нужен файл ключа OpenVPN (ta.key)")
		}
	default:
		return "", fmt.Errorf("kind должен быть dh или tls_auth")
	}
	if strings.HasSuffix(t, "\n") {
		return t, nil
	}
	return t + "\n", nil
}

type MaterialRow struct {
	ID                string `json:"id"`
	Kind              string `json:"kind"`
	Label             any    `json:"label"`
	CreatedAt         any    `json:"createdAt"`
	SizeBytes         int    `json:"sizeBytes"`
	FingerprintSha256 string `json:"fingerprintSha256"`
}

func ListNodeOpenvpnMaterials(ctx context.Context, pool *pgxpool.Pool, agentNodeID, kindFilter string) ([]MaterialRow, error) {
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT true FROM "AgentNode" WHERE id = $1`, agentNodeID).Scan(&exists); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	query := `
		SELECT id, kind, label, "createdAt", pem FROM "AgentNodeOpenvpnMaterial"
		WHERE "agentNodeId" = $1`
	args := []any{agentNodeID}
	if kindFilter != "" {
		query += ` AND kind = $2`
		args = append(args, kindFilter)
	}
	query += ` ORDER BY "createdAt" DESC`
	rows, err := pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]MaterialRow, 0)
	for rows.Next() {
		var id, kind, pem string
		var label *string
		var createdAt any
		if err := rows.Scan(&id, &kind, &label, &createdAt, &pem); err != nil {
			return nil, err
		}
		var labelVal any
		if label != nil {
			labelVal = *label
		}
		out = append(out, MaterialRow{
			ID: id, Kind: kind, Label: labelVal, CreatedAt: createdAt,
			SizeBytes: len(pem), FingerprintSha256: materialPemFingerprintSha256(pem),
		})
	}
	return out, nil
}

type CreatedMaterial struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Label     any    `json:"label"`
	CreatedAt any    `json:"createdAt"`
}

func CreateNodeOpenvpnMaterial(ctx context.Context, pool *pgxpool.Pool, agentNodeID, kind, label string, pemFromUpload *string) (*CreatedMaterial, error) {
	k := strings.TrimSpace(kind)
	if k != "dh" && k != "tls_auth" {
		return nil, fmt.Errorf("kind должен быть dh или tls_auth")
	}
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT true FROM "AgentNode" WHERE id = $1`, agentNodeID).Scan(&exists); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("Узел не найден")
		}
		return nil, err
	}
	var pem string
	var err error
	if pemFromUpload != nil && strings.TrimSpace(*pemFromUpload) != "" {
		pem, err = ValidateMaterialPem(k, *pemFromUpload)
		if err != nil {
			return nil, err
		}
	} else if k == "dh" {
		pem, err = generateDhPem2048()
		if err != nil {
			return nil, err
		}
	} else {
		pem, err = generateTlsAuthKeyPem()
		if err != nil {
			return nil, err
		}
	}
	var labelPtr *string
	if strings.TrimSpace(label) != "" {
		l := strings.TrimSpace(label)
		labelPtr = &l
	}
	id := ksuid.New().String()
	var created CreatedMaterial
	err = pool.QueryRow(ctx, `
		INSERT INTO "AgentNodeOpenvpnMaterial" (id, "agentNodeId", kind, label, pem, "createdAt")
		VALUES ($1, $2, $3, $4, $5, NOW())
		RETURNING id, kind, label, "createdAt"`, id, agentNodeID, k, labelPtr, pem,
	).Scan(&created.ID, &created.Kind, &created.Label, &created.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &created, nil
}

func DeleteNodeOpenvpnMaterial(ctx context.Context, pool *pgxpool.Pool, agentNodeID, materialID string) (bool, error) {
	var found bool
	err := pool.QueryRow(ctx, `
		SELECT true FROM "AgentNodeOpenvpnMaterial" WHERE id = $1 AND "agentNodeId" = $2`,
		materialID, agentNodeID).Scan(&found)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	_, err = pool.Exec(ctx, `DELETE FROM "AgentNodeOpenvpnMaterial" WHERE id = $1`, materialID)
	if err != nil {
		return false, err
	}
	settings, _, err := loadSettingsRow(ctx, pool, agentNodeID)
	if err == nil && settings != nil {
		changed := false
		if asString(settings["panelDhMaterialId"]) == materialID {
			settings["panelDhMaterialId"] = ""
			changed = true
		}
		if asString(settings["panelTlsAuthMaterialId"]) == materialID {
			settings["panelTlsAuthMaterialId"] = ""
			changed = true
		}
		if changed {
			_ = upsertSettings(ctx, pool, agentNodeID, settings, nil)
		}
	}
	return true, nil
}

func generateDhPem2048() (string, error) {
	out, err := exec.Command("openssl", "dhparam", "-outform", "PEM", "2048").Output()
	if err != nil {
		return "", fmt.Errorf("openssl dhparam: %w", err)
	}
	return string(out), nil
}

func generateTlsAuthKeyPem() (string, error) {
	f, err := os.CreateTemp("", "ov-ta-*.key")
	if err != nil {
		return generateTlsAuthStaticKeyFallback(), nil
	}
	tmp := f.Name()
	_ = f.Close()
	defer func() { _ = os.Remove(tmp) }()
	if err := exec.Command("openvpn", "--genkey", "secret", tmp).Run(); err != nil {
		return generateTlsAuthStaticKeyFallback(), nil
	}
	data, err := os.ReadFile(tmp)
	if err != nil {
		return generateTlsAuthStaticKeyFallback(), nil
	}
	return string(data), nil
}

func generateTlsAuthStaticKeyFallback() string {
	buf := make([]byte, 256)
	_, _ = rand.Read(buf)
	var lines []string
	for i := 0; i < 16; i++ {
		lines = append(lines, hex.EncodeToString(buf[i*16:(i+1)*16]))
	}
	return "#\n# 2048 bit OpenVPN static key\n#\n-----BEGIN OpenVPN Static key V1-----\n" +
		strings.Join(lines, "\n") + "\n-----END OpenVPN Static key V1-----\n"
}
