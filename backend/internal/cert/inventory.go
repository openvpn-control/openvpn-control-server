package cert

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/segmentio/ksuid"
)

const defaultImportedExpiry = 10 * 365 * 24 * time.Hour

var (
	easyRsaIndexLine = regexp.MustCompile(`(?i)^([VRE])\s+(\d{12}Z)(?:\s+(\d{12}Z))?\s+([0-9A-Fa-f]+)\s+`)
	cnFromDN         = regexp.MustCompile(`(?i)(?:/CN=|CN=)([^/\n,]+)`)
	inventoryStatus  = regexp.MustCompile(`(?i)^[VRE]$`)
)

// IssuedSyncStats mirrors Node syncIssuedInventory counters.
type IssuedSyncStats struct {
	Created     int `json:"created"`
	Skipped     int `json:"skipped"`
	Reactivated int `json:"reactivated"`
	Updated     int `json:"updated"`
}

// RevokedSyncStats mirrors Node syncRevokedInventory counters.
type RevokedSyncStats struct {
	Updated int `json:"updated"`
	Created int `json:"created"`
	Skipped int `json:"skipped"`
}

// RevokedCrlSyncStats mirrors Node syncRevokedFromCrl counters.
type RevokedCrlSyncStats struct {
	Revoked  int `json:"revoked"`
	Skipped  int `json:"skipped"`
	NotInDb  int `json:"notInDb"`
}

type easyRsaIndexEntry struct {
	status        string // V, R, E
	expiryUtc     string
	revocationUtc string
	serialHex     string
	cn            string
}

type inventoryLineEntry struct {
	status    string // V, R, E or empty
	cn        string
	serialHex string
	expiryUtc string
}

// ParseEasyRsaIndexLine parses OpenSSL Easy-RSA / pki.index.txt lines.
func ParseEasyRsaIndexLine(raw string) *easyRsaIndexEntry {
	line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}
	m := easyRsaIndexLine.FindStringSubmatch(line)
	if m == nil {
		return nil
	}
	serialHex := NormalizeSerialHex(m[4])
	if serialHex == "" {
		return nil
	}
	rest := line[len(m[0]):]
	cn := subjectCNFromDN(rest)
	if cn == "" {
		return nil
	}
	return &easyRsaIndexEntry{
		status:        strings.ToUpper(m[1]),
		expiryUtc:     m[2],
		revocationUtc: m[3],
		serialHex:     serialHex,
		cn:            cn,
	}
}

// ParseInventoryLine parses legacy tab-separated or CN-only inventory lines.
func ParseInventoryLine(raw string) *inventoryLineEntry {
	t := strings.TrimSpace(raw)
	if t == "" || strings.HasPrefix(t, "#") {
		return nil
	}
	if strings.Contains(t, "\t") {
		parts := strings.Split(t, "\t")
		status := parts[0]
		if !inventoryStatus.MatchString(status) {
			return nil
		}
		dn := parts[len(parts)-1]
		cn := subjectCNFromDN(dn)
		if cn == "" {
			return nil
		}
		return &inventoryLineEntry{status: strings.ToUpper(status), cn: cn}
	}
	if cn := subjectCNFromDN(t); cn != "" {
		return &inventoryLineEntry{cn: cn}
	}
	return &inventoryLineEntry{cn: t}
}

func subjectCNFromDN(s string) string {
	m := cnFromDN.FindStringSubmatch(s)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(m[1])
}

// OpenSSLUtcTimeToDate converts YYMMDDHHMMSSZ to time.Time (OpenSSL index format).
func OpenSSLUtcTimeToDate(utc string) *time.Time {
	if len(utc) < 12 {
		return nil
	}
	yy, _ := parseInt2(utc[0:2])
	year := 2000 + yy
	if yy >= 50 {
		year = 1900 + yy
	}
	mon, _ := parseInt2(utc[2:4])
	day, _ := parseInt2(utc[4:6])
	hh, _ := parseInt2(utc[6:8])
	mm, _ := parseInt2(utc[8:10])
	ss, _ := parseInt2(utc[10:12])
	t := time.Date(year, time.Month(mon), day, hh, mm, ss, 0, time.UTC)
	if t.IsZero() {
		return nil
	}
	return &t
}

func parseInt2(s string) (int, error) {
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}

type issuedMeta struct {
	serialHex string
	expiresAt time.Time
}

// SyncIssuedInventory imports issued certificates from index.txt text (Node syncIssuedInventory).
func SyncIssuedInventory(ctx context.Context, pool *pgxpool.Pool, rootCaID, issuedByName, text string, agentNodeID *string) (IssuedSyncStats, error) {
	stats := IssuedSyncStats{}
	if strings.TrimSpace(text) == "" {
		return stats, nil
	}

	byCN := map[string]issuedMeta{}
	defaultExp := time.Now().Add(defaultImportedExpiry)

	for _, raw := range strings.Split(text, "\n") {
		raw = strings.TrimSuffix(raw, "\r")
		if easy := ParseEasyRsaIndexLine(raw); easy != nil {
			if easy.status == "R" {
				continue
			}
			if easy.status != "V" && easy.status != "E" {
				continue
			}
			exp := defaultExp
			if d := OpenSSLUtcTimeToDate(easy.expiryUtc); d != nil {
				exp = *d
			}
			byCN[easy.cn] = issuedMeta{serialHex: easy.serialHex, expiresAt: exp}
			continue
		}

		p := ParseInventoryLine(raw)
		if p == nil || p.cn == "" {
			continue
		}
		if p.status == "R" {
			continue
		}
		if p.status != "" && p.status != "V" && p.status != "E" {
			continue
		}
		if _, ok := byCN[p.cn]; !ok {
			byCN[p.cn] = issuedMeta{expiresAt: defaultExp}
		}
	}

	for cn, meta := range byCN {
		serialNumber := meta.serialHex
		if serialNumber == "" {
			serialNumber = ksuid.New().String()
		}

		existing, err := findCertByCNAndNode(ctx, pool, cn, agentNodeID)
		if err != nil && err != pgx.ErrNoRows {
			return stats, err
		}

		if existing != nil {
			if existing.rootCaID != rootCaID {
				stats.Skipped++
				continue
			}
			dataSerial := serialNumber
			dataExp := meta.expiresAt
			if existing.revokedAt != nil {
				_, err := pool.Exec(ctx, `
					UPDATE "Certificate"
					SET "serialNumber" = $1, "expiresAt" = $2, "issuedBy" = $3,
						"revokedAt" = NULL, "revokedReason" = NULL
					WHERE id = $4`,
					dataSerial, dataExp, issuedByName, existing.id,
				)
				if err != nil {
					stats.Skipped++
					continue
				}
				stats.Reactivated++
				continue
			}

			serialChanged := NormalizeSerialHex(existing.serialNumber) != NormalizeSerialHex(serialNumber)
			expChanged := !existing.expiresAt.Equal(meta.expiresAt)
			if serialChanged || expChanged {
				_, err := pool.Exec(ctx, `
					UPDATE "Certificate"
					SET "serialNumber" = $1, "expiresAt" = $2, "issuedBy" = $3
					WHERE id = $4`,
					dataSerial, dataExp, issuedByName, existing.id,
				)
				if err != nil {
					stats.Skipped++
					continue
				}
				stats.Updated++
				continue
			}
			stats.Skipped++
			continue
		}

		id := ksuid.New().String()
		_, err = pool.Exec(ctx, `
			INSERT INTO "Certificate" (
				id, "commonName", "serialNumber", "issuedBy", "rootCaId", "agentNodeId", "expiresAt", "createdAt"
			) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())`,
			id, cn, serialNumber, issuedByName, rootCaID, agentNodeID, meta.expiresAt,
		)
		if err != nil {
			stats.Skipped++
			continue
		}
		stats.Created++
	}

	return stats, nil
}

type certRow struct {
	id           string
	rootCaID     string
	serialNumber string
	expiresAt    time.Time
	revokedAt    *time.Time
}

func findCertByCNAndNode(ctx context.Context, pool *pgxpool.Pool, cn string, agentNodeID *string) (*certRow, error) {
	var row certRow
	var revokedAt *time.Time
	var rootCaID *string

	if agentNodeID == nil {
		err := pool.QueryRow(ctx, `
			SELECT id, "rootCaId", "serialNumber", "expiresAt", "revokedAt"
			FROM "Certificate"
			WHERE "commonName" = $1 AND "agentNodeId" IS NULL
			LIMIT 1`, cn,
		).Scan(&row.id, &rootCaID, &row.serialNumber, &row.expiresAt, &revokedAt)
		if err != nil {
			return nil, err
		}
	} else {
		err := pool.QueryRow(ctx, `
			SELECT id, "rootCaId", "serialNumber", "expiresAt", "revokedAt"
			FROM "Certificate"
			WHERE "commonName" = $1 AND "agentNodeId" = $2
			LIMIT 1`, cn, *agentNodeID,
		).Scan(&row.id, &rootCaID, &row.serialNumber, &row.expiresAt, &revokedAt)
		if err != nil {
			return nil, err
		}
	}
	row.revokedAt = revokedAt
	if rootCaID != nil {
		row.rootCaID = *rootCaID
	}
	return &row, nil
}

var (
	crlPEMHeader1 = regexp.MustCompile(`(?i)BEGIN\s+X509\s+CRL`)
	crlPEMHeader2 = regexp.MustCompile(`(?i)BEGIN\s+CERTIFICATE\s+REVOCATION\s+LIST`)
)

// IsProbablyCrlPem detects PEM CRL payloads.
func IsProbablyCrlPem(text string) bool {
	t := strings.TrimSpace(text)
	return crlPEMHeader1.MatchString(t) || crlPEMHeader2.MatchString(t)
}

// RevokedSerialSetFromCRL extracts normalized serial hex set from a PEM CRL.
func RevokedSerialSetFromCRL(pemText string) (map[string]struct{}, error) {
	rest := []byte(strings.TrimSpace(pemText))
	set := map[string]struct{}{}
	var der []byte
	for len(rest) > 0 {
		block, rem := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = rem
		if block.Type == "X509 CRL" {
			der = block.Bytes
			break
		}
	}
	if len(der) == 0 {
		return nil, fmt.Errorf("Не удалось разобрать CRL (ожидается PEM crl.pem)")
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, fmt.Errorf("Не удалось разобрать CRL (ожидается PEM crl.pem)")
	}
	for _, e := range crl.RevokedCertificateEntries {
		hex := NormalizeSerialHex(serialHexBigInt(e.SerialNumber))
		if hex != "" {
			set[hex] = struct{}{}
		}
	}
	return set, nil
}

func serialHexBigInt(n *big.Int) string {
	if n == nil {
		return ""
	}
	return fmt.Sprintf("%X", n.Bytes())
}

// SyncRevokedInventory marks or creates revoked certs from a revoke index list.
func SyncRevokedInventory(ctx context.Context, pool *pgxpool.Pool, rootCaID, issuedByName, text string) (RevokedSyncStats, error) {
	stats := RevokedSyncStats{}
	if strings.TrimSpace(text) == "" {
		return stats, nil
	}
	seen := map[string]struct{}{}
	defaultExp := time.Now().Add(defaultImportedExpiry)
	now := time.Now()

	for _, raw := range strings.Split(text, "\n") {
		p := ParseInventoryLine(strings.TrimSuffix(raw, "\r"))
		if p == nil {
			continue
		}
		cn := p.cn
		if cn == "" {
			continue
		}
		if _, ok := seen[cn]; ok {
			continue
		}
		seen[cn] = struct{}{}

		existing, err := findCertByCNAndNode(ctx, pool, cn, nil)
		if err != nil && err != pgx.ErrNoRows {
			return stats, err
		}
		if existing != nil {
			if existing.rootCaID != rootCaID {
				stats.Skipped++
				continue
			}
			if existing.revokedAt == nil {
				_, err := pool.Exec(ctx, `
					UPDATE "Certificate"
					SET "revokedAt" = $1, "revokedReason" = $2
					WHERE id = $3`, now, "imported revoke list", existing.id)
				if err != nil {
					return stats, err
				}
				stats.Updated++
			}
			continue
		}

		id := ksuid.New().String()
		serial := ksuid.New().String()
		_, err = pool.Exec(ctx, `
			INSERT INTO "Certificate" (
				id, "commonName", "serialNumber", "issuedBy", "rootCaId", "agentNodeId",
				"expiresAt", "revokedAt", "revokedReason", "createdAt"
			) VALUES ($1, $2, $3, $4, $5, NULL, $6, $7, $8, NOW())`,
			id, cn, serial, issuedByName, rootCaID, defaultExp, now, "imported revoke list",
		)
		if err != nil {
			stats.Skipped++
			continue
		}
		stats.Created++
	}
	return stats, nil
}

// SyncRevokedFromCRL revokes panel certificates whose serial appears in a PEM CRL.
func SyncRevokedFromCRL(ctx context.Context, pool *pgxpool.Pool, rootCaID, pemText string) (RevokedCrlSyncStats, error) {
	stats := RevokedCrlSyncStats{}
	serials, err := RevokedSerialSetFromCRL(pemText)
	if err != nil {
		return stats, err
	}
	if len(serials) == 0 {
		return stats, nil
	}

	rows, err := pool.Query(ctx, `
		SELECT id, "serialNumber", "rootCaId", "revokedAt"
		FROM "Certificate"
		WHERE "rootCaId" = $1 AND "agentNodeId" IS NULL`, rootCaID)
	if err != nil {
		return stats, err
	}
	defer rows.Close()

	bySerial := map[string]certRow{}
	for rows.Next() {
		var row certRow
		var root *string
		if err := rows.Scan(&row.id, &row.serialNumber, &root, &row.revokedAt); err != nil {
			return stats, err
		}
		if root != nil {
			row.rootCaID = *root
		}
		bySerial[NormalizeSerialHex(row.serialNumber)] = row
	}
	if err := rows.Err(); err != nil {
		return stats, err
	}

	now := time.Now()
	for serial := range serials {
		existing, ok := bySerial[serial]
		if !ok {
			stats.NotInDb++
			continue
		}
		if existing.rootCaID != rootCaID {
			stats.Skipped++
			continue
		}
		if existing.revokedAt != nil {
			continue
		}
		_, err := pool.Exec(ctx, `
			UPDATE "Certificate"
			SET "revokedAt" = $1, "revokedReason" = $2
			WHERE id = $3`, now, "CRL (crl.pem)", existing.id)
		if err != nil {
			return stats, err
		}
		stats.Revoked++
	}
	return stats, nil
}
