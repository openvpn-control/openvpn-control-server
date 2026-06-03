package panelbackup

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/segmentio/ksuid"
)

type BackupRow struct {
	ID        string
	FileName  string
	SizeBytes int
	Trigger   string
	CreatedAt time.Time
}

type SettingsRow struct {
	IntervalMinutes int
	RetainCount     int
	LastScheduledAt *time.Time
}

func EnsureBackupSettingsRow(ctx context.Context, pool *pgxpool.Pool) (SettingsRow, error) {
	var s SettingsRow
	err := pool.QueryRow(ctx, `
		SELECT "intervalMinutes", "retainCount", "lastScheduledAt"
		FROM "PanelAppBackupSettings" WHERE id = 1`).Scan(&s.IntervalMinutes, &s.RetainCount, &s.LastScheduledAt)
	if err == nil {
		return s, nil
	}
	if err != pgx.ErrNoRows {
		return s, err
	}
	now := time.Now()
	_, err = pool.Exec(ctx, `
		INSERT INTO "PanelAppBackupSettings" (id, "intervalMinutes", "retainCount", "lastScheduledAt", "updatedAt")
		VALUES (1, 0, 10, $1, NOW())`, now)
	if err != nil {
		return s, err
	}
	s.IntervalMinutes = 0
	s.RetainCount = 10
	s.LastScheduledAt = &now
	return s, nil
}

func CreatePanelBackupZip(ctx context.Context, pool *pgxpool.Pool, backupDir, trigger string) (BackupRow, error) {
	if trigger == "" {
		trigger = "manual"
	}
	if err := os.MkdirAll(backupDir, 0o755); err != nil {
		return BackupRow{}, err
	}
	tablesRaw, err := exportAllTablesJSON(ctx, pool)
	if err != nil {
		return BackupRow{}, err
	}
	tables := make(map[string][]any, len(tablesRaw))
	for name, rows := range tablesRaw {
		tables[name] = deepSanitizeTable(rows)
	}
	tableNames := make([]string, 0, len(tables))
	for name := range tables {
		tableNames = append(tableNames, name)
	}

	manifest := map[string]any{
		"format":    Format,
		"version":   Version,
		"createdAt": time.Now().UTC().Format(time.RFC3339),
		"tables":    tableNames,
	}
	buf := &bytes.Buffer{}
	zw := zip.NewWriter(buf)
	if err := writeZipJSON(zw, "manifest.json", manifest); err != nil {
		_ = zw.Close()
		return BackupRow{}, err
	}
	for name, rows := range tables {
		if err := writeZipJSON(zw, "tables/"+name+".json", rows); err != nil {
			_ = zw.Close()
			return BackupRow{}, err
		}
	}
	if err := zw.Close(); err != nil {
		return BackupRow{}, err
	}
	zipBytes := buf.Bytes()
	fileName := "panel-backup-" + strings.NewReplacer(":", "-", ".", "-").Replace(time.Now().UTC().Format(time.RFC3339Nano)) + ".zip"
	id := ksuid.New().String()
	var created BackupRow
	err = pool.QueryRow(ctx, `
		INSERT INTO "PanelAppBackup" (id, "fileName", "sizeBytes", trigger, "createdAt")
		VALUES ($1, $2, $3, $4, NOW())
		RETURNING id, "fileName", "sizeBytes", trigger, "createdAt"`,
		id, fileName, len(zipBytes), trigger).Scan(&created.ID, &created.FileName, &created.SizeBytes, &created.Trigger, &created.CreatedAt)
	if err != nil {
		return BackupRow{}, err
	}
	if err := os.WriteFile(filepath.Join(backupDir, created.ID+".zip"), zipBytes, 0o644); err != nil {
		return BackupRow{}, err
	}
	if err := PruneOldBackups(ctx, pool, backupDir); err != nil {
		return BackupRow{}, err
	}
	return created, nil
}

func writeZipJSON(zw *zip.Writer, name string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	w, err := zw.Create(name)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

func PruneOldBackups(ctx context.Context, pool *pgxpool.Pool, backupDir string) error {
	settings, err := EnsureBackupSettingsRow(ctx, pool)
	if err != nil {
		return err
	}
	retain := settings.RetainCount
	if retain < 1 {
		retain = 1
	}
	if retain > 500 {
		retain = 500
	}
	rows, err := pool.Query(ctx, `SELECT id FROM "PanelAppBackup" ORDER BY "createdAt" DESC`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	if len(ids) <= retain {
		return nil
	}
	for _, id := range ids[retain:] {
		_ = os.Remove(filepath.Join(backupDir, id+".zip"))
		_, _ = pool.Exec(ctx, `DELETE FROM "PanelAppBackup" WHERE id = $1`, id)
	}
	return nil
}

func RestorePanelFromZipBuffer(ctx context.Context, pool *pgxpool.Pool, backupDir string, zipBytes []byte) error {
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		return err
	}
	var manifest map[string]any
	foundManifest := false
	for _, f := range zr.File {
		if f.Name != "manifest.json" {
			continue
		}
		foundManifest = true
		rc, err := f.Open()
		if err != nil {
			return err
		}
		dec := json.NewDecoder(rc)
		if err := dec.Decode(&manifest); err != nil {
			_ = rc.Close()
			return err
		}
		_ = rc.Close()
		break
	}
	if !foundManifest {
		return fmt.Errorf("В архиве нет manifest.json")
	}
	if manifest["format"] != Format {
		return fmt.Errorf("Неизвестный формат резервной копии")
	}
	ver, _ := manifest["version"].(float64)
	if int(ver) != Version {
		return fmt.Errorf("Версия архива %v не поддерживается (ожидается %d)", manifest["version"], Version)
	}
	data := map[string][]any{}
	names, _ := manifest["tables"].([]any)
	for _, n := range names {
		name, _ := n.(string)
		if name == "" {
			continue
		}
		entryName := "tables/" + name + ".json"
		for _, f := range zr.File {
			if f.Name != entryName {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				return err
			}
			var rows []any
			if err := json.NewDecoder(rc).Decode(&rows); err != nil {
				_ = rc.Close()
				return err
			}
			_ = rc.Close()
			data[name] = deepSanitizeTable(rows)
			break
		}
	}
	if err := os.MkdirAll(backupDir, 0o755); err != nil {
		return err
	}
	txCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	tx, err := pool.Begin(txCtx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(txCtx) }()
	if err := wipeApplicationData(txCtx, tx); err != nil {
		return err
	}
	if err := importAllFromJSON(txCtx, tx, data); err != nil {
		return err
	}
	if err := tx.Commit(txCtx); err != nil {
		return err
	}
	entries, err := os.ReadDir(backupDir)
	if err == nil {
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".zip") {
				continue
			}
			_ = os.Remove(filepath.Join(backupDir, e.Name()))
		}
	}
	_, _ = pool.Exec(ctx, `DELETE FROM "PanelAppBackup"`)
	return nil
}

func wipeApplicationData(ctx context.Context, tx pgx.Tx) error {
	stmts := []string{
		`DELETE FROM "PanelAppBackup"`,
		`DELETE FROM "AdminTotpRecoveryCode"`,
		`DELETE FROM "AdminActionLog"`,
		`DELETE FROM "OpenvpnServerLog"`,
		`DELETE FROM "PanelAsyncTask"`,
		`DELETE FROM "AgentMetricSnapshot"`,
		`DELETE FROM "ClientTrafficSample"`,
		`DELETE FROM "ClientSourceIpHistory"`,
		`DELETE FROM "ClientIpAssignment"`,
		`DELETE FROM "AgentNodeOpenvpnConfigVersion"`,
		`DELETE FROM "AgentNodeOpenvpnMaterial"`,
		`DELETE FROM "AgentNodeOpenvpnSettings"`,
		`DELETE FROM "Certificate"`,
		`DELETE FROM "VpnUser"`,
		`DELETE FROM "AgentNode"`,
		`DELETE FROM "RootCertificateAuthority"`,
		`DELETE FROM "Organization"`,
		`DELETE FROM "Admin"`,
		`DELETE FROM "PanelAppBackupSettings"`,
	}
	for _, s := range stmts {
		if _, err := tx.Exec(ctx, s); err != nil {
			return err
		}
	}
	return nil
}

func importAllFromJSON(ctx context.Context, tx pgx.Tx, data map[string][]any) error {
	if err := insertSimple(ctx, tx, "Organization", data["Organization"]); err != nil {
		return err
	}
	if err := insertSimple(ctx, tx, "RootCertificateAuthority", data["RootCertificateAuthority"]); err != nil {
		return err
	}
	if err := insertSimple(ctx, tx, "AgentNode", data["AgentNode"]); err != nil {
		return err
	}
	if err := insertAdmins(ctx, tx, data["Admin"]); err != nil {
		return err
	}
	if err := insertSimple(ctx, tx, "AdminTotpRecoveryCode", data["AdminTotpRecoveryCode"]); err != nil {
		return err
	}
	if err := insertSimple(ctx, tx, "VpnUser", data["VpnUser"]); err != nil {
		return err
	}
	if err := insertSimple(ctx, tx, "Certificate", data["Certificate"]); err != nil {
		return err
	}
	if err := insertSimple(ctx, tx, "AgentNodeOpenvpnSettings", data["AgentNodeOpenvpnSettings"]); err != nil {
		return err
	}
	if err := insertSimple(ctx, tx, "AgentNodeOpenvpnConfigVersion", data["AgentNodeOpenvpnConfigVersion"]); err != nil {
		return err
	}
	if err := insertSimple(ctx, tx, "AgentNodeOpenvpnMaterial", data["AgentNodeOpenvpnMaterial"]); err != nil {
		return err
	}
	if err := insertSimple(ctx, tx, "ClientIpAssignment", data["ClientIpAssignment"]); err != nil {
		return err
	}
	if err := insertSimple(ctx, tx, "ClientSourceIpHistory", data["ClientSourceIpHistory"]); err != nil {
		return err
	}
	if err := insertTrafficSamples(ctx, tx, data["ClientTrafficSample"]); err != nil {
		return err
	}
	if err := insertSimple(ctx, tx, "AgentMetricSnapshot", data["AgentMetricSnapshot"]); err != nil {
		return err
	}
	if err := insertSimple(ctx, tx, "OpenvpnServerLog", data["OpenvpnServerLog"]); err != nil {
		return err
	}
	if err := insertSimple(ctx, tx, "PanelAsyncTask", data["PanelAsyncTask"]); err != nil {
		return err
	}
	if err := insertSimple(ctx, tx, "AdminActionLog", data["AdminActionLog"]); err != nil {
		return err
	}
	bset := data["PanelAppBackupSettings"]
	if len(bset) > 0 {
		return insertSimple(ctx, tx, "PanelAppBackupSettings", bset)
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO "PanelAppBackupSettings" (id, "intervalMinutes", "retainCount", "lastScheduledAt", "updatedAt")
		VALUES (1, 0, 10, NOW(), NOW())`)
	return err
}

func insertAdmins(ctx context.Context, tx pgx.Tx, rows []any) error {
	if len(rows) == 0 {
		return nil
	}
	for _, row := range rows {
		m, ok := row.(map[string]any)
		if !ok {
			continue
		}
		fullName := strings.TrimSpace(strVal(m["fullName"]))
		email := strings.ToLower(strings.TrimSpace(strVal(m["email"])))
		var emailPtr any
		if email != "" {
			emailPtr = email
		}
		m["fullName"] = fullName
		m["email"] = emailPtr
		m["inviteToken"] = nil
		m["inviteExpiresAt"] = nil
		m["passwordResetToken"] = nil
		m["passwordResetExpiresAt"] = nil
		if m["totpEnabled"] == nil {
			m["totpEnabled"] = false
		}
	}
	return insertSimple(ctx, tx, "Admin", rows)
}

func insertTrafficSamples(ctx context.Context, tx pgx.Tx, rows []any) error {
	if len(rows) == 0 {
		return nil
	}
	for _, row := range rows {
		m, ok := row.(map[string]any)
		if !ok {
			continue
		}
		m["rxBytes"] = toInt64(m["rxBytes"])
		m["txBytes"] = toInt64(m["txBytes"])
	}
	return insertSimple(ctx, tx, "ClientTrafficSample", rows)
}

func insertSimple(ctx context.Context, tx pgx.Tx, table string, rows []any) error {
	if len(rows) == 0 {
		return nil
	}
	for _, row := range rows {
		m, ok := row.(map[string]any)
		if !ok {
			continue
		}
		cols := make([]string, 0, len(m))
		for k := range m {
			cols = append(cols, k)
		}
		sort.Strings(cols)
		vals := make([]any, len(cols))
		for i, k := range cols {
			vals[i] = normalizeInsertValue(m[k])
		}
		quoted := make([]string, len(cols))
		placeholders := make([]string, len(cols))
		for i, c := range cols {
			quoted[i] = quoteIdent(c)
			placeholders[i] = fmt.Sprintf("$%d", i+1)
		}
		q := fmt.Sprintf(`INSERT INTO %s (%s) VALUES (%s)`,
			quoteIdent(table), strings.Join(quoted, ", "), strings.Join(placeholders, ", "))
		if _, err := tx.Exec(ctx, q, vals...); err != nil {
			return fmt.Errorf("%s: %w", table, err)
		}
	}
	return nil
}

func normalizeInsertValue(v any) any {
	switch t := v.(type) {
	case map[string]any, []any:
		b, err := json.Marshal(t)
		if err != nil {
			return v
		}
		return string(b)
	default:
		return v
	}
}

func quoteIdent(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

func strVal(v any) string {
	if v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	default:
		return fmt.Sprint(t)
	}
}

func toInt64(v any) int64 {
	switch t := v.(type) {
	case float64:
		return int64(t)
	case json.Number:
		n, _ := t.Int64()
		return n
	case int64:
		return t
	case int:
		return int64(t)
	default:
		return 0
	}
}
