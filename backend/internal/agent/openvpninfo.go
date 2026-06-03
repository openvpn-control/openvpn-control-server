package agent

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/segmentio/ksuid"

	"github.com/openvpn-control/openvpn-control-server/backend/internal/config"
)

var openvpnLogLineRe = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+\-]\d{2}:?\d{2})?|\w{3}\s+\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+(.*)$`)

type parsedLogLine struct {
	OccurredAt  time.Time
	OccurredRaw *string
	Event       string
	Username    *string
	IPAddress   *string
	RawLine     string
}

func syncNodeOpenVPNInfo(ctx context.Context, pool *pgxpool.Pool, cfg config.Config, n node) syncResult {
	info, err := OpenVPNInfo(ctx, nodeFromInternal(n))
	if err != nil {
		msg := err.Error()
		_, _ = pool.Exec(ctx, `
			UPDATE "AgentNode" SET "openvpnRunning" = false, "openvpnServiceRecentLogs" = '[]'::jsonb,
				"openvpnLogsEnabled" = false, "openvpnLogsNote" = NULL, "openvpnInfoError" = $2
			WHERE id = $1`, n.ID, msg)
		return syncResult{Node: n.Name, OK: false, Error: msg}
	}

	logs := extractOpenvpnLogs(info)
	logsJSON, _ := json.Marshal(logs)
	if len(logs) > 1000 {
		logs = logs[len(logs)-1000:]
		logsJSON, _ = json.Marshal(logs)
	}

	mainPid := sqlNullInt(info["mainPid"])

	_, err = pool.Exec(ctx, `
		UPDATE "AgentNode" SET
			"agentVersion" = $2,
			"openvpnBinaryPath" = $3,
			"openvpnVersion" = $4,
			"openvpnBuild" = $5,
			"openvpnConfigPath" = $6,
			"openvpnServerLogPath" = $7,
			"openvpnManagementAddr" = $8,
			"openvpnRunning" = $9,
			"openvpnServiceUnit" = $10,
			"openvpnServiceActiveState" = $11,
			"openvpnServiceSubState" = $12,
			"openvpnServiceMainPid" = $13,
			"openvpnServiceActiveSince" = $14,
			"openvpnServiceRecentLogs" = $15::jsonb,
			"openvpnLogsEnabled" = $16,
			"openvpnLogsNote" = $17,
			"openvpnInfoError" = $18,
			"openvpnInfoSeenAt" = NOW()
		WHERE id = $1`,
		n.ID,
		strPtr(info["agentVersion"]),
		strPtr(info["binaryPath"]),
		strPtr(info["version"]),
		strPtr(info["build"]),
		strPtr(info["configPath"]),
		strPtr(info["serverLogPath"]),
		strPtr(info["managementAddr"]),
		boolVal(info["running"]),
		strPtr(info["serviceUnit"]),
		strPtr(info["activeState"]),
		strPtr(info["subState"]),
		mainPid,
		strPtr(info["activeSince"]),
		string(logsJSON),
		boolVal(info["logsEnabled"]),
		strPtr(info["logsNote"]),
		strPtr(info["lastError"]),
	)
	if err != nil {
		return syncResult{Node: n.Name, OK: false, Error: err.Error()}
	}
	_ = persistOpenvpnLogs(ctx, pool, n.ID, logs)
	_ = cleanupOldOpenvpnLogs(ctx, pool, cfg)
	return syncResult{Node: n.Name, OK: true}
}

func extractOpenvpnLogs(info map[string]any) []string {
	if arr, ok := info["recentLogs"].([]any); ok && len(arr) > 0 {
		return toStringSlice(arr)
	}
	b64, _ := info["compressedLogsB64"].(string)
	if b64 == "" {
		return nil
	}
	gz, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil
	}
	gr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil
	}
	defer gr.Close()
	text, err := io.ReadAll(gr)
	if err != nil {
		return nil
	}
	var lines []string
	for _, line := range strings.Split(string(text), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func toStringSlice(arr []any) []string {
	var out []string
	for _, v := range arr {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func parseOpenVpnLogLine(line string) *parsedLogLine {
	raw := strings.TrimSpace(line)
	if raw == "" {
		return nil
	}
	m := openvpnLogLineRe.FindStringSubmatch(raw)
	var occurredRaw *string
	event := raw
	if len(m) == 3 {
		occurredRaw = &m[1]
		event = m[2]
	}
	occurredAt := time.Now().UTC()
	if occurredRaw != nil {
		if t, err := time.Parse("2006-01-02 15:04:05", strings.Replace(*occurredRaw, ",", ".", 1)); err == nil {
			occurredAt = t.UTC()
		} else if t, err := time.Parse(time.RFC3339Nano, strings.Replace(*occurredRaw, ",", ".", 1)); err == nil {
			occurredAt = t.UTC()
		}
	}
	if strings.HasPrefix(strings.ToUpper(event), "MANAGEMENT:") {
		return nil
	}
	row := &parsedLogLine{OccurredAt: occurredAt, OccurredRaw: occurredRaw, Event: event, RawLine: raw}
	if u := matchGroup(`(?i)common name[:=]\s*([A-Za-z0-9._-]+)`, event); u != "" {
		row.Username = &u
	} else if u = matchGroup(`\bCN=([A-Za-z0-9._-]+)`, event); u != "" {
		row.Username = &u
	} else if u = matchGroup(`(?i)peer info:\s*IV_CLIUSER=([^\s,]+)`, event); u != "" {
		row.Username = &u
	} else if u = matchGroup(`\b([A-Za-z0-9._-]+)/\d{1,3}(?:\.\d{1,3}){3}:\d+\b`, event); u != "" {
		row.Username = &u
	}
	if ip := matchGroup(`\b(\d{1,3}(?:\.\d{1,3}){3})\b`, event); ip != "" {
		row.IPAddress = &ip
	}
	return row
}

func matchGroup(re, s string) string {
	r := regexp.MustCompile(re)
	m := r.FindStringSubmatch(s)
	if len(m) >= 2 {
		return m[1]
	}
	return ""
}

func persistOpenvpnLogs(ctx context.Context, pool *pgxpool.Pool, nodeID string, lines []string) error {
	if len(lines) == 0 {
		return nil
	}
	for _, line := range lines {
		row := parseOpenVpnLogLine(line)
		if row == nil {
			continue
		}
		fpRaw := nodeID + "|"
		if row.OccurredRaw != nil {
			fpRaw += *row.OccurredRaw
		}
		fpRaw += "|" + row.RawLine
		sum := sha1.Sum([]byte(fpRaw))
		fingerprint := hex.EncodeToString(sum[:])
		_, _ = pool.Exec(ctx, `
			INSERT INTO "OpenvpnServerLog" (id, "agentNodeId", "occurredAt", "occurredRaw", event, username, "ipAddress", "rawLine", fingerprint, "createdAt")
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
			ON CONFLICT (fingerprint) DO NOTHING`,
			ksuid.New().String(), nodeID, row.OccurredAt, row.OccurredRaw, row.Event, row.Username, row.IPAddress, row.RawLine, fingerprint)
	}
	return nil
}

func cleanupOldOpenvpnLogs(ctx context.Context, pool *pgxpool.Pool, cfg config.Config) error {
	days := cfg.OpenvpnLogRetentionDays
	if days < 1 {
		days = 10
	}
	cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
	_, err := pool.Exec(ctx, `DELETE FROM "OpenvpnServerLog" WHERE "occurredAt" < $1`, cutoff)
	return err
}

func strPtr(v any) *string {
	if s, ok := v.(string); ok && s != "" {
		return &s
	}
	return nil
}

func boolVal(v any) bool {
	if b, ok := v.(bool); ok {
		return b
	}
	return false
}

func sqlNullInt(v any) *int {
	if v == nil {
		return nil
	}
	n := int(num(v))
	return &n
}
