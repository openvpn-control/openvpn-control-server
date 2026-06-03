package panelbackup

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

func exportAllTablesJSON(ctx context.Context, pool *pgxpool.Pool) (map[string][]any, error) {
	tables := map[string]string{
		"Organization":                  organizationSQL(),
		"Admin":                         adminSQL(),
		"RootCertificateAuthority":      rootCASQL(),
		"AgentNode":                     agentNodeSQL(),
		"VpnUser":                       vpnUserSQL(),
		"Certificate":                   certificateSQL(),
		"AgentNodeOpenvpnSettings":      agentNodeOpenvpnSettingsSQL(),
		"AgentNodeOpenvpnConfigVersion": agentNodeOpenvpnConfigVersionSQL(),
		"AgentNodeOpenvpnMaterial":      agentNodeOpenvpnMaterialSQL(),
		"ClientIpAssignment":            clientIpAssignmentSQL(),
		"ClientSourceIpHistory":         clientSourceIpHistorySQL(),
		"ClientTrafficSample":           clientTrafficSampleSQL(),
		"AgentMetricSnapshot":           agentMetricSnapshotSQL(),
		"PanelAsyncTask":                panelAsyncTaskSQL(),
		"AdminActionLog":                adminActionLogSQL(),
		"PanelAppBackupSettings":        panelAppBackupSettingsSQL(),
		"AdminTotpRecoveryCode":         adminTotpRecoveryCodeSQL(),
	}
	out := make(map[string][]any, len(tables)+1)
	for name, q := range tables {
		rows, err := queryJSONArray(ctx, pool, q)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		out[name] = rows
	}
	logs, err := exportOpenvpnServerLogsSafe(ctx, pool)
	if err == nil {
		out["OpenvpnServerLog"] = logs
	} else {
		out["OpenvpnServerLog"] = []any{}
	}
	return out, nil
}

func queryJSONArray(ctx context.Context, pool *pgxpool.Pool, innerSQL string) ([]any, error) {
	q := `SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json) FROM (` + innerSQL + `) t`
	var raw json.RawMessage
	if err := pool.QueryRow(ctx, q).Scan(&raw); err != nil {
		return nil, err
	}
	var rows []any
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, err
	}
	if rows == nil {
		return []any{}, nil
	}
	return rows, nil
}

func exportOpenvpnServerLogsSafe(ctx context.Context, pool *pgxpool.Pool) ([]any, error) {
	strip := pgStripC0Controls
	q := fmt.Sprintf(`
		SELECT
			o.id,
			o."agentNodeId",
			o."occurredAt",
			CASE WHEN o."occurredRaw" IS NULL THEN NULL ELSE NULLIF(%s, '') END AS "occurredRaw",
			COALESCE(NULLIF(%s, ''), '(empty)') AS event,
			CASE WHEN o."username" IS NULL THEN NULL ELSE NULLIF(%s, '') END AS username,
			CASE WHEN o."ipAddress" IS NULL THEN NULL ELSE NULLIF(%s, '') END AS "ipAddress",
			COALESCE(NULLIF(%s, ''), '.') AS "rawLine",
			COALESCE(NULLIF(%s, ''), o.id) AS fingerprint,
			o."createdAt"
		FROM "OpenvpnServerLog" o`,
		strip(`o."occurredRaw"`), strip("o.event"), strip(`o."username"`), strip(`o."ipAddress"`), strip(`o."rawLine"`), strip(`o.fingerprint`))
	return queryJSONArray(ctx, pool, q)
}

func organizationSQL() string {
	return fmt.Sprintf(`
		SELECT o.id, %s AS name, %s AS inn, %s AS "legalAddress", %s AS "generalDirector",
			%s AS phone, %s AS email, %s AS "firewallRules", o."createdAt", o."updatedAt"
		FROM "Organization" o`,
		z("o.name"), zn("o.inn"), zn(`o."legalAddress"`), zn(`o."generalDirector"`), zn("o.phone"), zn("o.email"), zj(`o."firewallRules"`))
}

func adminSQL() string {
	return fmt.Sprintf(`
		SELECT a.id, %s AS "fullName", %s AS username, %s AS email, %s AS "passwordHash",
			a."isActive", %s AS "inviteToken", a."inviteExpiresAt", %s AS "passwordResetToken",
			a."passwordResetExpiresAt", a."totpEnabled", %s AS "totpSecretEnc", %s AS "totpPendingSecretEnc",
			a."totpPendingExpiresAt", a."createdAt", a."updatedAt"
		FROM "Admin" a`,
		z(`a."fullName"`), z("a.username"), zn("a.email"), z(`a."passwordHash"`), zn(`a."inviteToken"`), zn(`a."passwordResetToken"`), zn(`a."totpSecretEnc"`), zn(`a."totpPendingSecretEnc"`))
}

func rootCASQL() string {
	return fmt.Sprintf(`
		SELECT r.id, %s AS name, %s AS "commonName", %s AS "certPem", %s AS "keyPem",
			r."isActive", r."createdAt", r."updatedAt"
		FROM "RootCertificateAuthority" r`,
		z("r.name"), z(`r."commonName"`), z(`r."certPem"`), z(`r."keyPem"`))
}

func agentNodeSQL() string {
	return fmt.Sprintf(`
		SELECT n.id, %s AS name, %s AS protocol, %s AS host, n.port, %s AS "authToken",
			%s AS "agentVersion", %s AS status, n."cpuPercent", n."memoryPercent", n."diskPercent",
			n."diskReadBps", n."diskWriteBps", n."networkInBps", n."networkOutBps", n."activeClients",
			n."lastSeenAt", %s AS "openvpnBinaryPath", %s AS "openvpnVersion", %s AS "openvpnBuild",
			%s AS "openvpnConfigPath", %s AS "openvpnServerLogPath", %s AS "openvpnManagementAddr",
			n."openvpnRunning", %s AS "openvpnServiceUnit", %s AS "openvpnServiceActiveState",
			%s AS "openvpnServiceSubState", n."openvpnServiceMainPid", %s AS "openvpnServiceActiveSince",
			%s AS "openvpnServiceRecentLogs", n."openvpnLogsEnabled", %s AS "openvpnLogsNote",
			n."openvpnInfoSeenAt", %s AS "openvpnInfoError", n."createdAt", n."updatedAt"
		FROM "AgentNode" n`,
		z("n.name"), z("n.protocol"), z("n.host"), z(`n."authToken"`), zn(`n."agentVersion"`), z("n.status"),
		zn(`n."openvpnBinaryPath"`), zn(`n."openvpnVersion"`), zn(`n."openvpnBuild"`), zn(`n."openvpnConfigPath"`),
		zn(`n."openvpnServerLogPath"`), zn(`n."openvpnManagementAddr"`), zn(`n."openvpnServiceUnit"`),
		zn(`n."openvpnServiceActiveState"`), zn(`n."openvpnServiceSubState"`), zn(`n."openvpnServiceActiveSince"`),
		zj(`n."openvpnServiceRecentLogs"`), zn(`n."openvpnLogsNote"`), zn(`n."openvpnInfoError"`))
}

func vpnUserSQL() string {
	return fmt.Sprintf(`
		SELECT u.id, %s AS "fullName", %s AS position, %s AS email, %s AS phone,
			%s AS "organizationId", %s AS notes, %s AS "firewallRules", %s AS "ccdSettings",
			u."lastVpnActivityAt", u."createdAt", u."updatedAt"
		FROM "VpnUser" u`,
		z(`u."fullName"`), zn("u.position"), z("u.email"), zn("u.phone"), zn(`u."organizationId"`), zn("u.notes"), zj(`u."firewallRules"`), zj(`u."ccdSettings"`))
}

func certificateSQL() string {
	return fmt.Sprintf(`
		SELECT c.id, %s AS "commonName", %s AS "serialNumber", %s AS "issuedBy",
			%s AS "rootCaId", %s AS "agentNodeId", %s AS "vpnUserId", %s AS "certPem", %s AS "keyPem",
			c."expiresAt", c."createdAt", c."revokedAt", %s AS "revokedReason"
		FROM "Certificate" c`,
		z(`c."commonName"`), z(`c."serialNumber"`), z(`c."issuedBy"`), zn(`c."rootCaId"`), zn(`c."agentNodeId"`), zn(`c."vpnUserId"`), zn(`c."certPem"`), zn(`c."keyPem"`), zn(`c."revokedReason"`))
}

func agentNodeOpenvpnSettingsSQL() string {
	return fmt.Sprintf(`
		SELECT s.id, %s AS "agentNodeId", %s AS settings, %s AS "configPath", s."createdAt", s."updatedAt"
		FROM "AgentNodeOpenvpnSettings" s`, z(`s."agentNodeId"`), zj("s.settings"), zn(`s."configPath"`))
}

func agentNodeOpenvpnConfigVersionSQL() string {
	return fmt.Sprintf(`
		SELECT v.id, %s AS "agentNodeId", v.version, %s AS settings, %s AS checksum, v."appliedAt", v."createdAt"
		FROM "AgentNodeOpenvpnConfigVersion" v`, z(`v."agentNodeId"`), zj("v.settings"), z("v.checksum"))
}

func agentNodeOpenvpnMaterialSQL() string {
	return fmt.Sprintf(`
		SELECT m.id, %s AS "agentNodeId", %s AS kind, %s AS label, %s AS pem, m."createdAt"
		FROM "AgentNodeOpenvpnMaterial" m`, z(`m."agentNodeId"`), z("m.kind"), zn("m.label"), z("m.pem"))
}

func clientIpAssignmentSQL() string {
	return fmt.Sprintf(`
		SELECT i.id, %s AS "agentNodeId", %s AS "sessionId", %s AS "commonName", %s AS "realIp",
			%s AS "virtualIp", %s AS "connectedAt", i."firstSeenAt", i."lastSeenAt", i."endedAt"
		FROM "ClientIpAssignment" i`,
		z(`i."agentNodeId"`), z(`i."sessionId"`), z(`i."commonName"`), z(`i."realIp"`), z(`i."virtualIp"`), z(`i."connectedAt"`))
}

func clientSourceIpHistorySQL() string {
	return fmt.Sprintf(`
		SELECT h.id, %s AS "agentNodeId", %s AS "sessionId", %s AS "commonName", %s AS "realIp",
			%s AS "connectedAt", h."firstSeenAt", h."lastSeenAt", h."endedAt", h."durationSeconds"
		FROM "ClientSourceIpHistory" h`,
		z(`h."agentNodeId"`), z(`h."sessionId"`), z(`h."commonName"`), z(`h."realIp"`), z(`h."connectedAt"`))
}

func clientTrafficSampleSQL() string {
	return fmt.Sprintf(`
		SELECT t.id, %s AS "agentNodeId", %s AS "sessionId", %s AS "commonName", %s AS "virtualIp",
			%s AS "realIp", t."rxBytes", t."txBytes", t."inBps", t."outBps", t."sampledAt"
		FROM "ClientTrafficSample" t`,
		z(`t."agentNodeId"`), z(`t."sessionId"`), z(`t."commonName"`), z(`t."virtualIp"`), z(`t."realIp"`))
}

func agentMetricSnapshotSQL() string {
	return fmt.Sprintf(`
		SELECT m.id, %s AS "agentNodeId", m."cpuPercent", m."memoryPercent", m."diskPercent",
			m."diskReadBps", m."diskWriteBps", m."networkInBps", m."networkOutBps", m."activeClients", m."createdAt"
		FROM "AgentMetricSnapshot" m`, z(`m."agentNodeId"`))
}

func panelAsyncTaskSQL() string {
	return fmt.Sprintf(`
		SELECT t.id, %s AS type, %s AS status, %s AS "agentNodeId", %s AS payload,
			%s AS "lastError", t."createdAt", t."updatedAt", t."completedAt"
		FROM "PanelAsyncTask" t`, z("t.type"), z("t.status"), z(`t."agentNodeId"`), zj("t.payload"), zn(`t."lastError"`))
}

func adminActionLogSQL() string {
	return fmt.Sprintf(`
		SELECT l.id, %s AS "adminId", %s AS "adminUsername", %s AS method, %s AS path, %s AS action,
			%s AS "targetType", %s AS "targetId", %s AS "ipAddress", %s AS "userAgent", l."statusCode",
			%s AS details, l."createdAt"
		FROM "AdminActionLog" l`,
		z(`l."adminId"`), z(`l."adminUsername"`), z("l.method"), z("l.path"), z("l.action"),
		zn(`l."targetType"`), zn(`l."targetId"`), zn(`l."ipAddress"`), zn(`l."userAgent"`), zj("l.details"))
}

func panelAppBackupSettingsSQL() string {
	return `SELECT s.id, s."intervalMinutes", s."retainCount", s."lastScheduledAt", s."updatedAt" FROM "PanelAppBackupSettings" s`
}

func adminTotpRecoveryCodeSQL() string {
	return fmt.Sprintf(`
		SELECT r.id, %s AS "adminId", %s AS "codeHash", r."createdAt", r."usedAt"
		FROM "AdminTotpRecoveryCode" r`, z(`r."adminId"`), z(`r."codeHash"`))
}
