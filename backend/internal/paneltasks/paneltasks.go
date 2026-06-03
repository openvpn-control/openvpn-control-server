package paneltasks

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/segmentio/ksuid"

	"github.com/openvpn-control/openvpn-control-server/backend/internal/openvpn"
)

const (
	TypePanelAgentSnapshot    = "panel_agent_snapshot"
	TypeCrlDeploy             = "crl_deploy"
	TypeOpenvpnCASync           = "openvpn_ca_sync"
	TypeOpenvpnServerCertSync   = "openvpn_server_cert_sync"
	TypeOpenvpnDhSync           = "openvpn_dh_sync"
	TypeOpenvpnTlsAuthSync      = "openvpn_tls_auth_sync"
	TypeOpenvpnServiceRestart   = "openvpn_service_restart"
	TypeDnsmasqApply            = "dnsmasq_apply"
)

func upsertPendingTask(ctx context.Context, pool *pgxpool.Pool, agentNodeID, taskType string, payload any) error {
	if agentNodeID == "" {
		return nil
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, _ = pool.Exec(ctx, `
		DELETE FROM "PanelAsyncTask"
		WHERE "agentNodeId" = $1 AND type = $2 AND status = 'pending'`,
		agentNodeID, taskType)
	_, err = pool.Exec(ctx, `
		INSERT INTO "PanelAsyncTask" (id, type, status, "agentNodeId", payload, "createdAt", "updatedAt")
		VALUES ($1, $2, 'pending', $3, $4, NOW(), NOW())`,
		ksuid.New().String(), taskType, agentNodeID, payloadJSON)
	return err
}

func EnqueueOpenvpnServiceRestart(ctx context.Context, pool *pgxpool.Pool, agentNodeID, reason string) error {
	return upsertPendingTask(ctx, pool, agentNodeID, TypeOpenvpnServiceRestart, map[string]string{
		"reason": reason,
	})
}

// CancelPendingOpenvpnServiceRestarts removes queued restarts (apply already restarted OpenVPN).
func CancelPendingOpenvpnServiceRestarts(ctx context.Context, pool *pgxpool.Pool, agentNodeID string) error {
	if strings.TrimSpace(agentNodeID) == "" {
		return nil
	}
	_, err := pool.Exec(ctx, `
		DELETE FROM "PanelAsyncTask"
		WHERE "agentNodeId" = $1 AND type = $2 AND status = 'pending'`,
		agentNodeID, TypeOpenvpnServiceRestart)
	return err
}

func EnqueueDnsmasqApply(ctx context.Context, pool *pgxpool.Pool, agentNodeID, config string) error {
	id := strings.TrimSpace(agentNodeID)
	if id == "" {
		return nil
	}
	return upsertPendingTask(ctx, pool, id, TypeDnsmasqApply, map[string]string{"config": config})
}

func EnqueueOpenvpnMaterialSyncTasks(ctx context.Context, pool *pgxpool.Pool, nodeID string, settings map[string]any) error {
	if nodeID == "" || settings == nil {
		return nil
	}
	rootID := strings.TrimSpace(strVal(settings["panelRootCaId"]))
	caPath := strings.TrimSpace(strVal(settings["ca"]))
	crlPath := strings.TrimSpace(strVal(settings["crl-verify"]))
	if rootID != "" && caPath != "" {
		if err := upsertPendingTask(ctx, pool, nodeID, TypeOpenvpnCASync, map[string]string{
			"rootCaId": rootID, "remotePath": caPath,
		}); err != nil {
			return err
		}
	}
	if rootID != "" && crlPath != "" {
		if err := upsertPendingTask(ctx, pool, nodeID, TypeCrlDeploy, map[string]string{
			"rootCaId": rootID, "remotePath": crlPath,
		}); err != nil {
			return err
		}
	}
	certID := strings.TrimSpace(strVal(settings["panelServerCertId"]))
	certPath := strings.TrimSpace(strVal(settings["cert"]))
	keyPath := strings.TrimSpace(strVal(settings["key"]))
	if certID != "" && certPath != "" && keyPath != "" {
		if err := upsertPendingTask(ctx, pool, nodeID, TypeOpenvpnServerCertSync, map[string]string{
			"certId": certID, "certPath": certPath, "keyPath": keyPath,
		}); err != nil {
			return err
		}
	}
	dhMatID := strings.TrimSpace(strVal(settings["panelDhMaterialId"]))
	dhPath := strings.TrimSpace(strVal(settings["dh"]))
	if dhMatID != "" && dhPath != "" {
		if err := upsertPendingTask(ctx, pool, nodeID, TypeOpenvpnDhSync, map[string]string{
			"materialId": dhMatID, "remotePath": dhPath,
		}); err != nil {
			return err
		}
	}
	tlsMatID := strings.TrimSpace(strVal(settings["panelTlsAuthMaterialId"]))
	tlsPath := openvpn.FirstTlsAuthPath(strVal(settings["tls-auth"]))
	if tlsMatID != "" && tlsPath != "" {
		if err := upsertPendingTask(ctx, pool, nodeID, TypeOpenvpnTlsAuthSync, map[string]string{
			"materialId": tlsMatID, "remotePath": tlsPath,
		}); err != nil {
			return err
		}
	}
	return nil
}

func strVal(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func EnqueueSnapshotForVpnUser(ctx context.Context, pool *pgxpool.Pool, vpnUserID string) error {
	if vpnUserID == "" {
		return nil
	}
	rows, err := pool.Query(ctx, `
		SELECT DISTINCT "agentNodeId" FROM "Certificate"
		WHERE "vpnUserId" = $1 AND "agentNodeId" IS NOT NULL AND "revokedAt" IS NULL`, vpnUserID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			_ = EnqueueSnapshotForNode(ctx, pool, id)
		}
	}
	return nil
}

func EnqueueCrlDeployForRootCa(ctx context.Context, pool *pgxpool.Pool, rootCaID string) error {
	if rootCaID == "" {
		return nil
	}
	rows, err := pool.Query(ctx, `
		SELECT "agentNodeId", settings FROM "AgentNodeOpenvpnSettings"
		WHERE settings->>'panelRootCaId' = $1`, rootCaID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var nodeID string
		var settings []byte
		if rows.Scan(&nodeID, &settings) != nil {
			continue
		}
		var st map[string]any
		_ = json.Unmarshal(settings, &st)
		crlPath, _ := st["crl-verify"].(string)
		crlPath = strings.TrimSpace(crlPath)
		if crlPath == "" {
			continue
		}
		payload, _ := json.Marshal(map[string]string{"rootCaId": rootCaID, "remotePath": crlPath})
		_, _ = pool.Exec(ctx, `
			DELETE FROM "PanelAsyncTask"
			WHERE "agentNodeId" = $1 AND type = $2 AND status = 'pending'
			AND payload->>'rootCaId' = $3`, nodeID, TypeCrlDeploy, rootCaID)
		_, _ = pool.Exec(ctx, `
			INSERT INTO "PanelAsyncTask" (id, type, status, "agentNodeId", payload, "createdAt", "updatedAt")
			VALUES ($1, $2, 'pending', $3, $4, NOW(), NOW())`,
			ksuid.New().String(), TypeCrlDeploy, nodeID, payload)
	}
	return nil
}

func List(ctx context.Context, pool *pgxpool.Pool, limit int) ([]byte, error) {
	if limit < 1 {
		limit = 200
	}
	if limit > 500 {
		limit = 500
	}
	var raw []byte
	err := pool.QueryRow(ctx, `
		SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json)::text FROM (
			SELECT t.*, json_build_object('id', n.id, 'name', n.name) AS "agentNode"
			FROM "PanelAsyncTask" t
			LEFT JOIN "AgentNode" n ON n.id = t."agentNodeId"
			ORDER BY t."createdAt" DESC
			LIMIT $1
		) t`, limit).Scan(&raw)
	return raw, err
}

func Retry(ctx context.Context, pool *pgxpool.Pool, id string) (taskJSON []byte, errMsg string, notFound bool, err error) {
	var status string
	err = pool.QueryRow(ctx, `SELECT status FROM "PanelAsyncTask" WHERE id = $1`, id).Scan(&status)
	if err != nil {
		return nil, "", true, nil
	}
	if status == "processing" {
		return nil, "Задача уже выполняется.", false, nil
	}
	err = pool.QueryRow(ctx, `
		WITH upd AS (
			UPDATE "PanelAsyncTask"
			SET status = 'pending', "lastError" = NULL, "completedAt" = NULL, "updatedAt" = NOW()
			WHERE id = $1
			RETURNING *
		)
		SELECT row_to_json(u)::text FROM (
			SELECT upd.*, json_build_object('id', n.id, 'name', n.name) AS "agentNode"
			FROM upd
			LEFT JOIN "AgentNode" n ON n.id = upd."agentNodeId"
		) u`, id).Scan(&taskJSON)
	return taskJSON, "", false, err
}

func EnqueueSnapshotForNode(ctx context.Context, pool *pgxpool.Pool, agentNodeID string) error {
	return upsertPendingTask(ctx, pool, agentNodeID, TypePanelAgentSnapshot, map[string]string{"source": "node"})
}

func EnqueueSnapshotForOrgNodes(ctx context.Context, pool *pgxpool.Pool, orgID string) error {
	rows, err := pool.Query(ctx, `
		SELECT DISTINCT c."agentNodeId"
		FROM "Certificate" c
		INNER JOIN "VpnUser" u ON u.id = c."vpnUserId"
		WHERE c."revokedAt" IS NULL AND c."agentNodeId" IS NOT NULL AND u."organizationId" = $1`,
		orgID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var nodeID string
		if rows.Scan(&nodeID) == nil && nodeID != "" {
			_ = EnqueueSnapshotForNode(ctx, pool, nodeID)
		}
	}
	return nil
}
