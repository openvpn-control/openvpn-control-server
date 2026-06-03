package paneltasks

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/openvpn-control/openvpn-control-server/backend/internal/agent"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/agentsnapshot"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/crl"
)

type asyncTask struct {
	ID          string
	Type        string
	AgentNodeID string
	Payload     map[string]any
}

// ProcessPendingForNode executes queued panel tasks after a successful agent poll.
func ProcessPendingForNode(ctx context.Context, pool *pgxpool.Pool, n agent.Node, maxTasks int) {
	if maxTasks < 1 {
		maxTasks = 20
	}
	for i := 0; i < maxTasks; i++ {
		task, ok := claimPendingTask(ctx, pool, n.ID)
		if !ok {
			return
		}
		executeTask(ctx, pool, n, task)
	}
}

// ProcessPendingTasksForNode loads the node and runs pending tasks (panel API helper).
func ProcessPendingTasksForNode(ctx context.Context, pool *pgxpool.Pool, agentNodeID string, maxTasks int) error {
	n, err := agent.LoadNode(ctx, pool, agentNodeID)
	if err != nil {
		return err
	}
	ProcessPendingForNode(ctx, pool, n, maxTasks)
	return nil
}

// EnqueueDnsmasqApplyTask is an alias for EnqueueDnsmasqApply.
func EnqueueDnsmasqApplyTask(ctx context.Context, pool *pgxpool.Pool, agentNodeID, config string) error {
	return EnqueueDnsmasqApply(ctx, pool, agentNodeID, config)
}

func claimPendingTask(ctx context.Context, pool *pgxpool.Pool, agentNodeID string) (asyncTask, bool) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return asyncTask{}, false
	}
	defer tx.Rollback(ctx)

	var task asyncTask
	var payload []byte
	err = tx.QueryRow(ctx, `
		SELECT id, type, "agentNodeId", payload
		FROM "PanelAsyncTask"
		WHERE "agentNodeId" = $1 AND status = 'pending'
		ORDER BY "createdAt" ASC
		LIMIT 1`, agentNodeID).Scan(&task.ID, &task.Type, &task.AgentNodeID, &payload)
	if err != nil {
		return asyncTask{}, false
	}
	tag, err := tx.Exec(ctx, `
		UPDATE "PanelAsyncTask"
		 SET status = 'processing', "lastError" = NULL, "updatedAt" = NOW()
		WHERE id = $1 AND status = 'pending'`, task.ID)
	if err != nil || tag.RowsAffected() == 0 {
		return asyncTask{}, false
	}
	_ = json.Unmarshal(payload, &task.Payload)
	if task.Payload == nil {
		task.Payload = map[string]any{}
	}
	if err := tx.Commit(ctx); err != nil {
		return asyncTask{}, false
	}
	return task, true
}

func completeTask(ctx context.Context, pool *pgxpool.Pool, id, errMsg string) {
	if errMsg != "" {
		_, _ = pool.Exec(ctx, `
			UPDATE "PanelAsyncTask"
			SET status = 'failed', "lastError" = $2, "completedAt" = NOW(), "updatedAt" = NOW()
			WHERE id = $1`, id, errMsg)
		return
	}
	_, _ = pool.Exec(ctx, `
		UPDATE "PanelAsyncTask"
		SET status = 'completed', "lastError" = NULL, "completedAt" = NOW(), "updatedAt" = NOW()
		WHERE id = $1`, id)
}

func executeTask(ctx context.Context, pool *pgxpool.Pool, n agent.Node, task asyncTask) {
	var execErr error
	switch task.Type {
	case TypeCrlDeploy:
		execErr = execCrlDeploy(ctx, pool, n, task)
	case TypeOpenvpnCASync:
		execErr = execOpenvpnCASync(ctx, pool, n, task)
	case TypeOpenvpnServerCertSync:
		execErr = execOpenvpnServerCertSync(ctx, pool, n, task)
	case TypeOpenvpnDhSync:
		execErr = execOpenvpnDhSync(ctx, pool, n, task)
	case TypeOpenvpnTlsAuthSync:
		execErr = execOpenvpnTlsAuthSync(ctx, pool, n, task)
	case TypeOpenvpnServiceRestart:
		_, execErr = agent.OpenVPNService(ctx, n, "restart")
	case TypePanelAgentSnapshot:
		execErr = execPanelAgentSnapshot(ctx, pool, n, task)
	case TypeDnsmasqApply:
		execErr = execDnsmasqApply(ctx, n, task)
	default:
		execErr = fmt.Errorf("Неизвестный тип задачи: %s", task.Type)
	}
	completeTask(ctx, pool, task.ID, errString(execErr))
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func payloadStr(payload map[string]any, key string) string {
	if payload == nil {
		return ""
	}
	if s, ok := payload[key].(string); ok {
		return strings.TrimSpace(s)
	}
	return strings.TrimSpace(fmt.Sprint(payload[key]))
}

func execCrlDeploy(ctx context.Context, pool *pgxpool.Pool, n agent.Node, task asyncTask) error {
	rootCaID := payloadStr(task.Payload, "rootCaId")
	remotePath := payloadStr(task.Payload, "remotePath")
	if rootCaID == "" || remotePath == "" {
		return fmt.Errorf("Некорректный payload задачи CRL")
	}
	var certPem, keyPem string
	err := pool.QueryRow(ctx, `
		SELECT "certPem", "keyPem" FROM "RootCertificateAuthority" WHERE id = $1`, rootCaID).Scan(&certPem, &keyPem)
	if err != nil || certPem == "" {
		return fmt.Errorf("Корневой сертификат не найден")
	}
	rows, err := pool.Query(ctx, `
		SELECT "serialNumber", "commonName", "expiresAt", "revokedAt"
		FROM "Certificate"
		WHERE "rootCaId" = $1 AND "revokedAt" IS NOT NULL`, rootCaID)
	if err != nil {
		return err
	}
	defer rows.Close()
	var revoked []crl.RevokedRow
	for rows.Next() {
		var row crl.RevokedRow
		if rows.Scan(&row.SerialNumber, &row.CommonName, &row.ExpiresAt, &row.RevokedAt) == nil {
			revoked = append(revoked, row)
		}
	}
	pem, err := crl.GeneratePEM(certPem, keyPem, revoked)
	if err != nil {
		return err
	}
	_, err = agent.WriteOpenvpnFile(ctx, n, remotePath, []byte(pem))
	return err
}

func execOpenvpnCASync(ctx context.Context, pool *pgxpool.Pool, n agent.Node, task asyncTask) error {
	rootCaID := payloadStr(task.Payload, "rootCaId")
	remotePath := payloadStr(task.Payload, "remotePath")
	if rootCaID == "" || remotePath == "" {
		return fmt.Errorf("Некорректный payload задачи синхронизации корневого сертификата")
	}
	var certPem string
	err := pool.QueryRow(ctx, `SELECT "certPem" FROM "RootCertificateAuthority" WHERE id = $1`, rootCaID).Scan(&certPem)
	if err != nil || certPem == "" {
		return fmt.Errorf("Корневой сертификат не найден или без certPem")
	}
	if _, err := agent.WriteOpenvpnFile(ctx, n, remotePath, []byte(certPem)); err != nil {
		return err
	}
	return EnqueueOpenvpnServiceRestart(ctx, pool, n.ID, TypeOpenvpnCASync)
}

func execOpenvpnServerCertSync(ctx context.Context, pool *pgxpool.Pool, n agent.Node, task asyncTask) error {
	certID := payloadStr(task.Payload, "certId")
	certPath := payloadStr(task.Payload, "certPath")
	keyPath := payloadStr(task.Payload, "keyPath")
	if certID == "" || certPath == "" || keyPath == "" {
		return fmt.Errorf("Некорректный payload задачи sync cert/key")
	}
	var certPem, keyPem string
	var agentNodeID *string
	err := pool.QueryRow(ctx, `
		SELECT "certPem", "keyPem", "agentNodeId" FROM "Certificate" WHERE id = $1`, certID).
		Scan(&certPem, &keyPem, &agentNodeID)
	if err != nil || certPem == "" || keyPem == "" {
		return fmt.Errorf("Сертификат не найден или без PEM/key")
	}
	if agentNodeID != nil && *agentNodeID != "" && *agentNodeID != n.ID {
		return fmt.Errorf("Выбранный сертификат привязан к другому узлу")
	}
	if _, err := agent.WriteOpenvpnFile(ctx, n, certPath, []byte(certPem)); err != nil {
		return err
	}
	if _, err := agent.WriteOpenvpnFile(ctx, n, keyPath, []byte(keyPem)); err != nil {
		return err
	}
	return EnqueueOpenvpnServiceRestart(ctx, pool, n.ID, TypeOpenvpnServerCertSync)
}

func execOpenvpnDhSync(ctx context.Context, pool *pgxpool.Pool, n agent.Node, task asyncTask) error {
	materialID := payloadStr(task.Payload, "materialId")
	remotePath := payloadStr(task.Payload, "remotePath")
	if materialID == "" || remotePath == "" {
		return fmt.Errorf("Некорректный payload задачи sync DH")
	}
	var pem string
	err := pool.QueryRow(ctx, `
		SELECT pem FROM "AgentNodeOpenvpnMaterial"
		WHERE id = $1 AND "agentNodeId" = $2 AND kind = 'dh'`, materialID, n.ID).Scan(&pem)
	if err != nil || pem == "" {
		return fmt.Errorf("Материал DH не найден")
	}
	if _, err := agent.WriteOpenvpnFile(ctx, n, remotePath, []byte(pem)); err != nil {
		return err
	}
	return EnqueueOpenvpnServiceRestart(ctx, pool, n.ID, TypeOpenvpnDhSync)
}

func execOpenvpnTlsAuthSync(ctx context.Context, pool *pgxpool.Pool, n agent.Node, task asyncTask) error {
	materialID := payloadStr(task.Payload, "materialId")
	remotePath := payloadStr(task.Payload, "remotePath")
	if materialID == "" || remotePath == "" {
		return fmt.Errorf("Некорректный payload задачи sync TLS-auth")
	}
	var pem string
	err := pool.QueryRow(ctx, `
		SELECT pem FROM "AgentNodeOpenvpnMaterial"
		WHERE id = $1 AND "agentNodeId" = $2 AND kind = 'tls_auth'`, materialID, n.ID).Scan(&pem)
	if err != nil || pem == "" {
		return fmt.Errorf("Материал TLS-auth не найден")
	}
	if _, err := agent.WriteOpenvpnFile(ctx, n, remotePath, []byte(pem)); err != nil {
		return err
	}
	return EnqueueOpenvpnServiceRestart(ctx, pool, n.ID, TypeOpenvpnTlsAuthSync)
}

func execPanelAgentSnapshot(ctx context.Context, pool *pgxpool.Pool, n agent.Node, task asyncTask) error {
	_ = task
	snap, err := agentsnapshot.BuildForNode(ctx, pool, n.ID)
	if err != nil {
		return err
	}
	if snap == nil {
		return fmt.Errorf("Не удалось собрать снимок (нет настроек OpenVPN на панели для узла?)")
	}
	_, err = agent.PanelSnapshot(ctx, n, snap)
	return err
}

func execDnsmasqApply(ctx context.Context, n agent.Node, task asyncTask) error {
	config := payloadStr(task.Payload, "config")
	_, err := agent.Dnsmasq(ctx, n, map[string]any{"action": "apply", "config": config})
	return err
}
