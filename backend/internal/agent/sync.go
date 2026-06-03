package agent

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/segmentio/ksuid"

	"github.com/openvpn-control/openvpn-control-server/backend/internal/config"
)

type node struct {
	ID        string
	Name      string
	Protocol  string
	Host      string
	Port      int
	AuthToken string
}

func nodeFromInternal(n node) Node {
	return Node{ID: n.ID, Name: n.Name, Protocol: n.Protocol, Host: n.Host, Port: n.Port, AuthToken: n.AuthToken}
}

type syncResult struct {
	Node  string `json:"node"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func SyncAllNodes(ctx context.Context, pool *pgxpool.Pool, cfg config.Config) ([]syncResult, error) {
	rows, err := pool.Query(ctx, `SELECT id, name, protocol, host, port, "authToken" FROM "AgentNode"`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var nodes []node
	for rows.Next() {
		var n node
		if err := rows.Scan(&n.ID, &n.Name, &n.Protocol, &n.Host, &n.Port, &n.AuthToken); err != nil {
			return nil, err
		}
		nodes = append(nodes, n)
	}
	out := make([]syncResult, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, syncNodeMetrics(ctx, pool, cfg, n))
	}
	return out, nil
}

func syncNodeMetrics(ctx context.Context, pool *pgxpool.Pool, cfg config.Config, n node) syncResult {
	metrics, err := RequestJSON(ctx, nodeFromInternal(n), "/metrics", "GET", nil)
	if err != nil {
		_, _ = pool.Exec(ctx, `UPDATE "AgentNode" SET status = 'UNKNOWN', "activeClients" = 0 WHERE id = $1`, n.ID)
		return syncResult{Node: n.Name, OK: false, Error: err.Error()}
	}
	cpu := num(metrics["cpuPercent"])
	mem := num(metrics["memoryPercent"])
	disk := num(metrics["diskPercent"])
	status := str(metrics["status"], "ONLINE")
	_, err = pool.Exec(ctx, `
		UPDATE "AgentNode" SET status = $2, "cpuPercent" = $3, "memoryPercent" = $4, "diskPercent" = $5,
			"diskReadBps" = $6, "diskWriteBps" = $7, "networkInBps" = $8, "networkOutBps" = $9,
			"activeClients" = $10, "lastSeenAt" = NOW()
		WHERE id = $1`,
		n.ID, status, cpu, mem, disk,
		num(metrics["diskReadBps"]), num(metrics["diskWriteBps"]),
		num(metrics["networkInBps"]), num(metrics["networkOutBps"]),
		int(num(metrics["activeClients"])),
	)
	if err != nil {
		return syncResult{Node: n.Name, OK: false, Error: err.Error()}
	}
	_, _ = pool.Exec(ctx, `
		INSERT INTO "AgentMetricSnapshot" (id, "agentNodeId", "cpuPercent", "memoryPercent", "diskPercent",
			"diskReadBps", "diskWriteBps", "networkInBps", "networkOutBps", "activeClients", "createdAt")
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())`,
		ksuid.New().String(), n.ID, cpu, mem, disk,
		num(metrics["diskReadBps"]), num(metrics["diskWriteBps"]),
		num(metrics["networkInBps"]), num(metrics["networkOutBps"]),
		int(num(metrics["activeClients"])),
	)
	cutoff := time.Now().Add(-time.Duration(cfg.AgentMetricHistoryMinutes) * time.Minute)
	_, _ = pool.Exec(ctx, `DELETE FROM "AgentMetricSnapshot" WHERE "createdAt" < $1`, cutoff)

	if status == "ONLINE" && ProcessPanelTasks != nil {
		ProcessPanelTasks(ctx, pool, nodeFromInternal(n), 20)
	}
	return syncResult{Node: n.Name, OK: true}
}

func SyncAllOpenVPNInfo(ctx context.Context, pool *pgxpool.Pool, cfg config.Config) ([]syncResult, error) {
	rows, err := pool.Query(ctx, `SELECT id, name, protocol, host, port, "authToken" FROM "AgentNode"`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var nodes []node
	for rows.Next() {
		var n node
		if err := rows.Scan(&n.ID, &n.Name, &n.Protocol, &n.Host, &n.Port, &n.AuthToken); err != nil {
			return nil, err
		}
		nodes = append(nodes, n)
	}
	out := make([]syncResult, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, syncNodeOpenVPNInfo(ctx, pool, cfg, n))
	}
	return out, nil
}

func num(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case int:
		return float64(t)
	default:
		return 0
	}
}

func str(v any, def string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return def
}
