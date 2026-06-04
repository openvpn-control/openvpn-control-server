package handlers

import (
	"context"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/openvpn-control/openvpn-control-server/backend/internal/agent"
)

// supplementUserVpnSessions polls agents and persists live rows for this user's certificate CNs.
func supplementUserVpnSessions(ctx context.Context, pool *pgxpool.Pool, vpnUserID string, now time.Time) {
	cns, err := userCertificateCNs(ctx, pool, vpnUserID)
	if err != nil || len(cns) == 0 {
		return
	}
	cnSet := make(map[string]struct{}, len(cns))
	for _, cn := range cns {
		cnSet[strings.ToLower(cn)] = struct{}{}
	}

	rows, err := pool.Query(ctx, `
		SELECT id, name, protocol, host, port, "authToken"
		FROM "AgentNode"`)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var n agent.Node
		if rows.Scan(&n.ID, &n.Name, &n.Protocol, &n.Host, &n.Port, &n.AuthToken) != nil {
			continue
		}
		live, err := agent.ClientsList(ctx, n)
		if err != nil {
			continue
		}
		for _, c := range live {
			cn := strings.ToLower(strings.TrimSpace(anyStr(c["commonName"])))
			if cn == "" {
				continue
			}
			if _, ok := cnSet[cn]; !ok {
				continue
			}
			c["nodeId"] = n.ID
			c["nodeName"] = n.Name
			agent.UpsertClientFromAgent(ctx, pool, c, now)
		}
	}
}

func userCertificateCNs(ctx context.Context, pool *pgxpool.Pool, vpnUserID string) ([]string, error) {
	rows, err := pool.Query(ctx, `
		SELECT DISTINCT TRIM("commonName")
		FROM "Certificate"
		WHERE "vpnUserId" = $1 AND TRIM("commonName") <> ''`, vpnUserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var cn string
		if rows.Scan(&cn) == nil && cn != "" {
			out = append(out, cn)
		}
	}
	return out, nil
}

func anyStr(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
