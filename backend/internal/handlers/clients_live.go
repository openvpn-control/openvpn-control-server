package handlers

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/openvpn-control/openvpn-control-server/backend/internal/agent"
)

type agentNodeRow struct {
	ID            string
	Name          string
	Protocol      string
	Host          string
	Port          int
	AuthToken     string
	ActiveClients int
}

// supplementLiveClients polls agents when metrics show clients but DB rows are missing/stale.
func supplementLiveClients(ctx context.Context, pool *pgxpool.Pool, _ time.Time, out []map[string]any) []map[string]any {
	seen := make(map[string]struct{}, len(out))
	for _, row := range out {
		nodeID, _ := row["nodeId"].(string)
		sid, _ := row["id"].(string)
		if nodeID != "" && sid != "" {
			seen[nodeID+"\t"+sid] = struct{}{}
		}
	}

	rows, err := pool.Query(ctx, `
		SELECT id, name, protocol, host, port, "authToken", "activeClients"
		FROM "AgentNode"
		WHERE "activeClients" > 0`)
	if err != nil {
		return out
	}
	defer rows.Close()

	now := time.Now()
	for rows.Next() {
		var n agentNodeRow
		if rows.Scan(&n.ID, &n.Name, &n.Protocol, &n.Host, &n.Port, &n.AuthToken, &n.ActiveClients) != nil {
			continue
		}
		live, err := agent.ClientsList(ctx, agent.Node{
			ID: n.ID, Name: n.Name, Protocol: n.Protocol, Host: n.Host, Port: n.Port, AuthToken: n.AuthToken,
		})
		if err != nil {
			continue
		}
		for _, c := range live {
			nodeID, _ := c["nodeId"].(string)
			sid, _ := c["id"].(string)
			if nodeID == "" || sid == "" {
				continue
			}
			key := nodeID + "\t" + sid
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			agent.UpsertClientFromAgent(ctx, pool, c, now)
			inBps, outBps := agent.LatestSessionTrafficBps(ctx, pool, nodeID, sid)
			rip := ""
			if s, ok := c["remoteIp"].(string); ok {
				rip = remoteHost(s)
			}
			out = append(out, map[string]any{
				"id":             sid,
				"commonName":     c["commonName"],
				"remoteIp":       rip,
				"virtualIp":      c["virtualIp"],
				"connectedAt":    c["connectedAt"],
				"nodeId":         nodeID,
				"nodeName":       c["nodeName"],
				"inBps":          inBps,
				"outBps":         outBps,
				"trafficHistory": []map[string]any{},
			})
		}
	}
	return out
}
