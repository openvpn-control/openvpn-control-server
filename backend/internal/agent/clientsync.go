package agent

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/openvpn-control/openvpn-control-server/backend/internal/config"
)

type clientRow struct {
	NodeID      string
	NodeName    string
	OK          bool
	Clients     []map[string]any
}

// SyncClientsSnapshot polls all agents and updates client traffic, IP history, and assignments.
func SyncClientsSnapshot(ctx context.Context, pool *pgxpool.Pool, cfg config.Config) error {
	rows, err := pool.Query(ctx, `SELECT id, name, protocol, host, port, "authToken" FROM "AgentNode"`)
	if err != nil {
		return err
	}
	defer rows.Close()

	var nodeRows []node
	for rows.Next() {
		var n node
		if rows.Scan(&n.ID, &n.Name, &n.Protocol, &n.Host, &n.Port, &n.AuthToken) != nil {
			continue
		}
		nodeRows = append(nodeRows, n)
	}

	var clientRows []clientRow
	for _, n := range nodeRows {
		cr := clientRow{NodeID: n.ID, NodeName: n.Name}
		list, err := ClientsList(ctx, nodeFromInternal(n))
		if err != nil {
			cr.OK = false
			cr.Clients = nil
		} else {
			cr.OK = true
			for _, c := range list {
				c["nodeId"] = n.ID
				c["nodeName"] = n.Name
				cr.Clients = append(cr.Clients, c)
			}
		}
		clientRows = append(clientRows, cr)
	}

	now := time.Now()
	trafficCutoff := now.Add(-time.Duration(cfg.ClientTrafficHistoryMinutes) * time.Minute)
	sessionCutoff := now.Add(-cfg.ClientSessionFreshness)

	activeSessionsByNode := map[string]map[string]struct{}{}
	var allClients []map[string]any
	for _, row := range clientRows {
		if !row.OK {
			continue
		}
		ids := map[string]struct{}{}
		for _, c := range row.Clients {
			if id, _ := c["id"].(string); id != "" {
				ids[id] = struct{}{}
			}
			allClients = append(allClients, c)
		}
		activeSessionsByNode[row.NodeID] = ids
	}

	_, _ = pool.Exec(ctx, `DELETE FROM "ClientTrafficSample" WHERE "sampledAt" < $1`, trafficCutoff)

	for _, client := range allClients {
		UpsertClientFromAgent(ctx, pool, client, now)
	}

	for _, row := range clientRows {
		if !row.OK {
			continue
		}
		ids := make([]string, 0, len(row.Clients))
		for _, c := range row.Clients {
			if id := strVal(c["id"]); id != "" {
				ids = append(ids, id)
			}
		}
		CloseStaleAssignmentsForNode(ctx, pool, row.NodeID, ids, now)
	}

	openRows, err := pool.Query(ctx, `
		SELECT id, "agentNodeId", "sessionId", "firstSeenAt"
		FROM "ClientSourceIpHistory"
		WHERE "endedAt" IS NULL`)
	if err == nil {
		defer openRows.Close()
		for openRows.Next() {
			var id, agentNodeID, sessionID string
			var firstSeen time.Time
			if openRows.Scan(&id, &agentNodeID, &sessionID, &firstSeen) != nil {
				continue
			}
			activeSet, polled := activeSessionsByNode[agentNodeID]
			if !polled {
				continue
			}
			if _, ok := activeSet[sessionID]; ok {
				continue
			}
			duration := int(now.Sub(firstSeen).Seconds())
			if duration < 0 {
				duration = 0
			}
			_, _ = pool.Exec(ctx, `
				UPDATE "ClientSourceIpHistory"
				SET "endedAt" = $2, "durationSeconds" = $3
				WHERE id = $1`, id, now, duration)
		}
	}

	sourceRetention := now.Add(-90 * 24 * time.Hour)
	_, _ = pool.Exec(ctx, `DELETE FROM "ClientSourceIpHistory" WHERE "endedAt" IS NOT NULL AND "endedAt" < $1`, sourceRetention)

	activeCNLower := map[string]struct{}{}
	for _, client := range allClients {
		if cn := strings.ToLower(strings.TrimSpace(strVal(client["commonName"]))); cn != "" {
			activeCNLower[cn] = struct{}{}
		}
	}
	if len(activeCNLower) > 0 {
		cns := make([]string, 0, len(activeCNLower))
		for cn := range activeCNLower {
			cns = append(cns, cn)
		}
		_, _ = pool.Exec(ctx, `
			UPDATE "VpnUser" SET "lastVpnActivityAt" = NULL
			WHERE "lastVpnActivityAt" IS NOT NULL
			AND id NOT IN (
				SELECT DISTINCT c."vpnUserId" FROM "Certificate" c
				WHERE c."vpnUserId" IS NOT NULL
				AND LOWER(TRIM(c."commonName")) = ANY($1)
			)`, cns)
		_, _ = pool.Exec(ctx, `
			UPDATE "VpnUser" u SET "lastVpnActivityAt" = $2
			FROM "Certificate" c
			WHERE u.id = c."vpnUserId"
			AND LOWER(TRIM(c."commonName")) = ANY($1)`, now, cns)
	}

	// Закрываем устаревшие сессии только на узлах, где опрос management прошёл успешно.
	for _, row := range clientRows {
		if !row.OK {
			continue
		}
		_, _ = pool.Exec(ctx, `
			UPDATE "ClientIpAssignment"
			SET "endedAt" = $2
			WHERE "agentNodeId" = $1 AND "endedAt" IS NULL AND "lastSeenAt" < $3`,
			row.NodeID, now, sessionCutoff)
	}

	endedRetention := now.Add(-30 * 24 * time.Hour)
	_, _ = pool.Exec(ctx, `DELETE FROM "ClientIpAssignment" WHERE "endedAt" IS NOT NULL AND "endedAt" < $1`, endedRetention)
	return nil
}

func remoteAddrHostOnly(addr string) string {
	s := strings.TrimSpace(addr)
	if s == "" {
		return ""
	}
	if strings.HasPrefix(s, "[") {
		if end := strings.Index(s, "]"); end > 1 {
			return s[1:end]
		}
	}
	if lastColon := strings.LastIndex(s, ":"); lastColon > 0 {
		tail := s[lastColon+1:]
		allDigits := true
		for _, c := range tail {
			if c < '0' || c > '9' {
				allDigits = false
				break
			}
		}
		if allDigits && len(tail) >= 1 && len(tail) <= 5 {
			host := s[:lastColon]
			if strings.Contains(host, ".") {
				return host
			}
		}
	}
	return s
}

func bigIntVal(v any) int64 {
	switch t := v.(type) {
	case float64:
		return int64(t)
	case float32:
		return int64(t)
	case int64:
		return t
	case int:
		return int64(t)
	case int32:
		return int64(t)
	case uint64:
		return int64(t)
	case uint32:
		return int64(t)
	case uint:
		return int64(t)
	case json.Number:
		n, _ := t.Int64()
		return n
	default:
		return 0
	}
}
