package agent

import (
	"context"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/segmentio/ksuid"

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
		nodeID, _ := client["nodeId"].(string)
		sessionID, _ := client["id"].(string)
		if nodeID == "" || sessionID == "" {
			continue
		}
		hostIP := remoteAddrHostOnly(strVal(client["remoteIp"]))
		rxBytes := bigIntVal(client["rxBytes"])
		txBytes := bigIntVal(client["txBytes"])

		var lastRx, lastTx int64
		var lastAt time.Time
		_ = pool.QueryRow(ctx, `
			SELECT "rxBytes", "txBytes", "sampledAt"
			FROM "ClientTrafficSample"
			WHERE "agentNodeId" = $1 AND "sessionId" = $2
			ORDER BY "sampledAt" DESC
			LIMIT 1`, nodeID, sessionID).Scan(&lastRx, &lastTx, &lastAt)

		inBps, outBps := 0.0, 0.0
		if !lastAt.IsZero() {
			seconds := now.Sub(lastAt).Seconds()
			if seconds > 0 {
				if d := float64(rxBytes - lastRx); d > 0 {
					inBps = d / seconds
				}
				if d := float64(txBytes - lastTx); d > 0 {
					outBps = d / seconds
				}
			}
		}

		_, _ = pool.Exec(ctx, `
			INSERT INTO "ClientTrafficSample" (id, "agentNodeId", "sessionId", "commonName", "virtualIp", "realIp",
				"rxBytes", "txBytes", "inBps", "outBps", "sampledAt")
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
			ksuid.New().String(), nodeID, sessionID, strVal(client["commonName"]), strVal(client["virtualIp"]),
			hostIP, rxBytes, txBytes, inBps, outBps, now)

		_, _ = pool.Exec(ctx, `
			INSERT INTO "ClientSourceIpHistory" (id, "agentNodeId", "sessionId", "commonName", "realIp", "connectedAt", "firstSeenAt", "lastSeenAt")
			VALUES ($1, $2, $3, $4, $5, $6, $7, $7)
			ON CONFLICT ("agentNodeId", "sessionId", "realIp") DO UPDATE SET
				"commonName" = EXCLUDED."commonName",
				"connectedAt" = EXCLUDED."connectedAt",
				"lastSeenAt" = EXCLUDED."lastSeenAt",
				"endedAt" = NULL,
				"durationSeconds" = NULL`,
			ksuid.New().String(), nodeID, sessionID, strVal(client["commonName"]), hostIP,
			strVal(client["connectedAt"]), now)

		if vip := strVal(client["virtualIp"]); vip != "" {
			_, _ = pool.Exec(ctx, `
				INSERT INTO "ClientIpAssignment" (id, "agentNodeId", "sessionId", "commonName", "realIp", "virtualIp", "connectedAt", "firstSeenAt", "lastSeenAt")
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)
				ON CONFLICT ("agentNodeId", "sessionId") DO UPDATE SET
					"commonName" = EXCLUDED."commonName",
					"realIp" = EXCLUDED."realIp",
					"virtualIp" = EXCLUDED."virtualIp",
					"connectedAt" = EXCLUDED."connectedAt",
					"lastSeenAt" = EXCLUDED."lastSeenAt",
					"endedAt" = NULL`,
				ksuid.New().String(), nodeID, sessionID, strVal(client["commonName"]), hostIP, vip,
				strVal(client["connectedAt"]), now)
		}
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

	activeCN := map[string]struct{}{}
	for _, client := range allClients {
		if cn := strings.TrimSpace(strVal(client["commonName"])); cn != "" {
			activeCN[cn] = struct{}{}
		}
	}
	if len(activeCN) > 0 {
		cns := make([]string, 0, len(activeCN))
		for cn := range activeCN {
			cns = append(cns, cn)
		}
		userRows, err := pool.Query(ctx, `
			SELECT DISTINCT "vpnUserId" FROM "Certificate"
			WHERE "commonName" = ANY($1) AND "vpnUserId" IS NOT NULL`, cns)
		if err == nil {
			defer userRows.Close()
			var userIDs []string
			for userRows.Next() {
				var uid string
				if userRows.Scan(&uid) == nil && uid != "" {
					userIDs = append(userIDs, uid)
				}
			}
			if len(userIDs) > 0 {
				_, _ = pool.Exec(ctx, `
					UPDATE "VpnUser" SET "lastVpnActivityAt" = $2 WHERE id = ANY($1)`, userIDs, now)
			}
		}
	}

	_, _ = pool.Exec(ctx, `
		UPDATE "ClientIpAssignment"
		SET "endedAt" = $2
		WHERE "endedAt" IS NULL AND "lastSeenAt" < $1`, sessionCutoff, now)

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

func strVal(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func bigIntVal(v any) int64 {
	switch t := v.(type) {
	case float64:
		return int64(t)
	case int64:
		return t
	case int:
		return int64(t)
	default:
		return 0
	}
}
