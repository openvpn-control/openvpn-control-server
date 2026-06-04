package agent

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/segmentio/ksuid"
)

// UpsertClientFromAgent writes one live client row from management into panel DB.
func UpsertClientFromAgent(ctx context.Context, pool *pgxpool.Pool, client map[string]any, now time.Time) {
	nodeID, _ := client["nodeId"].(string)
	sessionID, _ := client["id"].(string)
	if nodeID == "" || sessionID == "" {
		return
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

	if _, err := pool.Exec(ctx, `
		INSERT INTO "ClientTrafficSample" (id, "agentNodeId", "sessionId", "commonName", "virtualIp", "realIp",
			"rxBytes", "txBytes", "inBps", "outBps", "sampledAt")
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		ksuid.New().String(), nodeID, sessionID, strVal(client["commonName"]), strVal(client["virtualIp"]),
		hostIP, rxBytes, txBytes, inBps, outBps, now); err != nil {
		log.Printf("ClientTrafficSample insert: %v", err)
	}

	if _, err := pool.Exec(ctx, `
		INSERT INTO "ClientSourceIpHistory" (id, "agentNodeId", "sessionId", "commonName", "realIp", "connectedAt", "firstSeenAt", "lastSeenAt")
		VALUES ($1, $2, $3, $4, $5, $6, $7, $7)
		ON CONFLICT ("agentNodeId", "sessionId", "realIp") DO UPDATE SET
			"commonName" = EXCLUDED."commonName",
			"connectedAt" = EXCLUDED."connectedAt",
			"lastSeenAt" = EXCLUDED."lastSeenAt",
			"endedAt" = NULL,
			"durationSeconds" = NULL`,
		ksuid.New().String(), nodeID, sessionID, strVal(client["commonName"]), hostIP,
		strVal(client["connectedAt"]), now); err != nil {
		log.Printf("ClientSourceIpHistory upsert: %v", err)
	}

	if _, err := pool.Exec(ctx, `
		INSERT INTO "ClientIpAssignment" (id, "agentNodeId", "sessionId", "commonName", "realIp", "virtualIp", "connectedAt", "firstSeenAt", "lastSeenAt")
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)
		ON CONFLICT ("agentNodeId", "sessionId") DO UPDATE SET
			"commonName" = EXCLUDED."commonName",
			"realIp" = EXCLUDED."realIp",
			"virtualIp" = EXCLUDED."virtualIp",
			"connectedAt" = EXCLUDED."connectedAt",
			"lastSeenAt" = EXCLUDED."lastSeenAt",
			"endedAt" = NULL`,
		ksuid.New().String(), nodeID, sessionID, strVal(client["commonName"]), hostIP, strVal(client["virtualIp"]),
		strVal(client["connectedAt"]), now); err != nil {
		log.Printf("ClientIpAssignment upsert: %v", err)
	}
}

// CloseStaleAssignmentsForNode marks endedAt for sessions not seen on the last successful agent poll.
func CloseStaleAssignmentsForNode(ctx context.Context, pool *pgxpool.Pool, nodeID string, activeSessionIDs []string, now time.Time) {
	if nodeID == "" {
		return
	}
	var err error
	if len(activeSessionIDs) == 0 {
		_, err = pool.Exec(ctx, `
			UPDATE "ClientIpAssignment"
			SET "endedAt" = $2
			WHERE "agentNodeId" = $1 AND "endedAt" IS NULL`,
			nodeID, now)
	} else {
		_, err = pool.Exec(ctx, `
			UPDATE "ClientIpAssignment"
			SET "endedAt" = $2
			WHERE "agentNodeId" = $1 AND "endedAt" IS NULL
			AND NOT ("sessionId" = ANY($3))`,
			nodeID, now, activeSessionIDs)
	}
	if err != nil {
		log.Printf("ClientIpAssignment close stale: %v", err)
	}
	closeOpenSourceIPForNodeSessions(ctx, pool, nodeID, activeSessionIDs, now)
}

// CloseClientSessionInDB closes panel history for a session (after management disconnect or agent drop).
func CloseClientSessionInDB(ctx context.Context, pool *pgxpool.Pool, nodeID, sessionID string, now time.Time) {
	if nodeID == "" || sessionID == "" {
		return
	}
	if _, err := pool.Exec(ctx, `
		UPDATE "ClientIpAssignment"
		SET "endedAt" = $3
		WHERE "agentNodeId" = $1 AND "sessionId" = $2 AND "endedAt" IS NULL`,
		nodeID, sessionID, now); err != nil {
		log.Printf("ClientIpAssignment close session: %v", err)
	}
	closeOpenSourceIPForSession(ctx, pool, nodeID, sessionID, now)
}

func closeOpenSourceIPForSession(ctx context.Context, pool *pgxpool.Pool, nodeID, sessionID string, now time.Time) {
	rows, err := pool.Query(ctx, `
		SELECT id, "firstSeenAt"
		FROM "ClientSourceIpHistory"
		WHERE "agentNodeId" = $1 AND "sessionId" = $2 AND "endedAt" IS NULL`,
		nodeID, sessionID)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var firstSeen time.Time
		if rows.Scan(&id, &firstSeen) != nil {
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

func closeOpenSourceIPForNodeSessions(ctx context.Context, pool *pgxpool.Pool, nodeID string, activeSessionIDs []string, now time.Time) {
	if nodeID == "" {
		return
	}
	var rows interface {
		Close()
		Next() bool
		Scan(dest ...any) error
	}
	var err error
	if len(activeSessionIDs) == 0 {
		rows, err = pool.Query(ctx, `
			SELECT id, "firstSeenAt"
			FROM "ClientSourceIpHistory"
			WHERE "agentNodeId" = $1 AND "endedAt" IS NULL`, nodeID)
	} else {
		rows, err = pool.Query(ctx, `
			SELECT id, "firstSeenAt"
			FROM "ClientSourceIpHistory"
			WHERE "agentNodeId" = $1 AND "endedAt" IS NULL
			AND NOT ("sessionId" = ANY($2))`, nodeID, activeSessionIDs)
	}
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var firstSeen time.Time
		if rows.Scan(&id, &firstSeen) != nil {
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
