package agent

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// LatestSessionTrafficBps returns the most recent in/out rates for a session, if sampled.
func LatestSessionTrafficBps(ctx context.Context, pool *pgxpool.Pool, nodeID, sessionID string) (inBps, outBps float64) {
	if pool == nil || nodeID == "" || sessionID == "" {
		return 0, 0
	}
	_ = pool.QueryRow(ctx, `
		SELECT COALESCE("inBps", 0), COALESCE("outBps", 0)
		FROM "ClientTrafficSample"
		WHERE "agentNodeId" = $1 AND "sessionId" = $2
		ORDER BY "sampledAt" DESC
		LIMIT 1`, nodeID, sessionID).Scan(&inBps, &outBps)
	return inBps, outBps
}
