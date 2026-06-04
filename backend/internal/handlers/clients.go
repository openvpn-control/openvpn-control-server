package handlers

import (
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/openvpn-control/openvpn-control-server/backend/internal/config"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/httpx"
)

type Clients struct {
	Cfg  config.Config
	Pool *pgxpool.Pool
}

func (h *Clients) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cutoff := time.Now().Add(-h.Cfg.ClientSessionFreshness)
	historyTake := h.Cfg.ClientTrafficHistoryMinutes * 30
	if historyTake > 300 {
		historyTake = 300
	}
	if historyTake < 1 {
		historyTake = 1
	}

	rows, err := h.Pool.Query(ctx, `
		SELECT c."sessionId", c."commonName", c."realIp", c."virtualIp", c."connectedAt",
			c."agentNodeId", COALESCE(n.name, '')
		FROM "ClientIpAssignment" c
		LEFT JOIN "AgentNode" n ON n.id = c."agentNodeId"
		WHERE c."endedAt" IS NULL AND c."lastSeenAt" >= $1
		ORDER BY c."lastSeenAt" DESC`, cutoff)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	type session struct {
		ID, CN, RealIP, VIP string
		ConnectedAt         time.Time
		NodeID, NodeName    string
	}
	var sessions []session
	for rows.Next() {
		var s session
		if rows.Scan(&s.ID, &s.CN, &s.RealIP, &s.VIP, &s.ConnectedAt, &s.NodeID, &s.NodeName) == nil {
			sessions = append(sessions, s)
		}
	}

	samples, _ := h.Pool.Query(ctx, `
		SELECT "agentNodeId", "sessionId", "sampledAt", "inBps", "outBps"
		FROM "ClientTrafficSample" WHERE "sampledAt" >= $1
		ORDER BY "sampledAt" DESC LIMIT 10000`, cutoff)
	traffic := map[string]struct {
		latestIn, latestOut float64
		hasLatest           bool
		history             []map[string]any
	}{}
	if samples != nil {
		defer samples.Close()
		for samples.Next() {
			var nodeID, sessID string
			var at time.Time
			var inBps, outBps float64
			if samples.Scan(&nodeID, &sessID, &at, &inBps, &outBps) != nil {
				continue
			}
			key := nodeID + ":" + sessID
			e := traffic[key]
			if !e.hasLatest {
				e.latestIn, e.latestOut = inBps, outBps
				e.hasLatest = true
			}
			if len(e.history) < historyTake {
				e.history = append(e.history, map[string]any{
					"sampledAt": at, "inBps": inBps, "outBps": outBps,
				})
			}
			traffic[key] = e
		}
	}

	out := make([]map[string]any, 0, len(sessions))
	for _, s := range sessions {
		key := s.NodeID + ":" + s.ID
		tr := traffic[key]
		hist := tr.history
		for i, j := 0, len(hist)-1; i < j; i, j = i+1, j-1 {
			hist[i], hist[j] = hist[j], hist[i]
		}
		out = append(out, map[string]any{
			"id":             s.ID,
			"commonName":     s.CN,
			"remoteIp":       remoteHost(s.RealIP),
			"virtualIp":      s.VIP,
			"connectedAt":    s.ConnectedAt,
			"nodeId":         s.NodeID,
			"nodeName":       s.NodeName,
			"inBps":          tr.latestIn,
			"outBps":         tr.latestOut,
			"trafficHistory": hist,
		})
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}
