package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/openvpn-control/openvpn-control-server/backend/internal/config"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/httpx"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/metrictime"
)

type Monitoring struct {
	Cfg  config.Config
	Pool *pgxpool.Pool
}

func (h *Monitoring) Overview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	agentNodeID := strings.TrimSpace(r.URL.Query().Get("agentNodeId"))

	var agentsRaw []byte
	var err error
	if agentNodeID != "" {
		err = h.Pool.QueryRow(ctx, `
			SELECT COALESCE(json_agg(row_to_json(a)), '[]'::json)::text
			FROM "AgentNode" a WHERE a.id = $1`, agentNodeID).Scan(&agentsRaw)
	} else {
		err = h.Pool.QueryRow(ctx, `SELECT COALESCE(json_agg(row_to_json(a)), '[]'::json)::text FROM "AgentNode" a`).Scan(&agentsRaw)
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var agents []map[string]any
	_ = json.Unmarshal(agentsRaw, &agents)

	since := time.Now().UTC().Add(-time.Duration(h.Cfg.AgentMetricHistoryMinutes) * time.Minute)
	var historyRaw []byte
	if agentNodeID != "" {
		_ = h.Pool.QueryRow(ctx, `
			SELECT COALESCE(json_agg(row_to_json(m)), '[]'::json)::text
			FROM "AgentMetricSnapshot" m
			WHERE "createdAt" >= $1 AND m."agentNodeId" = $2`, since, agentNodeID).Scan(&historyRaw)
	} else {
		_ = h.Pool.QueryRow(ctx, `
			SELECT COALESCE(json_agg(row_to_json(m)), '[]'::json)::text
			FROM "AgentMetricSnapshot" m WHERE "createdAt" >= $1`, since).Scan(&historyRaw)
	}
	var history []map[string]any
	_ = json.Unmarshal(historyRaw, &history)

	byNode := map[string][]map[string]any{}
	for _, row := range history {
		metrictime.ApplyToMetricRow(row)
		nid, _ := row["agentNodeId"].(string)
		byNode[nid] = append(byNode[nid], row)
	}

	var totalClients int
	var sumCPU, sumMem, sumIn, sumOut float64
	for _, a := range agents {
		if v, ok := a["activeClients"].(float64); ok {
			totalClients += int(v)
		}
		if v, ok := a["cpuPercent"].(float64); ok {
			sumCPU += v
		}
		if v, ok := a["memoryPercent"].(float64); ok {
			sumMem += v
		}
		if v, ok := a["networkInBps"].(float64); ok {
			sumIn += v
		}
		if v, ok := a["networkOutBps"].(float64); ok {
			sumOut += v
		}
		id, _ := a["id"].(string)
		a["recentMetrics"] = byNode[id]
	}
	n := float64(len(agents))
	avgCPU, avgMem := 0.0, 0.0
	if n > 0 {
		avgCPU = sumCPU / n
		avgMem = sumMem / n
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"totalServers":           len(agents),
		"totalClients":           totalClients,
		"avgCpuPercent":          avgCPU,
		"avgMemoryPercent":       avgMem,
		"totalNetworkInBps":      sumIn,
		"totalNetworkOutBps":     sumOut,
		"metricHistoryMinutes":   h.Cfg.AgentMetricHistoryMinutes,
		"servers":                agents,
	})
}
