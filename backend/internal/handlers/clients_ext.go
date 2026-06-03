package handlers

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/openvpn-control/openvpn-control-server/backend/internal/agent"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/httpx"
)

func (h *Clients) Mount(r chi.Router) {
	r.Get("/", h.List)
	r.Get("/history", h.History)
	r.Get("/source-history", h.SourceHistory)
	r.Post("/{nodeId}/{id}/disconnect", h.Disconnect)
}

func remoteHost(ip string) string {
	ip = strings.TrimSpace(ip)
	if i := strings.Index(ip, ":"); i >= 0 {
		return ip[:i]
	}
	return ip
}

func (h *Clients) History(w http.ResponseWriter, r *http.Request) {
	var raw []byte
	err := h.Pool.QueryRow(r.Context(), `
		SELECT COALESCE(json_agg(row_to_json(x)), '[]'::json)::text FROM (
			SELECT c.*, json_build_object('id', n.id, 'name', n.name, 'host', n.host, 'port', n.port) AS "agentNode"
			FROM "ClientIpAssignment" c
			LEFT JOIN "AgentNode" n ON n.id = c."agentNodeId"
			WHERE c."virtualIp" <> ''
			ORDER BY c."lastSeenAt" DESC
			LIMIT 1000
		) x`).Scan(&raw)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeRawJSON(w, raw)
}

func (h *Clients) SourceHistory(w http.ResponseWriter, r *http.Request) {
	var raw []byte
	err := h.Pool.QueryRow(r.Context(), `
		SELECT COALESCE(json_agg(row_to_json(x)), '[]'::json)::text FROM (
			SELECT h.*, json_build_object('id', n.id, 'name', n.name, 'host', n.host, 'port', n.port) AS "agentNode"
			FROM "ClientSourceIpHistory" h
			LEFT JOIN "AgentNode" n ON n.id = h."agentNodeId"
			ORDER BY h."lastSeenAt" DESC
			LIMIT 1000
		) x`).Scan(&raw)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeRawJSON(w, raw)
}

func (h *Clients) Disconnect(w http.ResponseWriter, r *http.Request) {
	nodeID := chi.URLParam(r, "nodeId")
	clientID := chi.URLParam(r, "id")
	result, err := agent.DisconnectClient(r.Context(), h.Pool, nodeID, clientID)
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "Failed to disconnect client: "+err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, result)
}

func writeRawJSON(w http.ResponseWriter, raw []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}
