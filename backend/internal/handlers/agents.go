package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/openvpn-control/openvpn-control-server/backend/internal/agent"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/config"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/httpx"
)

type Agents struct {
	Cfg  config.Config
	Pool *pgxpool.Pool
}

func (h *Agents) Mount(r chi.Router) {
	r.Route("/agent", func(ar chi.Router) {
		ar.Get("/nodes", h.ListNodes)
		ar.Post("/nodes", h.CreateNode)
		ar.Patch("/nodes/{id}", h.PatchNode)
		ar.Delete("/nodes/{id}", h.DeleteNode)
		ar.Post("/sync", h.Sync)
	})
}

func (h *Agents) ListNodes(w http.ResponseWriter, r *http.Request) {
	var raw []byte
	err := h.Pool.QueryRow(r.Context(), `
		SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json)::text FROM (
			SELECT id, name, protocol, host, port, "agentVersion", status,
				"cpuPercent", "memoryPercent", "diskPercent", "diskReadBps", "diskWriteBps",
				"networkInBps", "networkOutBps", "activeClients", "lastSeenAt",
				"openvpnBinaryPath", "openvpnVersion", "openvpnBuild", "openvpnConfigPath",
				"openvpnServerLogPath", "openvpnManagementAddr", "openvpnRunning",
				"openvpnServiceUnit", "openvpnServiceActiveState", "openvpnServiceSubState",
				"openvpnServiceMainPid", "openvpnServiceActiveSince", "openvpnServiceRecentLogs",
				"openvpnLogsEnabled", "openvpnLogsNote", "openvpnInfoSeenAt", "openvpnInfoError",
				"createdAt", "updatedAt"
			FROM "AgentNode" ORDER BY "createdAt" DESC
		) t`).Scan(&raw)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

func (h *Agents) Sync(w http.ResponseWriter, r *http.Request) {
	results, err := agent.SyncAllNodes(r.Context(), h.Pool, h.Cfg)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, results)
}

func (h *Agents) CreateNode(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name      string `json:"name"`
		Protocol  string `json:"protocol"`
		Host      string `json:"host"`
		Port      int    `json:"port"`
		AuthToken string `json:"authToken"`
	}
	if err := httpx.DecodeJSON(r, &body); err != nil || body.Name == "" || body.Host == "" || body.Port == 0 || body.AuthToken == "" {
		httpx.WriteError(w, http.StatusBadRequest, "name, host, port and authToken are required")
		return
	}
	protocol := body.Protocol
	if protocol == "" {
		protocol = "http"
	}
	id := newID()
	var row json.RawMessage
	err := h.Pool.QueryRow(r.Context(), `
		WITH ins AS (
			INSERT INTO "AgentNode" (id, name, protocol, host, port, "authToken", status, "createdAt", "updatedAt")
			VALUES ($1, $2, $3, $4, $5, $6, 'UNKNOWN', NOW(), NOW())
			RETURNING *
		) SELECT row_to_json(ins)::text FROM ins`,
		id, body.Name, protocol, body.Host, body.Port, body.AuthToken).Scan(&row)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write(row)
}

func (h *Agents) PatchNode(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var exists bool
	if err := h.Pool.QueryRow(r.Context(), `SELECT true FROM "AgentNode" WHERE id = $1`, id).Scan(&exists); err != nil || !exists {
		httpx.WriteError(w, http.StatusNotFound, "Узел не найден")
		return
	}
	var body map[string]any
	if err := httpx.DecodeJSONLoose(r, &body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}
	sets := []string{}
	args := []any{}
	n := 1
	if _, ok := body["name"]; ok {
		name := strings.TrimSpace(strAny(body["name"]))
		if name == "" {
			httpx.WriteError(w, http.StatusBadRequest, "Имя узла обязательно")
			return
		}
		sets = append(sets, fmt.Sprintf(`name = $%d`, n))
		args = append(args, name)
		n++
	}
	if _, ok := body["protocol"]; ok {
		p := strings.TrimSpace(strAny(body["protocol"]))
		if p == "" {
			p = "http"
		}
		sets = append(sets, fmt.Sprintf(`protocol = $%d`, n))
		args = append(args, p)
		n++
	}
	if _, ok := body["host"]; ok {
		host := strings.TrimSpace(strAny(body["host"]))
		if host == "" {
			httpx.WriteError(w, http.StatusBadRequest, "Хост обязателен")
			return
		}
		sets = append(sets, fmt.Sprintf(`host = $%d`, n))
		args = append(args, host)
		n++
	}
	if _, ok := body["port"]; ok {
		port := int(numAny(body["port"]))
		if port < 1 || port > 65535 {
			httpx.WriteError(w, http.StatusBadRequest, "Некорректный порт")
			return
		}
		sets = append(sets, fmt.Sprintf(`port = $%d`, n))
		args = append(args, port)
		n++
	}
	if _, ok := body["authToken"]; ok {
		token := strings.TrimSpace(strAny(body["authToken"]))
		if token != "" {
			sets = append(sets, fmt.Sprintf(`"authToken" = $%d`, n))
			args = append(args, token)
			n++
		}
	}
	if len(sets) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "Нет полей для обновления")
		return
	}
	sets = append(sets, `"updatedAt" = NOW()`)
	args = append(args, id)
	q := `UPDATE "AgentNode" SET ` + strings.Join(sets, ", ") + fmt.Sprintf(` WHERE id = $%d`, n)
	_, err := h.Pool.Exec(r.Context(), q, args...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var row json.RawMessage
	err = h.Pool.QueryRow(r.Context(), `
		SELECT row_to_json(t)::text FROM (
			SELECT id, name, protocol, host, port, "agentVersion", status,
				"cpuPercent", "memoryPercent", "diskPercent", "diskReadBps", "diskWriteBps",
				"networkInBps", "networkOutBps", "activeClients", "lastSeenAt",
				"openvpnBinaryPath", "openvpnVersion", "openvpnBuild", "openvpnConfigPath",
				"openvpnServerLogPath", "openvpnManagementAddr", "openvpnRunning",
				"openvpnServiceUnit", "openvpnServiceActiveState", "openvpnServiceSubState",
				"openvpnServiceMainPid", "openvpnServiceActiveSince", "openvpnServiceRecentLogs",
				"openvpnLogsEnabled", "openvpnLogsNote", "openvpnInfoSeenAt", "openvpnInfoError",
				"createdAt", "updatedAt"
			FROM "AgentNode" WHERE id = $1
		) t`, id).Scan(&row)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(row)
}

func numAny(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case int:
		return float64(t)
	default:
		return 0
	}
}

func (h *Agents) DeleteNode(w http.ResponseWriter, r *http.Request) {
	_, err := h.Pool.Exec(r.Context(), `DELETE FROM "AgentNode" WHERE id = $1`, chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
