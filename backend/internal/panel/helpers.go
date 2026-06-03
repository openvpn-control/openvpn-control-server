package panel

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/segmentio/ksuid"

	"github.com/openvpn-control/openvpn-control-server/backend/internal/agent"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/openvpn"
)

func jsonUnmarshal(raw []byte, dst any) error {
	if len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, dst)
}

var fallbackHints = []string{
	"Проверьте, что агент доступен по host/port и токену.",
	"Задайте на агенте OPENVPN_SERVER_CONF к пути server.conf.",
}

func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func loadNodeRef(ctx context.Context, pool *pgxpool.Pool, nodeID string) (nodeRef, error) {
	var n nodeRef
	err := pool.QueryRow(ctx, `SELECT id, name FROM "AgentNode" WHERE id = $1`, nodeID).Scan(&n.ID, &n.Name)
	return n, err
}

func loadAgentNode(ctx context.Context, pool *pgxpool.Pool, nodeID string) (agent.Node, error) {
	return agent.LoadNode(ctx, pool, nodeID)
}

func loadSettingsRow(ctx context.Context, pool *pgxpool.Pool, nodeID string) (map[string]any, *string, error) {
	var raw []byte
	var configPath *string
	err := pool.QueryRow(ctx, `
		SELECT settings, "configPath" FROM "AgentNodeOpenvpnSettings" WHERE "agentNodeId" = $1`, nodeID,
	).Scan(&raw, &configPath)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, pgx.ErrNoRows
	}
	if err != nil {
		return nil, nil, err
	}
	var settings map[string]any
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &settings)
	}
	if settings == nil {
		settings = map[string]any{}
	}
	return settings, configPath, nil
}

func upsertSettings(ctx context.Context, pool *pgxpool.Pool, nodeID string, settings map[string]any, configPath *string) error {
	raw, err := json.Marshal(settings)
	if err != nil {
		return err
	}
	id := ksuid.New().String()
	if configPath != nil {
		_, err = pool.Exec(ctx, `
			INSERT INTO "AgentNodeOpenvpnSettings" (id, "agentNodeId", settings, "configPath", "createdAt", "updatedAt")
			VALUES ($1, $2, $3, $4, NOW(), NOW())
			ON CONFLICT ("agentNodeId") DO UPDATE SET settings = $3, "configPath" = $4, "updatedAt" = NOW()`,
			id, nodeID, raw, *configPath)
		return err
	}
	_, err = pool.Exec(ctx, `
		INSERT INTO "AgentNodeOpenvpnSettings" (id, "agentNodeId", settings, "createdAt", "updatedAt")
		VALUES ($1, $2, $3, NOW(), NOW())
		ON CONFLICT ("agentNodeId") DO UPDATE SET settings = $3, "updatedAt" = NOW()`,
		id, nodeID, raw)
	return err
}

func upsertSettingsTx(ctx context.Context, tx pgx.Tx, nodeID string, settings map[string]any) error {
	raw, err := json.Marshal(settings)
	if err != nil {
		return err
	}
	id := ksuid.New().String()
	_, err = tx.Exec(ctx, `
		INSERT INTO "AgentNodeOpenvpnSettings" (id, "agentNodeId", settings, "createdAt", "updatedAt")
		VALUES ($1, $2, $3, NOW(), NOW())
		ON CONFLICT ("agentNodeId") DO UPDATE SET settings = $3, "updatedAt" = NOW()`,
		id, nodeID, raw)
	return err
}

func mergeSettings(prev, incoming map[string]any) map[string]any {
	out := make(map[string]any, len(prev)+len(incoming))
	for k, v := range prev {
		out[k] = v
	}
	for k, v := range incoming {
		out[k] = v
	}
	return out
}

func ensureOpenvpnSettingsReady(settings map[string]any) {
	openvpn.NormalizeServerSettings(settings)
	openvpn.EnsureMaterialPaths(settings)
}

func mapAgentError(err error) Result {
	var ae *agent.Error
	if errors.As(err, &ae) {
		status := 502
		if ae.StatusCode == 422 {
			status = 422
		} else if ae.StatusCode >= 400 && ae.StatusCode < 500 {
			status = ae.StatusCode
		}
		body := map[string]any{
			"error":  ae.Message,
			"hints":  ae.Hints,
			"output": agentBodyString(ae.Body, "output"),
			"serviceLog": agentBodyString(ae.Body, "serviceLog"),
			"backupPath": agentBodyString(ae.Body, "backupPath"),
			"rolledBack": agentBodyBool(ae.Body, "rolledBack"),
		}
		return Result{Status: status, Body: body}
	}
	return Result{Status: 400, Body: map[string]any{
		"error": err.Error(),
		"hints": []string{},
	}}
}

func agentBodyString(body map[string]any, key string) string {
	if s, ok := body[key].(string); ok {
		return s
	}
	return ""
}

func agentBodyBool(body map[string]any, key string) bool {
	if b, ok := body[key].(bool); ok {
		return b
	}
	return false
}

func tunnelFromBody(body map[string]any) (defaultPolicy string, rules []FirewallRule, natRules []FirewallNatRule) {
	tunnel, _ := body["tunnel"].(map[string]any)
	if tunnel == nil {
		tunnel = map[string]any{}
	}
	defaultPolicy = NormalizeFirewallDefaultPolicy(tunnel["defaultPolicy"])
	rules = NormalizeFirewallBaseRules(tunnel["rules"])
	natRules = NormalizeFirewallNatRules(tunnel["natRules"])
	return defaultPolicy, rules, natRules
}

func strField(body map[string]any, key string) string {
	return strings.TrimSpace(asString(body[key]))
}
