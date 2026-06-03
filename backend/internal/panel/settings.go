package panel

import (
	"context"
	"errors"
	"log"
	"math"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/openvpn-control/openvpn-control-server/backend/internal/agent"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/openvpn"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/paneltasks"
)

func GetFirewallConfigForPanel(ctx context.Context, pool *pgxpool.Pool, nodeID string) Result {
	node, err := loadNodeRef(ctx, pool, nodeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Result{Status: http.StatusNotFound, Body: map[string]string{"error": "Узел не найден"}}
	}
	if err != nil {
		return Result{Status: http.StatusInternalServerError, Body: map[string]string{"error": err.Error()}}
	}
	settings, _, err := loadSettingsRow(ctx, pool, node.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		settings = map[string]any{}
	} else if err != nil {
		return Result{Status: http.StatusInternalServerError, Body: map[string]string{"error": err.Error()}}
	}
	fallbackDefault := NormalizeFirewallDefaultPolicy(settings[panelFirewallDefaultPolicyKey])
	fallbackRules := NormalizeFirewallBaseRules(settings[panelFirewallBaseRulesKey])
	var tunnelDefaultPolicy string
	if settings[panelFirewallTunnelDefaultPolicyKey] != nil {
		tunnelDefaultPolicy = NormalizeFirewallDefaultPolicy(settings[panelFirewallTunnelDefaultPolicyKey])
	} else {
		tunnelDefaultPolicy = fallbackDefault
	}
	var tunnelRules []FirewallRule
	if settings[panelFirewallTunnelRulesKey] != nil {
		tunnelRules = NormalizeFirewallBaseRules(settings[panelFirewallTunnelRulesKey])
	} else {
		tunnelRules = fallbackRules
	}
	natRules := NormalizeFirewallNatRules(settings[panelFirewallTunnelNatRulesKey])
	tunnelContext := ParseTunnelContext(settings)
	body := firewallBody(node, tunnelDefaultPolicy, tunnelRules, natRules, tunnelContext)
	return Result{Status: http.StatusOK, Body: body}
}

func ApplyFirewallConfigForPanel(ctx context.Context, pool *pgxpool.Pool, nodeID string, reqBody map[string]any) Result {
	node, err := loadNodeRef(ctx, pool, nodeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Result{Status: http.StatusNotFound, Body: map[string]string{"error": "Узел не найден"}}
	}
	if err != nil {
		return Result{Status: http.StatusInternalServerError, Body: map[string]string{"error": err.Error()}}
	}
	tunnelDefaultPolicy, tunnelRules, natRules := tunnelFromBody(reqBody)
	prev, _, err := loadSettingsRow(ctx, pool, node.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		prev = map[string]any{}
	} else if err != nil {
		return Result{Status: http.StatusInternalServerError, Body: map[string]string{"error": err.Error()}}
	}
	tunnelContext := ParseTunnelContext(prev)
	next := mergeSettings(prev, map[string]any{
		panelFirewallTunnelDefaultPolicyKey: tunnelDefaultPolicy,
		panelFirewallTunnelRulesKey:         toAnySlice(tunnelRules),
		panelFirewallTunnelNatRulesKey:      toAnySliceNat(natRules),
	})
	if err := upsertSettings(ctx, pool, node.ID, next, nil); err != nil {
		return Result{Status: http.StatusInternalServerError, Body: map[string]string{"error": err.Error()}}
	}
	go func() {
		if err := paneltasks.EnqueueSnapshotForNode(context.Background(), pool, node.ID); err != nil {
			log.Printf("EnqueueSnapshotForNode: %v", err)
		}
	}()
	body := firewallBody(node, tunnelDefaultPolicy, tunnelRules, natRules, tunnelContext)
	body["ok"] = true
	body["message"] = "Конфигурация tunnel firewall сохранена."
	return Result{Status: http.StatusOK, Body: body}
}

func CheckFirewallConfigForPanel(ctx context.Context, pool *pgxpool.Pool, nodeID string, reqBody map[string]any) Result {
	node, err := loadNodeRef(ctx, pool, nodeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Result{Status: http.StatusNotFound, Body: map[string]string{"error": "Узел не найден"}}
	}
	if err != nil {
		return Result{Status: http.StatusInternalServerError, Body: map[string]string{"error": err.Error()}}
	}
	tunnelDefaultPolicy, tunnelRules, natRules := tunnelFromBody(reqBody)
	settings, _, err := loadSettingsRow(ctx, pool, node.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		settings = map[string]any{}
	} else if err != nil {
		return Result{Status: http.StatusInternalServerError, Body: map[string]string{"error": err.Error()}}
	}
	tunnelContext := ParseTunnelContext(settings)
	body := firewallBody(node, tunnelDefaultPolicy, tunnelRules, natRules, tunnelContext)
	body["ok"] = true
	body["message"] = "Конфигурация tunnel firewall валидна."
	return Result{Status: http.StatusOK, Body: body}
}

func GetOpenvpnSettingsForPanel(ctx context.Context, pool *pgxpool.Pool, nodeID string) Result {
	an, err := loadAgentNode(ctx, pool, nodeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Result{Status: http.StatusNotFound, Body: map[string]string{"error": "Узел не найден"}}
	}
	if err != nil {
		return Result{Status: http.StatusInternalServerError, Body: map[string]string{"error": err.Error()}}
	}
	data, err := agent.GetOpenVPNSettings(ctx, an)
	if err == nil {
		agentSettings, ok := data["settings"].(map[string]any)
		if !ok {
			return Result{Status: http.StatusBadGateway, Body: map[string]string{"error": "Некорректный ответ агента (settings)"}}
		}
		configPath := strField(data, "configPath")
		var cp *string
		if configPath != "" {
			cp = &configPath
		}
		prev, _, _ := loadSettingsRow(ctx, pool, an.ID)
		if prev == nil {
			prev = map[string]any{}
		}
		// Снимок server.conf (агент) важнее устаревшей БД; user/group и panel* — из БД.
		merged := openvpn.MergeSettingsForDisplay(prev, agentSettings)
		ensureOpenvpnSettingsReady(merged)
		if err := upsertSettings(ctx, pool, an.ID, merged, cp); err != nil {
			return Result{Status: http.StatusInternalServerError, Body: map[string]string{"error": err.Error()}}
		}
		return Result{Status: http.StatusOK, Body: map[string]any{
			"settings": merged, "configPath": cp, "source": "agent",
		}}
	}
	hints := fallbackHints
	var ae *agent.Error
	if errors.As(err, &ae) && len(ae.Hints) > 0 {
		hints = ae.Hints
	}
	prev, configPath, err := loadSettingsRow(ctx, pool, an.ID)
	if err == nil {
		return Result{Status: http.StatusOK, Body: map[string]any{
			"settings": prev, "configPath": configPath, "source": "database", "hints": hints,
		}}
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Result{Status: http.StatusInternalServerError, Body: map[string]string{"error": err.Error()}}
	}
	initial := openvpn.InitialServerSettings()
	if err := upsertSettings(ctx, pool, an.ID, initial, nil); err != nil {
		return Result{Status: http.StatusInternalServerError, Body: map[string]string{"error": err.Error()}}
	}
	return Result{Status: http.StatusOK, Body: map[string]any{
		"settings": initial, "configPath": nil, "source": "seed", "hints": hints,
	}}
}

func PostOpenvpnSettingsForPanel(ctx context.Context, pool *pgxpool.Pool, nodeID string, reqBody map[string]any) Result {
	an, err := loadAgentNode(ctx, pool, nodeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Result{Status: http.StatusNotFound, Body: map[string]string{"error": "Узел не найден"}}
	}
	if err != nil {
		return Result{Status: http.StatusInternalServerError, Body: map[string]string{"error": err.Error()}}
	}
	incoming, ok := reqBody["settings"].(map[string]any)
	if !ok || incoming == nil {
		return Result{Status: http.StatusBadRequest, Body: map[string]string{"error": "Требуется объект settings"}}
	}
	prev, _, _ := loadSettingsRow(ctx, pool, an.ID)
	if prev == nil {
		prev = map[string]any{}
	}
	merged := mergeSettings(prev, incoming)
	ensureOpenvpnSettingsReady(merged)
	if !openvpn.AgentSettingsEqual(prev, merged) {
		if _, err := agent.PostOpenVPNSettings(ctx, an, openvpn.StripPanelOnlySettings(merged)); err != nil {
			return mapAgentError(err)
		}
	}
	if err := paneltasks.EnqueueOpenvpnMaterialSyncTasks(ctx, pool, an.ID, merged); err != nil {
		return Result{Status: http.StatusInternalServerError, Body: map[string]string{"error": err.Error()}}
	}
	if err := upsertSettings(ctx, pool, an.ID, merged, nil); err != nil {
		return Result{Status: http.StatusInternalServerError, Body: map[string]string{"error": err.Error()}}
	}
	go func() {
		if err := paneltasks.EnqueueSnapshotForNode(context.Background(), pool, an.ID); err != nil {
			log.Printf("EnqueueSnapshotForNode: %v", err)
		}
	}()
	return Result{Status: http.StatusOK, Body: map[string]bool{"ok": true}}
}

func RemoveRootCaForPanel(ctx context.Context, pool *pgxpool.Pool, nodeID string, reqBody map[string]any) Result {
	agentNodeID := strings.TrimSpace(nodeID)
	an, err := loadAgentNode(ctx, pool, agentNodeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Result{Status: http.StatusNotFound, Body: map[string]string{"error": "Узел не найден"}}
	}
	if err != nil {
		return Result{Status: http.StatusInternalServerError, Body: map[string]string{"error": err.Error()}}
	}
	prev, _, err := loadSettingsRow(ctx, pool, agentNodeID)
	if errors.Is(err, pgx.ErrNoRows) {
		prev = map[string]any{}
	} else if err != nil {
		return Result{Status: http.StatusInternalServerError, Body: map[string]string{"error": err.Error()}}
	}
	rootID := strings.TrimSpace(asString(prev["panelRootCaId"]))
	if rootID == "" {
		return Result{Status: http.StatusBadRequest, Body: map[string]string{"error": "Для этого сервера не задан корневой сертификат"}}
	}
	var expectedCN string
	err = pool.QueryRow(ctx, `SELECT "commonName" FROM "RootCertificateAuthority" WHERE id = $1`, rootID).Scan(&expectedCN)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return Result{Status: http.StatusInternalServerError, Body: map[string]string{"error": err.Error()}}
	}
	expectedCN = strings.TrimSpace(expectedCN)
	providedCN := strField(reqBody, "confirmCommonName")
	if expectedCN == "" || providedCN != expectedCN {
		return Result{Status: http.StatusBadRequest, Body: map[string]string{
			"error": "Подтвердите удаление: введите точный Common Name (CN) корневого сертификата.",
		}}
	}
	nextSettings := mergeSettings(prev, map[string]any{"panelRootCaId": "", "panelServerCertId": ""})
	tx, err := pool.Begin(ctx)
	if err != nil {
		return Result{Status: http.StatusInternalServerError, Body: map[string]string{"error": err.Error()}}
	}
	defer tx.Rollback(ctx)
	_, _ = tx.Exec(ctx, `DELETE FROM "Certificate" WHERE "agentNodeId" = $1 AND "rootCaId" = $2`, agentNodeID, rootID)
	_, _ = tx.Exec(ctx, `DELETE FROM "ClientIpAssignment" WHERE "agentNodeId" = $1`, agentNodeID)
	_, _ = tx.Exec(ctx, `DELETE FROM "ClientSourceIpHistory" WHERE "agentNodeId" = $1`, agentNodeID)
	_, _ = tx.Exec(ctx, `DELETE FROM "ClientTrafficSample" WHERE "agentNodeId" = $1`, agentNodeID)
	_, _ = tx.Exec(ctx, `DELETE FROM "OpenvpnServerLog" WHERE "agentNodeId" = $1`, agentNodeID)
	if err := upsertSettingsTx(ctx, tx, agentNodeID, nextSettings); err != nil {
		return Result{Status: http.StatusInternalServerError, Body: map[string]string{"error": err.Error()}}
	}
	if err := tx.Commit(ctx); err != nil {
		return Result{Status: http.StatusInternalServerError, Body: map[string]string{"error": err.Error()}}
	}
	var settingsRefs int
	rows, err := pool.Query(ctx, `SELECT settings FROM "AgentNodeOpenvpnSettings"`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var raw []byte
			if rows.Scan(&raw) != nil {
				continue
			}
			var s map[string]any
			_ = jsonUnmarshal(raw, &s)
			if strings.TrimSpace(asString(s["panelRootCaId"])) == rootID {
				settingsRefs++
			}
		}
	}
	var certRefs int
	_ = pool.QueryRow(ctx, `SELECT COUNT(*)::int FROM "Certificate" WHERE "rootCaId" = $1`, rootID).Scan(&certRefs)
	if settingsRefs == 0 && certRefs == 0 {
		_, _ = pool.Exec(ctx, `DELETE FROM "RootCertificateAuthority" WHERE id = $1`, rootID)
	}
	merged, _, _ := loadSettingsRow(ctx, pool, agentNodeID)
	if merged == nil {
		merged = nextSettings
	}
	if err := paneltasks.EnqueueOpenvpnMaterialSyncTasks(ctx, pool, an.ID, merged); err != nil {
		log.Printf("EnqueueOpenvpnMaterialSyncTasks after root remove: %v", err)
	}
	return Result{Status: http.StatusOK, Body: map[string]any{"ok": true, "settings": merged}}
}

func ApplyOpenvpnSettingsForPanel(ctx context.Context, pool *pgxpool.Pool, nodeID string, reqBody map[string]any) Result {
	an, err := loadAgentNode(ctx, pool, nodeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Result{Status: http.StatusNotFound, Body: map[string]string{"error": "Узел не найден"}}
	}
	if err != nil {
		return Result{Status: http.StatusInternalServerError, Body: map[string]string{"error": err.Error()}}
	}
	prev, _, _ := loadSettingsRow(ctx, pool, an.ID)
	if prev == nil {
		prev = map[string]any{}
	}
	incoming, _ := reqBody["settings"].(map[string]any)
	if incoming == nil {
		incoming = map[string]any{}
	}
	settings := mergeSettings(prev, incoming)
	ensureOpenvpnSettingsReady(settings)
	if err := paneltasks.EnqueueOpenvpnMaterialSyncTasks(ctx, pool, an.ID, settings); err != nil {
		return Result{Status: http.StatusInternalServerError, Body: map[string]string{"error": err.Error()}}
	}
	_ = paneltasks.ProcessPendingTasksForNode(ctx, pool, an.ID, 50)
	if _, err := agent.PostOpenVPNSettingsStage(ctx, an, openvpn.StripPanelOnlySettings(settings)); err != nil {
		return mapAgentError(err)
	}
	applyData, err := agent.PostOpenVPNApplyConfig(ctx, an)
	if err != nil {
		return mapAgentError(err)
	}
	if agentData, err := agent.GetOpenVPNSettings(ctx, an); err == nil {
		if onDisk, ok := agentData["settings"].(map[string]any); ok {
			settings = openvpn.MergeSettingsForDisplay(settings, onDisk)
		}
	}
	if err := upsertSettings(ctx, pool, an.ID, settings, nil); err != nil {
		return Result{Status: http.StatusInternalServerError, Body: map[string]string{"error": err.Error()}}
	}
	go func() {
		if err := paneltasks.EnqueueSnapshotForNode(context.Background(), pool, an.ID); err != nil {
			log.Printf("EnqueueSnapshotForNode: %v", err)
		}
	}()
	return Result{Status: http.StatusOK, Body: map[string]any{
		"ok": true, "message": "Настройки применены на агенте.",
		"output": agentBodyString(applyData, "output"),
		"serviceLog": agentBodyString(applyData, "serviceLog"),
	}}
}

func GetOpenvpnRawConfigForPanel(ctx context.Context, pool *pgxpool.Pool, nodeID string) Result {
	an, err := loadAgentNode(ctx, pool, nodeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Result{Status: http.StatusNotFound, Body: map[string]string{"error": "Узел не найден"}}
	}
	if err != nil {
		return Result{Status: http.StatusInternalServerError, Body: map[string]string{"error": err.Error()}}
	}
	data, err := agent.GetOpenVPNRawConfig(ctx, an)
	if err != nil {
		msg := err.Error()
		var ae *agent.Error
		if errors.As(err, &ae) {
			msg = ae.Message
		}
		return Result{Status: http.StatusBadGateway, Body: map[string]string{"error": msg}}
	}
	cp := strField(data, "configPath")
	var configPath any = nil
	if cp != "" {
		configPath = cp
	}
	rawConfig := asString(data["rawConfig"])
	return Result{Status: http.StatusOK, Body: map[string]any{
		"configPath": configPath, "rawConfig": rawConfig,
	}}
}

func GetNodeNetworkInfoForPanel(ctx context.Context, pool *pgxpool.Pool, nodeID string) Result {
	an, err := loadAgentNode(ctx, pool, nodeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Result{Status: http.StatusNotFound, Body: map[string]string{"error": "Узел не найден"}}
	}
	if err != nil {
		return Result{Status: http.StatusInternalServerError, Body: map[string]string{"error": err.Error()}}
	}
	data, err := agent.GetSystemNetwork(ctx, an)
	if err != nil {
		msg := err.Error()
		var ae *agent.Error
		if errors.As(err, &ae) {
			msg = ae.Message
		}
		return Result{Status: http.StatusBadGateway, Body: map[string]string{"error": msg}}
	}
	return Result{Status: http.StatusOK, Body: map[string]any{
		"interfaces": mapNetworkInterfaces(data["interfaces"]),
		"addresses":  mapStringList(data["addresses"]),
	}}
}

func GetNodeSystemServicesForPanel(ctx context.Context, pool *pgxpool.Pool, nodeID string) Result {
	an, err := loadAgentNode(ctx, pool, nodeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Result{Status: http.StatusNotFound, Body: map[string]string{"error": "Узел не найден"}}
	}
	if err != nil {
		return Result{Status: http.StatusInternalServerError, Body: map[string]string{"error": err.Error()}}
	}
	data, err := agent.GetSystemServices(ctx, an)
	if err != nil {
		msg := err.Error()
		var ae *agent.Error
		if errors.As(err, &ae) {
			msg = ae.Message
		}
		return Result{Status: http.StatusBadGateway, Body: map[string]string{"error": msg}}
	}
	return Result{Status: http.StatusOK, Body: map[string]any{"services": mapSystemServices(data["services"])}}
}

func PostNodeSystemServiceUnitActionForPanel(ctx context.Context, pool *pgxpool.Pool, nodeID string, reqBody map[string]any) Result {
	an, err := loadAgentNode(ctx, pool, nodeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Result{Status: http.StatusNotFound, Body: map[string]string{"error": "Узел не найден"}}
	}
	if err != nil {
		return Result{Status: http.StatusInternalServerError, Body: map[string]string{"error": err.Error()}}
	}
	unit := strField(reqBody, "unit")
	action := strings.ToLower(strField(reqBody, "action"))
	if !isAllowedSystemdServiceUnitName(unit) {
		return Result{Status: http.StatusBadRequest, Body: map[string]string{"error": "Недопустимое имя unit (ожидается *.service)"}}
	}
	if action != "start" && action != "stop" && action != "restart" {
		return Result{Status: http.StatusBadRequest, Body: map[string]string{"error": "action должен быть start|stop|restart"}}
	}
	data, err := agent.PostSystemServiceUnitAction(ctx, an, unit, action)
	if err != nil {
		var ae *agent.Error
		rawOutput := ""
		msg := err.Error()
		if errors.As(err, &ae) {
			msg = ae.Message
			rawOutput = strings.TrimSpace(agentBodyString(ae.Body, "output"))
		}
		if rawOutput != "" {
			msg = msg + ": " + rawOutput
		}
		body := map[string]any{"error": msg}
		if rawOutput != "" {
			body["output"] = rawOutput
		} else {
			body["output"] = nil
		}
		return Result{Status: http.StatusBadGateway, Body: body}
	}
	return Result{Status: http.StatusOK, Body: data}
}

func GetDnsmasqForPanel(ctx context.Context, pool *pgxpool.Pool, nodeID string) Result {
	an, err := loadAgentNode(ctx, pool, nodeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Result{Status: http.StatusNotFound, Body: map[string]string{"error": "Узел не найден"}}
	}
	if err != nil {
		return Result{Status: http.StatusInternalServerError, Body: map[string]string{"error": err.Error()}}
	}
	data, err := agent.GetDnsmasq(ctx, an)
	if err != nil {
		msg := err.Error()
		var ae *agent.Error
		if errors.As(err, &ae) {
			msg = ae.Message
		}
		return Result{Status: http.StatusBadGateway, Body: map[string]string{"error": msg}}
	}
	service, _ := data["service"].(map[string]any)
	if service == nil {
		service = map[string]any{}
	}
	return Result{Status: http.StatusOK, Body: map[string]any{
		"service": service, "configPath": asString(data["configPath"]), "config": asString(data["config"]),
	}}
}

func PostDnsmasqForPanel(ctx context.Context, pool *pgxpool.Pool, nodeID string, reqBody map[string]any) Result {
	an, err := loadAgentNode(ctx, pool, nodeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Result{Status: http.StatusNotFound, Body: map[string]string{"error": "Узел не найден"}}
	}
	if err != nil {
		return Result{Status: http.StatusInternalServerError, Body: map[string]string{"error": err.Error()}}
	}
	action := strings.ToLower(strField(reqBody, "action"))
	if action == "" {
		action = "save"
	}
	switch action {
	case "save", "apply", "start", "stop", "restart":
	default:
		return Result{Status: http.StatusBadRequest, Body: map[string]string{"error": "action должен быть save|apply|start|stop|restart"}}
	}
	data, err := agent.PostDnsmasq(ctx, an, action, asString(reqBody["config"]))
	if err != nil {
		var ae *agent.Error
		msg := err.Error()
		output := ""
		if errors.As(err, &ae) {
			msg = ae.Message
			output = agentBodyString(ae.Body, "output")
		}
		return Result{Status: http.StatusBadGateway, Body: map[string]any{"error": msg, "output": output}}
	}
	return Result{Status: http.StatusOK, Body: data}
}

func EnqueueDnsmasqApplyTaskForPanel(ctx context.Context, pool *pgxpool.Pool, nodeID string, reqBody map[string]any) Result {
	_, err := loadNodeRef(ctx, pool, nodeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Result{Status: http.StatusNotFound, Body: map[string]string{"error": "Узел не найден"}}
	}
	if err != nil {
		return Result{Status: http.StatusInternalServerError, Body: map[string]string{"error": err.Error()}}
	}
	config := asString(reqBody["config"])
	if err := paneltasks.EnqueueDnsmasqApply(ctx, pool, nodeID, config); err != nil {
		return Result{Status: http.StatusInternalServerError, Body: map[string]string{"error": err.Error()}}
	}
	return Result{Status: http.StatusAccepted, Body: map[string]any{
		"ok": true,
		"message": "Задача применения DNSMasq поставлена в очередь. Статус выполнения — в разделе «Задачи» (тип dnsmasq_apply).",
	}}
}

func PostOpenvpnServiceActionForPanel(ctx context.Context, pool *pgxpool.Pool, nodeID string, reqBody map[string]any) Result {
	an, err := loadAgentNode(ctx, pool, nodeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Result{Status: http.StatusNotFound, Body: map[string]string{"error": "Узел не найден"}}
	}
	if err != nil {
		return Result{Status: http.StatusInternalServerError, Body: map[string]string{"error": err.Error()}}
	}
	action := strings.ToLower(strField(reqBody, "action"))
	if action != "start" && action != "stop" && action != "restart" {
		return Result{Status: http.StatusBadRequest, Body: map[string]string{"error": "action должен быть start|stop|restart"}}
	}
	data, err := agent.PostOpenVPNServiceAction(ctx, an, action)
	if err != nil {
		var ae *agent.Error
		rawOutput := ""
		msg := err.Error()
		if errors.As(err, &ae) {
			msg = ae.Message
			rawOutput = strings.TrimSpace(agentBodyString(ae.Body, "output"))
		}
		if rawOutput != "" {
			msg = msg + ": " + rawOutput
		}
		hintUnit := "openvpn.service"
		var unit string
		_ = pool.QueryRow(ctx, `SELECT "openvpnServiceUnit" FROM "AgentNode" WHERE id = $1`, an.ID).Scan(&unit)
		if strings.TrimSpace(unit) != "" {
			hintUnit = unit
		}
		body := map[string]any{
			"error": msg,
			"hints": []string{
				"Проверьте unit OpenVPN: " + hintUnit + ".",
				"При необходимости задайте OPENVPN_SERVICE_UNIT или OPENVPN_SERVICE_*_CMD на агенте.",
				"Проверьте права пользователя агента на выполнение systemctl.",
			},
		}
		if rawOutput != "" {
			body["output"] = rawOutput
		} else {
			body["output"] = nil
		}
		return Result{Status: http.StatusBadGateway, Body: body}
	}
	return Result{Status: http.StatusOK, Body: data}
}

func PostOpenvpnCheckConfigForPanel(ctx context.Context, pool *pgxpool.Pool, nodeID string) Result {
	an, err := loadAgentNode(ctx, pool, nodeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Result{Status: http.StatusNotFound, Body: map[string]string{"error": "Узел не найден"}}
	}
	if err != nil {
		return Result{Status: http.StatusInternalServerError, Body: map[string]string{"error": err.Error()}}
	}
	// Проверяем активный server.conf на узле (не перезаписываем черновиком из БД перед check).
	data, err := agent.PostOpenVPNCheckConfig(ctx, an)
	if err != nil {
		status := http.StatusBadGateway
		var ae *agent.Error
		if errors.As(err, &ae) && ae.StatusCode == 422 {
			status = http.StatusUnprocessableEntity
		}
		body := map[string]any{"error": err.Error(), "hints": []string{}}
		if errors.As(err, &ae) {
			body["error"] = ae.Message
			body["hints"] = ae.Hints
			body["output"] = agentBodyString(ae.Body, "output")
			body["command"] = agentBodyString(ae.Body, "command")
			body["configPath"] = agentBodyString(ae.Body, "configPath")
		}
		return Result{Status: status, Body: body}
	}
	return Result{Status: http.StatusOK, Body: data}
}

func PostAgentUpdateForPanel(ctx context.Context, pool *pgxpool.Pool, nodeID string, reqBody map[string]any) Result {
	an, err := loadAgentNode(ctx, pool, nodeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Result{Status: http.StatusNotFound, Body: map[string]string{"error": "Узел не найден"}}
	}
	if err != nil {
		return Result{Status: http.StatusInternalServerError, Body: map[string]string{"error": err.Error()}}
	}
	binaryBase64 := strField(reqBody, "binaryBase64")
	if binaryBase64 == "" {
		return Result{Status: http.StatusBadRequest, Body: map[string]string{"error": "Требуется binaryBase64"}}
	}
	data, err := agent.PostBinaryUpdate(ctx, an, strField(reqBody, "fileName"), binaryBase64, strField(reqBody, "checksumSha256"))
	if err != nil {
		var ae *agent.Error
		msg := err.Error()
		var output any = nil
		if errors.As(err, &ae) {
			msg = ae.Message
			if ae.Body != nil {
				output = ae.Body["output"]
			}
		}
		return Result{Status: http.StatusBadGateway, Body: map[string]any{"error": msg, "output": output}}
	}
	return Result{Status: http.StatusOK, Body: data}
}

type LogsQuery struct {
	Page     int
	PageSize int
	Q        string
}

func GetOpenvpnLogsForPanel(ctx context.Context, pool *pgxpool.Pool, nodeID string, query LogsQuery) Result {
	node, err := loadNodeRef(ctx, pool, nodeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Result{Status: http.StatusNotFound, Body: map[string]string{"error": "Узел не найден"}}
	}
	if err != nil {
		return Result{Status: http.StatusInternalServerError, Body: map[string]string{"error": err.Error()}}
	}
	page := query.Page
	if page < 1 {
		page = 1
	}
	pageSize := query.PageSize
	if pageSize < 10 {
		pageSize = 50
	}
	if pageSize > 200 {
		pageSize = 200
	}
	q := strings.TrimSpace(query.Q)
	var total int
	var rowsJSON []byte
	if q == "" {
		err = pool.QueryRow(ctx, `SELECT COUNT(*)::int FROM "OpenvpnServerLog" WHERE "agentNodeId" = $1`, node.ID).Scan(&total)
		if err != nil {
			return Result{Status: http.StatusInternalServerError, Body: map[string]string{"error": err.Error()}}
		}
		err = pool.QueryRow(ctx, `
			SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json)::text FROM (
				SELECT id, "occurredAt", "occurredRaw", event, username, "ipAddress"
				FROM "OpenvpnServerLog"
				WHERE "agentNodeId" = $1
				ORDER BY "occurredAt" DESC, id DESC
				LIMIT $2 OFFSET $3
			) t`, node.ID, pageSize, (page-1)*pageSize).Scan(&rowsJSON)
	} else {
		pattern := "%" + q + "%"
		err = pool.QueryRow(ctx, `
			SELECT COUNT(*)::int FROM "OpenvpnServerLog"
			WHERE "agentNodeId" = $1 AND (
				username ILIKE $2 OR event ILIKE $2 OR "occurredRaw" ILIKE $2 OR
				"ipAddress" ILIKE $2 OR "rawLine" ILIKE $2
			)`, node.ID, pattern).Scan(&total)
		if err != nil {
			return Result{Status: http.StatusInternalServerError, Body: map[string]string{"error": err.Error()}}
		}
		err = pool.QueryRow(ctx, `
			SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json)::text FROM (
				SELECT id, "occurredAt", "occurredRaw", event, username, "ipAddress"
				FROM "OpenvpnServerLog"
				WHERE "agentNodeId" = $1 AND (
					username ILIKE $2 OR event ILIKE $2 OR "occurredRaw" ILIKE $2 OR
					"ipAddress" ILIKE $2 OR "rawLine" ILIKE $2
				)
				ORDER BY "occurredAt" DESC, id DESC
				LIMIT $3 OFFSET $4
			) t`, node.ID, pattern, pageSize, (page-1)*pageSize).Scan(&rowsJSON)
	}
	if err != nil {
		return Result{Status: http.StatusInternalServerError, Body: map[string]string{"error": err.Error()}}
	}
	totalPages := int(math.Max(1, math.Ceil(float64(total)/float64(pageSize))))
	var rows any
	_ = jsonUnmarshal(rowsJSON, &rows)
	if rows == nil {
		rows = []any{}
	}
	return Result{Status: http.StatusOK, Body: map[string]any{
		"page": page, "pageSize": pageSize, "total": total, "totalPages": totalPages, "rows": rows,
	}}
}

func isAllowedSystemdServiceUnitName(unit string) bool {
	if unit == "" || len(unit) > 256 || !strings.HasSuffix(unit, ".service") {
		return false
	}
	base := strings.TrimSuffix(unit, ".service")
	if base == "" {
		return false
	}
	for _, r := range base {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '@' || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func mapNetworkInterfaces(raw any) []map[string]any {
	arr, ok := raw.([]any)
	if !ok {
		return []map[string]any{}
	}
	out := make([]map[string]any, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		addrs := mapStringList(m["addresses"])
		out = append(out, map[string]any{
			"name": asString(m["name"]), "addresses": addrs,
		})
	}
	return out
}

func mapSystemServices(raw any) []map[string]any {
	arr, ok := raw.([]any)
	if !ok {
		return []map[string]any{}
	}
	out := make([]map[string]any, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		row := map[string]any{
			"unit":        asString(m["unit"]),
			"loadState":   asString(m["loadState"]),
			"activeState": asString(m["activeState"]),
			"subState":    asString(m["subState"]),
			"description": asString(m["description"]),
		}
		if v, ok := m["mainPid"].(float64); ok && !math.IsNaN(v) && !math.IsInf(v, 0) {
			row["mainPid"] = int(v)
		}
		if v, ok := m["uptimeSeconds"].(float64); ok && !math.IsNaN(v) && !math.IsInf(v, 0) {
			row["uptimeSeconds"] = int(v)
		}
		out = append(out, row)
	}
	return out
}

func mapStringList(raw any) []string {
	arr, ok := raw.([]any)
	if !ok {
		return []string{}
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		s := strings.TrimSpace(asString(item))
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func toAnySlice(rules []FirewallRule) []any {
	out := make([]any, len(rules))
	for i, r := range rules {
		out[i] = r
	}
	return out
}

func toAnySliceNat(rules []FirewallNatRule) []any {
	out := make([]any, len(rules))
	for i, r := range rules {
		out[i] = r
	}
	return out
}
