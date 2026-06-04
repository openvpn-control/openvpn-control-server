package openvpn

import (
	"fmt"
	"strings"
)

// MergeSettingsForDisplay combines panel DB and agent snapshot (server.conf).
// Директивы OpenVPN: непустое значение с агента (файл) важнее БД; panel* и user/group — из БД.
func MergeSettingsForDisplay(db, agent map[string]any) map[string]any {
	if db == nil {
		db = map[string]any{}
	}
	if agent == nil {
		agent = map[string]any{}
	}
	out := mergeMaps(agent, map[string]any{})
	for k, v := range db {
		if strings.HasPrefix(k, "panel") {
			out[k] = v
			continue
		}
		if k == "user" || k == "group" {
			if _, ok := db[k]; ok {
				out[k] = v
			}
			continue
		}
		if settingValueIsEmpty(v) {
			continue
		}
		if staleZeroFragmentFromDB(k, v, agent) {
			continue
		}
		if settingValueIsEmpty(out[k]) {
			out[k] = v
		}
	}
	for k := range panelOnlyKeys {
		if v, ok := db[k]; ok {
			out[k] = v
		}
	}
	// auth (HMAC) — настройка панели; в server.conf при GCM не пишется, снимок агента не должен затирать БД.
	if v, ok := db["auth"]; ok && !settingValueIsEmpty(v) {
		out["auth"] = v
	}
	return out
}

// staleZeroFragmentFromDB: в БД остался fragment 0, в server.conf директивы нет — не подставляем в форму.
func staleZeroFragmentFromDB(key string, dbVal any, agent map[string]any) bool {
	if key != "fragment" {
		return false
	}
	if _, ok := agent["fragment"]; ok {
		return false
	}
	n, ok := numericSettingValue(dbVal)
	return ok && n == 0
}

func settingValueIsEmpty(v any) bool {
	if v == nil {
		return true
	}
	switch x := v.(type) {
	case bool:
		return false
	case []any:
		return len(x) == 0
	case []string:
		return len(x) == 0
	case float64, float32, int, int64:
		return false
	default:
		return strings.TrimSpace(fmt.Sprint(v)) == ""
	}
}

func mergeMaps(base, overlay map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(overlay))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range overlay {
		out[k] = v
	}
	return out
}
