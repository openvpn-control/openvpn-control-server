package openvpn

import "strings"

// MergeSettingsForDisplay combines panel DB and agent snapshot (server.conf).
// По умолчанию побеждает агент (факт на сервере); panel* и user/group — из БД панели.
func MergeSettingsForDisplay(db, agent map[string]any) map[string]any {
	if db == nil {
		db = map[string]any{}
	}
	if agent == nil {
		agent = map[string]any{}
	}
	out := mergeMaps(db, agent)
	for k, v := range db {
		if strings.HasPrefix(k, "panel") {
			out[k] = v
		}
	}
	if _, ok := db["user"]; ok {
		out["user"] = db["user"]
	}
	if _, ok := db["group"]; ok {
		out["group"] = db["group"]
	}
	return out
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
