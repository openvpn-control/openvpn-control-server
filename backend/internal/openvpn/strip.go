package openvpn

import (
	"bytes"
	"encoding/json"
	"strings"
)

var panelOnlyKeys = map[string]struct{}{
	"remote":        {},
	"resolv-retry":  {},
	"nobind":        {},
	"key-direction": {},
	"client-verb":   {},
}

// StripPanelOnlySettings removes panel metadata and client-only keys before writing server.conf.
func StripPanelOnlySettings(settings map[string]any) map[string]any {
	if settings == nil {
		return map[string]any{}
	}
	out := make(map[string]any, len(settings))
	for k, v := range settings {
		if strings.HasPrefix(k, "panel") {
			continue
		}
		if _, skip := panelOnlyKeys[k]; skip {
			continue
		}
		out[k] = v
	}
	return out
}

// AgentSettingsEqual reports whether server.conf-relevant settings changed.
func AgentSettingsEqual(prev, merged map[string]any) bool {
	a, err1 := json.Marshal(StripPanelOnlySettings(prev))
	b, err2 := json.Marshal(StripPanelOnlySettings(merged))
	if err1 != nil || err2 != nil {
		return false
	}
	return bytes.Equal(a, b)
}
