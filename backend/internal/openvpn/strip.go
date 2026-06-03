package openvpn

import "strings"

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
