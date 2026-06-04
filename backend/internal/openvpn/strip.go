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

// materialPathKeys — пути к PEM на узле; файлы выкладывает sync, не сразу при POST openvpn-settings.
var materialPathKeys = map[string]struct{}{
	"ca":           {},
	"cert":         {},
	"key":          {},
	"dh":           {},
	"ecdh-curve":   {},
	"crl-verify":   {},
	"tls-auth":     {},
	"tls-crypt":    {},
	"tls-crypt-v2": {},
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

// StripEmptyManagedDirectiveValues убирает пустые пути (dh, ca, …), чтобы overlay на агенте
// не снимал уже заданные в server.conf директивы.
func StripEmptyManagedDirectiveValues(settings map[string]any) map[string]any {
	if settings == nil {
		return map[string]any{}
	}
	out := make(map[string]any, len(settings))
	for k, v := range settings {
		if _, ok := materialPathKeys[k]; ok && settingStr(settings, k) == "" {
			continue
		}
		out[k] = v
	}
	return out
}

// PrepareAgentSettings — payload для POST /openvpn/settings на агенте.
func PrepareAgentSettings(settings map[string]any) map[string]any {
	return StripEmptyManagedDirectiveValues(StripPanelOnlySettings(settings))
}

func isPanelMetadataOrMaterialPath(key string) bool {
	if strings.HasPrefix(key, "panel") {
		return true
	}
	_, ok := materialPathKeys[key]
	return ok
}

// OnlyPanelMetadataAndMaterialPathsChanged — true, если изменились только panel* и пути к материалам
// (привязка УЦ, cert/dh/tls sync). В этом случае server.conf на агенте не пересобираем.
func OnlyPanelMetadataAndMaterialPathsChanged(prev, merged map[string]any) bool {
	if prev == nil {
		prev = map[string]any{}
	}
	if merged == nil {
		merged = map[string]any{}
	}
	seen := make(map[string]struct{}, len(prev)+len(merged))
	for k := range prev {
		seen[k] = struct{}{}
	}
	for k := range merged {
		seen[k] = struct{}{}
	}
	for k := range seen {
		if jsonEqual(prev[k], merged[k]) {
			continue
		}
		if !isPanelMetadataOrMaterialPath(k) {
			return false
		}
	}
	return true
}

func jsonEqual(a, b any) bool {
	ab, err1 := json.Marshal(a)
	bb, err2 := json.Marshal(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return bytes.Equal(ab, bb)
}

// AgentSettingsEqual reports whether server.conf-relevant settings changed.
func AgentSettingsEqual(prev, merged map[string]any) bool {
	a, err1 := json.Marshal(PrepareAgentSettings(prev))
	b, err2 := json.Marshal(PrepareAgentSettings(merged))
	if err1 != nil || err2 != nil {
		return false
	}
	return bytes.Equal(a, b)
}
