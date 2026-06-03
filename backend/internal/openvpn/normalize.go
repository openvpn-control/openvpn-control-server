package openvpn

import (
	"fmt"
	"net"
	"strings"
)

// NormalizeServerSettings fixes values before writing server.conf (crypto, management, etc.).
func NormalizeServerSettings(settings map[string]any) {
	if settings == nil {
		return
	}
	EnsureServerCryptoDefaults(settings)
	normalizeManagementSetting(settings)
	normalizeTunnelSetting(settings)
}

func normalizeTunnelSetting(settings map[string]any) {
	if settings == nil {
		return
	}
	if n, ok := numericSettingValue(settings["fragment"]); ok && n == 0 {
		delete(settings, "fragment")
	}
	if settingStr(settings, "user") == "" {
		delete(settings, "user")
	}
	if settingStr(settings, "group") == "" {
		delete(settings, "group")
	}
}

func numericSettingValue(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	default:
		s := strings.TrimSpace(fmt.Sprint(v))
		if s == "" {
			return 0, false
		}
		var f float64
		_, err := fmt.Sscanf(s, "%f", &f)
		return f, err == nil
	}
}

func normalizeManagementSetting(settings map[string]any) {
	raw := settingStr(settings, "management")
	if raw == "" {
		return
	}
	settings["management"] = NormalizeManagementValue(raw)
}

// NormalizeManagementValue converts host:port to "host port" for OpenVPN --config.
func NormalizeManagementValue(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, " ") {
		return raw
	}
	if host, port, err := net.SplitHostPort(raw); err == nil && host != "" && port != "" {
		return host + " " + port
	}
	return raw
}

func dataCiphersUseAuth(dc string) bool {
	low := strings.ToLower(strings.TrimSpace(dc))
	if low == "" {
		return true
	}
	if strings.Contains(low, "cbc") {
		return true
	}
	if strings.Contains(low, "gcm") {
		return false
	}
	return true
}
