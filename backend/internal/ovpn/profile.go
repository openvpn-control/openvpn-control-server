package ovpn

import (
	"encoding/json"
	"fmt"
	"strings"
)

type Node struct {
	Host string
	Name string
}

type BuildInput struct {
	Node       Node
	Settings   map[string]any
	CertPEM    string
	KeyPEM     string
	RootCAPEM  string
	TLSAuthPEM string
}

func BuildClientOvpn(in BuildInput) string {
	settings := in.Settings
	if settings == nil {
		settings = map[string]any{}
	}
	proto := str(settings["proto"])
	if proto == "" {
		proto = "udp"
	}
	port := num(settings["port"])
	if port <= 0 {
		port = 1194
	}
	host := strings.TrimSpace(in.Node.Host)
	keyDir := strings.ReplaceAll(str(settings["key-direction"]), "{{key_direction}}", parseTLSAuthDir(settings["tls-auth"]))
	clientKeyDir := invertDir(keyDir)
	dev := normalizeDev(settings["dev"])
	remoteTpl := str(settings["remote"])
	if remoteTpl == "" {
		remoteTpl = "{{host}} {{port}}"
	}
	remoteVal := strings.ReplaceAll(strings.ReplaceAll(remoteTpl, "{{host}}", host), "{{port}}", fmt.Sprint(port))
	resolv := str(settings["resolv-retry"])
	if resolv == "" {
		resolv = "infinite"
	}
	lines := []string{
		"client",
		"dev " + dev,
		"proto " + proto,
		"remote " + remoteVal,
		"resolv-retry " + resolv,
	}
	if boolOr(settings["nobind"], true) {
		lines = append(lines, "nobind")
	}
	if directiveFlagEnabled(settings, "persist-key") {
		lines = append(lines, "persist-key")
	}
	if directiveFlagEnabled(settings, "persist-tun") {
		lines = append(lines, "persist-tun")
	}
	if v := str(settings["data-ciphers"]); v != "" {
		lines = append(lines, "data-ciphers "+v)
	}
	if v := str(settings["data-ciphers-fallback"]); v != "" {
		lines = append(lines, "data-ciphers-fallback "+v)
	}
	lines = append(lines, "remote-cert-tls "+deriveRemoteCertTLS(settings["remote-cert-tls"]))
	if in.TLSAuthPEM != "" {
		lines = append(lines, "key-direction "+clientKeyDir)
	}
	lines = append(lines, fmt.Sprintf("verb %d", clientVerbFromSettings(settings)))
	lines = append(lines, "", "<ca>", strings.TrimSpace(in.RootCAPEM), "</ca>", "")
	lines = append(lines, "<cert>", strings.TrimSpace(in.CertPEM), "</cert>", "")
	lines = append(lines, "<key>", strings.TrimSpace(in.KeyPEM), "</key>")
	if in.TLSAuthPEM != "" {
		lines = append(lines, "", "<tls-auth>", strings.TrimSpace(in.TLSAuthPEM), "</tls-auth>")
	}
	lines = append(lines, "")
	return strings.Join(lines, "\n")
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return strings.TrimSpace(s)
	}
	return ""
}

func num(v any) float64 {
	n, ok := parseNumericSetting(v)
	if !ok {
		return 0
	}
	return n
}

// clientVerbFromSettings reads client-verb from panel DB (fallback: verb, then 3).
func clientVerbFromSettings(settings map[string]any) int {
	if settings == nil {
		return 3
	}
	for _, key := range []string{"client-verb", "verb"} {
		v, ok := settings[key]
		if !ok || v == nil {
			continue
		}
		n, ok := parseNumericSetting(v)
		if !ok || n < 0 || n > 11 {
			continue
		}
		return int(n)
	}
	return 3
}

func parseNumericSetting(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case float32:
		return float64(t), true
	case int:
		return float64(t), true
	case int64:
		return float64(t), true
	case json.Number:
		f, err := t.Float64()
		return f, err == nil
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

// directiveFlagEnabled — флаговые директивы OpenVPN без значения (persist-key, persist-tun, …).
func directiveFlagEnabled(settings map[string]any, key string) bool {
	if settings == nil {
		return false
	}
	v, ok := settings[key]
	if !ok {
		return false
	}
	switch t := v.(type) {
	case bool:
		return t
	case string:
		s := strings.TrimSpace(strings.ToLower(t))
		return s == "1" || s == "true" || s == "yes"
	default:
		return false
	}
}

func boolOr(v any, def bool) bool {
	if v == nil {
		return def
	}
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t != "0" && t != "false"
	default:
		return def
	}
}

func parseTLSAuthDir(raw any) string {
	text := str(raw)
	parts := strings.Fields(text)
	if len(parts) < 2 {
		return "1"
	}
	return parts[1]
}

func invertDir(v string) string {
	switch strings.TrimSpace(v) {
	case "0":
		return "1"
	case "1":
		return "0"
	default:
		return "1"
	}
}

func normalizeDev(raw any) string {
	v := strings.ToLower(str(raw))
	if strings.HasPrefix(v, "tap") {
		return "tap"
	}
	return "tun"
}

func deriveRemoteCertTLS(raw any) string {
	v := strings.ToLower(str(raw))
	if v == "client" {
		return "server"
	}
	if v == "server" {
		return "client"
	}
	return "server"
}
