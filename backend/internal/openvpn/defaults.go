package openvpn

import (
	"fmt"
	"strings"
)

// Conventional paths on the VPN node (written by panel sync tasks).
const (
	DefaultCAPath         = "/etc/openvpn/ca.crt"
	DefaultServerCertPath = "/etc/openvpn/server.crt"
	DefaultServerKeyPath  = "/etc/openvpn/server.key"
	DefaultCrlPath        = "/etc/openvpn/crl.pem"
	DefaultDhPath         = "/etc/openvpn/dh.pem"
)

// InitialServerSettings is the seed when the agent is unreachable.
func InitialServerSettings() map[string]any {
	return map[string]any{
		"port":                   1194,
		"proto":                  "udp",
		"dev":                    "tun0",
		"remote":                 "{{host}} {{port}}",
		"resolv-retry":           "infinite",
		"nobind":                 true,
		"key-direction":          "{{key_direction}}",
		"topology":               "subnet",
		"local":                  "",
		"daemon":                 false,
		"mode":                   "server",
		"server":                 "10.8.0.0 255.255.255.0",
		"server-bridge":          "",
		"max-clients":            100,
		"keepalive":              "10 120",
		"ca":                     "",
		"cert":                   "",
		"key":                    "",
		"dh":                     "",
		"ecdh-curve":             "",
		"tls-auth":               "",
		"tls-crypt":              "",
		"tls-crypt-v2":           "",
		"crl-verify":             "",
		"remote-cert-tls":        "",
		"verify-x509-name":       "",
		"management":             "",
		"status":                 "",
		"log":                    "",
		"log-append":             "",
		"plugin":                 []any{},
		"up":                     "",
		"down":                   "",
		"persist-key":            true,
		"persist-tun":            true,
		"duplicate-cn":           false,
		"client-to-client":       false,
		"float":                  false,
		"data-ciphers":           "AES-256-GCM:AES-128-GCM",
		"tls-ciphersuites":       "",
		"cipher":                 "",
		"auth":                   "SHA256",
		"tls-version-min":        "1.2",
		"verb":                   3,
		"client-verb":            3,
		"mute":                   20,
		"mute-replay-warnings":   false,
		"script-security":        2,
		"reneg-sec":              0,
		"hand-window":            60,
		"tun-mtu":                1500,
		"mssfix":                 1450,
		"fragment":               0,
		"user":                   "nobody",
		"group":                  "nogroup",
		"ifconfig-pool-persist":  "",
		"comp-lzo":               "",
		"allow-compression":      "",
		"panelRootCaId":          "",
		"panelServerCertId":      "",
		"panelDhMaterialId":      "",
		"panelTlsAuthMaterialId": "",
		"push":                   []any{},
		"route":                  []any{},
	}
}

func settingStr(settings map[string]any, key string) string {
	if settings == nil {
		return ""
	}
	v, ok := settings[key]
	if !ok || v == nil {
		return ""
	}
	return strings.TrimSpace(strings.Trim(strings.ReplaceAll(strings.ReplaceAll(
		strings.TrimSpace(fmtAny(v)), "\n", " "), "\r", ""), `"`))
}

func fmtAny(v any) string {
	switch t := v.(type) {
	case string:
		return t
	default:
		return fmt.Sprint(v)
	}
}

// EnsureServerCryptoDefaults fills data-ciphers for OpenVPN 2.5+ and drops empty cipher.
func EnsureServerCryptoDefaults(settings map[string]any) {
	if settings == nil {
		return
	}
	if settingStr(settings, "data-ciphers") == "" {
		settings["data-ciphers"] = "AES-256-GCM:AES-128-GCM"
	}
	if settingStr(settings, "auth") == "" {
		settings["auth"] = "SHA256"
	}
	if settingStr(settings, "tls-version-min") == "" {
		settings["tls-version-min"] = "1.2"
	}
	if _, ok := settings["cipher"]; ok && settingStr(settings, "cipher") == "" {
		delete(settings, "cipher")
	}
}

// EnsureMaterialPaths sets OpenVPN file paths when panel links exist but paths are empty.
func EnsureMaterialPaths(settings map[string]any) {
	if settings == nil {
		return
	}
	if settingStr(settings, "panelRootCaId") != "" {
		if settingStr(settings, "ca") == "" {
			settings["ca"] = DefaultCAPath
		}
		if settingStr(settings, "crl-verify") == "" {
			settings["crl-verify"] = DefaultCrlPath
		}
	}
	if settingStr(settings, "panelServerCertId") != "" {
		if settingStr(settings, "cert") == "" {
			settings["cert"] = DefaultServerCertPath
		}
		if settingStr(settings, "key") == "" {
			settings["key"] = DefaultServerKeyPath
		}
	}
	if settingStr(settings, "panelDhMaterialId") != "" && settingStr(settings, "dh") == "" {
		settings["dh"] = DefaultDhPath
	}
	if settingStr(settings, "panelTlsAuthMaterialId") != "" && settingStr(settings, "tls-auth") == "" {
		settings["tls-auth"] = "/etc/openvpn/ta.key 0"
	}
}
