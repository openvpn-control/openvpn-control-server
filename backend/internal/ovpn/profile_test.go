package ovpn

import (
	"strings"
	"testing"
)

func TestClientVerbFromSettings(t *testing.T) {
	if got := clientVerbFromSettings(map[string]any{"client-verb": float64(3)}); got != 3 {
		t.Fatalf("float64: got %d", got)
	}
	if got := clientVerbFromSettings(map[string]any{"client-verb": "3"}); got != 3 {
		t.Fatalf("string: got %d", got)
	}
	if got := clientVerbFromSettings(map[string]any{"verb": float64(0)}); got != 0 {
		t.Fatalf("verb zero: got %d", got)
	}
	if got := clientVerbFromSettings(map[string]any{"client-verb": float64(3), "verb": float64(0)}); got != 3 {
		t.Fatalf("client-verb wins: got %d", got)
	}
	if got := clientVerbFromSettings(map[string]any{}); got != 3 {
		t.Fatalf("default: got %d", got)
	}
}

func TestBuildClientOvpnIncludesDataCiphersFallback(t *testing.T) {
	ovpnText := BuildClientOvpn(BuildInput{
		Node: Node{Host: "vpn.example.com"},
		Settings: map[string]any{
			"data-ciphers-fallback": "AES-256-CBC:AES-128-CBC",
			"proto":                 "udp",
			"port":                  float64(1194),
		},
	})
	if !strings.Contains(ovpnText, "data-ciphers-fallback AES-256-CBC:AES-128-CBC") {
		t.Fatalf("missing data-ciphers-fallback:\n%s", ovpnText)
	}
}

func TestBuildClientOvpnIncludesPersistFlags(t *testing.T) {
	ovpnText := BuildClientOvpn(BuildInput{
		Node: Node{Host: "vpn.example.com"},
		Settings: map[string]any{
			"persist-key": true,
			"persist-tun": true,
			"proto":       "udp",
			"port":        float64(1194),
		},
	})
	if !strings.Contains(ovpnText, "persist-key") {
		t.Fatalf("missing persist-key:\n%s", ovpnText)
	}
	if !strings.Contains(ovpnText, "persist-tun") {
		t.Fatalf("missing persist-tun:\n%s", ovpnText)
	}
}

func TestBuildClientOvpnUsesExplicitKeyDirection(t *testing.T) {
	ovpnText := BuildClientOvpn(BuildInput{
		Node:       Node{Host: "vpn.example.com"},
		TLSAuthPEM: "static-key",
		Settings: map[string]any{
			"key-direction": "1",
			"proto":         "udp",
			"port":          float64(1194),
		},
	})
	if !strings.Contains(ovpnText, "key-direction 1") {
		t.Fatalf("expected key-direction 1, got:\n%s", ovpnText)
	}
}

func TestBuildClientOvpnDerivesKeyDirectionFromServerTlsAuth(t *testing.T) {
	ovpnText := BuildClientOvpn(BuildInput{
		Node:       Node{Host: "vpn.example.com"},
		TLSAuthPEM: "static-key",
		Settings: map[string]any{
			"tls-auth": "/etc/openvpn/ta.key 0",
			"proto":    "udp",
			"port":     float64(1194),
		},
	})
	if !strings.Contains(ovpnText, "key-direction 1") {
		t.Fatalf("server 0 should become client 1, got:\n%s", ovpnText)
	}
}

func TestBuildClientOvpnIncludesAuthFromPanelSettings(t *testing.T) {
	ovpnText := BuildClientOvpn(BuildInput{
		Node: Node{Host: "vpn.example.com"},
		Settings: map[string]any{
			"data-ciphers": "AES-256-GCM:AES-128-GCM",
			"auth":         "SHA256",
			"proto":        "udp",
			"port":         float64(1194),
		},
	})
	if !strings.Contains(ovpnText, "auth SHA256") {
		t.Fatalf("missing auth:\n%s", ovpnText)
	}
}

func TestBuildClientOvpnUsesClientVerb(t *testing.T) {
	ovpnText := BuildClientOvpn(BuildInput{
		Node:     Node{Host: "vpn.example.com"},
		Settings: map[string]any{"client-verb": 3, "proto": "udp", "port": float64(1194)},
	})
	if !strings.Contains(ovpnText, "verb 3") {
		t.Fatalf("missing verb 3:\n%s", ovpnText)
	}
}
