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

func TestBuildClientOvpnUsesClientVerb(t *testing.T) {
	ovpnText := BuildClientOvpn(BuildInput{
		Node:     Node{Host: "vpn.example.com"},
		Settings: map[string]any{"client-verb": 3, "proto": "udp", "port": float64(1194)},
	})
	if !strings.Contains(ovpnText, "verb 3") {
		t.Fatalf("missing verb 3:\n%s", ovpnText)
	}
}
