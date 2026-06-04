package openvpn

import "testing"

func TestMergeSettingsForDisplayFillsEmptyAgentFromDB(t *testing.T) {
	agent := map[string]any{"tls-crypt": "", "port": float64(1194)}
	db := map[string]any{"tls-crypt": "1", "port": float64(1194)}
	got := MergeSettingsForDisplay(db, agent)
	if got["tls-crypt"] != "1" {
		t.Fatalf("tls-crypt=%v want 1", got["tls-crypt"])
	}
}

func TestMergeSettingsForDisplayAgentWinsOverStaleDB(t *testing.T) {
	agent := map[string]any{"port": float64(1195)}
	db := map[string]any{"port": float64(1194)}
	got := MergeSettingsForDisplay(db, agent)
	if got["port"] != float64(1195) {
		t.Fatalf("port=%v want 1195", got["port"])
	}
}

func TestMergeSettingsForDisplayEmptyDBDoesNotWipeAgent(t *testing.T) {
	agent := map[string]any{"tls-crypt": "/etc/openvpn/tc.key"}
	db := map[string]any{"tls-crypt": ""}
	got := MergeSettingsForDisplay(db, agent)
	if got["tls-crypt"] != "/etc/openvpn/tc.key" {
		t.Fatalf("tls-crypt=%v", got["tls-crypt"])
	}
}
