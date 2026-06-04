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

func TestMergeSettingsForDisplayKeepsAuthFromDBWithGcmAgentSnapshot(t *testing.T) {
	agent := map[string]any{"data-ciphers": "AES-256-GCM:AES-128-GCM", "port": float64(1194)}
	db := map[string]any{"data-ciphers": "AES-256-GCM:AES-128-GCM", "port": float64(1194), "auth": "SHA256"}
	got := MergeSettingsForDisplay(db, agent)
	if got["auth"] != "SHA256" {
		t.Fatalf("auth=%v", got["auth"])
	}
}

func TestMergeSettingsForDisplayKeepsRemoteCertTlsFromDBForClientProfile(t *testing.T) {
	agent := map[string]any{"port": float64(1194)}
	db := map[string]any{"port": float64(1194), "remote-cert-tls": "server"}
	got := MergeSettingsForDisplay(db, agent)
	if got["remote-cert-tls"] != "server" {
		t.Fatalf("remote-cert-tls=%v", got["remote-cert-tls"])
	}
}

func TestMergeSettingsForDisplayIgnoresStaleFragmentZeroInDB(t *testing.T) {
	agent := map[string]any{"port": float64(1194)}
	db := map[string]any{"port": float64(1194), "fragment": float64(0)}
	got := MergeSettingsForDisplay(db, agent)
	if _, ok := got["fragment"]; ok {
		t.Fatalf("stale fragment 0 should not appear, got %v", got["fragment"])
	}
}

func TestMergeSettingsForDisplayKeepsPanelClientVerbFromDB(t *testing.T) {
	agent := map[string]any{"verb": float64(0)}
	db := map[string]any{"client-verb": float64(3), "verb": float64(0)}
	got := MergeSettingsForDisplay(db, agent)
	if got["client-verb"] != float64(3) {
		t.Fatalf("client-verb=%v", got["client-verb"])
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
