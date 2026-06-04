package openvpn

import "testing"

func TestStripPanelOnlySettingsRemovesRemoteCertTls(t *testing.T) {
	in := map[string]any{"port": float64(1194), "remote-cert-tls": "server", "auth": "SHA256"}
	got := StripPanelOnlySettings(in)
	if _, ok := got["remote-cert-tls"]; ok {
		t.Fatal("remote-cert-tls is client-only, must not go to agent")
	}
	if got["auth"] != "SHA256" {
		t.Fatalf("auth=%v", got["auth"])
	}
}

func TestStripEmptyManagedDirectiveValuesDropsEmptyDh(t *testing.T) {
	in := map[string]any{"port": float64(1194), "dh": "", "ca": "/etc/openvpn/ca.crt"}
	got := StripEmptyManagedDirectiveValues(in)
	if _, ok := got["dh"]; ok {
		t.Fatalf("empty dh should be stripped, got %v", got["dh"])
	}
	if got["ca"] != "/etc/openvpn/ca.crt" {
		t.Fatalf("ca=%v", got["ca"])
	}
}

func TestOnlyPanelMetadataAndMaterialPathsChanged(t *testing.T) {
	prev := map[string]any{"port": float64(1194), "panelRootCaId": ""}
	merged := map[string]any{
		"port": float64(1194), "panelRootCaId": "ca1",
		"ca": "/etc/openvpn/ca.crt", "crl-verify": "/etc/openvpn/crl.pem",
	}
	if !OnlyPanelMetadataAndMaterialPathsChanged(prev, merged) {
		t.Fatal("expected panel/material-only change")
	}
}

func TestIncomingIsPanelMetadataOrMaterialPathsOnly(t *testing.T) {
	incoming := map[string]any{
		"panelRootCaId": "ca1",
		"ca":            "/etc/openvpn/ca.crt",
		"crl-verify":    "/etc/openvpn/crl.pem",
	}
	if !IncomingIsPanelMetadataOrMaterialPathsOnly(incoming) {
		t.Fatal("expected panel partial incoming")
	}
	incoming["port"] = float64(1195)
	if IncomingIsPanelMetadataOrMaterialPathsOnly(incoming) {
		t.Fatal("port in incoming should not be panel-only")
	}
}

func TestSkipAgentSettingsPushDespiteEnsureSideEffects(t *testing.T) {
	prev := map[string]any{"port": float64(1194), "dh": ""}
	incoming := map[string]any{
		"panelRootCaId": "ca1",
		"ca":            "/etc/openvpn/ca.crt",
		"crl-verify":    "/etc/openvpn/crl.pem",
	}
	merged := map[string]any{"port": float64(1194), "dh": "", "panelRootCaId": "ca1", "ca": "/etc/openvpn/ca.crt", "crl-verify": "/etc/openvpn/crl.pem"}
	// simulate ensureOpenvpnSettingsReady side effect on merged only
	merged["data-ciphers"] = "AES-256-GCM:AES-128-GCM"
	merged["auth"] = "SHA256"
	if !SkipAgentSettingsPush(prev, merged, incoming) {
		t.Fatal("panel partial must skip agent even if merged gained crypto defaults")
	}
}

func TestOnlyPanelMetadataAndMaterialPathsChangedFalseOnPort(t *testing.T) {
	prev := map[string]any{"port": float64(1194)}
	merged := map[string]any{"port": float64(1195)}
	if OnlyPanelMetadataAndMaterialPathsChanged(prev, merged) {
		t.Fatal("port change should require agent push")
	}
}
