package openvpn

import "testing"

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

func TestOnlyPanelMetadataAndMaterialPathsChangedFalseOnPort(t *testing.T) {
	prev := map[string]any{"port": float64(1194)}
	merged := map[string]any{"port": float64(1195)}
	if OnlyPanelMetadataAndMaterialPathsChanged(prev, merged) {
		t.Fatal("port change should require agent push")
	}
}
