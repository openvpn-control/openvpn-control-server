package openvpn

import "testing"

func TestNormalizeServerSettingsKeepsFragmentZero(t *testing.T) {
	settings := map[string]any{"fragment": float64(0), "port": float64(1194)}
	NormalizeServerSettings(settings)
	if _, ok := settings["fragment"]; !ok {
		t.Fatal("fragment 0 should remain in settings for DB")
	}
	if settings["fragment"] != float64(0) {
		t.Fatalf("fragment=%v", settings["fragment"])
	}
}

func TestNormalizeServerSettingsKeepsAuthWithGcmDataCiphers(t *testing.T) {
	settings := map[string]any{
		"data-ciphers": "AES-256-GCM:AES-128-GCM",
		"auth":         "SHA256",
		"port":         float64(1194),
	}
	NormalizeServerSettings(settings)
	if settings["auth"] != "SHA256" {
		t.Fatalf("auth should remain in DB settings, got %v", settings["auth"])
	}
	out := PrepareAgentSettings(settings)
	if _, ok := out["auth"]; ok {
		t.Fatal("auth should be stripped for agent/server.conf with GCM")
	}
}

func TestNormalizeServerSettingsClearsEmptyFragment(t *testing.T) {
	settings := map[string]any{"fragment": "", "port": float64(1194)}
	NormalizeServerSettings(settings)
	if _, ok := settings["fragment"]; ok {
		t.Fatalf("fragment should be removed, got %v", settings["fragment"])
	}
}
