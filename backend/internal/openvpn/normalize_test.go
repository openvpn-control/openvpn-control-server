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

func TestNormalizeServerSettingsClearsEmptyRemoteCertTls(t *testing.T) {
	settings := map[string]any{"remote-cert-tls": "", "port": float64(1194)}
	NormalizeServerSettings(settings)
	if _, ok := settings["remote-cert-tls"]; ok {
		t.Fatalf("remote-cert-tls should be removed, got %v", settings["remote-cert-tls"])
	}
}

func TestNormalizeServerSettingsKeepsRemoteCertTls(t *testing.T) {
	settings := map[string]any{"remote-cert-tls": "client", "port": float64(1194)}
	NormalizeServerSettings(settings)
	if settings["remote-cert-tls"] != "client" {
		t.Fatalf("remote-cert-tls=%v", settings["remote-cert-tls"])
	}
}

func TestNormalizeServerSettingsClearsEmptyFragment(t *testing.T) {
	settings := map[string]any{"fragment": "", "port": float64(1194)}
	NormalizeServerSettings(settings)
	if _, ok := settings["fragment"]; ok {
		t.Fatalf("fragment should be removed, got %v", settings["fragment"])
	}
}
