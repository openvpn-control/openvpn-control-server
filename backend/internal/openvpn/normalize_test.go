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
