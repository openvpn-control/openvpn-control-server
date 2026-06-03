package openvpn

import "testing"

func TestNormalizeManagementValue(t *testing.T) {
	got := NormalizeManagementValue("127.0.0.1:7505")
	if got != "127.0.0.1 7505" {
		t.Fatalf("got %q", got)
	}
}

func TestEnsureServerCryptoDefaultsDropsAuthForGCM(t *testing.T) {
	s := map[string]any{
		"data-ciphers": "AES-256-GCM:AES-128-GCM",
		"auth":         "SHA256",
	}
	EnsureServerCryptoDefaults(s)
	if _, ok := s["auth"]; ok {
		t.Fatal("auth should be removed")
	}
}
