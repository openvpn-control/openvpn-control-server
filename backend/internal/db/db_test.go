package db

import "testing"

func TestNormalizeDatabaseURL(t *testing.T) {
	raw := "postgresql://postgres:postgres@postgres:5432/openvpn_control?schema=public"
	got, err := normalizeDatabaseURL(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got == raw {
		t.Fatalf("expected schema stripped, got %q", got)
	}
	if got != "postgresql://postgres:postgres@postgres:5432/openvpn_control?sslmode=disable" {
		t.Fatalf("unexpected url: %q", got)
	}
}
