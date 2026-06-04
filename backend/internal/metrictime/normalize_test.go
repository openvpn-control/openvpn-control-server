package metrictime

import (
	"strings"
	"testing"
	"time"
)

func TestNormalizeCreatedAtNaiveAsUTC(t *testing.T) {
	iso, ok := NormalizeCreatedAt("2026-06-03T15:20:00.000")
	if !ok {
		t.Fatal("expected ok")
	}
	if !strings.HasSuffix(iso, "Z") {
		t.Fatalf("expected Z suffix, got %q", iso)
	}
	parsed, err := time.Parse(time.RFC3339Nano, iso)
	if err != nil || parsed.UTC().Hour() != 15 || parsed.UTC().Minute() != 20 {
		t.Fatalf("got %q", iso)
	}
}

func TestNormalizeCreatedAtRFC3339(t *testing.T) {
	iso, ok := NormalizeCreatedAt("2026-06-03T12:00:00+03:00")
	if !ok {
		t.Fatal("expected ok")
	}
	parsed, err := time.Parse(time.RFC3339Nano, iso)
	if err != nil || parsed.UTC().Format(time.RFC3339) != "2026-06-03T09:00:00Z" {
		t.Fatalf("got %q", iso)
	}
}
