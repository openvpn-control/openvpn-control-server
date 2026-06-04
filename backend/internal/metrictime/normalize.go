package metrictime

import (
	"strings"
	"time"
)

// NormalizeCreatedAt returns metric snapshot time as RFC3339 UTC (with Z).
// Naive timestamps from PostgreSQL TIMESTAMP(3) are interpreted as UTC wall time.
func NormalizeCreatedAt(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return normalizeCreatedAtString(t)
	case time.Time:
		return t.UTC().Format(time.RFC3339Nano), true
	default:
		return "", false
	}
}

func normalizeCreatedAtString(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	if parsed, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return parsed.UTC().Format(time.RFC3339Nano), true
	}
	if parsed, err := time.Parse(time.RFC3339, s); err == nil {
		return parsed.UTC().Format(time.RFC3339Nano), true
	}
	// PostgreSQL row_to_json: "2006-01-02T15:04:05.999" or with space separator.
	s = strings.Replace(s, " ", "T", 1)
	layouts := []string{
		"2006-01-02T15:04:05.999999",
		"2006-01-02T15:04:05.999",
		"2006-01-02T15:04:05",
	}
	for _, layout := range layouts {
		if parsed, err := time.ParseInLocation(layout, s, time.UTC); err == nil {
			return parsed.UTC().Format(time.RFC3339Nano), true
		}
	}
	return "", false
}

// ApplyToMetricRow sets createdAt on a metric snapshot map when present.
func ApplyToMetricRow(row map[string]any) {
	if row == nil {
		return
	}
	if iso, ok := NormalizeCreatedAt(row["createdAt"]); ok {
		row["createdAt"] = iso
	}
}
