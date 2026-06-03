package handlers

import (
	"strconv"
	"strings"
)

func itoa(n int) string {
	return strconv.Itoa(n)
}

func strAny(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return strings.TrimSpace(strings.Trim(strings.ReplaceAll(strings.ReplaceAll(
		strings.TrimSpace(formatAny(v)), "\n", " "), "\r", ""), `"`))
}

func formatAny(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}
