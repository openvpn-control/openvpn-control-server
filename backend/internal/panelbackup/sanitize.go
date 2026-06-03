package panelbackup

import (
	"regexp"
	"strconv"
	"time"
)

var backupControlChars = regexp.MustCompile(`[\x00\x01-\x08\x0b\x0c\x0e-\x1f]`)

func stripBackupControlChars(s string) string {
	return backupControlChars.ReplaceAllString(s, "")
}

func deepSanitizeForBackup(x any) any {
	if x == nil {
		return nil
	}
	switch v := x.(type) {
	case string:
		return stripBackupControlChars(v)
	case float64, bool, int, int64, uint64:
		return v
	case time.Time:
		return v.UTC().Format(time.RFC3339Nano)
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = deepSanitizeForBackup(item)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, val := range v {
			out[k] = deepSanitizeForBackup(val)
		}
		return out
	default:
		return v
	}
}

func deepSanitizeTable(rows []any) []any {
	out := make([]any, len(rows))
	for i, row := range rows {
		out[i] = deepSanitizeForBackup(row)
	}
	return out
}

func pgStripC0Controls(colExpr string) string {
	codepoints := []int{1, 2, 3, 4, 5, 6, 7, 8, 11, 12, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}
	out := colExpr
	for _, c := range codepoints {
		out = "replace(" + out + ", CHR(" + strconv.Itoa(c) + "), '')"
	}
	return out
}

func z(col string) string  { return pgStripC0Controls(col) }
func zn(col string) string { return "CASE WHEN " + col + " IS NULL THEN NULL ELSE " + pgStripC0Controls(col) + " END" }
func zj(col string) string {
	return "CASE WHEN " + col + " IS NULL THEN NULL ELSE (" + pgStripC0Controls(col + "::text") + ")::jsonb END"
}
