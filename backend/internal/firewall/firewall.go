package firewall

import (
	"encoding/json"
	"fmt"
	"strings"
)

type Stored struct {
	Mode     string           `json:"mode"`
	Rules    []map[string]any `json:"rules"`
	NatRules []map[string]any `json:"natRules"`
}

func ParseStored(raw []byte) Stored {
	if len(raw) == 0 {
		return Stored{Mode: "merge", Rules: []map[string]any{}, NatRules: []map[string]any{}}
	}
	var arr []map[string]any
	if json.Unmarshal(raw, &arr) == nil {
		return Stored{Mode: "merge", Rules: normalizeRules(arr), NatRules: []map[string]any{}}
	}
	var obj map[string]any
	if json.Unmarshal(raw, &obj) != nil {
		return Stored{Mode: "merge", Rules: []map[string]any{}, NatRules: []map[string]any{}}
	}
	mode := "merge"
	if strings.ToLower(str(obj["mode"])) == "replace" {
		mode = "replace"
	}
	rules, _ := obj["rules"].([]any)
	nat, _ := obj["natRules"].([]any)
	return Stored{
		Mode:     mode,
		Rules:    normalizeRulesAny(rules),
		NatRules: normalizeNatAny(nat),
	}
}

func SerializeForDB(mode string, rules, natRules any) ([]byte, error) {
	m := "merge"
	if strings.ToLower(strings.TrimSpace(mode)) == "replace" {
		m = "replace"
	}
	var ruleSlice []any
	switch v := rules.(type) {
	case []any:
		ruleSlice = v
	case nil:
	default:
		b, _ := json.Marshal(rules)
		_ = json.Unmarshal(b, &ruleSlice)
	}
	var natSlice []any
	switch v := natRules.(type) {
	case []any:
		natSlice = v
	case nil:
	default:
		b, _ := json.Marshal(natRules)
		_ = json.Unmarshal(b, &natSlice)
	}
	return json.Marshal(map[string]any{
		"mode":     m,
		"rules":    normalizeRulesAny(ruleSlice),
		"natRules": normalizeNatAny(natSlice),
	})
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func normalizeRules(rows []map[string]any) []map[string]any {
	out := make([]any, len(rows))
	for i, r := range rows {
		out[i] = r
	}
	return normalizeRulesAny(out)
}

func normalizeRulesAny(rows []any) []map[string]any {
	var out []map[string]any
	for i, raw := range rows {
		src, _ := raw.(map[string]any)
		if src == nil {
			continue
		}
		action := "allow"
		if strings.ToLower(str(src["action"])) == "deny" {
			action = "deny"
		}
		proto := strings.ToLower(str(src["proto"]))
		if proto != "tcp" && proto != "udp" && proto != "icmp" && proto != "any" {
			proto = "tcp"
		}
		id := str(src["id"])
		if id == "" {
			id = fmtID("rule", i+1)
		}
		out = append(out, map[string]any{
			"id":          id,
			"action":      action,
			"proto":       proto,
			"destination": strings.TrimSpace(str(src["destination"])),
			"ports":       strings.TrimSpace(str(src["ports"])),
			"note":        strings.TrimSpace(str(src["note"])),
		})
	}
	return out
}

func normalizeNatAny(rows []any) []map[string]any {
	var out []map[string]any
	for i, raw := range rows {
		src, _ := raw.(map[string]any)
		if src == nil {
			continue
		}
		t := strings.ToLower(str(src["type"]))
		if t != "masquerade" && t != "snat" && t != "dnat" {
			t = "masquerade"
		}
		id := str(src["id"])
		if id == "" {
			id = fmtID("nat", i+1)
		}
		out = append(out, map[string]any{
			"id":           id,
			"type":         t,
			"src":          strings.TrimSpace(str(src["src"])),
			"dst":          strings.TrimSpace(str(src["dst"])),
			"outInterface": strings.TrimSpace(str(src["outInterface"])),
			"toAddress":    strings.TrimSpace(str(src["toAddress"])),
			"note":         strings.TrimSpace(str(src["note"])),
		})
	}
	return out
}

func fmtID(prefix string, n int) string {
	return fmt.Sprintf("%s-%d", prefix, n+1)
}
