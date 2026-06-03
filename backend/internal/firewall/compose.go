package firewall

import "strings"

// Composed holds effective firewall rules after merging org and user levels.
type Composed struct {
	Mode     string
	Rules    []map[string]any
	NatRules []map[string]any
}

// ComposeLevels merges organization and user firewall settings like the Node backend.
func ComposeLevels(orgLike, userLike Stored) Composed {
	orgMode := "merge"
	if strings.ToLower(orgLike.Mode) == "replace" {
		orgMode = "replace"
	}
	userMode := "merge"
	if strings.ToLower(userLike.Mode) == "replace" {
		userMode = "replace"
	}
	if userMode == "replace" {
		return Composed{Mode: "replace", Rules: userLike.Rules, NatRules: userLike.NatRules}
	}
	if orgMode == "replace" {
		return Composed{
			Mode:     "replace",
			Rules:    append(append([]map[string]any{}, orgLike.Rules...), userLike.Rules...),
			NatRules: append(append([]map[string]any{}, orgLike.NatRules...), userLike.NatRules...),
		}
	}
	return Composed{
		Mode:     "merge",
		Rules:    append(append([]map[string]any{}, orgLike.Rules...), userLike.Rules...),
		NatRules: append(append([]map[string]any{}, orgLike.NatRules...), userLike.NatRules...),
	}
}

// DeriveSessionNatRules expands per-session NAT rules for runtime firewall sync.
func DeriveSessionNatRules(sessions []map[string]any) []map[string]any {
	var out []map[string]any
	for _, s := range sessions {
		vip := strings.TrimSpace(str(s["virtualIp"]))
		if vip == "" {
			continue
		}
		nat, _ := s["natRules"].([]any)
		for _, raw := range nat {
			r, _ := raw.(map[string]any)
			if r == nil {
				continue
			}
			src := strings.TrimSpace(str(r["src"]))
			if src == "" {
				src = vip + "/32"
			}
			out = append(out, map[string]any{
				"type":         str(r["type"]),
				"src":          src,
				"dst":          strings.TrimSpace(str(r["dst"])),
				"outInterface": strings.TrimSpace(str(r["outInterface"])),
				"toAddress":    strings.TrimSpace(str(r["toAddress"])),
				"note":         strings.TrimSpace(str(r["note"])),
			})
		}
	}
	return out
}
