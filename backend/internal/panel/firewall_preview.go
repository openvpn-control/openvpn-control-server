package panel

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const (
	panelFirewallDefaultPolicyKey       = "panelFirewallDefaultPolicy"
	panelFirewallBaseRulesKey           = "panelFirewallBaseRules"
	panelFirewallTunnelDefaultPolicyKey = "panelFirewallTunnelDefaultPolicy"
	panelFirewallTunnelRulesKey         = "panelFirewallTunnelRules"
	panelFirewallTunnelNatRulesKey      = "panelFirewallTunnelNatRules"
)

type nodeRef struct {
	ID   string
	Name string
}

type FirewallRule struct {
	ID          string `json:"id"`
	Action      string `json:"action"`
	Proto       string `json:"proto"`
	Destination string `json:"destination"`
	Ports       string `json:"ports"`
	Note        string `json:"note"`
}

type FirewallNatRule struct {
	ID           string `json:"id"`
	Type         string `json:"type"`
	Src          string `json:"src"`
	Dst          string `json:"dst"`
	OutInterface string `json:"outInterface"`
	ToAddress    string `json:"toAddress"`
	Note         string `json:"note"`
}

type TunnelContext struct {
	TunnelInterface string `json:"tunnelInterface"`
	VpnSubnet       string `json:"vpnSubnet"`
	VpnSubnetCidr   string `json:"vpnSubnetCidr"`
}

func ipv4OctetsToInt(s string) *uint32 {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return nil
	}
	var octets [4]int
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 || n > 255 {
			return nil
		}
		octets[i] = n
	}
	v := (uint32(octets[0]) << 24) | (uint32(octets[1]) << 16) | (uint32(octets[2]) << 8) | uint32(octets[3])
	return &v
}

func netmaskDottedToPrefix(maskStr string) *int {
	n := ipv4OctetsToInt(maskStr)
	if n == nil {
		return nil
	}
	prefix := 0
	v := *n
	for v&0x80000000 != 0 {
		prefix++
		v <<= 1
	}
	if v != 0 {
		return nil
	}
	return &prefix
}

var serverLineRe = regexp.MustCompile(`^(\S+)\s+(\S+)$`)

func openvpnServerLineToCidr(serverLine string) string {
	m := serverLineRe.FindStringSubmatch(strings.TrimSpace(serverLine))
	if m == nil {
		return ""
	}
	ip := m[1]
	second := m[2]
	if pl, err := strconv.Atoi(second); err == nil && pl >= 0 && pl <= 32 {
		return fmt.Sprintf("%s/%d", ip, pl)
	}
	if strings.Contains(second, ".") {
		if pref := netmaskDottedToPrefix(second); pref != nil {
			return fmt.Sprintf("%s/%d", ip, *pref)
		}
	}
	return ""
}

func linuxIfaceFromOpenvpnDev(dev string) string {
	s := strings.TrimSpace(dev)
	if s == "" {
		return ""
	}
	switch strings.ToLower(s) {
	case "tun":
		return "tun0"
	case "tap":
		return "tap0"
	default:
		return s
	}
}

func ParseTunnelContext(openvpnSettings map[string]any) TunnelContext {
	src := openvpnSettings
	if src == nil {
		src = map[string]any{}
	}
	rawDev := strings.TrimSpace(asString(src["dev"]))
	tunnelInterface := "tun0"
	if rawDev != "" {
		tunnelInterface = linuxIfaceFromOpenvpnDev(rawDev)
	}
	serverDirective := strings.TrimSpace(asString(src["server"]))
	vpnSubnet := ""
	if m := serverLineRe.FindStringSubmatch(serverDirective); m != nil {
		vpnSubnet = m[1] + " " + m[2]
	}
	return TunnelContext{
		TunnelInterface: tunnelInterface,
		VpnSubnet:       vpnSubnet,
		VpnSubnetCidr:   openvpnServerLineToCidr(serverDirective),
	}
}

func normalizeFirewallRule(rule map[string]any, idx int) FirewallRule {
	src := rule
	if src == nil {
		src = map[string]any{}
	}
	id := strings.TrimSpace(asString(src["id"]))
	if id == "" {
		id = fmt.Sprintf("rule-%d", idx+1)
	}
	action := "allow"
	if strings.EqualFold(asString(src["action"]), "deny") {
		action = "deny"
	}
	proto := strings.ToLower(strings.TrimSpace(asString(src["proto"])))
	switch proto {
	case "tcp", "udp", "icmp", "any":
	default:
		proto = "tcp"
	}
	return FirewallRule{
		ID:          id,
		Action:      action,
		Proto:       proto,
		Destination: strings.TrimSpace(asString(src["destination"])),
		Ports:       strings.TrimSpace(asString(src["ports"])),
		Note:        strings.TrimSpace(asString(src["note"])),
	}
}

func NormalizeFirewallBaseRules(raw any) []FirewallRule {
	rows, ok := raw.([]any)
	if !ok {
		return []FirewallRule{}
	}
	out := make([]FirewallRule, 0, len(rows))
	for i, row := range rows {
		m, _ := row.(map[string]any)
		out = append(out, normalizeFirewallRule(m, i))
	}
	return out
}

func normalizeFirewallNatRule(rule map[string]any, idx int) FirewallNatRule {
	src := rule
	if src == nil {
		src = map[string]any{}
	}
	id := strings.TrimSpace(asString(src["id"]))
	if id == "" {
		id = fmt.Sprintf("nat-%d", idx+1)
	}
	ruleType := strings.ToLower(strings.TrimSpace(asString(src["type"])))
	switch ruleType {
	case "masquerade", "snat", "dnat":
	default:
		ruleType = "masquerade"
	}
	rawOut := strings.TrimSpace(asString(src["outInterface"]))
	outIface := ""
	if rawOut != "" {
		outIface = linuxIfaceFromOpenvpnDev(rawOut)
	}
	return FirewallNatRule{
		ID:           id,
		Type:         ruleType,
		Src:          strings.TrimSpace(asString(src["src"])),
		Dst:          strings.TrimSpace(asString(src["dst"])),
		OutInterface: outIface,
		ToAddress:    strings.TrimSpace(asString(src["toAddress"])),
		Note:         strings.TrimSpace(asString(src["note"])),
	}
}

func NormalizeFirewallNatRules(raw any) []FirewallNatRule {
	rows, ok := raw.([]any)
	if !ok {
		return []FirewallNatRule{}
	}
	out := make([]FirewallNatRule, 0, len(rows))
	for i, row := range rows {
		m, _ := row.(map[string]any)
		out = append(out, normalizeFirewallNatRule(m, i))
	}
	return out
}

func NormalizeFirewallDefaultPolicy(raw any) string {
	if strings.EqualFold(asString(raw), "allow") {
		return "allow"
	}
	return "deny"
}

func renderFirewallScriptPreview(node nodeRef, defaultPolicy string, baseRules []FirewallRule, tunnelContext TunnelContext) string {
	chainPolicy := "drop"
	if defaultPolicy == "allow" {
		chainPolicy = "accept"
	}
	cidr := strings.TrimSpace(tunnelContext.VpnSubnetCidr)
	nodeLabel := node.Name
	if nodeLabel == "" {
		nodeLabel = node.ID
	}
	if nodeLabel == "" {
		nodeLabel = "unknown"
	}
	subnetLabel := cidr
	if subnetLabel == "" {
		subnetLabel = tunnelContext.VpnSubnet
	}
	if subnetLabel == "" {
		subnetLabel = "n/a"
	}
	lines := []string{
		fmt.Sprintf("# firewall preview for node: %s", nodeLabel),
		fmt.Sprintf(`# scope: tunnel interface "%s" + VPN subnet "%s"`, tunnelContext.TunnelInterface, subnetLabel),
		"table inet ovpn_clients {",
		"  chain forward {",
		"    type filter hook forward priority 0;",
		fmt.Sprintf("    policy %s;", chainPolicy),
	}
	for _, r := range baseRules {
		intf := ""
		if tunnelContext.TunnelInterface != "" {
			intf = fmt.Sprintf(`iifname "%s" `, tunnelContext.TunnelInterface)
		}
		subnet := ""
		if cidr != "" {
			subnet = fmt.Sprintf("ip saddr %s ", cidr)
		}
		proto := ""
		if r.Proto != "any" {
			proto = r.Proto + " "
		}
		dst := ""
		if r.Destination != "" {
			dst = fmt.Sprintf("ip daddr %s ", r.Destination)
		}
		ports := ""
		if r.Ports != "" {
			ports = fmt.Sprintf("dport { %s } ", r.Ports)
		}
		verdict := "accept"
		if r.Action == "deny" {
			verdict = "drop"
		}
		line := strings.TrimSpace(fmt.Sprintf("%s%s%s%s%s%s", intf, subnet, proto, dst, ports, verdict)) + ";"
		lines = append(lines, "    "+line)
	}
	lines = append(lines, "  }", "}")
	return strings.Join(lines, "\n")
}

func RenderFirewallDualScriptPreview(node nodeRef, tunnelDefaultPolicy string, tunnelRules []FirewallRule, natRules []FirewallNatRule, tunnelContext TunnelContext) string {
	tunnel := renderFirewallScriptPreview(node, tunnelDefaultPolicy, tunnelRules, tunnelContext)
	nat := []string{"table ip ovpn_nat {"}
	post := []string{
		"  chain postrouting {",
		"    type nat hook postrouting priority 100;",
	}
	pre := []string{
		"  chain prerouting {",
		"    type nat hook prerouting priority -100;",
	}
	for _, r := range natRules {
		switch r.Type {
		case "dnat":
			src, dst, inIface, to := "", "", "", ""
			if r.Src != "" {
				src = fmt.Sprintf("ip saddr %s ", r.Src)
			}
			if r.Dst != "" {
				dst = fmt.Sprintf("ip daddr %s ", r.Dst)
			}
			if r.OutInterface != "" {
				inIface = fmt.Sprintf(`iifname "%s" `, r.OutInterface)
			}
			if r.ToAddress != "" {
				to = "to " + r.ToAddress
			}
			line := strings.TrimSpace(fmt.Sprintf("%s%s%sdnat %s", src, dst, inIface, to)) + ";"
			pre = append(pre, "    "+line)
		case "snat":
			src, dst, out, to := "", "", "", ""
			if r.Src != "" {
				src = fmt.Sprintf("ip saddr %s ", r.Src)
			}
			if r.Dst != "" {
				dst = fmt.Sprintf("ip daddr %s ", r.Dst)
			}
			if r.OutInterface != "" {
				out = fmt.Sprintf(`oifname "%s" `, r.OutInterface)
			}
			if r.ToAddress != "" {
				to = "to " + r.ToAddress
			}
			line := strings.TrimSpace(fmt.Sprintf("%s%s%s snat %s", src, dst, out, to)) + ";"
			post = append(post, "    "+line)
		default:
			src, dst, out := "", "", ""
			if r.Src != "" {
				src = fmt.Sprintf("ip saddr %s ", r.Src)
			}
			if r.Dst != "" {
				dst = fmt.Sprintf("ip daddr %s ", r.Dst)
			}
			if r.OutInterface != "" {
				out = fmt.Sprintf(`oifname "%s" `, r.OutInterface)
			}
			line := strings.TrimSpace(fmt.Sprintf("%s%s%s masquerade", src, dst, out)) + ";"
			post = append(post, "    "+line)
		}
	}
	post = append(post, "  }")
	pre = append(pre, "  }")
	nat = append(nat, post...)
	nat = append(nat, pre...)
	nat = append(nat, "}")
	parts := []string{tunnel, "", "# --- tunnel nat ---", strings.Join(nat, "\n")}
	return strings.Join(parts, "\n")
}

func firewallBody(node nodeRef, tunnelDefaultPolicy string, tunnelRules []FirewallRule, natRules []FirewallNatRule, tunnelContext TunnelContext) map[string]any {
	return map[string]any{
		"tunnel": map[string]any{
			"defaultPolicy": tunnelDefaultPolicy,
			"rules":         tunnelRules,
			"natRules":      natRules,
		},
		"tunnelContext": tunnelContext,
		"preview":       RenderFirewallDualScriptPreview(node, tunnelDefaultPolicy, tunnelRules, natRules, tunnelContext),
	}
}
