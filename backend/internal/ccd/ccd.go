package ccd

import "strings"

type Settings struct {
	IfconfigPushLocal  string `json:"ifconfigPushLocal"`
	IfconfigPushRemote string `json:"ifconfigPushRemote"`
	PushRoutes         string `json:"pushRoutes"`
	Iroutes            string `json:"iroutes"`
	DNSServers         string `json:"dnsServers"`
	CustomDirectives   string `json:"customDirectives"`
}

func Normalize(raw any) Settings {
	m, _ := raw.(map[string]any)
	if m == nil {
		return Settings{}
	}
	return Settings{
		IfconfigPushLocal:  str(m["ifconfigPushLocal"]),
		IfconfigPushRemote: str(m["ifconfigPushRemote"]),
		PushRoutes:         str(m["pushRoutes"]),
		Iroutes:            str(m["iroutes"]),
		DNSServers:         str(m["dnsServers"]),
		CustomDirectives:   str(m["customDirectives"]),
	}
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return strings.TrimSpace(s)
	}
	return ""
}

// RenderText builds CCD file content for a VPN user.
func RenderText(userDisplayName string, settings any) string {
	s := Normalize(settings)
	name := strings.TrimSpace(userDisplayName)
	if name == "" {
		name = "unknown-user"
	}
	var lines []string
	lines = append(lines, "# ccd for user: "+name)
	if s.IfconfigPushLocal != "" && s.IfconfigPushRemote != "" {
		lines = append(lines, "ifconfig-push "+s.IfconfigPushLocal+" "+s.IfconfigPushRemote)
	}
	lines = append(lines, pushLinesFromMultiline("push", s.PushRoutes)...)
	lines = append(lines, pushLinesFromMultiline("iroute", s.Iroutes)...)
	for _, dns := range strings.FieldsFunc(s.DNSServers, func(r rune) bool {
		return r == ' ' || r == ','
	}) {
		dns = strings.TrimSpace(dns)
		if dns != "" {
			lines = append(lines, "push dhcp-option DNS "+dns)
		}
	}
	for _, rawLine := range strings.Split(s.CustomDirectives, "\n") {
		if t := strings.TrimSpace(rawLine); t != "" {
			lines = append(lines, t)
		}
	}
	text := strings.Join(lines, "\n")
	if text != "" {
		text += "\n"
	}
	return text
}

func pushLinesFromMultiline(prefix, text string) []string {
	var lines []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, prefix+" "+line)
		}
	}
	return lines
}
