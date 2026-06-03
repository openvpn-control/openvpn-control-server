package agentsnapshot

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/openvpn-control/openvpn-control-server/backend/internal/ccd"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/firewall"
)

const (
	keyFirewallDefaultPolicy     = "panelFirewallDefaultPolicy"
	keyFirewallBaseRules         = "panelFirewallBaseRules"
	keyFirewallTunnelDefault     = "panelFirewallTunnelDefaultPolicy"
	keyFirewallTunnelRules       = "panelFirewallTunnelRules"
	keyFirewallTunnelNatRules    = "panelFirewallTunnelNatRules"
)

type tunnelConfig struct {
	DefaultPolicy string
	Rules         []map[string]any
	NatRules      []map[string]any
}

type tunnelContext struct {
	TunnelInterface string `json:"tunnelInterface"`
	VpnSubnet       string `json:"vpnSubnet"`
	VpnSubnetCidr   string `json:"vpnSubnetCidr"`
}

// BuildForNode assembles the panel snapshot payload for an agent node.
func BuildForNode(ctx context.Context, pool *pgxpool.Pool, agentNodeID string) (map[string]any, error) {
	id := strings.TrimSpace(agentNodeID)
	if id == "" {
		return nil, nil
	}
	var nodeName string
	err := pool.QueryRow(ctx, `SELECT name FROM "AgentNode" WHERE id = $1`, id).Scan(&nodeName)
	if err != nil {
		return nil, nil
	}
	tunnel, tunnelCtx, err := loadTunnelFirewall(ctx, pool, id)
	if err != nil {
		return nil, err
	}

	rows, err := pool.Query(ctx, `
		SELECT c."commonName", c."vpnUserId", u."fullName", u."firewallRules", u."ccdSettings", o."firewallRules"
		FROM "Certificate" c
		LEFT JOIN "VpnUser" u ON u.id = c."vpnUserId"
		LEFT JOIN "Organization" o ON o.id = u."organizationId"
		WHERE c."agentNodeId" = $1 AND c."revokedAt" IS NULL`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	usersByCn := map[string]map[string]any{}
	for rows.Next() {
		var cn string
		var vpnUserID *string
		var fullName *string
		var userFw, orgFw, ccdSettings []byte
		if rows.Scan(&cn, &vpnUserID, &fullName, &userFw, &ccdSettings, &orgFw) != nil {
			continue
		}
		cn = strings.TrimSpace(cn)
		if cn == "" {
			continue
		}
		userStored := firewall.ParseStored(userFw)
		orgStored := firewall.ParseStored(orgFw)
		effective := firewall.ComposeLevels(orgStored, userStored)
		var ccdNorm ccd.Settings
		var ccdText string
		displayName := ""
		if fullName != nil {
			displayName = *fullName
		}
		if len(ccdSettings) > 0 {
			var raw any
			_ = json.Unmarshal(ccdSettings, &raw)
			ccdNorm = ccd.Normalize(raw)
			ccdText = ccd.RenderText(displayName, raw)
		} else {
			ccdNorm = ccd.Normalize(nil)
		}
		var uid any
		if vpnUserID != nil {
			uid = *vpnUserID
		}
		usersByCn[cn] = map[string]any{
			"vpnUserId":        uid,
			"firewallMode":     effective.Mode,
			"firewallRules":    effective.Rules,
			"firewallNatRules": effective.NatRules,
			"ccdSettings":      ccdNorm,
			"ccdText":          ccdText,
		}
	}

	sortedCn := make([]string, 0, len(usersByCn))
	for k := range usersByCn {
		sortedCn = append(sortedCn, k)
	}
	sort.Strings(sortedCn)
	usersOrdered := make(map[string]any, len(sortedCn))
	for _, k := range sortedCn {
		usersOrdered[k] = usersByCn[k]
	}

	bodyForHash := map[string]any{
		"schemaVersion": 1,
		"agentNodeId":   id,
		"tunnelContext": map[string]any{
			"tunnelInterface": defaultStr(tunnelCtx.TunnelInterface, "tun0"),
			"vpnSubnet":       tunnelCtx.VpnSubnet,
			"vpnSubnetCidr":   tunnelCtx.VpnSubnetCidr,
		},
		"tunnelFirewall": map[string]any{
			"defaultPolicy": tunnel.DefaultPolicy,
			"rules":         tunnel.Rules,
			"natRules":      tunnel.NatRules,
		},
		"usersByCn": usersOrdered,
	}
	hashBytes, _ := json.Marshal(bodyForHash)
	sum := sha256.Sum256(hashBytes)
	revision := hex.EncodeToString(sum[:])

	out := map[string]any{
		"schemaVersion": 1,
		"agentNodeId":   id,
		"tunnelContext": bodyForHash["tunnelContext"],
		"tunnelFirewall": bodyForHash["tunnelFirewall"],
		"usersByCn":     usersOrdered,
		"revision":      revision,
		"updatedAt":     time.Now().UTC().Format(time.RFC3339Nano),
		"nodeName":      nodeName,
	}
	return out, nil
}

func loadTunnelFirewall(ctx context.Context, pool *pgxpool.Pool, nodeID string) (*tunnelConfig, tunnelContext, error) {
	var settings []byte
	err := pool.QueryRow(ctx, `
		SELECT settings FROM "AgentNodeOpenvpnSettings" WHERE "agentNodeId" = $1`, nodeID).Scan(&settings)
	if err != nil && err != pgx.ErrNoRows {
		return nil, tunnelContext{}, err
	}
	var st map[string]any
	if len(settings) > 0 {
		_ = json.Unmarshal(settings, &st)
	}
	if st == nil {
		st = map[string]any{}
	}
	fallbackDefault := normalizeDefaultPolicy(st[keyFirewallDefaultPolicy])
	fallbackRules := normalizeBaseRules(st[keyFirewallBaseRules])
	tunnelDefault := normalizeDefaultPolicy(st[keyFirewallTunnelDefault])
	if tunnelDefault == "deny" && st[keyFirewallTunnelDefault] == nil {
		tunnelDefault = fallbackDefault
	}
	tunnelRules := normalizeBaseRules(st[keyFirewallTunnelRules])
	if len(tunnelRules) == 0 {
		tunnelRules = fallbackRules
	}
	natRules := normalizeNatRules(st[keyFirewallTunnelNatRules])
	ctxParsed := parseTunnelContext(st)
	return &tunnelConfig{
		DefaultPolicy: tunnelDefault,
		Rules:         tunnelRules,
		NatRules:      natRules,
	}, ctxParsed, nil
}

func normalizeDefaultPolicy(raw any) string {
	if s, ok := raw.(string); ok && strings.ToLower(s) == "allow" {
		return "allow"
	}
	return "deny"
}

func normalizeBaseRules(raw any) []map[string]any {
	arr, _ := raw.([]any)
	if arr == nil {
		if b, err := json.Marshal(raw); err == nil {
			_ = json.Unmarshal(b, &arr)
		}
	}
	var rows []any
	for _, v := range arr {
		rows = append(rows, v)
	}
	return firewall.ParseStored(jsonMustObject(map[string]any{"rules": rows})).Rules
}

func normalizeNatRules(raw any) []map[string]any {
	arr, _ := raw.([]any)
	if arr == nil {
		if b, err := json.Marshal(raw); err == nil {
			_ = json.Unmarshal(b, &arr)
		}
	}
	var rows []any
	for _, v := range arr {
		rows = append(rows, v)
	}
	st := firewall.ParseStored(jsonMustObject(map[string]any{"natRules": rows}))
	return st.NatRules
}

func jsonMustObject(m map[string]any) []byte {
	b, _ := json.Marshal(m)
	return b
}

func parseTunnelContext(settings map[string]any) tunnelContext {
	rawDev := strings.TrimSpace(strVal(settings["dev"]))
	tunnelInterface := linuxIfaceFromOpenvpnDev(rawDev)
	if tunnelInterface == "" {
		tunnelInterface = "tun0"
	}
	serverDirective := strings.TrimSpace(strVal(settings["server"]))
	subnetMatch := strings.Fields(serverDirective)
	vpnSubnet := ""
	if len(subnetMatch) >= 2 {
		vpnSubnet = subnetMatch[0] + " " + subnetMatch[1]
	}
	return tunnelContext{
		TunnelInterface: tunnelInterface,
		VpnSubnet:       vpnSubnet,
		VpnSubnetCidr:   openvpnServerLineToCidr(serverDirective),
	}
}

func linuxIfaceFromOpenvpnDev(dev string) string {
	if dev == "" {
		return ""
	}
	switch strings.ToLower(dev) {
	case "tun":
		return "tun0"
	case "tap":
		return "tap0"
	default:
		return dev
	}
}

func openvpnServerLineToCidr(serverLine string) string {
	parts := strings.Fields(strings.TrimSpace(serverLine))
	if len(parts) != 2 {
		return ""
	}
	ip, second := parts[0], parts[1]
	if pl, err := strconv.Atoi(second); err == nil && pl >= 0 && pl <= 32 {
		return ip + "/" + second
	}
	if strings.Contains(second, ".") {
		if pref := netmaskDottedToPrefix(second); pref >= 0 {
			return ip + "/" + strconv.Itoa(pref)
		}
	}
	return ""
}

func netmaskDottedToPrefix(maskStr string) int {
	n := ipv4OctetsToInt(maskStr)
	if n < 0 {
		return -1
	}
	prefix := 0
	v := uint32(n)
	for v&0x80000000 != 0 {
		prefix++
		v <<= 1
	}
	if v != 0 {
		return -1
	}
	return prefix
}

func ipv4OctetsToInt(s string) int {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return -1
	}
	var octets [4]int
	for i, p := range parts {
		n := 0
		for _, c := range p {
			if c < '0' || c > '9' {
				return -1
			}
			n = n*10 + int(c-'0')
		}
		if n < 0 || n > 255 {
			return -1
		}
		octets[i] = n
	}
	return ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) & 0xffffffff
}

func strVal(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func defaultStr(s, def string) string {
	if s != "" {
		return s
	}
	return def
}
