package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// vpnClientJSON matches openvpn-control-agent VPNClient JSON.
type vpnClientJSON struct {
	ID          string `json:"id"`
	CommonName  string `json:"commonName"`
	RemoteIP    string `json:"remoteIp"`
	VirtualIP   string `json:"virtualIp"`
	ConnectedAt string `json:"connectedAt"`
	RxBytes     uint64 `json:"rxBytes"`
	TxBytes     uint64 `json:"txBytes"`
}

func parseClientsJSON(raw []byte) ([]vpnClientJSON, error) {
	raw = bytes.TrimSpace(bytes.TrimPrefix(raw, []byte("\ufeff")))
	if len(raw) == 0 {
		return nil, nil
	}
	var typed []vpnClientJSON
	if err := json.Unmarshal(raw, &typed); err == nil {
		return typed, nil
	}
	var loose []map[string]any
	if err := json.Unmarshal(raw, &loose); err != nil {
		return nil, fmt.Errorf("invalid clients JSON: %w", err)
	}
	out := make([]vpnClientJSON, 0, len(loose))
	for _, m := range loose {
		c := vpnClientJSON{
			ID:          strVal(m["id"]),
			CommonName:  strVal(m["commonName"]),
			RemoteIP:    strVal(m["remoteIp"]),
			VirtualIP:   strVal(m["virtualIp"]),
			ConnectedAt: strVal(m["connectedAt"]),
			RxBytes:     uint64(bigIntVal(m["rxBytes"])),
			TxBytes:     uint64(bigIntVal(m["txBytes"])),
		}
		if c.ID == "" || c.CommonName == "" || c.RemoteIP == "" {
			continue
		}
		out = append(out, c)
	}
	return out, nil
}

func clientToMap(c vpnClientJSON, nodeID, nodeName string) map[string]any {
	return map[string]any{
		"id":          c.ID,
		"commonName":  c.CommonName,
		"remoteIp":    c.RemoteIP,
		"virtualIp":   c.VirtualIP,
		"connectedAt": c.ConnectedAt,
		"rxBytes":     int64(c.RxBytes),
		"txBytes":     int64(c.TxBytes),
		"nodeId":      nodeID,
		"nodeName":    nodeName,
	}
}

// ClientsList polls GET /clients on the agent (OpenVPN management).
func ClientsList(ctx context.Context, n Node) ([]map[string]any, error) {
	raw, err := requestRaw(ctx, n, "/clients", http.MethodGet, nil, defaultTimeout)
	if err != nil {
		return nil, err
	}
	typed, err := parseClientsJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("agent %s: %w", n.Name, err)
	}
	out := make([]map[string]any, 0, len(typed))
	for _, c := range typed {
		out = append(out, clientToMap(c, n.ID, n.Name))
	}
	return out, nil
}
