package agent

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const defaultTimeout = 8 * time.Second

// AgentError is returned when the agent responds with HTTP >= 400.
type AgentError struct {
	StatusCode int
	Message    string
	Hints      []string
	Body       map[string]any
}

func (e *AgentError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return fmt.Sprintf("agent returned %d", e.StatusCode)
}

// RequestOpts configures an agent HTTP call.
type RequestOpts struct {
	Timeout time.Duration
}

func timeoutFrom(opts []RequestOpts) time.Duration {
	if len(opts) > 0 && opts[0].Timeout > 0 {
		return opts[0].Timeout
	}
	return defaultTimeout
}

// RequestJSON calls the agent and decodes a JSON object response.
func RequestJSON(ctx context.Context, n Node, path, method string, body any, opts ...RequestOpts) (map[string]any, error) {
	raw, err := requestRaw(ctx, n, path, method, body, timeoutFrom(opts))
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return map[string]any{}, nil
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("invalid JSON from agent %s", n.Name)
	}
	return out, nil
}

func requestRaw(ctx context.Context, n Node, path, method string, body any, timeout time.Duration) ([]byte, error) {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		r = bytes.NewReader(b)
	}
	proto := n.Protocol
	if proto == "" {
		proto = "http"
	}
	url := fmt.Sprintf("%s://%s:%d%s", proto, n.Host, n.Port, path)
	req, err := http.NewRequestWithContext(ctx, method, url, r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Agent-Token", n.AuthToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: timeout}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if res.StatusCode >= 400 {
		var parsed map[string]any
		_ = json.Unmarshal(data, &parsed)
		msg := string(data)
		if parsed != nil {
			if e, ok := parsed["error"].(string); ok && e != "" {
				msg = e
			}
		}
		if msg == "" {
			msg = fmt.Sprintf("Agent %s returned %d", n.Name, res.StatusCode)
		}
		var hints []string
		if parsed != nil {
			if arr, ok := parsed["hints"].([]any); ok {
				for _, h := range arr {
					if s, ok := h.(string); ok {
						hints = append(hints, s)
					}
				}
			}
		}
		return nil, &AgentError{StatusCode: res.StatusCode, Message: msg, Hints: hints, Body: parsed}
	}
	return data, nil
}

func WriteOpenvpnFile(ctx context.Context, n Node, pathStr string, content []byte) (map[string]any, error) {
	b64 := base64.StdEncoding.EncodeToString(content)
	return RequestJSON(ctx, n, "/openvpn/write-file", http.MethodPost, map[string]string{
		"path": pathStr, "contentBase64": b64,
	}, RequestOpts{Timeout: 120 * time.Second})
}

func PanelSnapshot(ctx context.Context, n Node, snapshot any) (map[string]any, error) {
	return RequestJSON(ctx, n, "/panel/snapshot", http.MethodPost, snapshot, RequestOpts{Timeout: 120 * time.Second})
}

func Dnsmasq(ctx context.Context, n Node, body map[string]any) (map[string]any, error) {
	return RequestJSON(ctx, n, "/dnsmasq", http.MethodPost, body, RequestOpts{Timeout: 60 * time.Second})
}

func OpenVPNService(ctx context.Context, n Node, action string) (map[string]any, error) {
	return RequestJSON(ctx, n, "/openvpn/service", http.MethodPost, map[string]string{"action": action}, RequestOpts{Timeout: 30 * time.Second})
}

func OpenVPNSettings(ctx context.Context, n Node, settings map[string]any, validate bool) (map[string]any, error) {
	body := map[string]any{"settings": settings}
	if !validate {
		body["validate"] = false
	}
	return RequestJSON(ctx, n, "/openvpn/settings", http.MethodPost, body, RequestOpts{Timeout: 120 * time.Second})
}

func OpenVPNApplyRaw(ctx context.Context, n Node, rawConfig string) (map[string]any, error) {
	return RequestJSON(ctx, n, "/openvpn/apply-config", http.MethodPost, map[string]any{
		"rawConfig": rawConfig,
	}, RequestOpts{Timeout: 120 * time.Second})
}

func OpenVPNCheck(ctx context.Context, n Node, settings map[string]any) (map[string]any, error) {
	body := map[string]any{}
	if settings != nil && len(settings) > 0 {
		body["settings"] = settings
	}
	return RequestJSON(ctx, n, "/openvpn/check-config", http.MethodPost, body, RequestOpts{Timeout: 30 * time.Second})
}

func OpenVPNRawConfig(ctx context.Context, n Node) (map[string]any, error) {
	return RequestJSON(ctx, n, "/openvpn/raw-config", http.MethodGet, nil, RequestOpts{Timeout: 30 * time.Second})
}

func OpenVPNSettingsGet(ctx context.Context, n Node) (map[string]any, error) {
	return RequestJSON(ctx, n, "/openvpn/settings", http.MethodGet, nil, RequestOpts{Timeout: 30 * time.Second})
}

func SystemNetwork(ctx context.Context, n Node) (map[string]any, error) {
	return RequestJSON(ctx, n, "/system/network", http.MethodGet, nil, RequestOpts{Timeout: 30 * time.Second})
}

func SystemServices(ctx context.Context, n Node) (map[string]any, error) {
	return RequestJSON(ctx, n, "/system/services", http.MethodGet, nil, RequestOpts{Timeout: 30 * time.Second})
}

func SystemServiceUnit(ctx context.Context, n Node, body map[string]any) (map[string]any, error) {
	return RequestJSON(ctx, n, "/system/service-unit", http.MethodPost, body, RequestOpts{Timeout: 90 * time.Second})
}

func BinaryUpdate(ctx context.Context, n Node, fileName, binaryBase64, checksumSha256 string) (map[string]any, error) {
	return RequestJSON(ctx, n, "/agent/update", http.MethodPost, map[string]string{
		"fileName": fileName, "binaryBase64": binaryBase64, "checksumSha256": checksumSha256,
	}, RequestOpts{Timeout: 180 * time.Second})
}

func OpenvpnFileSha256(ctx context.Context, n Node, pathStr string) (map[string]any, error) {
	return RequestJSON(ctx, n, "/openvpn/file-sha256", http.MethodPost, map[string]string{"path": pathStr}, RequestOpts{Timeout: 30 * time.Second})
}

func ClientsList(ctx context.Context, n Node) ([]map[string]any, error) {
	raw, err := requestRaw(ctx, n, "/clients", http.MethodGet, nil, defaultTimeout)
	if err != nil {
		return nil, err
	}
	var arr []map[string]any
	if len(raw) == 0 {
		return []map[string]any{}, nil
	}
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil, fmt.Errorf("invalid JSON from agent %s", n.Name)
	}
	return arr, nil
}

func OpenVPNInfo(ctx context.Context, n Node) (map[string]any, error) {
	return RequestJSON(ctx, n, "/openvpn/info", http.MethodGet, nil, RequestOpts{Timeout: 10 * time.Second})
}
