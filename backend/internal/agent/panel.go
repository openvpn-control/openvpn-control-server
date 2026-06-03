package agent

import (
	"context"
	"net/http"
	"time"
)

// Error is an alias for AgentError (legacy panel handlers).
type Error = AgentError

func GetOpenVPNSettings(ctx context.Context, n Node) (map[string]any, error) {
	return OpenVPNSettingsGet(ctx, n)
}

func GetOpenVPNRawConfig(ctx context.Context, n Node) (map[string]any, error) {
	return OpenVPNRawConfig(ctx, n)
}

func GetSystemNetwork(ctx context.Context, n Node) (map[string]any, error) {
	return SystemNetwork(ctx, n)
}

func GetSystemServices(ctx context.Context, n Node) (map[string]any, error) {
	return SystemServices(ctx, n)
}

func PostSystemServiceUnitAction(ctx context.Context, n Node, unit, action string) (map[string]any, error) {
	return SystemServiceUnit(ctx, n, map[string]any{"unit": unit, "action": action})
}

func GetDnsmasq(ctx context.Context, n Node) (map[string]any, error) {
	return RequestJSON(ctx, n, "/dnsmasq", http.MethodGet, nil, RequestOpts{Timeout: 30 * time.Second})
}

func PostDnsmasq(ctx context.Context, n Node, action, config string) (map[string]any, error) {
	return Dnsmasq(ctx, n, map[string]any{"action": action, "config": config})
}

func PostOpenVPNSettings(ctx context.Context, n Node, settings map[string]any) (map[string]any, error) {
	return OpenVPNSettings(ctx, n, settings)
}

func PostOpenVPNApplyConfig(ctx context.Context, n Node) (map[string]any, error) {
	return OpenVPNApply(ctx, n)
}

func PostOpenVPNServiceAction(ctx context.Context, n Node, action string) (map[string]any, error) {
	return OpenVPNService(ctx, n, action)
}

func PostOpenVPNCheckConfig(ctx context.Context, n Node) (map[string]any, error) {
	return OpenVPNCheck(ctx, n)
}

func PostBinaryUpdate(ctx context.Context, n Node, fileName, binaryBase64, checksumSha256 string) (map[string]any, error) {
	return BinaryUpdate(ctx, n, fileName, binaryBase64, checksumSha256)
}
