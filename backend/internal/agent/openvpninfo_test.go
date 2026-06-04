package agent

import "testing"

func TestReconcileOpenVPNRunningFromSystemd(t *testing.T) {
	info := map[string]any{
		"running":     false,
		"activeState": "active",
		"subState":    "running",
		"mainPid":     float64(1234),
	}
	if !reconcileOpenVPNRunning(info) {
		t.Fatal("expected running from systemd state")
	}
}

func TestReconcileOpenVPNRunningKeepsManagement(t *testing.T) {
	info := map[string]any{"running": true, "activeState": "inactive"}
	if !reconcileOpenVPNRunning(info) {
		t.Fatal("expected true when agent reports running")
	}
}
