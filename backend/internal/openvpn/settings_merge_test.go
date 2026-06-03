package openvpn

import "testing"

func TestMergeSettingsForDisplayAgentWins(t *testing.T) {
	db := map[string]any{"management": "", "port": float64(1194)}
	agent := map[string]any{"management": "127.0.0.1 7505", "port": float64(1194)}
	got := MergeSettingsForDisplay(db, agent)
	if got["management"] != "127.0.0.1 7505" {
		t.Fatalf("management=%v", got["management"])
	}
}

func TestMergeSettingsForDisplayPanelGroup(t *testing.T) {
	db := map[string]any{"group": "nobody", "panelRootCaId": "ca1"}
	agent := map[string]any{"group": "nogroup"}
	got := MergeSettingsForDisplay(db, agent)
	if got["group"] != "nobody" {
		t.Fatalf("group=%v", got["group"])
	}
	if got["panelRootCaId"] != "ca1" {
		t.Fatalf("panelRootCaId=%v", got["panelRootCaId"])
	}
}
