import test from "node:test";
import assert from "node:assert/strict";
import { renderFirewallRuntimeIptablesScript } from "./firewallIptablesRuntime.js";

test("renderFirewallRuntimeIptablesScript places dnat in prerouting", () => {
  const script = renderFirewallRuntimeIptablesScript({
    nodeLabel: "node-1",
    tunnelInterface: "tun0",
    vpnSubnetCidr: "10.220.0.0/22",
    tunnelDefaultPolicy: "deny",
    tunnelRules: [],
    natRules: [{ type: "dnat", outInterface: "eth0", toAddress: "172.16.10.2" }],
    sessions: [],
  });

  assert.match(script, /iptables -t nat -I PREROUTING 1 -j OPENVPN_PANEL_NAT_PRE/);
  assert.match(
    script,
    /iptables -t nat -A OPENVPN_PANEL_NAT_PRE -i 'eth0' -j DNAT --to-destination '172\.16\.10\.2'/,
  );
});

test("renderFirewallRuntimeIptablesScript places snat/masquerade in postrouting", () => {
  const script = renderFirewallRuntimeIptablesScript({
    nodeLabel: "node-1",
    tunnelInterface: "tun0",
    vpnSubnetCidr: "10.220.0.0/22",
    tunnelDefaultPolicy: "deny",
    tunnelRules: [],
    natRules: [
      { type: "masquerade", src: "10.220.0.0/22", outInterface: "eth0" },
      { type: "snat", src: "10.220.0.10/32", outInterface: "eth1", toAddress: "203.0.113.11" },
    ],
    sessions: [],
  });

  assert.match(script, /iptables -t nat -I POSTROUTING 1 -s '10\.220\.0\.0\/22' -j OPENVPN_PANEL_NAT_POST/);
  assert.match(script, /-A OPENVPN_PANEL_NAT_POST .* -j MASQUERADE/);
  assert.match(script, /-A OPENVPN_PANEL_NAT_POST .* -j SNAT --to-source '203\.0\.113\.11'/);
});
