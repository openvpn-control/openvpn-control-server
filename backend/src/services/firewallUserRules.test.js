import test from "node:test";
import assert from "node:assert/strict";
import {
  normalizeFirewallNatRulesArray,
  normalizeFirewallRulesArray,
  parseUserFirewallStored,
  serializeUserFirewallForDb,
} from "./firewallUserRules.js";

test("normalizeFirewallRulesArray normalizes proto/action and trims fields", () => {
  const out = normalizeFirewallRulesArray([
    { action: "DENY", proto: "UDP", destination: " 10.0.0.0/8 ", ports: " 53 ", note: " dns " },
  ]);
  assert.equal(out.length, 1);
  assert.equal(out[0].action, "deny");
  assert.equal(out[0].proto, "udp");
  assert.equal(out[0].destination, "10.0.0.0/8");
  assert.equal(out[0].ports, "53");
  assert.equal(out[0].note, "dns");
});

test("normalizeFirewallNatRulesArray defaults invalid type to masquerade", () => {
  const out = normalizeFirewallNatRulesArray([{ type: "invalid", outInterface: " eth0 " }]);
  assert.equal(out[0].type, "masquerade");
  assert.equal(out[0].outInterface, "eth0");
});

test("parseUserFirewallStored supports legacy array format", () => {
  const out = parseUserFirewallStored([{ action: "allow", proto: "tcp", destination: "172.16.0.0/21" }]);
  assert.equal(out.mode, "merge");
  assert.equal(out.rules.length, 1);
  assert.equal(out.natRules.length, 0);
});

test("serializeUserFirewallForDb returns normalized payload", () => {
  const out = serializeUserFirewallForDb(
    "replace",
    [{ action: "allow", proto: "icmp", destination: " 192.168.0.0/16 " }],
    [{ type: "dnat", toAddress: " 172.16.10.2 " }],
  );
  assert.equal(out.mode, "replace");
  assert.equal(out.rules[0].destination, "192.168.0.0/16");
  assert.equal(out.natRules[0].type, "dnat");
  assert.equal(out.natRules[0].toAddress, "172.16.10.2");
});
