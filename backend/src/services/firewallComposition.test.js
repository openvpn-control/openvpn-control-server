import test from "node:test";
import assert from "node:assert/strict";
import { composeFirewallLevels, deriveSessionNatRules } from "./firewallComposition.js";

test("composeFirewallLevels: user replace fully overrides upper levels", () => {
  const org = { mode: "merge", rules: [{ id: "org-1" }], natRules: [{ type: "snat" }] };
  const user = { mode: "replace", rules: [{ id: "user-1" }], natRules: [{ type: "dnat" }] };
  const res = composeFirewallLevels(org, user);
  assert.equal(res.mode, "replace");
  assert.deepEqual(res.rules, [{ id: "user-1" }]);
  assert.deepEqual(res.natRules, [{ type: "dnat" }]);
});

test("composeFirewallLevels: organization replace includes org + user", () => {
  const org = { mode: "replace", rules: [{ id: "org-1" }], natRules: [{ type: "snat" }] };
  const user = { mode: "merge", rules: [{ id: "user-1" }], natRules: [{ type: "dnat" }] };
  const res = composeFirewallLevels(org, user);
  assert.equal(res.mode, "replace");
  assert.deepEqual(res.rules, [{ id: "org-1" }, { id: "user-1" }]);
  assert.deepEqual(res.natRules, [{ type: "snat" }, { type: "dnat" }]);
});

test("composeFirewallLevels: merge combines organization + user", () => {
  const org = { mode: "merge", rules: [{ id: "org-1" }], natRules: [{ type: "masquerade" }] };
  const user = { mode: "merge", rules: [{ id: "user-1" }], natRules: [{ type: "snat" }] };
  const res = composeFirewallLevels(org, user);
  assert.equal(res.mode, "merge");
  assert.deepEqual(res.rules, [{ id: "org-1" }, { id: "user-1" }]);
  assert.deepEqual(res.natRules, [{ type: "masquerade" }, { type: "snat" }]);
});

test("deriveSessionNatRules: auto-fills src from user virtual IP", () => {
  const sessions = [
    {
      commonName: "u1",
      virtualIp: "10.220.0.10",
      natRules: [{ type: "snat", outInterface: "eth0", toAddress: "203.0.113.7" }],
    },
  ];
  const res = deriveSessionNatRules(sessions);
  assert.equal(res.length, 1);
  assert.equal(res[0].src, "10.220.0.10/32");
  assert.equal(res[0].outInterface, "eth0");
  assert.equal(res[0].toAddress, "203.0.113.7");
});

test("deriveSessionNatRules: keeps explicit src and ignores sessions without virtual IP", () => {
  const sessions = [
    { commonName: "u1", virtualIp: "", natRules: [{ type: "dnat", src: "10.0.0.0/8" }] },
    { commonName: "u2", virtualIp: "10.220.0.20", natRules: [{ type: "dnat", src: "10.10.0.0/16" }] },
  ];
  const res = deriveSessionNatRules(sessions);
  assert.equal(res.length, 1);
  assert.equal(res[0].src, "10.10.0.0/16");
  assert.equal(res[0].type, "dnat");
});
