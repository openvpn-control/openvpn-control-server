import test from "node:test";
import assert from "node:assert/strict";
import { normalizeUserCcdSettings, renderUserCcdText } from "./userCcd.js";

test("normalizeUserCcdSettings trims all text fields", () => {
  const out = normalizeUserCcdSettings({
    ifconfigPushLocal: " 10.220.0.10 ",
    ifconfigPushRemote: " 255.255.252.0 ",
    pushRoutes: " 10.10.0.0 255.255.0.0 ",
  });
  assert.equal(out.ifconfigPushLocal, "10.220.0.10");
  assert.equal(out.ifconfigPushRemote, "255.255.252.0");
  assert.equal(out.pushRoutes, "10.10.0.0 255.255.0.0");
});

test("renderUserCcdText renders ifconfig/push/iroute/dns/custom directives", () => {
  const text = renderUserCcdText("John Doe", {
    ifconfigPushLocal: "10.220.0.10",
    ifconfigPushRemote: "255.255.252.0",
    pushRoutes: "10.10.0.0 255.255.0.0\n172.16.0.0 255.255.0.0",
    iroutes: "192.168.1.0 255.255.255.0",
    dnsServers: "1.1.1.1, 8.8.8.8",
    customDirectives: "push \"redirect-gateway def1\"\nkeepalive 10 60",
  });

  assert.match(text, /# ccd for user: John Doe/);
  assert.match(text, /ifconfig-push 10\.220\.0\.10 255\.255\.252\.0/);
  assert.match(text, /push 10\.10\.0\.0 255\.255\.0\.0/);
  assert.match(text, /push 172\.16\.0\.0 255\.255\.0\.0/);
  assert.match(text, /iroute 192\.168\.1\.0 255\.255\.255\.0/);
  assert.match(text, /push dhcp-option DNS 1\.1\.1\.1/);
  assert.match(text, /push dhcp-option DNS 8\.8\.8\.8/);
  assert.match(text, /push "redirect-gateway def1"/);
  assert.match(text, /keepalive 10 60/);
});
