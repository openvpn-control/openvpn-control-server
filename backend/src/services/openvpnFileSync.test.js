import test from "node:test";
import assert from "node:assert/strict";
import { sha256HexUtf8, stripPanelOnlyOpenvpnSettings } from "./openvpnFileSync.js";

test("sha256HexUtf8 returns deterministic digest", () => {
  const a = sha256HexUtf8("hello");
  const b = sha256HexUtf8("hello");
  const c = sha256HexUtf8("world");
  assert.equal(a, b);
  assert.notEqual(a, c);
  assert.match(a, /^[a-f0-9]{64}$/);
});

test("stripPanelOnlyOpenvpnSettings removes panel-only fields", () => {
  const out = stripPanelOnlyOpenvpnSettings({
    dev: "tun",
    panelRootCaId: "root-1",
    panelServerCertId: "cert-1",
    panelDhMaterialId: "dh-1",
    panelTlsAuthMaterialId: "tls-1",
    panelFirewallDefaultPolicy: "deny",
    panelFirewallBaseRules: [{ x: 1 }],
    panelFirewallTunnelRules: [{ a: 1 }, { b: 2 }],
  });
  assert.equal(out.dev, "tun");
  assert.equal(Object.prototype.hasOwnProperty.call(out, "panelRootCaId"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(out, "panelServerCertId"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(out, "panelDhMaterialId"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(out, "panelTlsAuthMaterialId"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(out, "panelFirewallDefaultPolicy"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(out, "panelFirewallBaseRules"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(out, "panelFirewallTunnelRules"), false);
});
