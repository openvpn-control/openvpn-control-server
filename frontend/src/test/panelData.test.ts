import { describe, expect, it } from "vitest";
import { panelDataKeysForRoute, panelDataRouteKey } from "../panelData";
import { parseAppRoute } from "../appRoutes";

describe("panelDataKeysForRoute", () => {
  it("polls overview on servers list only", () => {
    const keys = panelDataKeysForRoute(parseAppRoute("/servers", ""));
    expect(keys).toEqual(["overview"]);
  });

  it("polls monitoring overview on server monitoring tab", () => {
    const keys = panelDataKeysForRoute(parseAppRoute("/servers/s1", "?tab=monitoring"));
    expect(keys).toEqual(["overview"]);
  });

  it("polls session-related data on server sessions tab", () => {
    const keys = panelDataKeysForRoute(parseAppRoute("/servers/s1", "?tab=sessions"));
    expect(keys).toEqual(expect.arrayContaining(["clients", "vpnUsers", "certificates", "overview", "nodes"]));
  });

  it("polls admins only on settings admins", () => {
    const keys = panelDataKeysForRoute(parseAppRoute("/settings", ""));
    expect(keys).toEqual(["admins"]);
  });

  it("polls nothing on documentation", () => {
    const keys = panelDataKeysForRoute(parseAppRoute("/documentation", ""));
    expect(keys).toEqual([]);
  });

  it("polls vpn ip history on logs vpn tab", () => {
    const keys = panelDataKeysForRoute(parseAppRoute("/logs", "?tab=vpn-ip"));
    expect(keys).toEqual(["ipHistory"]);
  });

  it("polls admin actions on logs admin tab", () => {
    const keys = panelDataKeysForRoute(parseAppRoute("/logs", "?tab=admin"));
    expect(keys).toEqual(["adminActionLogs"]);
  });
});

describe("panelDataRouteKey", () => {
  it("changes when server detail tab changes", () => {
    const a = panelDataRouteKey(parseAppRoute("/servers/s1", "?tab=overview"));
    const b = panelDataRouteKey(parseAppRoute("/servers/s1", "?tab=sessions"));
    expect(a).not.toBe(b);
  });
});
