import { describe, expect, it } from "vitest";
import {
  panelDataFetchContext,
  panelDataKeysForRoute,
  panelDataPollIntervalMs,
  panelDataRouteKey,
} from "../panelData";
import { parseAppRoute } from "../appRoutes";

describe("panelDataKeysForRoute", () => {
  it("polls nodes on servers list (not heavy overview)", () => {
    const keys = panelDataKeysForRoute(parseAppRoute("/servers", ""));
    expect(keys).toEqual(["nodes"]);
  });

  it("polls scoped overview on server monitoring tab", () => {
    const keys = panelDataKeysForRoute(parseAppRoute("/servers/s1", "?tab=monitoring"));
    expect(keys).toEqual(["overview"]);
    expect(panelDataFetchContext(parseAppRoute("/servers/s1", "?tab=monitoring"))).toEqual({
      selectedServerId: "s1",
    });
  });

  it("polls nodes without overview on server sessions tab", () => {
    const keys = panelDataKeysForRoute(parseAppRoute("/servers/s1", "?tab=sessions"));
    expect(keys).toEqual(expect.arrayContaining(["nodes", "clients", "vpnUsers", "certificates"]));
    expect(keys).not.toContain("overview");
  });

  it("polls root CAs on user add form for cert validity cap", () => {
    const keys = panelDataKeysForRoute(parseAppRoute("/users/new", ""));
    expect(keys).toEqual(["rootCAs"]);
  });

  it("polls profile tab-specific keys", () => {
    const keys = panelDataKeysForRoute(parseAppRoute("/users/u1", "?tab=certs"));
    expect(keys).toEqual(["vpnUsers", "certificates", "rootCAs"]);
  });

  it("polls admins only on settings admins", () => {
    const keys = panelDataKeysForRoute(parseAppRoute("/settings", ""));
    expect(keys).toEqual(["admins"]);
  });

  it("polls nothing on documentation", () => {
    const keys = panelDataKeysForRoute(parseAppRoute("/documentation", ""));
    expect(keys).toEqual([]);
  });
});

describe("panelDataPollIntervalMs", () => {
  it("uses slower interval for heavy user list", () => {
    const ms = panelDataPollIntervalMs(parseAppRoute("/users", ""));
    expect(ms).toBe(4000);
  });

  it("returns 0 when no keys", () => {
    expect(panelDataPollIntervalMs(parseAppRoute("/tasks", ""))).toBe(0);
  });
});

describe("panelDataRouteKey", () => {
  it("changes when server detail tab changes", () => {
    const a = panelDataRouteKey(parseAppRoute("/servers/s1", "?tab=overview"));
    const b = panelDataRouteKey(parseAppRoute("/servers/s1", "?tab=sessions"));
    expect(a).not.toBe(b);
  });
});
