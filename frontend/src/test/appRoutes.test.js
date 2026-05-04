import { describe, expect, it } from "vitest";
import { parseAppRoute, paths } from "../appRoutes.js";

describe("appRoutes", () => {
  it("parses organization firewall tab", () => {
    const route = parseAppRoute("/organizations/org-1/edit", "?tab=firewall");
    expect(route.primaryNav).toBe("organizations");
    expect(route.organizationsView).toBe("edit");
    expect(route.organizationEditId).toBe("org-1");
    expect(route.organizationEditTab).toBe("firewall");
  });

  it("falls back to default tab for unknown value", () => {
    const route = parseAppRoute("/users/u-1", "?tab=unknown");
    expect(route.primaryNav).toBe("users");
    expect(route.usersSub).toBe("profile");
    expect(route.userProfileTab).toBe("overview");
  });

  it("builds tabbed path only for non-default tab", () => {
    expect(paths.organizationEdit("org-1", "overview")).toBe("/organizations/org-1/edit");
    expect(paths.organizationEdit("org-1", "firewall")).toBe("/organizations/org-1/edit?tab=firewall");
  });

  it("parses admin profile, settings backup and restore sections", () => {
    expect(parseAppRoute("/profile", "").primaryNav).toBe("myProfile");
    expect(parseAppRoute("/settings/profile", "").primaryNav).toBe("myProfile");
    expect(parseAppRoute("/settings/backup", "").settingsSection).toBe("backup");
    expect(parseAppRoute("/settings/restore", "").settingsSection).toBe("restore");
    expect(parseAppRoute("/settings", "").settingsSection).toBe("admins");
    expect(paths.profile()).toBe("/profile");
    expect(paths.settingsBackup()).toBe("/settings/backup");
    expect(paths.settingsRestore()).toBe("/settings/restore");
  });

  it("parses invite-admin route with token", () => {
    const route = parseAppRoute("/invite-admin", "?token=abc123");
    expect(route.primaryNav).toBe("inviteAdmin");
    expect(route.inviteAdminToken).toBe("abc123");
    expect(paths.inviteAdmin("abc123")).toBe("/invite-admin?token=abc123");
  });

  it("parses reset-admin-password route with token", () => {
    const route = parseAppRoute("/reset-admin-password", "?token=xyz");
    expect(route.primaryNav).toBe("resetAdminPassword");
    expect(route.resetAdminPasswordToken).toBe("xyz");
    expect(paths.resetAdminPassword("xyz")).toBe("/reset-admin-password?token=xyz");
  });

  it("parses logs section from tab query", () => {
    expect(parseAppRoute("/logs", "").logsView).toBe("vpn-ip");
    expect(parseAppRoute("/logs", "?tab=source-ip").logsView).toBe("source-ip");
    expect(parseAppRoute("/logs", "?tab=admin").logsView).toBe("admin");
    expect(parseAppRoute("/logs", "?tab=unknown").logsView).toBe("vpn-ip");
    expect(paths.logs()).toBe("/logs");
    expect(paths.logs("source-ip")).toBe("/logs?tab=source-ip");
  });
});
