const SERVER_TABS = new Set([
  "overview",
  "agent",
  "monitoring",
  "sessions",
  "certificates",
  "ca-center",
  "keys",
  "settings",
  "firewall",
  "service",
  "services",
  "dns",
  "journal",
]);
const USER_TABS = new Set(["overview", "sessions", "certs", "vpn", "ccd", "firewall"]);
const ORGANIZATION_TABS = new Set(["overview", "firewall"]);
const LOGS_VIEWS = new Set(["vpn-ip", "source-ip", "admin"]);
const DOCUMENTATION_SECTIONS = new Set([
  "intro",
  "concepts",
  "interface",
  "servers",
  "working-with-node",
  "dns-firewall",
  "users-organizations",
  "logs-tasks",
  "panel-settings",
  "agent-security",
  "troubleshooting",
]);

function pickTab(value, allowed, fallback) {
  const v = String(value || "").trim();
  return allowed.has(v) ? v : fallback;
}

function withQuery(base, tabKey, tabVal, defaultTab) {
  if (!tabVal || tabVal === defaultTab) return base;
  const q = new URLSearchParams();
  q.set(tabKey, tabVal);
  return `${base}?${q.toString()}`;
}

/**
 * @param {string} pathname
 * @param {string} search
 */
export function parseAppRoute(pathname, search) {
  const sp = new URLSearchParams(search);
  const path = pathname.replace(/\/+$/, "") || "/";
  const seg = path.split("/").filter(Boolean);

  const base = {
    primaryNav: "servers",
    serversView: "list",
    selectedServerId: "",
    serverDetailTab: "overview",
    serverCenterCertId: "",
    organizationsView: "list",
    organizationEditId: "",
    organizationEditTab: "overview",
    usersSub: "list",
    selectedUserId: "",
    userProfileTab: "overview",
    caRootWizard: null,
    selectedRootCaId: "",
    selectedCertId: "",
    rootCaProfileTab: "overview",
    certProfileTab: "overview",
    adminsPage: "list",
    selectedAdminId: "",
    tasksView: "list",
    logsView: "vpn-ip",
    docsSection: "intro",
    settingsSection: "admins",
    inviteAdminToken: "",
    resetAdminPasswordToken: "",
  };

  if (seg[0] === "reset-admin-password") {
    return {
      ...base,
      primaryNav: "resetAdminPassword",
      resetAdminPasswordToken: sp.get("token") || "",
    };
  }

  if (seg[0] === "invite-admin") {
    return {
      ...base,
      primaryNav: "inviteAdmin",
      inviteAdminToken: sp.get("token") || "",
    };
  }

  if (seg.length === 1 && seg[0] === "profile") {
    return { ...base, primaryNav: "myProfile" };
  }

  if (seg.length === 0 || (seg.length === 1 && seg[0] === "servers")) {
    return { ...base, primaryNav: "servers", serversView: "list" };
  }

  if (seg[0] === "servers") {
    if (seg[1] === "new") {
      return { ...base, primaryNav: "servers", serversView: "add" };
    }
    if (seg.length >= 2) {
      return {
        ...base,
        primaryNav: "servers",
        serversView: "detail",
        selectedServerId: decodeURIComponent(seg[1]),
        serverDetailTab: pickTab(sp.get("tab"), SERVER_TABS, "overview"),
        serverCenterCertId: sp.get("certId") || "",
      };
    }
  }

  if (seg[0] === "organizations") {
    if (seg.length === 1) {
      return { ...base, primaryNav: "organizations", organizationsView: "list" };
    }
    if (seg[1] === "new") {
      return { ...base, primaryNav: "organizations", organizationsView: "add" };
    }
    if (seg.length >= 3 && seg[2] === "edit") {
      return {
        ...base,
        primaryNav: "organizations",
        organizationsView: "edit",
        organizationEditId: decodeURIComponent(seg[1]),
        organizationEditTab: pickTab(sp.get("tab"), ORGANIZATION_TABS, "overview"),
      };
    }
  }

  if (seg[0] === "users") {
    if (seg.length === 1) {
      return { ...base, primaryNav: "users", usersSub: "list" };
    }
    if (seg[1] === "new") {
      return { ...base, primaryNav: "users", usersSub: "add" };
    }
    return {
      ...base,
      primaryNav: "users",
      usersSub: "profile",
      selectedUserId: decodeURIComponent(seg[1]),
      userProfileTab: pickTab(sp.get("tab"), USER_TABS, "overview"),
    };
  }

  if (seg[0] === "ca") return { ...base, primaryNav: "servers", serversView: "list" };

  if (seg[0] === "settings") {
    if (seg[1] === "profile") {
      return { ...base, primaryNav: "myProfile" };
    }
    if (seg[1] === "backup") {
      return { ...base, primaryNav: "settings", settingsSection: "backup", adminsPage: "list", selectedAdminId: "" };
    }
    if (seg[1] === "restore") {
      return { ...base, primaryNav: "settings", settingsSection: "restore", adminsPage: "list", selectedAdminId: "" };
    }
    if (seg.length >= 3 && seg[1] === "admins") {
      if (seg[2] === "new") {
        return { ...base, primaryNav: "settings", settingsSection: "admins", adminsPage: "list", selectedAdminId: "" };
      }
      return {
        ...base,
        primaryNav: "settings",
        settingsSection: "admins",
        adminsPage: "detail",
        selectedAdminId: decodeURIComponent(seg[2]),
      };
    }
    return { ...base, primaryNav: "settings", settingsSection: "admins", adminsPage: "list", selectedAdminId: "" };
  }

  if (seg[0] === "logs") {
    return { ...base, primaryNav: "logs", logsView: pickTab(sp.get("tab"), LOGS_VIEWS, "vpn-ip") };
  }

  if (seg[0] === "tasks") {
    return { ...base, primaryNav: "tasks", tasksView: "list" };
  }

  if (seg[0] === "documentation" || seg[0] === "docs") {
    return {
      ...base,
      primaryNav: "documentation",
      docsSection: pickTab(sp.get("section"), DOCUMENTATION_SECTIONS, "intro"),
    };
  }

  return { ...base, primaryNav: "servers", serversView: "list" };
}

export const paths = {
  home: () => "/servers",
  servers: () => "/servers",
  serverNew: () => "/servers/new",
  serverDetail: (id, tab = "overview") => withQuery(`/servers/${encodeURIComponent(id)}`, "tab", tab, "overview"),
  serverCaCenterCert: (id, certId) =>
    `/servers/${encodeURIComponent(id)}?tab=ca-center&certId=${encodeURIComponent(certId)}`,
  organizations: () => "/organizations",
  organizationNew: () => "/organizations/new",
  organizationEdit: (id, tab = "overview") => withQuery(`/organizations/${encodeURIComponent(id)}/edit`, "tab", tab, "overview"),
  users: () => "/users",
  userNew: () => "/users/new",
  userProfile: (id, tab = "overview") => withQuery(`/users/${encodeURIComponent(id)}`, "tab", tab, "overview"),
  settings: () => "/settings",
  profile: () => "/profile",
  settingsBackup: () => "/settings/backup",
  settingsRestore: () => "/settings/restore",
  /** Открывает модальное окно добавления администратора (после редиректа на /settings). */
  settingsAdminNew: () => "/settings/admins/new",
  settingsAdmin: (id) => `/settings/admins/${encodeURIComponent(id)}`,
  logs: (tab = "vpn-ip") => withQuery("/logs", "tab", tab, "vpn-ip"),
  tasks: () => "/tasks",
  documentation: (section = "intro") => withQuery("/documentation", "section", section, "intro"),
  inviteAdmin: (token) => `/invite-admin?token=${encodeURIComponent(token)}`,
  resetAdminPassword: (token) => `/reset-admin-password?token=${encodeURIComponent(token)}`,
};
