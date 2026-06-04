import type { AppRouteState } from "./appRoutes";

export type PanelDataKey =
  | "overview"
  | "admins"
  | "certificates"
  | "clients"
  | "nodes"
  | "ipHistory"
  | "sourceIpHistory"
  | "adminActionLogs"
  | "rootCAs"
  | "organizations"
  | "vpnUsers";

export type PanelRequestFn = (
  path: string,
  method?: string,
  token?: string,
  body?: unknown,
) => Promise<unknown>;

export type PanelDataFetchContext = {
  /** Для overview — только метрики и агент одного узла. */
  selectedServerId?: string;
};

const PANEL_DATA_ENDPOINTS: Record<PanelDataKey, string> = {
  overview: "/api/monitoring/overview",
  admins: "/api/admins",
  certificates: "/api/certificates",
  clients: "/api/clients",
  nodes: "/api/agent/nodes",
  ipHistory: "/api/clients/history",
  sourceIpHistory: "/api/clients/source-history",
  adminActionLogs: "/api/monitoring/admin-actions?limit=300",
  rootCAs: "/api/certificates/root-ca",
  organizations: "/api/organizations",
  vpnUsers: "/api/vpn-users",
};

function uniqueKeys(keys: readonly PanelDataKey[]): PanelDataKey[] {
  return [...new Set(keys)];
}

function endpointForKey(key: PanelDataKey, ctx?: PanelDataFetchContext): string {
  if (key === "overview" && ctx?.selectedServerId) {
    return `${PANEL_DATA_ENDPOINTS.overview}?agentNodeId=${encodeURIComponent(ctx.selectedServerId)}`;
  }
  return PANEL_DATA_ENDPOINTS[key];
}

/** Все сущности панели (после полного restore БД). */
export const ALL_PANEL_DATA_KEYS: PanelDataKey[] = uniqueKeys(
  Object.keys(PANEL_DATA_ENDPOINTS) as PanelDataKey[],
);

/** После мутаций — обновить связанные сущности (шире, чем poll по маршруту). */
export const PANEL_DATA_REFRESH = {
  servers: ["nodes", "overview"] satisfies PanelDataKey[],
  admins: ["admins"] satisfies PanelDataKey[],
  organizations: ["organizations"] satisfies PanelDataKey[],
  vpnUsers: ["vpnUsers", "certificates", "clients"] satisfies PanelDataKey[],
  certificates: ["certificates", "rootCAs", "nodes", "clients", "vpnUsers"] satisfies PanelDataKey[],
  clients: ["clients", "nodes"] satisfies PanelDataKey[],
} as const;

export type PanelDataSetters = {
  setOverview: (v: unknown) => void;
  setAdmins: (v: unknown) => void;
  setCertificates: (v: unknown) => void;
  setClients: (v: unknown) => void;
  setNodes: (v: unknown) => void;
  setIpHistory: (v: unknown) => void;
  setSourceIpHistory: (v: unknown) => void;
  setAdminActionLogs: (v: unknown) => void;
  setRootCAs: (v: unknown) => void;
  setOrganizations: (v: unknown) => void;
  setVpnUsers: (v: unknown) => void;
};

export function mergePanelDataKeys(...groups: readonly PanelDataKey[][]): PanelDataKey[] {
  return uniqueKeys(groups.flat());
}

/** Стабильный ключ маршрута для эффектов опроса. */
export function panelDataRouteKey(route: AppRouteState): string {
  return [
    route.primaryNav,
    route.serversView,
    route.selectedServerId,
    route.serverDetailTab,
    route.organizationsView,
    route.organizationEditId,
    route.usersSub,
    route.selectedUserId,
    route.userProfileTab,
    route.adminsPage,
    route.settingsSection,
    route.logsView,
  ].join("|");
}

function userProfileKeys(tab: string): PanelDataKey[] {
  if (tab === "certs" || tab === "vpn") {
    return ["vpnUsers", "certificates"];
  }
  if (tab === "ccd" || tab === "firewall") {
    return ["vpnUsers", "organizations"];
  }
  if (tab === "sessions") {
    return ["vpnUsers", "clients", "certificates"];
  }
  return ["vpnUsers", "organizations"];
}

function serverDetailKeys(tab: string): PanelDataKey[] {
  if (tab === "monitoring") {
    return ["overview"];
  }
  if (tab === "sessions") {
    return ["nodes", "clients", "vpnUsers", "certificates"];
  }
  if (tab === "certificates" || tab === "ca-center") {
    return ["nodes", "certificates", "rootCAs"];
  }
  return ["nodes"];
}

/** Какие сущности опрашивать на текущей странице. */
export function panelDataKeysForRoute(route: AppRouteState): PanelDataKey[] {
  const { primaryNav } = route;

  if (primaryNav === "inviteAdmin" || primaryNav === "resetAdminPassword") {
    return [];
  }
  if (primaryNav === "documentation" || primaryNav === "tasks" || primaryNav === "myProfile") {
    return [];
  }

  if (primaryNav === "settings") {
    if (route.settingsSection === "admins") {
      return ["admins"];
    }
    return [];
  }

  if (primaryNav === "logs") {
    if (route.logsView === "source-ip") return ["sourceIpHistory"];
    if (route.logsView === "admin") return ["adminActionLogs"];
    return ["ipHistory"];
  }

  if (primaryNav === "organizations") {
    if (route.organizationsView === "list" || route.organizationsView === "edit") {
      return ["organizations"];
    }
    return [];
  }

  if (primaryNav === "users") {
    if (route.usersSub === "list") {
      return ["vpnUsers", "clients", "certificates"];
    }
    if (route.usersSub === "add") {
      return [];
    }
    if (route.usersSub === "profile") {
      return userProfileKeys(route.userProfileTab);
    }
    return ["vpnUsers"];
  }

  if (primaryNav === "servers") {
    if (route.serversView === "list") {
      return ["nodes"];
    }
    if (route.serversView === "add") {
      return [];
    }
    if (route.serversView === "detail") {
      return serverDetailKeys(route.serverDetailTab);
    }
    return ["nodes"];
  }

  return [];
}

/** Интервал фонового опроса (мс) — тяжёлые страницы реже. */
export function panelDataPollIntervalMs(route: AppRouteState): number {
  const keys = panelDataKeysForRoute(route);
  if (!keys.length) return 0;

  if (route.primaryNav === "servers" && route.serversView === "detail" && route.serverDetailTab === "monitoring") {
    return 2000;
  }
  if (route.primaryNav === "servers" && route.serversView === "list") {
    return 3000;
  }
  if (keys.includes("certificates") && keys.length >= 3) {
    return 4000;
  }
  if (route.primaryNav === "logs") {
    return 5000;
  }
  return 3000;
}

/** Нужен ли agentNodeId в overview (один сервер, вкладка мониторинг). */
export function panelDataFetchContext(route: AppRouteState): PanelDataFetchContext {
  if (
    route.primaryNav === "servers" &&
    route.serversView === "detail" &&
    route.serverDetailTab === "monitoring" &&
    route.selectedServerId
  ) {
    return { selectedServerId: route.selectedServerId };
  }
  return {};
}

export async function fetchPanelDataKeys(
  requestFn: PanelRequestFn,
  token: string,
  keys: readonly PanelDataKey[],
  ctx?: PanelDataFetchContext,
): Promise<Partial<Record<PanelDataKey, unknown>>> {
  const unique = uniqueKeys(keys);
  if (!unique.length) return {};

  const entries = await Promise.all(
    unique.map(async (key) => {
      const data = await requestFn(endpointForKey(key, ctx), "GET", token);
      return [key, data] as const;
    }),
  );

  return Object.fromEntries(entries);
}

export function applyPanelDataPatch(patch: Partial<Record<PanelDataKey, unknown>>, setters: PanelDataSetters) {
  if ("overview" in patch) setters.setOverview(patch.overview);
  if ("admins" in patch) setters.setAdmins(patch.admins);
  if ("certificates" in patch) setters.setCertificates(patch.certificates);
  if ("clients" in patch) setters.setClients(patch.clients);
  if ("nodes" in patch) setters.setNodes(patch.nodes);
  if ("ipHistory" in patch) setters.setIpHistory(patch.ipHistory);
  if ("sourceIpHistory" in patch) setters.setSourceIpHistory(patch.sourceIpHistory);
  if ("adminActionLogs" in patch) setters.setAdminActionLogs(patch.adminActionLogs);
  if ("rootCAs" in patch) setters.setRootCAs(patch.rootCAs);
  if ("organizations" in patch) setters.setOrganizations(patch.organizations);
  if ("vpnUsers" in patch) setters.setVpnUsers(patch.vpnUsers);
}
