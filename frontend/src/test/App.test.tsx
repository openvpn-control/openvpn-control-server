/// <reference types="vitest/globals" />
import "./matchMedia-polyfill";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import App from "../App";

const memoryRouterFuture = { v7_startTransition: true, v7_relativeSplatPath: true };

/** Диалог правил/NAT: заголовок оканчивается на «· Межсетевой экран». */
async function findFirewallRuleDialog() {
  return screen.findByRole("dialog", { name: /· Межсетевой экран$/ });
}

function makeJwt(expSecondsFromNow = 3600) {
  const header = btoa(JSON.stringify({ alg: "none", typ: "JWT" }))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
  const payload = btoa(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + expSecondsFromNow }))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
  return `${header}.${payload}.`;
}

function jsonResponse(body, status = 200) {
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  });
}

function mockApiFetch() {
  const nodes = [{ id: "s1", name: "Server 1", status: "ONLINE", host: "127.0.0.1", port: 8081 }];
  const organizations = [{ id: "o1", name: "Org 1" }];
  const users = [{ id: "u1", fullName: "User 1", organizationId: "o1" }];
  const openvpnSettingsPayload = {
    versions: [
      { id: "v1", version: 1, createdAt: "2026-01-01T00:00:00.000Z", settings: { dev: "tun", port: 1194 } },
      { id: "v2", version: 2, createdAt: "2026-01-02T00:00:00.000Z", settings: { dev: "tun", port: 1195 } },
    ],
    activeVersionId: "v1",
    selectedVersionId: "v2",
  };

  return vi.fn((input, init) => {
    const url = String(input || "");
    const method = String(init?.method || "GET").toUpperCase();
    if (url.includes("/api/auth/login/mfa")) return jsonResponse({ token: makeJwt(3600) });
    if (url.includes("/api/auth/login")) return jsonResponse({ token: makeJwt(3600), admin: { id: "a1", username: "admin" } });
    if (url.includes("/api/monitoring/overview")) return jsonResponse({});
    if (url.includes("/password-reset-link") && method === "POST") {
      return jsonResponse({ resetPath: "/reset-admin-password?token=mock" });
    }
    if (url.includes("/api/admins/") && method === "PATCH") {
      return jsonResponse({
        id: "a1",
        fullName: "Admin",
        username: "admin",
        email: "a@b.com",
        isActive: true,
        invitePending: false,
      });
    }
    if (url.includes("/api/admins")) return jsonResponse([]);
    if (url.includes("/api/certificates/root-ca")) return jsonResponse([]);
    if (url.includes("/api/certificates")) return jsonResponse([]);
    if (url.includes("/api/clients/source-history")) return jsonResponse([]);
    if (url.includes("/api/clients/history")) return jsonResponse([]);
    if (url.includes("/api/clients")) return jsonResponse([]);
    if (url.includes("/api/monitoring/admin-actions")) return jsonResponse([]);
    if (url.includes("/api/agent/nodes") && method === "POST") return jsonResponse({ id: "s2", name: "Server 2" });
    if (url.includes("/api/agent/nodes")) return jsonResponse(nodes);
    if (url.includes("/api/organizations") && method === "POST") return jsonResponse({ id: "o2", name: "Org 2" });
    if (url.includes("/api/vpn-users/issue-certificate/servers")) return jsonResponse({ servers: [] });
    if (url.includes("/api/vpn-users") && method === "POST") return jsonResponse({ id: "u2", fullName: "User 2" });
    if (url.includes("/api/organizations/o1/firewall")) return jsonResponse({ mode: "merge", rules: [], natRules: [] });
    if (url.includes("/api/organizations")) return jsonResponse(organizations);
    if (url.includes("/api/vpn-users/u1/firewall")) return jsonResponse({ mode: "merge", rules: [], natRules: [] });
    if (url.includes("/api/vpn-users")) return jsonResponse(users);
    if (url.includes("/api/panel/nodes/s1/openvpn-settings-save")) return jsonResponse({ message: "Настройки сохранены на панели." });
    if (url.includes("/api/panel/nodes/s1/openvpn-settings-apply")) {
      return jsonResponse({ message: "Конфигурация успешно применена.", output: "ok", serviceLog: "ok", activeVersionId: "v2" });
    }
    if (url.includes("/api/panel/nodes/s1/openvpn-settings")) return jsonResponse(openvpnSettingsPayload);
    if (url.includes("/api/panel/nodes/s1/system/network")) {
      return jsonResponse({ interfaces: [{ name: "eth0", addresses: ["192.0.2.10"] }] });
    }
    if (url.includes("/api/panel/nodes/") && url.includes("/network-info")) {
      return jsonResponse({
        interfaces: [{ name: "eth0" }],
        addresses: ["192.0.2.10"],
      });
    }
    if (url.includes("/api/panel/nodes/s1/firewall/check")) return jsonResponse({ ok: true });
    if (url.includes("/api/panel/nodes/s1/firewall")) {
      return jsonResponse({
        tunnelDefaultPolicy: "deny",
        tunnelRules: [],
        tunnelNatRules: [],
      });
    }
    if (url.includes("/api/panel/app-backups/restore") && method === "POST") {
      return jsonResponse({ ok: true, message: "Восстановлено." });
    }
    if (url.includes("/api/panel/app-backups/settings") && method === "PUT") {
      return jsonResponse({ settings: { intervalMinutes: 60, retainCount: 5, lastScheduledAt: null } });
    }
    if (url.includes("/api/panel/app-backups/run") && method === "POST") {
      return jsonResponse({
        backup: {
          id: "b1",
          fileName: "panel-backup.zip",
          sizeBytes: 1024,
          trigger: "manual",
          createdAt: new Date().toISOString(),
        },
      });
    }
    if (url.includes("/api/panel/app-backups") && method === "GET") {
      return jsonResponse({
        settings: { intervalMinutes: 0, retainCount: 10, lastScheduledAt: null },
        backups: [],
      });
    }
    if (url.includes("/api/tasks")) return jsonResponse([]);
    if (url.includes("/api/auth/refresh")) return jsonResponse({ token: makeJwt(3600) });
    return jsonResponse([]);
  });
}

function mockApiFetchLoginFailure() {
  const base = mockApiFetch();
  return vi.fn((input, init) => {
    const url = String(input || "");
    if (url.includes("/api/auth/login") && String(init?.method || "GET").toUpperCase() === "POST") {
      return jsonResponse({ error: "Bad credentials" }, 401);
    }
    return base(input, init);
  });
}

function getFieldInputByLabelText(labelPattern) {
  const labelNode = screen.getByText(labelPattern, { selector: ".user-profile-field-label" });
  const block = labelNode.closest(".user-profile-field-block");
  if (!block) return null;
  return block.querySelector("input, textarea, select");
}

describe("App UI", () => {
  beforeEach(() => {
    localStorage.clear();
    vi.restoreAllMocks();
  });

  it("shows login screen for unauthorized user", async () => {
    global.fetch = mockApiFetch();
    render(
      <MemoryRouter future={memoryRouterFuture} initialEntries={["/servers"]}>
        <App />
      </MemoryRouter>,
    );

    expect(await screen.findByText("Вход администратора")).toBeInTheDocument();
    expect(screen.getByLabelText("Логин")).toBeInTheDocument();
    expect(screen.getByLabelText("Пароль")).toBeInTheDocument();
  });

  it("renders main app for authorized user", async () => {
    localStorage.setItem("ovpn_control_admin_token", makeJwt(3600));
    global.fetch = mockApiFetch();

    render(
      <MemoryRouter future={memoryRouterFuture} initialEntries={["/servers"]}>
        <App />
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(screen.queryByText("Вход администратора")).not.toBeInTheDocument();
    });
    expect(await screen.findByText("Серверы VPN")).toBeInTheDocument();
  });

  it("login flow: signs in and stores token", async () => {
    const fetchMock = mockApiFetch();
    global.fetch = fetchMock;

    render(
      <MemoryRouter future={memoryRouterFuture} initialEntries={["/servers"]}>
        <App />
      </MemoryRouter>,
    );

    fireEvent.change(await screen.findByLabelText("Логин"), { target: { value: "admin" } });
    fireEvent.change(screen.getByLabelText("Пароль"), { target: { value: "secret" } });
    fireEvent.click(screen.getByRole("button", { name: "Войти" }));

    await waitFor(() => {
      expect(screen.queryByText("Вход администратора")).not.toBeInTheDocument();
    });
    expect(localStorage.getItem("ovpn_control_admin_token")).toBeTruthy();
    expect(fetchMock).toHaveBeenCalled();
  });

  it("login flow: shows backend error on failed auth", async () => {
    global.fetch = mockApiFetchLoginFailure();

    render(
      <MemoryRouter future={memoryRouterFuture} initialEntries={["/servers"]}>
        <App />
      </MemoryRouter>,
    );

    fireEvent.change(await screen.findByLabelText("Логин"), { target: { value: "admin" } });
    fireEvent.change(screen.getByLabelText("Пароль"), { target: { value: "wrong" } });
    fireEvent.click(screen.getByRole("button", { name: "Войти" }));

    expect(await screen.findByText("Bad credentials")).toBeInTheDocument();
  });

  it("login flow: opens 2FA modal and completes MFA step", async () => {
    const base = mockApiFetch();
    global.fetch = vi.fn((input, init) => {
      const url = String(input || "");
      const method = String(init?.method || "GET").toUpperCase();
      if (url.includes("/api/auth/login/mfa") && method === "POST") {
        return jsonResponse({ token: makeJwt(3600) });
      }
      if (url.includes("/api/auth/login") && method === "POST" && !url.includes("/login/mfa")) {
        return jsonResponse({ mfaRequired: true, mfaPendingToken: "mfa.pending.token" });
      }
      return base(input, init);
    });

    render(
      <MemoryRouter future={memoryRouterFuture} initialEntries={["/servers"]}>
        <App />
      </MemoryRouter>,
    );

    fireEvent.change(await screen.findByLabelText("Логин"), { target: { value: "admin" } });
    fireEvent.change(screen.getByLabelText("Пароль"), { target: { value: "secret" } });
    fireEvent.click(screen.getByRole("button", { name: "Войти" }));

    expect(await screen.findByRole("heading", { name: "Двухфакторная аутентификация" })).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Код из приложения (TOTP)"), { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: "Подтвердить и войти" }));

    await waitFor(() => {
      expect(screen.queryByText("Вход администратора")).not.toBeInTheDocument();
    });
    expect(localStorage.getItem("ovpn_control_admin_token")).toBeTruthy();
  });

  it("renders server firewall controls and opens Effective Policy modal", async () => {
    localStorage.setItem("ovpn_control_admin_token", makeJwt(3600));
    global.fetch = mockApiFetch();

    render(
      <MemoryRouter future={memoryRouterFuture} initialEntries={["/servers/s1?tab=firewall"]}>
        <App />
      </MemoryRouter>,
    );

    expect(
      await screen.findByRole("heading", { level: 2, name: "Межсетевой экран" }),
    ).toBeInTheDocument();
    expect(await screen.findByRole("button", { name: "+ Правило" })).toBeInTheDocument();
    expect(await screen.findByRole("button", { name: "+ NAT" })).toBeInTheDocument();
    fireEvent.click(await screen.findByRole("button", { name: "Effective Policy" }));
    expect(await screen.findByText("Effective Policy · Сервер")).toBeInTheDocument();
  });

  it("renders organization firewall controls and opens Effective Policy modal", async () => {
    localStorage.setItem("ovpn_control_admin_token", makeJwt(3600));
    global.fetch = mockApiFetch();

    render(
      <MemoryRouter future={memoryRouterFuture} initialEntries={["/organizations/o1/edit?tab=firewall"]}>
        <App />
      </MemoryRouter>,
    );

    expect(
      await screen.findByRole("heading", { level: 2, name: "Межсетевой экран" }),
    ).toBeInTheDocument();
    expect(await screen.findByRole("button", { name: "+ Правило" })).toBeInTheDocument();
    expect(await screen.findByRole("button", { name: "+ NAT" })).toBeInTheDocument();
    fireEvent.click(await screen.findByRole("button", { name: "Effective Policy" }));
    expect(await screen.findByText("Effective Policy · Организация")).toBeInTheDocument();
  });

  it("renders user firewall controls and opens Effective Policy modal", async () => {
    localStorage.setItem("ovpn_control_admin_token", makeJwt(3600));
    global.fetch = mockApiFetch();

    render(
      <MemoryRouter future={memoryRouterFuture} initialEntries={["/users/u1?tab=firewall"]}>
        <App />
      </MemoryRouter>,
    );

    expect(
      await screen.findByRole("heading", { level: 2, name: "Межсетевой экран" }),
    ).toBeInTheDocument();
    expect(await screen.findByRole("button", { name: "+ Правило" })).toBeInTheDocument();
    expect(await screen.findByRole("button", { name: "+ NAT" })).toBeInTheDocument();
    fireEvent.click(await screen.findByRole("button", { name: "Effective Policy" }));
    expect(await screen.findByText("Effective Policy · Пользователь")).toBeInTheDocument();
    expect(screen.queryByText("Отношение к общим правилам сервера")).not.toBeInTheDocument();
  });

  it("NAT modal: toggles between preset and manual for server firewall", async () => {
    localStorage.setItem("ovpn_control_admin_token", makeJwt(3600));
    global.fetch = mockApiFetch();

    render(
      <MemoryRouter future={memoryRouterFuture} initialEntries={["/servers/s1?tab=firewall"]}>
        <App />
      </MemoryRouter>,
    );

    fireEvent.click(await screen.findByRole("button", { name: "+ NAT" }));
    const natDlg = await findFirewallRuleDialog();

    const outInput = await within(natDlg).findByPlaceholderText("eth0");
    const toInput = await within(natDlg).findByPlaceholderText("203.0.113.10");
    const selects = natDlg.querySelectorAll("select");
    expect(selects.length).toBeGreaterThanOrEqual(3);
    const [, outSelect, toSelect] = selects;
    expect(outInput).not.toBeDisabled();
    expect(toInput).not.toBeDisabled();

    await waitFor(() => {
      expect(outSelect.querySelector('option[value="eth0"]')).toBeTruthy();
    });
    fireEvent.change(outSelect, { target: { value: "eth0" } });
    fireEvent.change(toSelect, { target: { value: "192.0.2.10" } });
    expect(outInput).toBeDisabled();
    expect(toInput).toBeDisabled();
    expect(outInput).toHaveValue("eth0");
    expect(toInput).toHaveValue("192.0.2.10");

    fireEvent.change(outSelect, { target: { value: "__manual__" } });
    fireEvent.change(toSelect, { target: { value: "__manual__" } });
    expect(outInput).not.toBeDisabled();
    expect(toInput).not.toBeDisabled();

    fireEvent.change(outInput, { target: { value: "tun99" } });
    fireEvent.change(toInput, { target: { value: "198.51.100.77" } });
    expect(outInput).toHaveValue("tun99");
    expect(toInput).toHaveValue("198.51.100.77");
  });

  it("NAT modal: keeps preset mode when editing existing server NAT rule", async () => {
    localStorage.setItem("ovpn_control_admin_token", makeJwt(3600));
    global.fetch = mockApiFetch();

    render(
      <MemoryRouter future={memoryRouterFuture} initialEntries={["/servers/s1?tab=firewall"]}>
        <App />
      </MemoryRouter>,
    );

    fireEvent.click(await screen.findByRole("button", { name: "+ NAT" }));
    let natDlg = await findFirewallRuleDialog();
    let outInput = await within(natDlg).findByPlaceholderText("eth0");
    let toInput = await within(natDlg).findByPlaceholderText("203.0.113.10");
    let selects = natDlg.querySelectorAll("select");
    let [, outSelect, toSelect] = selects;

    await waitFor(() => {
      expect(outSelect.querySelector('option[value="eth0"]')).toBeTruthy();
    });
    fireEvent.change(outSelect, { target: { value: "eth0" } });
    fireEvent.change(toSelect, { target: { value: "192.0.2.10" } });
    fireEvent.click(within(natDlg).getByRole("button", { name: "Сохранить" }));

    fireEvent.click(await screen.findByRole("button", { name: "Изменить" }));
    natDlg = await findFirewallRuleDialog();
    outInput = await within(natDlg).findByPlaceholderText("eth0");
    toInput = await within(natDlg).findByPlaceholderText("203.0.113.10");
    selects = natDlg.querySelectorAll("select");
    [, outSelect, toSelect] = selects;
    expect(outInput).toHaveValue("eth0");
    expect(toInput).toHaveValue("192.0.2.10");
    expect(outInput).toBeDisabled();
    expect(toInput).toBeDisabled();
  });

  it("NAT modal: same select/manual behavior works for organization scope", async () => {
    localStorage.setItem("ovpn_control_admin_token", makeJwt(3600));
    global.fetch = mockApiFetch();

    render(
      <MemoryRouter future={memoryRouterFuture} initialEntries={["/organizations/o1/edit?tab=firewall"]}>
        <App />
      </MemoryRouter>,
    );

    fireEvent.click(await screen.findByRole("button", { name: "+ NAT" }));
    const outInput = await screen.findByPlaceholderText("eth0");
    const toInput = await screen.findByPlaceholderText("203.0.113.10");
    const modal = outInput.closest(".modal-dialog");
    const [outSelect, toSelect] = modal ? Array.from(modal.querySelectorAll("select")).slice(-2) : [null, null];

    fireEvent.change(outSelect, { target: { value: "eth0" } });
    fireEvent.change(toSelect, { target: { value: "192.0.2.10" } });
    expect(outInput).toBeDisabled();
    expect(toInput).toBeDisabled();

    fireEvent.change(outSelect, { target: { value: "__manual__" } });
    fireEvent.change(toSelect, { target: { value: "__manual__" } });
    expect(outInput).not.toBeDisabled();
    expect(toInput).not.toBeDisabled();
  });

  it("NAT modal: same select/manual behavior works for user scope", async () => {
    localStorage.setItem("ovpn_control_admin_token", makeJwt(3600));
    global.fetch = mockApiFetch();
    cleanup();

    render(
      <MemoryRouter future={memoryRouterFuture} initialEntries={["/users/u1?tab=firewall"]}>
        <App />
      </MemoryRouter>,
    );

    fireEvent.click(await screen.findByRole("button", { name: "+ NAT" }));
    const outInput = await screen.findByPlaceholderText("eth0");
    const toInput = await screen.findByPlaceholderText("203.0.113.10");
    const modal = outInput.closest(".modal-dialog");
    const [outSelect, toSelect] = modal ? Array.from(modal.querySelectorAll("select")).slice(-2) : [null, null];

    fireEvent.change(outSelect, { target: { value: "eth0" } });
    fireEvent.change(toSelect, { target: { value: "192.0.2.10" } });
    expect(outInput).toBeDisabled();
    expect(toInput).toBeDisabled();

    fireEvent.change(outSelect, { target: { value: "__manual__" } });
    fireEvent.change(toSelect, { target: { value: "__manual__" } });
    expect(outInput).not.toBeDisabled();
    expect(toInput).not.toBeDisabled();
  });

  it("firewall tables: render expected columns and empty states on server page", async () => {
    localStorage.setItem("ovpn_control_admin_token", makeJwt(3600));
    global.fetch = mockApiFetch();
    cleanup();

    render(
      <MemoryRouter future={memoryRouterFuture} initialEntries={["/servers/s1?tab=firewall"]}>
        <App />
      </MemoryRouter>,
    );

    expect(
      await screen.findByRole("heading", { level: 2, name: "Межсетевой экран" }),
    ).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Action" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Proto" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Destination" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Ports" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Type" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Hook" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Out iface" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "To address" })).toBeInTheDocument();
    expect(screen.getByText("Нет правил.")).toBeInTheDocument();
    expect(screen.getByText("Нет NAT-правил.")).toBeInTheDocument();
  });

  it("firewall NAT table: shows POSTROUTING for masquerade and PREROUTING for dnat", async () => {
    localStorage.setItem("ovpn_control_admin_token", makeJwt(3600));
    global.fetch = mockApiFetch();
    cleanup();

    render(
      <MemoryRouter future={memoryRouterFuture} initialEntries={["/servers/s1?tab=firewall"]}>
        <App />
      </MemoryRouter>,
    );

    fireEvent.click(await screen.findByRole("button", { name: "+ NAT" }));
    let natDialog = await findFirewallRuleDialog();
    fireEvent.click(within(natDialog).getByRole("button", { name: "Сохранить" }));
    expect(await screen.findByText("POSTROUTING")).toBeInTheDocument();

    fireEvent.click(await screen.findByRole("button", { name: "+ NAT" }));
    natDialog = await findFirewallRuleDialog();
    const natTypeSelect = within(natDialog).getByDisplayValue("masquerade");
    fireEvent.change(natTypeSelect, { target: { value: "dnat" } });
    fireEvent.click(within(natDialog).getByRole("button", { name: "Сохранить" }));
    expect(await screen.findByText("PREROUTING")).toBeInTheDocument();
  });

  it("CRUD: creates agent node from new server form", async () => {
    const fetchMock = mockApiFetch();
    localStorage.setItem("ovpn_control_admin_token", makeJwt(3600));
    global.fetch = fetchMock;
    cleanup();

    render(
      <MemoryRouter future={memoryRouterFuture} initialEntries={["/servers/new"]}>
        <App />
      </MemoryRouter>,
    );

    const nameInput = getFieldInputByLabelText(/Имя узла/i);
    const hostInput = getFieldInputByLabelText(/Хост/i);
    const portInput = getFieldInputByLabelText(/Порт/i);
    const tokenInput = getFieldInputByLabelText(/Токен агента/i);
    expect(nameInput).toBeTruthy();
    expect(hostInput).toBeTruthy();
    expect(portInput).toBeTruthy();
    expect(tokenInput).toBeTruthy();
    fireEvent.change(nameInput, { target: { value: "edge-1" } });
    fireEvent.change(hostInput, { target: { value: "10.0.0.10" } });
    fireEvent.change(portInput, { target: { value: "8081" } });
    fireEvent.change(tokenInput, { target: { value: "token-1" } });
    fireEvent.click(screen.getByRole("button", { name: "Добавить агента" }));

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining("/api/agent/nodes"),
        expect.objectContaining({ method: "POST" }),
      );
    });
  });

  it("CRUD: creates organization", async () => {
    const fetchMock = mockApiFetch();
    localStorage.setItem("ovpn_control_admin_token", makeJwt(3600));
    global.fetch = fetchMock;
    cleanup();

    render(
      <MemoryRouter future={memoryRouterFuture} initialEntries={["/organizations/new"]}>
        <App />
      </MemoryRouter>,
    );

    fireEvent.change(await screen.findByPlaceholderText("ООО «Пример»"), { target: { value: "ООО Тест" } });
    fireEvent.click(screen.getByRole("button", { name: "Сохранить организацию" }));

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining("/api/organizations"),
        expect.objectContaining({ method: "POST" }),
      );
    });
  });

  it("CRUD: creates vpn user profile", async () => {
    const fetchMock = mockApiFetch();
    localStorage.setItem("ovpn_control_admin_token", makeJwt(3600));
    global.fetch = fetchMock;
    cleanup();

    render(
      <MemoryRouter future={memoryRouterFuture} initialEntries={["/users/new"]}>
        <App />
      </MemoryRouter>,
    );

    fireEvent.change(await screen.findByPlaceholderText("Иванов Иван Иванович"), { target: { value: "Петров Петр" } });
    fireEvent.change(screen.getByPlaceholderText("user@company.ru"), { target: { value: "petrov@example.com" } });
    fireEvent.click(screen.getByRole("button", { name: "Создать профиль" }));

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining("/api/vpn-users"),
        expect.objectContaining({ method: "POST" }),
      );
    });
  });

  it("OpenVPN settings: apply sends current draft to panel", async () => {
    const fetchMock = mockApiFetch();
    localStorage.setItem("ovpn_control_admin_token", makeJwt(3600));
    global.fetch = fetchMock;
    cleanup();

    render(
      <MemoryRouter future={memoryRouterFuture} initialEntries={["/servers/s1?tab=settings"]}>
        <App />
      </MemoryRouter>,
    );

    await screen.findByRole("heading", { name: "Служба OpenVPN" });
    fireEvent.click(await screen.findByRole("button", { name: "Применить" }));
    expect(await screen.findByText("Подтверждение применения")).toBeInTheDocument();
    const modal = screen.getByText("Подтверждение применения").closest(".modal-dialog");
    const confirmBtn = modal ? Array.from(modal.querySelectorAll("button")).find((b) => b.textContent?.trim() === "Подтвердить") : null;
    expect(confirmBtn).toBeTruthy();
    fireEvent.click(confirmBtn);
    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining("/openvpn-settings-apply"),
        expect.objectContaining({ method: "POST" }),
      );
    });
  });
});
