import test from "node:test";
import assert from "node:assert/strict";
import jwt from "jsonwebtoken";
import request from "supertest";
import { createApp } from "./app.js";
import { config } from "./config.js";
import { prisma } from "./prisma.js";

function authHeader() {
  const token = jwt.sign({ sub: "admin-1", username: "admin" }, config.jwtSecret, { expiresIn: "5m" });
  return { Authorization: `Bearer ${token}` };
}

test("tasks route: GET /api/tasks returns list from prisma", async (t) => {
  const app = createApp();
  const original = prisma.panelAsyncTask.findMany;
  prisma.panelAsyncTask.findMany = async () => [{ id: "t1", status: "pending", type: "panel_agent_snapshot" }];
  t.after(() => {
    prisma.panelAsyncTask.findMany = original;
  });

  const res = await request(app).get("/api/tasks").set(authHeader());
  assert.equal(res.status, 200);
  assert.equal(Array.isArray(res.body), true);
  assert.equal(res.body[0]?.id, "t1");
});

test("tasks route: POST /api/tasks/:id/retry returns 404 when task not found", async (t) => {
  const app = createApp();
  const originalFindUnique = prisma.panelAsyncTask.findUnique;
  prisma.panelAsyncTask.findUnique = async () => null;
  t.after(() => {
    prisma.panelAsyncTask.findUnique = originalFindUnique;
  });

  const res = await request(app).post("/api/tasks/missing/retry").set(authHeader());
  assert.equal(res.status, 404);
  assert.equal(res.body?.error, "Задача не найдена");
});

test("tasks route: POST /api/tasks/:id/retry returns 409 for processing task", async (t) => {
  const app = createApp();
  const originalFindUnique = prisma.panelAsyncTask.findUnique;
  prisma.panelAsyncTask.findUnique = async () => ({ id: "t2", status: "processing" });
  t.after(() => {
    prisma.panelAsyncTask.findUnique = originalFindUnique;
  });

  const res = await request(app).post("/api/tasks/t2/retry").set(authHeader());
  assert.equal(res.status, 409);
  assert.equal(res.body?.error, "Задача уже выполняется.");
});

test("tasks route: POST /api/tasks/:id/retry returns updated task", async (t) => {
  const app = createApp();
  const originalFindUnique = prisma.panelAsyncTask.findUnique;
  const originalUpdate = prisma.panelAsyncTask.update;
  prisma.panelAsyncTask.findUnique = async () => ({ id: "t3", status: "failed" });
  prisma.panelAsyncTask.update = async () => ({ id: "t3", status: "pending", lastError: null });
  t.after(() => {
    prisma.panelAsyncTask.findUnique = originalFindUnique;
    prisma.panelAsyncTask.update = originalUpdate;
  });

  const res = await request(app).post("/api/tasks/t3/retry").set(authHeader());
  assert.equal(res.status, 200);
  assert.equal(res.body?.id, "t3");
  assert.equal(res.body?.status, "pending");
});

test("organizations route: POST /api/organizations validates required name", async () => {
  const app = createApp();
  const res = await request(app).post("/api/organizations").set(authHeader()).send({ name: "   " });
  assert.equal(res.status, 400);
  assert.equal(res.body?.error, "Название организации обязательно");
});

test("organizations route: POST /api/organizations creates organization", async (t) => {
  const app = createApp();
  const originalCreate = prisma.organization.create;
  prisma.organization.create = async ({ data }) => ({ id: "o2", ...data });
  t.after(() => {
    prisma.organization.create = originalCreate;
  });

  const res = await request(app).post("/api/organizations").set(authHeader()).send({ name: " Org 2 " });
  assert.equal(res.status, 201);
  assert.equal(res.body?.id, "o2");
  assert.equal(res.body?.name, "Org 2");
});

test("organizations route: PATCH /api/organizations/:id returns 404 when missing", async (t) => {
  const app = createApp();
  const originalUpdate = prisma.organization.update;
  prisma.organization.update = async () => {
    throw new Error("not found");
  };
  t.after(() => {
    prisma.organization.update = originalUpdate;
  });

  const res = await request(app)
    .patch("/api/organizations/o-missing")
    .set(authHeader())
    .send({ name: "Org Missing" });
  assert.equal(res.status, 404);
  assert.equal(res.body?.error, "Организация не найдена");
});

test("organizations route: POST /api/organizations/:id/firewall-check returns normalized payload", async (t) => {
  const app = createApp();
  const originalFindUnique = prisma.organization.findUnique;
  prisma.organization.findUnique = async () => ({ id: "o1" });
  t.after(() => {
    prisma.organization.findUnique = originalFindUnique;
  });

  const res = await request(app)
    .post("/api/organizations/o1/firewall-check")
    .set(authHeader())
    .send({
      mode: "replace",
      rules: [{ action: "allow", proto: "tcp", destination: "172.16.0.0/21", ports: "443" }],
      natRules: [{ type: "dnat", outInterface: "eth0", toAddress: "172.16.10.2" }],
    });
  assert.equal(res.status, 200);
  assert.equal(res.body?.ok, true);
  assert.equal(res.body?.mode, "replace");
  assert.equal(Array.isArray(res.body?.rules), true);
  assert.equal(Array.isArray(res.body?.natRules), true);
  assert.equal(res.body?.natRules?.[0]?.type, "dnat");
});

test("vpn-users route: POST /api/vpn-users validates required fields", async () => {
  const app = createApp();
  const res = await request(app).post("/api/vpn-users").set(authHeader()).send({ fullName: "", email: "" });
  assert.equal(res.status, 400);
  assert.match(String(res.body?.error || ""), /Обязательное поле:/);
});

test("vpn-users route: POST /api/vpn-users returns 404 when organization missing", async (t) => {
  const app = createApp();
  const originalOrgFindUnique = prisma.organization.findUnique;
  prisma.organization.findUnique = async () => null;
  t.after(() => {
    prisma.organization.findUnique = originalOrgFindUnique;
  });

  const res = await request(app)
    .post("/api/vpn-users")
    .set(authHeader())
    .send({ fullName: "User A", email: "usera@example.com", organizationId: "missing-org" });
  assert.equal(res.status, 404);
  assert.equal(res.body?.error, "Организация не найдена");
});

test("vpn-users route: POST /api/vpn-users creates user", async (t) => {
  const app = createApp();
  const originalOrgFindUnique = prisma.organization.findUnique;
  const originalUserCreate = prisma.vpnUser.create;
  prisma.organization.findUnique = async () => ({ id: "o1", name: "Org 1" });
  prisma.vpnUser.create = async ({ data }) => ({ id: "u2", ...data, organization: { id: "o1", name: "Org 1" } });
  t.after(() => {
    prisma.organization.findUnique = originalOrgFindUnique;
    prisma.vpnUser.create = originalUserCreate;
  });

  const res = await request(app)
    .post("/api/vpn-users")
    .set(authHeader())
    .send({ fullName: "User B", email: "USERB@EXAMPLE.COM", organizationId: "o1" });
  assert.equal(res.status, 201);
  assert.equal(res.body?.id, "u2");
  assert.equal(res.body?.email, "userb@example.com");
});

test("vpn-users route: POST /api/vpn-users/:id/firewall-check returns 404 when user missing", async (t) => {
  const app = createApp();
  const originalUserFindUnique = prisma.vpnUser.findUnique;
  prisma.vpnUser.findUnique = async () => null;
  t.after(() => {
    prisma.vpnUser.findUnique = originalUserFindUnique;
  });

  const res = await request(app).post("/api/vpn-users/u-missing/firewall-check").set(authHeader()).send({});
  assert.equal(res.status, 404);
  assert.equal(res.body?.error, "Пользователь не найден");
});

test("vpn-users route: POST /api/vpn-users/:id/firewall-check returns normalized response", async (t) => {
  const app = createApp();
  const originalUserFindUnique = prisma.vpnUser.findUnique;
  prisma.vpnUser.findUnique = async () => ({ id: "u1" });
  t.after(() => {
    prisma.vpnUser.findUnique = originalUserFindUnique;
  });

  const res = await request(app)
    .post("/api/vpn-users/u1/firewall-check")
    .set(authHeader())
    .send({
      mode: "replace",
      rules: [{ action: "allow", proto: "icmp", destination: "10.0.0.0/8" }],
      natRules: [{ type: "snat", toAddress: "203.0.113.9" }],
    });
  assert.equal(res.status, 200);
  assert.equal(res.body?.ok, true);
  assert.equal(res.body?.mode, "replace");
  assert.equal(res.body?.natRules?.[0]?.type, "snat");
});

test("vpn-users route: POST /api/vpn-users/:id/ccd returns saved normalized settings", async (t) => {
  const app = createApp();
  const originalUserFindUnique = prisma.vpnUser.findUnique;
  const originalUserUpdate = prisma.vpnUser.update;
  prisma.vpnUser.findUnique = async () => ({ id: "u1" });
  prisma.vpnUser.update = async () => ({ id: "u1" });
  t.after(() => {
    prisma.vpnUser.findUnique = originalUserFindUnique;
    prisma.vpnUser.update = originalUserUpdate;
  });

  const res = await request(app)
    .post("/api/vpn-users/u1/ccd")
    .set(authHeader())
    .send({ ifconfigPushLocal: " 10.220.0.10 ", ifconfigPushRemote: " 255.255.252.0 " });
  assert.equal(res.status, 200);
  assert.equal(res.body?.ok, true);
  assert.equal(res.body?.ifconfigPushLocal, "10.220.0.10");
  assert.equal(res.body?.ifconfigPushRemote, "255.255.252.0");
});

test("agents route: GET /api/agent/nodes returns node list", async (t) => {
  const app = createApp();
  const originalFindMany = prisma.agentNode.findMany;
  prisma.agentNode.findMany = async () => [{ id: "n1", name: "Node 1", status: "ONLINE" }];
  t.after(() => {
    prisma.agentNode.findMany = originalFindMany;
  });

  const res = await request(app).get("/api/agent/nodes").set(authHeader());
  assert.equal(res.status, 200);
  assert.equal(Array.isArray(res.body), true);
  assert.equal(res.body[0]?.id, "n1");
});

test("agents route: POST /api/agent/nodes validates required fields", async () => {
  const app = createApp();
  const res = await request(app).post("/api/agent/nodes").set(authHeader()).send({ name: "node" });
  assert.equal(res.status, 400);
  assert.equal(res.body?.error, "name, host, port and authToken are required");
});

test("agents route: POST /api/agent/nodes creates node", async (t) => {
  const app = createApp();
  const originalCreate = prisma.agentNode.create;
  prisma.agentNode.create = async ({ data }) => ({ id: "n2", ...data });
  t.after(() => {
    prisma.agentNode.create = originalCreate;
  });

  const res = await request(app)
    .post("/api/agent/nodes")
    .set(authHeader())
    .send({ name: "node-2", host: "127.0.0.1", port: 8081, authToken: "token", protocol: "http" });
  assert.equal(res.status, 201);
  assert.equal(res.body?.id, "n2");
  assert.equal(res.body?.status, "UNKNOWN");
});

test("agents route: PATCH /api/agent/nodes/:id returns 404 when node missing", async (t) => {
  const app = createApp();
  const originalFindUnique = prisma.agentNode.findUnique;
  prisma.agentNode.findUnique = async () => null;
  t.after(() => {
    prisma.agentNode.findUnique = originalFindUnique;
  });

  const res = await request(app).patch("/api/agent/nodes/missing").set(authHeader()).send({ name: "new-name" });
  assert.equal(res.status, 404);
  assert.equal(res.body?.error, "Узел не найден");
});

test("agents route: PATCH /api/agent/nodes/:id validates port range", async (t) => {
  const app = createApp();
  const originalFindUnique = prisma.agentNode.findUnique;
  prisma.agentNode.findUnique = async () => ({ id: "n1", name: "Node 1" });
  t.after(() => {
    prisma.agentNode.findUnique = originalFindUnique;
  });

  const res = await request(app).patch("/api/agent/nodes/n1").set(authHeader()).send({ port: 70000 });
  assert.equal(res.status, 400);
  assert.equal(res.body?.error, "Некорректный порт");
});

test("agents route: PATCH /api/agent/nodes/:id updates node", async (t) => {
  const app = createApp();
  const originalFindUnique = prisma.agentNode.findUnique;
  const originalUpdate = prisma.agentNode.update;
  prisma.agentNode.findUnique = async () => ({ id: "n1", name: "Node 1" });
  prisma.agentNode.update = async ({ data }) => ({ id: "n1", ...data });
  t.after(() => {
    prisma.agentNode.findUnique = originalFindUnique;
    prisma.agentNode.update = originalUpdate;
  });

  const res = await request(app)
    .patch("/api/agent/nodes/n1")
    .set(authHeader())
    .send({ name: "Node Updated", host: "10.0.0.2", port: 8082 });
  assert.equal(res.status, 200);
  assert.equal(res.body?.name, "Node Updated");
  assert.equal(res.body?.port, 8082);
});

test("admins route: GET /api/admins returns admin list", async (t) => {
  const app = createApp();
  const originalFindMany = prisma.admin.findMany;
  prisma.admin.findMany = async () => [{ id: "a1", username: "admin", isActive: true }];
  t.after(() => {
    prisma.admin.findMany = originalFindMany;
  });

  const res = await request(app).get("/api/admins").set(authHeader());
  assert.equal(res.status, 200);
  assert.equal(Array.isArray(res.body), true);
  assert.equal(res.body[0]?.username, "admin");
});

test("admins route: POST /api/admins validates required fields", async () => {
  const app = createApp();
  const res = await request(app).post("/api/admins").set(authHeader()).send({ username: "admin" });
  assert.equal(res.status, 400);
  assert.equal(res.body?.error, "ФИО обязательно");
});

test("admins route: POST /api/admins returns 409 when admin exists", async (t) => {
  const app = createApp();
  const originalFindUnique = prisma.admin.findUnique;
  prisma.admin.findUnique = async () => ({ id: "a1", username: "admin" });
  t.after(() => {
    prisma.admin.findUnique = originalFindUnique;
  });

  const res = await request(app)
    .post("/api/admins")
    .set(authHeader())
    .send({ fullName: "Иван Иванов", username: "admin", email: "admin@example.com" });
  assert.equal(res.status, 409);
  assert.equal(res.body?.error, "Администратор с таким аккаунтом уже есть");
});

test("clients route: GET /api/clients returns sessions with node names and traffic", async (t) => {
  const app = createApp();
  const originalNodeFindMany = prisma.agentNode.findMany;
  const originalAssignFindMany = prisma.clientIpAssignment.findMany;
  const originalTrafficFindMany = prisma.clientTrafficSample.findMany;
  prisma.agentNode.findMany = async () => [{ id: "n1", name: "Node 1" }];
  prisma.clientIpAssignment.findMany = async () => [{
    agentNodeId: "n1",
    sessionId: "s1",
    commonName: "user1",
    realIp: "198.51.100.1",
    virtualIp: "10.220.0.10",
    connectedAt: new Date().toISOString(),
    lastSeenAt: new Date().toISOString(),
  }];
  prisma.clientTrafficSample.findMany = async () => [{
    agentNodeId: "n1",
    sessionId: "s1",
    sampledAt: new Date().toISOString(),
    inBps: 100,
    outBps: 200,
  }];
  t.after(() => {
    prisma.agentNode.findMany = originalNodeFindMany;
    prisma.clientIpAssignment.findMany = originalAssignFindMany;
    prisma.clientTrafficSample.findMany = originalTrafficFindMany;
  });

  const res = await request(app).get("/api/clients").set(authHeader());
  assert.equal(res.status, 200);
  assert.equal(Array.isArray(res.body), true);
  assert.equal(res.body[0]?.nodeName, "Node 1");
  assert.equal(res.body[0]?.inBps, 100);
  assert.equal(res.body[0]?.outBps, 200);
});

test("monitoring route: GET /api/monitoring/overview aggregates metrics", async (t) => {
  const app = createApp();
  const originalNodeFindMany = prisma.agentNode.findMany;
  const originalSnapFindMany = prisma.agentMetricSnapshot.findMany;
  prisma.agentNode.findMany = async () => [
    { id: "n1", cpuPercent: 50, memoryPercent: 30, activeClients: 2, networkInBps: 1000, networkOutBps: 2000 },
    { id: "n2", cpuPercent: 70, memoryPercent: 50, activeClients: 3, networkInBps: 1500, networkOutBps: 2500 },
  ];
  prisma.agentMetricSnapshot.findMany = async () => [];
  t.after(() => {
    prisma.agentNode.findMany = originalNodeFindMany;
    prisma.agentMetricSnapshot.findMany = originalSnapFindMany;
  });

  const res = await request(app).get("/api/monitoring/overview").set(authHeader());
  assert.equal(res.status, 200);
  assert.equal(res.body?.totalServers, 2);
  assert.equal(res.body?.totalClients, 5);
  assert.equal(res.body?.avgCpuPercent, 60);
  assert.equal(res.body?.avgMemoryPercent, 40);
  assert.equal(res.body?.totalNetworkInBps, 2500);
  assert.equal(res.body?.totalNetworkOutBps, 4500);
});

test("admins route: PATCH /api/admins/:id updates isActive and password", async (t) => {
  const app = createApp();
  const originalUpdate = prisma.admin.update;
  prisma.admin.update = async ({ where, data }) => ({
    id: where.id,
    username: "admin",
    isActive: data.isActive ?? true,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  });
  t.after(() => {
    prisma.admin.update = originalUpdate;
  });

  const res = await request(app)
    .patch("/api/admins/a1")
    .set(authHeader())
    .send({ isActive: false, password: "new-secret" });
  assert.equal(res.status, 200);
  assert.equal(res.body?.id, "a1");
  assert.equal(res.body?.isActive, false);
});

test("clients route: GET /api/clients/history returns assignment history", async (t) => {
  const app = createApp();
  const originalFindMany = prisma.clientIpAssignment.findMany;
  const originalCertFindMany = prisma.certificate.findMany;
  prisma.clientIpAssignment.findMany = async () => [
    {
      id: "h1",
      sessionId: "s1",
      commonName: "user1",
      virtualIp: "10.220.0.10",
      agentNode: { id: "n1", name: "N1", host: "127.0.0.1", port: 9443 },
    },
  ];
  prisma.certificate.findMany = async () => [
    {
      commonName: "user1",
      vpnUserId: "u1",
      revokedAt: null,
      vpnUser: { id: "u1", fullName: "Тест Пользователь", email: "u@test" },
    },
  ];
  t.after(() => {
    prisma.clientIpAssignment.findMany = originalFindMany;
    prisma.certificate.findMany = originalCertFindMany;
  });

  const res = await request(app).get("/api/clients/history").set(authHeader());
  assert.equal(res.status, 200);
  assert.equal(Array.isArray(res.body), true);
  assert.equal(res.body[0]?.id, "h1");
  assert.equal(res.body[0]?.vpnUserId, "u1");
  assert.equal(res.body[0]?.vpnUserFullName, "Тест Пользователь");
});

test("clients route: GET /api/clients/source-history returns source IP history", async (t) => {
  const app = createApp();
  const originalFindMany = prisma.clientSourceIpHistory.findMany;
  const originalCertFindMany = prisma.certificate.findMany;
  prisma.clientSourceIpHistory.findMany = async () => [
    {
      id: "src1",
      commonName: "user1",
      realIp: "203.0.113.5",
      agentNode: { id: "n1", name: "N1", host: "127.0.0.1", port: 9443 },
    },
  ];
  prisma.certificate.findMany = async () => [];
  t.after(() => {
    prisma.clientSourceIpHistory.findMany = originalFindMany;
    prisma.certificate.findMany = originalCertFindMany;
  });

  const res = await request(app).get("/api/clients/source-history").set(authHeader());
  assert.equal(res.status, 200);
  assert.equal(Array.isArray(res.body), true);
  assert.equal(res.body[0]?.id, "src1");
  assert.equal(res.body[0]?.vpnUserId, null);
});

test("monitoring route: GET /api/monitoring/admin-actions respects limit and node filter", async (t) => {
  const app = createApp();
  const originalFindMany = prisma.adminActionLog.findMany;
  prisma.adminActionLog.findMany = async () => [
    { id: "log1", action: "agent.patch", targetType: "agent-node", targetId: "n1" },
  ];
  t.after(() => {
    prisma.adminActionLog.findMany = originalFindMany;
  });

  const res = await request(app).get("/api/monitoring/admin-actions?limit=10&nodeId=n1").set(authHeader());
  assert.equal(res.status, 200);
  assert.equal(Array.isArray(res.body), true);
  assert.equal(res.body[0]?.id, "log1");
});

test("openvpn-panel route: GET /api/panel/nodes/:id/openvpn-materials returns 404 for unknown node", async (t) => {
  const app = createApp();
  const originalFindUnique = prisma.agentNode.findUnique;
  prisma.agentNode.findUnique = async () => null;
  t.after(() => {
    prisma.agentNode.findUnique = originalFindUnique;
  });

  const res = await request(app).get("/api/panel/nodes/missing/openvpn-materials").set(authHeader());
  assert.equal(res.status, 404);
  assert.equal(res.body?.error, "Node not found");
});

test("openvpn-panel route: POST /api/panel/nodes/:id/openvpn-materials validates kind", async () => {
  const app = createApp();
  const res = await request(app)
    .post("/api/panel/nodes/n1/openvpn-materials")
    .set(authHeader())
    .send({ kind: "bad-kind", label: "x", pem: "BEGIN TEST" });
  assert.equal(res.status, 400);
  assert.match(String(res.body?.error || ""), /kind должен быть dh или tls_auth/);
});

test("openvpn-panel route: DELETE /api/panel/nodes/:id/openvpn-materials/:materialId returns 404 when missing", async (t) => {
  const app = createApp();
  const originalFindFirst = prisma.agentNodeOpenvpnMaterial.findFirst;
  prisma.agentNodeOpenvpnMaterial.findFirst = async () => null;
  t.after(() => {
    prisma.agentNodeOpenvpnMaterial.findFirst = originalFindFirst;
  });

  const res = await request(app)
    .delete("/api/panel/nodes/n1/openvpn-materials/missing-material")
    .set(authHeader());
  assert.equal(res.status, 404);
  assert.equal(res.body?.error, "Материал не найден");
});

test("openvpn-panel route: DELETE /api/panel/nodes/:id/server-certificate returns 400 on service error", async (t) => {
  const app = createApp();
  const originalNodeFindUnique = prisma.agentNode.findUnique;
  prisma.agentNode.findUnique = async () => null;
  t.after(() => {
    prisma.agentNode.findUnique = originalNodeFindUnique;
  });

  const res = await request(app).delete("/api/panel/nodes/missing/server-certificate").set(authHeader());
  assert.equal(res.status, 400);
  assert.equal(res.body?.error, "Узел не найден");
});

test("openvpn-panel route: GET /api/panel/nodes/:id/system-services returns 404 for unknown node", async (t) => {
  const app = createApp();
  const originalNodeFindUnique = prisma.agentNode.findUnique;
  prisma.agentNode.findUnique = async () => null;
  t.after(() => {
    prisma.agentNode.findUnique = originalNodeFindUnique;
  });

  const res = await request(app).get("/api/panel/nodes/missing/system-services").set(authHeader());
  assert.equal(res.status, 404);
  assert.equal(res.body?.error, "Узел не найден");
});

test("openvpn-panel route: POST /api/panel/nodes/:id/system-service-unit returns 404 for unknown node", async (t) => {
  const app = createApp();
  const originalNodeFindUnique = prisma.agentNode.findUnique;
  prisma.agentNode.findUnique = async () => null;
  t.after(() => {
    prisma.agentNode.findUnique = originalNodeFindUnique;
  });

  const res = await request(app)
    .post("/api/panel/nodes/missing/system-service-unit")
    .set(authHeader())
    .send({ unit: "dnsmasq.service", action: "start" });
  assert.equal(res.status, 404);
  assert.equal(res.body?.error, "Узел не найден");
});

test("openvpn-panel route: POST /api/panel/nodes/:id/system-service-unit returns 400 for invalid unit", async (t) => {
  const app = createApp();
  const originalNodeFindUnique = prisma.agentNode.findUnique;
  prisma.agentNode.findUnique = async () => ({
    id: "node-1",
    name: "test",
    host: "127.0.0.1",
    port: 9,
    protocol: "http",
    authToken: "x",
  });
  t.after(() => {
    prisma.agentNode.findUnique = originalNodeFindUnique;
  });

  const res = await request(app)
    .post("/api/panel/nodes/node-1/system-service-unit")
    .set(authHeader())
    .send({ unit: "bad;name.service", action: "start" });
  assert.equal(res.status, 400);
  assert.ok(String(res.body?.error || "").includes("unit"));
});

test("openvpn-panel route: GET /api/panel/nodes/:id/dnsmasq returns 404 for unknown node", async (t) => {
  const app = createApp();
  const originalNodeFindUnique = prisma.agentNode.findUnique;
  prisma.agentNode.findUnique = async () => null;
  t.after(() => {
    prisma.agentNode.findUnique = originalNodeFindUnique;
  });

  const res = await request(app).get("/api/panel/nodes/missing/dnsmasq").set(authHeader());
  assert.equal(res.status, 404);
  assert.equal(res.body?.error, "Узел не найден");
});

test("openvpn-panel route: POST /api/panel/nodes/:id/dnsmasq/apply-task returns 404 for unknown node", async (t) => {
  const app = createApp();
  const originalNodeFindUnique = prisma.agentNode.findUnique;
  prisma.agentNode.findUnique = async () => null;
  t.after(() => {
    prisma.agentNode.findUnique = originalNodeFindUnique;
  });

  const res = await request(app)
    .post("/api/panel/nodes/missing/dnsmasq/apply-task")
    .set(authHeader())
    .send({ config: "cache-size=100" });
  assert.equal(res.status, 404);
  assert.equal(res.body?.error, "Узел не найден");
});

test("clients route: POST /api/clients/:nodeId/:id/disconnect returns 502 on agent error", async (t) => {
  const app = createApp();
  const originalFindUnique = prisma.agentNode.findUnique;
  prisma.agentNode.findUnique = async () => null;
  t.after(() => {
    prisma.agentNode.findUnique = originalFindUnique;
  });

  const res = await request(app)
    .post("/api/clients/node-1/session-1/disconnect")
    .set(authHeader());
  assert.equal(res.status, 502);
  assert.match(String(res.body?.error || ""), /Failed to disconnect client:/);
});

test("agents route: DELETE /api/agent/nodes/:id returns 204", async (t) => {
  const app = createApp();
  const originalDelete = prisma.agentNode.delete;
  prisma.agentNode.delete = async () => ({ id: "n1" });
  t.after(() => {
    prisma.agentNode.delete = originalDelete;
  });

  const res = await request(app).delete("/api/agent/nodes/n1").set(authHeader());
  assert.equal(res.status, 204);
});

test("admins route: PATCH /api/admins/:id returns 500 on prisma error", async (t) => {
  const app = createApp();
  const originalUpdate = prisma.admin.update;
  prisma.admin.update = async () => {
    throw new Error("db failed");
  };
  t.after(() => {
    prisma.admin.update = originalUpdate;
  });

  const res = await request(app)
    .patch("/api/admins/a1")
    .set(authHeader())
    .send({ isActive: true });
  assert.equal(res.status, 500);
});
