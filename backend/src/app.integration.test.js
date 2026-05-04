import test from "node:test";
import assert from "node:assert/strict";
import request from "supertest";
import jwt from "jsonwebtoken";
import { createApp } from "./app.js";
import { config } from "./config.js";
import { prisma } from "./prisma.js";

const PROTECTED_PREFIXES = [
  "/api/agent",
  "/api/panel/nodes",
  "/api/tasks",
  "/api/admins",
  "/api/monitoring",
  "/api/certificates",
  "/api/clients",
  "/api/organizations",
  "/api/vpn-users",
];

test("GET /health returns ok", async () => {
  const app = createApp();
  const res = await request(app).get("/health");
  assert.equal(res.status, 200);
  assert.deepEqual(res.body, { status: "ok" });
});

test("health route includes CORS headers", async () => {
  const app = createApp();
  const res = await request(app).get("/health").set("Origin", "http://localhost:3000");
  assert.equal(res.status, 200);
  assert.ok(typeof res.headers["access-control-allow-origin"] === "string");
});

test("protected route without Bearer token returns 401 Unauthorized", async () => {
  const app = createApp();
  const res = await request(app).get("/api/tasks").set("Authorization", "Token abc");
  assert.equal(res.status, 401);
  assert.equal(res.body?.error, "Unauthorized");
});

test("protected route with invalid token returns 401 Invalid token", async () => {
  const app = createApp();
  const res = await request(app).get("/api/tasks").set("Authorization", "Bearer invalid.token.value");
  assert.equal(res.status, 401);
  assert.equal(res.body?.error, "Invalid token");
});

test("protected route with valid token passes auth middleware", async (t) => {
  const app = createApp();
  const original = prisma.panelAsyncTask.findMany;
  prisma.panelAsyncTask.findMany = async () => [];
  t.after(() => {
    prisma.panelAsyncTask.findMany = original;
  });
  const token = jwt.sign({ sub: "admin-1", username: "admin" }, config.jwtSecret, { expiresIn: "5m" });
  const res = await request(app).get("/api/tasks").set("Authorization", `Bearer ${token}`);
  assert.notEqual(res.status, 401);
});

test("all protected prefixes require auth token", async () => {
  const app = createApp();
  for (const prefix of PROTECTED_PREFIXES) {
    const res = await request(app).get(prefix);
    assert.equal(res.status, 401, `expected 401 for ${prefix}`);
    assert.equal(res.body?.error, "Unauthorized");
  }
});

test("valid token reaches router layer and returns 404 for unknown protected path", async () => {
  const app = createApp();
  const token = jwt.sign({ sub: "admin-1" }, config.jwtSecret, { expiresIn: "5m" });
  const res = await request(app)
    .get("/api/tasks/this-route-does-not-exist")
    .set("Authorization", `Bearer ${token}`);
  assert.equal(res.status, 404);
});
