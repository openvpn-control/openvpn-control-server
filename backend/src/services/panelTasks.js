import { prisma } from "../prisma.js";
import { generateCrlPem } from "./crlService.js";
import {
  postAgentDnsmasq,
  postAgentOpenVPNServiceAction,
  postAgentPanelSnapshot,
  postAgentWriteOpenvpnFile,
} from "./agentChannel.js";
import { firstTlsAuthPath } from "./openvpnPemGenerators.js";
const TASK_CRL_DEPLOY = "crl_deploy";
const TASK_OPENVPN_CA_SYNC = "openvpn_ca_sync";
const TASK_OPENVPN_SERVER_CERT_SYNC = "openvpn_server_cert_sync";
const TASK_OPENVPN_DH_SYNC = "openvpn_dh_sync";
const TASK_OPENVPN_TLS_AUTH_SYNC = "openvpn_tls_auth_sync";
const TASK_OPENVPN_SERVICE_RESTART = "openvpn_service_restart";
const TASK_PANEL_AGENT_SNAPSHOT = "panel_agent_snapshot";
const TASK_DNSMASQ_APPLY = "dnsmasq_apply";

/**
 * Доставить на узел актуальный снимок (CCD, пер-пользовательский firewall, туннель).
 * Одна pending-задача на узел (upsert).
 */
export async function enqueuePanelAgentSnapshotForNode(agentNodeId) {
  const id = String(agentNodeId || "").trim();
  if (!id) return;
  await upsertPendingTask(id, TASK_PANEL_AGENT_SNAPSHOT, { source: "node" });
}

export async function enqueuePanelAgentSnapshotForVpnUser(vpnUserId) {
  const uid = String(vpnUserId || "").trim();
  if (!uid) return;
  const rows = await prisma.certificate.findMany({
    where: { vpnUserId: uid, agentNodeId: { not: null }, revokedAt: null },
    select: { agentNodeId: true },
  });
  const nodeIds = [...new Set(rows.map((r) => r.agentNodeId).filter(Boolean))];
  for (const nid of nodeIds) {
    await enqueuePanelAgentSnapshotForNode(nid);
  }
}

/**
 * После отзыва сертификата — поставить доставку CRL на узлы, у которых в настройках указан этот корневой
 * сертификат и путь crl-verify.
 */
export async function enqueueCrlDeployTasksForRootCa(rootCaId) {
  if (!rootCaId) return;

  const rows = await prisma.agentNodeOpenvpnSettings.findMany({
    where: {
      settings: {
        path: ["panelRootCaId"],
        equals: rootCaId,
      },
    },
    select: { agentNodeId: true, settings: true },
  });

  for (const row of rows) {
    const st = row.settings && typeof row.settings === "object" ? row.settings : {};
    const crlPath = String(st["crl-verify"] || "").trim();
    if (!crlPath) continue;

    await prisma.panelAsyncTask.deleteMany({
      where: {
        type: TASK_CRL_DEPLOY,
        status: "pending",
        agentNodeId: row.agentNodeId,
        payload: {
          path: ["rootCaId"],
          equals: rootCaId,
        },
      },
    });

    await prisma.panelAsyncTask.create({
      data: {
        type: TASK_CRL_DEPLOY,
        status: "pending",
        agentNodeId: row.agentNodeId,
        payload: { rootCaId, remotePath: crlPath },
      },
    });
  }
}

async function upsertPendingTask(agentNodeId, type, payload) {
  await prisma.panelAsyncTask.deleteMany({
    where: {
      type,
      status: "pending",
      agentNodeId,
    },
  });
  await prisma.panelAsyncTask.create({
    data: {
      type,
      status: "pending",
      agentNodeId,
      payload,
    },
  });
}

async function enqueueOpenvpnServiceRestartTask(agentNodeId, reason) {
  await upsertPendingTask(agentNodeId, TASK_OPENVPN_SERVICE_RESTART, {
    reason: String(reason || "material_sync"),
  });
}

/**
 * Применить конфигурацию DNSMasq на узле (выполняется при следующей синхронизации с агентом).
 * Одна ожидающая задача на узел — при повторном вызове подставляется актуальный конфиг.
 */
export async function enqueueDnsmasqApplyTask(agentNodeId, config) {
  const id = String(agentNodeId || "").trim();
  if (!id) return;
  const cfg = String(config ?? "");
  await upsertPendingTask(id, TASK_DNSMASQ_APPLY, { config: cfg });
}

export async function enqueueOpenvpnMaterialSyncTasks(node, settings) {
  if (!node?.id || !settings || typeof settings !== "object" || Array.isArray(settings)) return;
  const rootId = String(settings.panelRootCaId || "").trim();
  const caPath = String(settings.ca || "").trim();
  const crlPath = String(settings["crl-verify"] || "").trim();
  if (rootId && caPath) {
    await upsertPendingTask(node.id, TASK_OPENVPN_CA_SYNC, { rootCaId: rootId, remotePath: caPath });
  }
  if (rootId && crlPath) {
    await upsertPendingTask(node.id, TASK_CRL_DEPLOY, { rootCaId: rootId, remotePath: crlPath });
  }

  const certId = String(settings.panelServerCertId || "").trim();
  const certPath = String(settings.cert || "").trim();
  const keyPath = String(settings.key || "").trim();
  if (certId && certPath && keyPath) {
    await upsertPendingTask(node.id, TASK_OPENVPN_SERVER_CERT_SYNC, {
      certId,
      certPath,
      keyPath,
    });
  }

  const dhMatId = String(settings.panelDhMaterialId || "").trim();
  const dhPath = String(settings.dh || "").trim();
  if (dhMatId && dhPath) {
    await upsertPendingTask(node.id, TASK_OPENVPN_DH_SYNC, { materialId: dhMatId, remotePath: dhPath });
  }

  const tlsMatId = String(settings.panelTlsAuthMaterialId || "").trim();
  const tlsPath = firstTlsAuthPath(settings["tls-auth"]);
  if (tlsMatId && tlsPath) {
    await upsertPendingTask(node.id, TASK_OPENVPN_TLS_AUTH_SYNC, { materialId: tlsMatId, remotePath: tlsPath });
  }
}

async function claimPendingTask(agentNodeId) {
  return prisma.$transaction(async (tx) => {
    const next = await tx.panelAsyncTask.findFirst({
      where: { agentNodeId, status: "pending" },
      orderBy: { createdAt: "asc" },
    });
    if (!next) return null;
    const u = await tx.panelAsyncTask.updateMany({
      where: { id: next.id, status: "pending" },
      data: { status: "processing", lastError: null },
    });
    if (u.count === 0) return null;
    return tx.panelAsyncTask.findUnique({ where: { id: next.id } });
  });
}

async function completeTask(id, errMsg) {
  const now = new Date();
  if (errMsg) {
    await prisma.panelAsyncTask.update({
      where: { id },
      data: { status: "failed", lastError: errMsg, completedAt: now },
    });
  } else {
    await prisma.panelAsyncTask.update({
      where: { id },
      data: { status: "completed", lastError: null, completedAt: now },
    });
  }
}

async function executeTask(task, node) {
  try {
    if (task.type === TASK_CRL_DEPLOY) {
      const payload = task.payload && typeof task.payload === "object" ? task.payload : {};
      const rootCaId = payload.rootCaId;
      const remotePath = String(payload.remotePath || "").trim();
      if (!rootCaId || !remotePath) {
        await completeTask(task.id, "Некорректный payload задачи CRL");
        return;
      }
      const rootCa = await prisma.rootCertificateAuthority.findUnique({
        where: { id: rootCaId },
      });
      if (!rootCa) {
        await completeTask(task.id, "Корневой сертификат не найден");
        return;
      }
      const revoked = await prisma.certificate.findMany({
        where: { rootCaId, revokedAt: { not: null } },
        select: { serialNumber: true, commonName: true, expiresAt: true, revokedAt: true },
      });
      const pem = generateCrlPem(
        { certPem: rootCa.certPem, keyPem: rootCa.keyPem },
        revoked,
      );
      await postAgentWriteOpenvpnFile(node, remotePath, Buffer.from(pem, "utf8"));
      await completeTask(task.id, null);
      return;
    }
    if (task.type === TASK_OPENVPN_CA_SYNC) {
      const payload = task.payload && typeof task.payload === "object" ? task.payload : {};
      const rootCaId = String(payload.rootCaId || "").trim();
      const remotePath = String(payload.remotePath || "").trim();
      if (!rootCaId || !remotePath) {
        await completeTask(task.id, "Некорректный payload задачи синхронизации корневого сертификата");
        return;
      }
      const rootCa = await prisma.rootCertificateAuthority.findUnique({ where: { id: rootCaId } });
      if (!rootCa?.certPem) {
        await completeTask(task.id, "Корневой сертификат не найден или без certPem");
        return;
      }
      await postAgentWriteOpenvpnFile(node, remotePath, Buffer.from(rootCa.certPem, "utf8"));
      await completeTask(task.id, null);
      await enqueueOpenvpnServiceRestartTask(node.id, TASK_OPENVPN_CA_SYNC);
      return;
    }
    if (task.type === TASK_OPENVPN_SERVER_CERT_SYNC) {
      const payload = task.payload && typeof task.payload === "object" ? task.payload : {};
      const certId = String(payload.certId || "").trim();
      const certPath = String(payload.certPath || "").trim();
      const keyPath = String(payload.keyPath || "").trim();
      if (!certId || !certPath || !keyPath) {
        await completeTask(task.id, "Некорректный payload задачи sync cert/key");
        return;
      }
      const certRow = await prisma.certificate.findUnique({
        where: { id: certId },
        select: { certPem: true, keyPem: true, agentNodeId: true },
      });
      if (!certRow?.certPem || !certRow?.keyPem) {
        await completeTask(task.id, "Сертификат не найден или без PEM/key");
        return;
      }
      if (certRow.agentNodeId && certRow.agentNodeId !== node.id) {
        await completeTask(task.id, "Выбранный сертификат привязан к другому узлу");
        return;
      }
      await postAgentWriteOpenvpnFile(node, certPath, Buffer.from(certRow.certPem, "utf8"));
      await postAgentWriteOpenvpnFile(node, keyPath, Buffer.from(certRow.keyPem, "utf8"));
      await completeTask(task.id, null);
      await enqueueOpenvpnServiceRestartTask(node.id, TASK_OPENVPN_SERVER_CERT_SYNC);
      return;
    }
    if (task.type === TASK_OPENVPN_DH_SYNC) {
      const payload = task.payload && typeof task.payload === "object" ? task.payload : {};
      const materialId = String(payload.materialId || "").trim();
      const remotePath = String(payload.remotePath || "").trim();
      if (!materialId || !remotePath) {
        await completeTask(task.id, "Некорректный payload задачи sync DH");
        return;
      }
      const mat = await prisma.agentNodeOpenvpnMaterial.findFirst({
        where: { id: materialId, agentNodeId: node.id, kind: "dh" },
      });
      if (!mat?.pem) {
        await completeTask(task.id, "Материал DH не найден");
        return;
      }
      await postAgentWriteOpenvpnFile(node, remotePath, Buffer.from(mat.pem, "utf8"));
      await completeTask(task.id, null);
      await enqueueOpenvpnServiceRestartTask(node.id, TASK_OPENVPN_DH_SYNC);
      return;
    }
    if (task.type === TASK_OPENVPN_TLS_AUTH_SYNC) {
      const payload = task.payload && typeof task.payload === "object" ? task.payload : {};
      const materialId = String(payload.materialId || "").trim();
      const remotePath = String(payload.remotePath || "").trim();
      if (!materialId || !remotePath) {
        await completeTask(task.id, "Некорректный payload задачи sync TLS-auth");
        return;
      }
      const mat = await prisma.agentNodeOpenvpnMaterial.findFirst({
        where: { id: materialId, agentNodeId: node.id, kind: "tls_auth" },
      });
      if (!mat?.pem) {
        await completeTask(task.id, "Материал TLS-auth не найден");
        return;
      }
      await postAgentWriteOpenvpnFile(node, remotePath, Buffer.from(mat.pem, "utf8"));
      await completeTask(task.id, null);
      await enqueueOpenvpnServiceRestartTask(node.id, TASK_OPENVPN_TLS_AUTH_SYNC);
      return;
    }
    if (task.type === TASK_OPENVPN_SERVICE_RESTART) {
      await postAgentOpenVPNServiceAction(node, "restart");
      await completeTask(task.id, null);
      return;
    }
    if (task.type === TASK_PANEL_AGENT_SNAPSHOT) {
      const { buildAgentSnapshotForNode } = await import("./agentSnapshot.js");
      const snap = await buildAgentSnapshotForNode(node.id);
      if (!snap) {
        await completeTask(task.id, "Не удалось собрать снимок (нет настроек OpenVPN на панели для узла?)");
        return;
      }
      await postAgentPanelSnapshot(node, snap);
      await completeTask(task.id, null);
      return;
    }
    if (task.type === TASK_DNSMASQ_APPLY) {
      const payload = task.payload && typeof task.payload === "object" ? task.payload : {};
      const config = String(payload.config ?? "");
      await postAgentDnsmasq(node, { action: "apply", config });
      await completeTask(task.id, null);
      return;
    }
    await completeTask(task.id, `Неизвестный тип задачи: ${task.type}`);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    await completeTask(task.id, msg);
  }
}

/**
 * Выполнить очередь задач для узла (после успешного опроса метрик).
 */
export async function processPendingTasksForNode(node, maxTasks = 20) {
  for (let i = 0; i < maxTasks; i++) {
    const task = await claimPendingTask(node.id);
    if (!task) return;
    await executeTask(task, node);
  }
}

export async function listPanelTasks(limit = 200) {
  return prisma.panelAsyncTask.findMany({
    orderBy: { createdAt: "desc" },
    take: Math.min(500, Math.max(1, limit)),
    include: { agentNode: { select: { id: true, name: true } } },
  });
}

export async function retryPanelTask(taskId) {
  const id = String(taskId || "").trim();
  if (!id) return null;
  const task = await prisma.panelAsyncTask.findUnique({ where: { id } });
  if (!task) return null;
  if (task.status === "processing") {
    return { error: "Задача уже выполняется." };
  }
  const updated = await prisma.panelAsyncTask.update({
    where: { id },
    data: {
      status: "pending",
      lastError: null,
      completedAt: null,
    },
    include: { agentNode: { select: { id: true, name: true } } },
  });
  return { task: updated };
}
