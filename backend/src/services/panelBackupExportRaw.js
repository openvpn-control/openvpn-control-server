/**
 * Экспорт таблиц через $queryRawUnsafe: NUL в TEXT/JSONB в PostgreSQL запрещён — Prisma findMany падает до JS.
 * @param {import("@prisma/client").PrismaClient} prisma
 */

/** C0 (кроме NUL/tab/LF/CR): ломают передачу строк в JS через Prisma/libpq. NUL не трогаем в SQL: CHR(0) в PostgreSQL недопустим. */
const C0_STRIP_CODEPOINTS = [1, 2, 3, 4, 5, 6, 7, 8, 11, 12, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31];

/** @param {string} colExpr — выражение SQL */
function pgStripC0Controls(colExpr) {
  let out = colExpr;
  for (const c of C0_STRIP_CODEPOINTS) {
    out = `replace(${out}, CHR(${c}), '')`;
  }
  return out;
}

/** обязательный TEXT — очистка перед отдачей в клиент */
function Z(col) {
  return pgStripC0Controls(col);
}
/** nullable TEXT */
function ZN(col) {
  return `CASE WHEN ${col} IS NULL THEN NULL ELSE ${pgStripC0Controls(col)} END`;
}
/** nullable JSONB: снимаем C0 с текстового представления, затем обратно в jsonb */
function ZJ(col) {
  return `CASE WHEN ${col} IS NULL THEN NULL ELSE (${pgStripC0Controls(`${col}::text`)})::jsonb END`;
}

async function exportOpenvpnServerLogsSafe(prisma) {
  const strip = pgStripC0Controls;
  try {
    return await prisma.$queryRawUnsafe(`
      SELECT
        o.id,
        o."agentNodeId",
        o."occurredAt",
        CASE
          WHEN o."occurredRaw" IS NULL THEN NULL
          ELSE NULLIF(${strip('o."occurredRaw"')}, '')
        END AS "occurredRaw",
        COALESCE(NULLIF(${strip("o.event")}, ''), '(empty)') AS event,
        CASE
          WHEN o."username" IS NULL THEN NULL
          ELSE NULLIF(${strip('o."username"')}, '')
        END AS username,
        CASE
          WHEN o."ipAddress" IS NULL THEN NULL
          ELSE NULLIF(${strip('o."ipAddress"')}, '')
        END AS "ipAddress",
        COALESCE(NULLIF(${strip('o."rawLine"')}, ''), '.') AS "rawLine",
        COALESCE(NULLIF(${strip("o.fingerprint")}, ''), o.id) AS fingerprint,
        o."createdAt"
      FROM "OpenvpnServerLog" o
    `);
  } catch (e) {
    console.warn("[panel-backup] OpenvpnServerLog export skipped:", e?.message || e);
    return [];
  }
}

/**
 * @param {import("@prisma/client").PrismaClient} prisma
 * @returns {Promise<Record<string, unknown[]>>}
 */
export async function exportAllTablesJsonFromRawQueries(prisma) {
  const [
    organizations,
    admins,
    rootCertificateAuthorities,
    agentNodes,
    vpnUsers,
    certificates,
    agentNodeOpenvpnSettings,
    agentNodeOpenvpnConfigVersions,
    agentNodeOpenvpnMaterials,
    clientIpAssignments,
    clientSourceIpHistories,
    clientTrafficSamples,
    agentMetricSnapshots,
    openvpnServerLogs,
    panelAsyncTasks,
    adminActionLogs,
    panelAppBackupSettings,
    adminTotpRecoveryCodes,
  ] = await Promise.all([
    prisma.$queryRawUnsafe(`
      SELECT
        o.id,
        ${Z("o.name")} AS name,
        ${ZN("o.inn")} AS inn,
        ${ZN('o."legalAddress"')} AS "legalAddress",
        ${ZN('o."generalDirector"')} AS "generalDirector",
        ${ZN("o.phone")} AS phone,
        ${ZN("o.email")} AS email,
        ${ZJ('o."firewallRules"')} AS "firewallRules",
        o."createdAt",
        o."updatedAt"
      FROM "Organization" o
    `),
    prisma.$queryRawUnsafe(`
      SELECT
        a.id,
        ${Z('a."fullName"')} AS "fullName",
        ${Z("a.username")} AS username,
        ${ZN("a.email")} AS email,
        ${Z('a."passwordHash"')} AS "passwordHash",
        a."isActive",
        ${ZN('a."inviteToken"')} AS "inviteToken",
        a."inviteExpiresAt",
        ${ZN('a."passwordResetToken"')} AS "passwordResetToken",
        a."passwordResetExpiresAt",
        a."totpEnabled",
        ${ZN('a."totpSecretEnc"')} AS "totpSecretEnc",
        ${ZN('a."totpPendingSecretEnc"')} AS "totpPendingSecretEnc",
        a."totpPendingExpiresAt",
        a."createdAt",
        a."updatedAt"
      FROM "Admin" a
    `),
    prisma.$queryRawUnsafe(`
      SELECT
        r.id,
        ${Z("r.name")} AS name,
        ${Z('r."commonName"')} AS "commonName",
        ${Z('r."certPem"')} AS "certPem",
        ${Z('r."keyPem"')} AS "keyPem",
        r."isActive",
        r."createdAt",
        r."updatedAt"
      FROM "RootCertificateAuthority" r
    `),
    prisma.$queryRawUnsafe(`
      SELECT
        n.id,
        ${Z("n.name")} AS name,
        ${Z("n.protocol")} AS protocol,
        ${Z("n.host")} AS host,
        n.port,
        ${Z('n."authToken"')} AS "authToken",
        ${ZN('n."agentVersion"')} AS "agentVersion",
        ${Z("n.status")} AS status,
        n."cpuPercent",
        n."memoryPercent",
        n."diskPercent",
        n."diskReadBps",
        n."diskWriteBps",
        n."networkInBps",
        n."networkOutBps",
        n."activeClients",
        n."lastSeenAt",
        ${ZN('n."openvpnBinaryPath"')} AS "openvpnBinaryPath",
        ${ZN('n."openvpnVersion"')} AS "openvpnVersion",
        ${ZN('n."openvpnBuild"')} AS "openvpnBuild",
        ${ZN('n."openvpnConfigPath"')} AS "openvpnConfigPath",
        ${ZN('n."openvpnServerLogPath"')} AS "openvpnServerLogPath",
        ${ZN('n."openvpnManagementAddr"')} AS "openvpnManagementAddr",
        n."openvpnRunning",
        ${ZN('n."openvpnServiceUnit"')} AS "openvpnServiceUnit",
        ${ZN('n."openvpnServiceActiveState"')} AS "openvpnServiceActiveState",
        ${ZN('n."openvpnServiceSubState"')} AS "openvpnServiceSubState",
        n."openvpnServiceMainPid",
        ${ZN('n."openvpnServiceActiveSince"')} AS "openvpnServiceActiveSince",
        ${ZJ('n."openvpnServiceRecentLogs"')} AS "openvpnServiceRecentLogs",
        n."openvpnLogsEnabled",
        ${ZN('n."openvpnLogsNote"')} AS "openvpnLogsNote",
        n."openvpnInfoSeenAt",
        ${ZN('n."openvpnInfoError"')} AS "openvpnInfoError",
        n."createdAt",
        n."updatedAt"
      FROM "AgentNode" n
    `),
    prisma.$queryRawUnsafe(`
      SELECT
        u.id,
        ${Z('u."fullName"')} AS "fullName",
        ${ZN("u.position")} AS position,
        ${Z("u.email")} AS email,
        ${ZN("u.phone")} AS phone,
        ${ZN('u."organizationId"')} AS "organizationId",
        ${ZN("u.notes")} AS notes,
        ${ZJ('u."firewallRules"')} AS "firewallRules",
        ${ZJ('u."ccdSettings"')} AS "ccdSettings",
        u."lastVpnActivityAt",
        u."createdAt",
        u."updatedAt"
      FROM "VpnUser" u
    `),
    prisma.$queryRawUnsafe(`
      SELECT
        c.id,
        ${Z('c."commonName"')} AS "commonName",
        ${Z('c."serialNumber"')} AS "serialNumber",
        ${Z('c."issuedBy"')} AS "issuedBy",
        ${ZN('c."rootCaId"')} AS "rootCaId",
        ${ZN('c."agentNodeId"')} AS "agentNodeId",
        ${ZN('c."vpnUserId"')} AS "vpnUserId",
        ${ZN('c."certPem"')} AS "certPem",
        ${ZN('c."keyPem"')} AS "keyPem",
        c."expiresAt",
        c."createdAt",
        c."revokedAt",
        ${ZN('c."revokedReason"')} AS "revokedReason"
      FROM "Certificate" c
    `),
    prisma.$queryRawUnsafe(`
      SELECT
        s.id,
        ${Z('s."agentNodeId"')} AS "agentNodeId",
        ${ZJ("s.settings")} AS settings,
        ${ZN('s."configPath"')} AS "configPath",
        s."createdAt",
        s."updatedAt"
      FROM "AgentNodeOpenvpnSettings" s
    `),
    prisma.$queryRawUnsafe(`
      SELECT
        v.id,
        ${Z('v."agentNodeId"')} AS "agentNodeId",
        v.version,
        ${ZJ("v.settings")} AS settings,
        ${Z("v.checksum")} AS checksum,
        v."appliedAt",
        v."createdAt"
      FROM "AgentNodeOpenvpnConfigVersion" v
    `),
    prisma.$queryRawUnsafe(`
      SELECT
        m.id,
        ${Z('m."agentNodeId"')} AS "agentNodeId",
        ${Z("m.kind")} AS kind,
        ${ZN("m.label")} AS label,
        ${Z("m.pem")} AS pem,
        m."createdAt"
      FROM "AgentNodeOpenvpnMaterial" m
    `),
    prisma.$queryRawUnsafe(`
      SELECT
        i.id,
        ${Z('i."agentNodeId"')} AS "agentNodeId",
        ${Z('i."sessionId"')} AS "sessionId",
        ${Z('i."commonName"')} AS "commonName",
        ${Z('i."realIp"')} AS "realIp",
        ${Z('i."virtualIp"')} AS "virtualIp",
        ${Z('i."connectedAt"')} AS "connectedAt",
        i."firstSeenAt",
        i."lastSeenAt",
        i."endedAt"
      FROM "ClientIpAssignment" i
    `),
    prisma.$queryRawUnsafe(`
      SELECT
        h.id,
        ${Z('h."agentNodeId"')} AS "agentNodeId",
        ${Z('h."sessionId"')} AS "sessionId",
        ${Z('h."commonName"')} AS "commonName",
        ${Z('h."realIp"')} AS "realIp",
        ${Z('h."connectedAt"')} AS "connectedAt",
        h."firstSeenAt",
        h."lastSeenAt",
        h."endedAt",
        h."durationSeconds"
      FROM "ClientSourceIpHistory" h
    `),
    prisma.$queryRawUnsafe(`
      SELECT
        t.id,
        ${Z('t."agentNodeId"')} AS "agentNodeId",
        ${Z('t."sessionId"')} AS "sessionId",
        ${Z('t."commonName"')} AS "commonName",
        ${Z('t."virtualIp"')} AS "virtualIp",
        ${Z('t."realIp"')} AS "realIp",
        t."rxBytes",
        t."txBytes",
        t."inBps",
        t."outBps",
        t."sampledAt"
      FROM "ClientTrafficSample" t
    `),
    prisma.$queryRawUnsafe(`
      SELECT
        m.id,
        ${Z('m."agentNodeId"')} AS "agentNodeId",
        m."cpuPercent",
        m."memoryPercent",
        m."diskPercent",
        m."diskReadBps",
        m."diskWriteBps",
        m."networkInBps",
        m."networkOutBps",
        m."activeClients",
        m."createdAt"
      FROM "AgentMetricSnapshot" m
    `),
    exportOpenvpnServerLogsSafe(prisma),
    prisma.$queryRawUnsafe(`
      SELECT
        t.id,
        ${Z("t.type")} AS type,
        ${Z("t.status")} AS status,
        ${Z('t."agentNodeId"')} AS "agentNodeId",
        ${ZJ("t.payload")} AS payload,
        ${ZN('t."lastError"')} AS "lastError",
        t."createdAt",
        t."updatedAt",
        t."completedAt"
      FROM "PanelAsyncTask" t
    `),
    prisma.$queryRawUnsafe(`
      SELECT
        l.id,
        ${Z('l."adminId"')} AS "adminId",
        ${Z('l."adminUsername"')} AS "adminUsername",
        ${Z("l.method")} AS method,
        ${Z("l.path")} AS path,
        ${Z("l.action")} AS action,
        ${ZN('l."targetType"')} AS "targetType",
        ${ZN('l."targetId"')} AS "targetId",
        ${ZN('l."ipAddress"')} AS "ipAddress",
        ${ZN('l."userAgent"')} AS "userAgent",
        l."statusCode",
        ${ZJ("l.details")} AS details,
        l."createdAt"
      FROM "AdminActionLog" l
    `),
    prisma.$queryRawUnsafe(`
      SELECT
        s.id,
        s."intervalMinutes",
        s."retainCount",
        s."lastScheduledAt",
        s."updatedAt"
      FROM "PanelAppBackupSettings" s
    `),
    prisma.$queryRawUnsafe(`
      SELECT
        r.id,
        ${Z('r."adminId"')} AS "adminId",
        ${Z('r."codeHash"')} AS "codeHash",
        r."createdAt",
        r."usedAt"
      FROM "AdminTotpRecoveryCode" r
    `),
  ]);

  return {
    Organization: organizations,
    Admin: admins,
    RootCertificateAuthority: rootCertificateAuthorities,
    AgentNode: agentNodes,
    VpnUser: vpnUsers,
    Certificate: certificates,
    AgentNodeOpenvpnSettings: agentNodeOpenvpnSettings,
    AgentNodeOpenvpnConfigVersion: agentNodeOpenvpnConfigVersions,
    AgentNodeOpenvpnMaterial: agentNodeOpenvpnMaterials,
    ClientIpAssignment: clientIpAssignments,
    ClientSourceIpHistory: clientSourceIpHistories,
    ClientTrafficSample: clientTrafficSamples,
    AgentMetricSnapshot: agentMetricSnapshots,
    OpenvpnServerLog: openvpnServerLogs,
    PanelAsyncTask: panelAsyncTasks,
    AdminActionLog: adminActionLogs,
    PanelAppBackupSettings: panelAppBackupSettings,
    AdminTotpRecoveryCode: adminTotpRecoveryCodes,
  };
}
