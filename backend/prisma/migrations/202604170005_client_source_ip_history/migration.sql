CREATE TABLE "ClientSourceIpHistory" (
    "id" TEXT NOT NULL,
    "agentNodeId" TEXT NOT NULL,
    "sessionId" TEXT NOT NULL,
    "commonName" TEXT NOT NULL,
    "realIp" TEXT NOT NULL,
    "connectedAt" TEXT NOT NULL,
    "firstSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "ClientSourceIpHistory_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "ClientSourceIpHistory_agentNodeId_sessionId_realIp_key"
ON "ClientSourceIpHistory"("agentNodeId", "sessionId", "realIp");

CREATE INDEX "ClientSourceIpHistory_commonName_firstSeenAt_idx"
ON "ClientSourceIpHistory"("commonName", "firstSeenAt");

CREATE INDEX "ClientSourceIpHistory_realIp_firstSeenAt_idx"
ON "ClientSourceIpHistory"("realIp", "firstSeenAt");

ALTER TABLE "ClientSourceIpHistory"
ADD CONSTRAINT "ClientSourceIpHistory_agentNodeId_fkey"
FOREIGN KEY ("agentNodeId") REFERENCES "AgentNode"("id")
ON DELETE CASCADE ON UPDATE CASCADE;
