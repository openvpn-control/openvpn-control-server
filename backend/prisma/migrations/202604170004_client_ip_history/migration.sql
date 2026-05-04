CREATE TABLE "ClientIpAssignment" (
    "id" TEXT NOT NULL,
    "agentNodeId" TEXT NOT NULL,
    "sessionId" TEXT NOT NULL,
    "commonName" TEXT NOT NULL,
    "realIp" TEXT NOT NULL,
    "virtualIp" TEXT NOT NULL,
    "connectedAt" TEXT NOT NULL,
    "firstSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "ClientIpAssignment_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "ClientIpAssignment_agentNodeId_sessionId_key"
ON "ClientIpAssignment"("agentNodeId", "sessionId");

CREATE INDEX "ClientIpAssignment_commonName_firstSeenAt_idx"
ON "ClientIpAssignment"("commonName", "firstSeenAt");

CREATE INDEX "ClientIpAssignment_virtualIp_firstSeenAt_idx"
ON "ClientIpAssignment"("virtualIp", "firstSeenAt");

ALTER TABLE "ClientIpAssignment"
ADD CONSTRAINT "ClientIpAssignment_agentNodeId_fkey"
FOREIGN KEY ("agentNodeId") REFERENCES "AgentNode"("id")
ON DELETE CASCADE ON UPDATE CASCADE;
