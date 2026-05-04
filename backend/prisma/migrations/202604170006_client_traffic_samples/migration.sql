CREATE TABLE "ClientTrafficSample" (
    "id" TEXT NOT NULL,
    "agentNodeId" TEXT NOT NULL,
    "sessionId" TEXT NOT NULL,
    "commonName" TEXT NOT NULL,
    "virtualIp" TEXT NOT NULL,
    "realIp" TEXT NOT NULL,
    "rxBytes" BIGINT NOT NULL,
    "txBytes" BIGINT NOT NULL,
    "inBps" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "outBps" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "sampledAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "ClientTrafficSample_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "ClientTrafficSample_agentNodeId_sessionId_sampledAt_idx"
ON "ClientTrafficSample"("agentNodeId", "sessionId", "sampledAt");

CREATE INDEX "ClientTrafficSample_commonName_sampledAt_idx"
ON "ClientTrafficSample"("commonName", "sampledAt");

ALTER TABLE "ClientTrafficSample"
ADD CONSTRAINT "ClientTrafficSample_agentNodeId_fkey"
FOREIGN KEY ("agentNodeId") REFERENCES "AgentNode"("id")
ON DELETE CASCADE ON UPDATE CASCADE;
