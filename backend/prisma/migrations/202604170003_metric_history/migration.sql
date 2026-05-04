CREATE TABLE "AgentMetricSnapshot" (
    "id" TEXT NOT NULL,
    "agentNodeId" TEXT NOT NULL,
    "cpuPercent" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "memoryPercent" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "diskPercent" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "networkInBps" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "networkOutBps" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "activeClients" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "AgentMetricSnapshot_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "AgentMetricSnapshot_agentNodeId_createdAt_idx"
ON "AgentMetricSnapshot"("agentNodeId", "createdAt");

ALTER TABLE "AgentMetricSnapshot"
ADD CONSTRAINT "AgentMetricSnapshot_agentNodeId_fkey"
FOREIGN KEY ("agentNodeId") REFERENCES "AgentNode"("id")
ON DELETE CASCADE ON UPDATE CASCADE;
