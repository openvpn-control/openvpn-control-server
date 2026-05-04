CREATE TABLE "AgentNodeOpenvpnClientConfigVersion" (
  "id" TEXT NOT NULL,
  "agentNodeId" TEXT NOT NULL,
  "version" INTEGER NOT NULL,
  "settings" JSONB NOT NULL,
  "checksum" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "AgentNodeOpenvpnClientConfigVersion_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "AgentNodeOpenvpnClientConfigVersion_agentNodeId_version_key"
  ON "AgentNodeOpenvpnClientConfigVersion"("agentNodeId", "version");

CREATE INDEX "AgentNodeOpenvpnClientConfigVersion_agentNodeId_createdAt_idx"
  ON "AgentNodeOpenvpnClientConfigVersion"("agentNodeId", "createdAt");

ALTER TABLE "AgentNodeOpenvpnClientConfigVersion"
  ADD CONSTRAINT "AgentNodeOpenvpnClientConfigVersion_agentNodeId_fkey"
  FOREIGN KEY ("agentNodeId") REFERENCES "AgentNode"("id") ON DELETE CASCADE ON UPDATE CASCADE;
