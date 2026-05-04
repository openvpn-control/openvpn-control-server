-- CreateTable
CREATE TABLE "AgentNodeOpenvpnSettings" (
    "id" TEXT NOT NULL,
    "agentNodeId" TEXT NOT NULL,
    "settings" JSONB NOT NULL,
    "configPath" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AgentNodeOpenvpnSettings_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "AgentNodeOpenvpnSettings_agentNodeId_key" ON "AgentNodeOpenvpnSettings"("agentNodeId");

-- AddForeignKey
ALTER TABLE "AgentNodeOpenvpnSettings" ADD CONSTRAINT "AgentNodeOpenvpnSettings_agentNodeId_fkey" FOREIGN KEY ("agentNodeId") REFERENCES "AgentNode"("id") ON DELETE CASCADE ON UPDATE CASCADE;
