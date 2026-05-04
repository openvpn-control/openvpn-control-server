-- CreateTable
CREATE TABLE IF NOT EXISTS "AgentNodeOpenvpnConfigVersion" (
    "id" TEXT NOT NULL,
    "agentNodeId" TEXT NOT NULL,
    "version" INTEGER NOT NULL,
    "settings" JSONB NOT NULL,
    "checksum" TEXT NOT NULL,
    "appliedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AgentNodeOpenvpnConfigVersion_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX IF NOT EXISTS "AgentNodeOpenvpnConfigVersion_agentNodeId_version_key"
ON "AgentNodeOpenvpnConfigVersion"("agentNodeId", "version");

-- CreateIndex
CREATE INDEX IF NOT EXISTS "AgentNodeOpenvpnConfigVersion_agentNodeId_createdAt_idx"
ON "AgentNodeOpenvpnConfigVersion"("agentNodeId", "createdAt");

-- CreateIndex
CREATE INDEX IF NOT EXISTS "AgentNodeOpenvpnConfigVersion_agentNodeId_appliedAt_idx"
ON "AgentNodeOpenvpnConfigVersion"("agentNodeId", "appliedAt");

-- AddForeignKey
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'AgentNodeOpenvpnConfigVersion_agentNodeId_fkey'
    ) THEN
        ALTER TABLE "AgentNodeOpenvpnConfigVersion"
        ADD CONSTRAINT "AgentNodeOpenvpnConfigVersion_agentNodeId_fkey"
        FOREIGN KEY ("agentNodeId") REFERENCES "AgentNode"("id") ON DELETE CASCADE ON UPDATE CASCADE;
    END IF;
END $$;
