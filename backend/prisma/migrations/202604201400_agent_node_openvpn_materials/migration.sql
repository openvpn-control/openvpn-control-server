-- CreateTable
CREATE TABLE "AgentNodeOpenvpnMaterial" (
    "id" TEXT NOT NULL,
    "agentNodeId" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "label" TEXT,
    "pem" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AgentNodeOpenvpnMaterial_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "AgentNodeOpenvpnMaterial_agentNodeId_kind_idx" ON "AgentNodeOpenvpnMaterial"("agentNodeId", "kind");

-- AddForeignKey
ALTER TABLE "AgentNodeOpenvpnMaterial" ADD CONSTRAINT "AgentNodeOpenvpnMaterial_agentNodeId_fkey" FOREIGN KEY ("agentNodeId") REFERENCES "AgentNode"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- DropTable (DH/tls-auth больше не привязаны к корневому CA)
DROP TABLE IF EXISTS "RootCaOpenvpnMaterial";
