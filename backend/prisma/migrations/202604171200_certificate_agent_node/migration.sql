-- AlterTable
ALTER TABLE "Certificate" ADD COLUMN "agentNodeId" TEXT;

-- DropIndex
DROP INDEX IF EXISTS "Certificate_commonName_key";

-- CreateIndex
CREATE UNIQUE INDEX "Certificate_commonName_agentNodeId_key" ON "Certificate"("commonName", "agentNodeId");

-- AddForeignKey
ALTER TABLE "Certificate"
ADD CONSTRAINT "Certificate_agentNodeId_fkey"
FOREIGN KEY ("agentNodeId") REFERENCES "AgentNode"("id") ON DELETE SET NULL ON UPDATE CASCADE;
