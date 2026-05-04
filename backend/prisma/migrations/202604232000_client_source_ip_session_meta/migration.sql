-- AlterTable
ALTER TABLE "ClientSourceIpHistory" ADD COLUMN "endedAt" TIMESTAMP(3),
ADD COLUMN "durationSeconds" INTEGER;

-- CreateIndex
CREATE INDEX "ClientSourceIpHistory_agentNodeId_endedAt_idx" ON "ClientSourceIpHistory"("agentNodeId", "endedAt");
