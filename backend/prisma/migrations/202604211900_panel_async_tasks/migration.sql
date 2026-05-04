-- CreateTable
CREATE TABLE "PanelAsyncTask" (
    "id" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'pending',
    "agentNodeId" TEXT NOT NULL,
    "payload" JSONB NOT NULL,
    "lastError" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "completedAt" TIMESTAMP(3),

    CONSTRAINT "PanelAsyncTask_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "PanelAsyncTask_status_idx" ON "PanelAsyncTask"("status");

-- CreateIndex
CREATE INDEX "PanelAsyncTask_agentNodeId_status_idx" ON "PanelAsyncTask"("agentNodeId", "status");

-- AddForeignKey
ALTER TABLE "PanelAsyncTask" ADD CONSTRAINT "PanelAsyncTask_agentNodeId_fkey" FOREIGN KEY ("agentNodeId") REFERENCES "AgentNode"("id") ON DELETE CASCADE ON UPDATE CASCADE;
