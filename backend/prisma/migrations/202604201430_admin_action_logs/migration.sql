-- CreateTable
CREATE TABLE "AdminActionLog" (
    "id" TEXT NOT NULL,
    "adminId" TEXT NOT NULL,
    "adminUsername" TEXT NOT NULL,
    "method" TEXT NOT NULL,
    "path" TEXT NOT NULL,
    "action" TEXT NOT NULL,
    "targetType" TEXT,
    "targetId" TEXT,
    "ipAddress" TEXT,
    "userAgent" TEXT,
    "statusCode" INTEGER NOT NULL,
    "details" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AdminActionLog_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "AdminActionLog_createdAt_idx" ON "AdminActionLog"("createdAt");
CREATE INDEX "AdminActionLog_adminId_createdAt_idx" ON "AdminActionLog"("adminId", "createdAt");
CREATE INDEX "AdminActionLog_targetType_targetId_createdAt_idx" ON "AdminActionLog"("targetType", "targetId", "createdAt");

-- AddForeignKey
ALTER TABLE "AdminActionLog" ADD CONSTRAINT "AdminActionLog_adminId_fkey" FOREIGN KEY ("adminId") REFERENCES "Admin"("id") ON DELETE CASCADE ON UPDATE CASCADE;
