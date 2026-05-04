-- CreateTable
CREATE TABLE "PanelAppBackupSettings" (
    "id" INTEGER NOT NULL DEFAULT 1,
    "intervalMinutes" INTEGER NOT NULL DEFAULT 0,
    "retainCount" INTEGER NOT NULL DEFAULT 10,
    "lastScheduledAt" TIMESTAMP(3),
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "PanelAppBackupSettings_pkey" PRIMARY KEY ("id")
);

INSERT INTO "PanelAppBackupSettings" ("id", "intervalMinutes", "retainCount", "lastScheduledAt", "updatedAt")
VALUES (1, 0, 10, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

-- CreateTable
CREATE TABLE "PanelAppBackup" (
    "id" TEXT NOT NULL,
    "fileName" TEXT NOT NULL,
    "sizeBytes" INTEGER NOT NULL,
    "trigger" TEXT NOT NULL DEFAULT 'manual',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PanelAppBackup_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "PanelAppBackup_createdAt_idx" ON "PanelAppBackup"("createdAt");
