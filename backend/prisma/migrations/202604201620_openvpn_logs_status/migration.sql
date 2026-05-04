-- AlterTable
ALTER TABLE "AgentNode"
ADD COLUMN "openvpnLogsEnabled" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN "openvpnLogsNote" TEXT;
