-- AlterTable
ALTER TABLE "AgentNode"
ADD COLUMN "openvpnServiceUnit" TEXT,
ADD COLUMN "openvpnServiceActiveState" TEXT,
ADD COLUMN "openvpnServiceSubState" TEXT,
ADD COLUMN "openvpnServiceMainPid" INTEGER,
ADD COLUMN "openvpnServiceActiveSince" TEXT,
ADD COLUMN "openvpnServiceRecentLogs" JSONB;
