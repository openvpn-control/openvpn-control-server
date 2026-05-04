-- AlterTable
ALTER TABLE "AgentNode"
ADD COLUMN "openvpnBinaryPath" TEXT,
ADD COLUMN "openvpnVersion" TEXT,
ADD COLUMN "openvpnBuild" TEXT,
ADD COLUMN "openvpnConfigPath" TEXT,
ADD COLUMN "openvpnManagementAddr" TEXT,
ADD COLUMN "openvpnRunning" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN "openvpnInfoSeenAt" TIMESTAMP(3),
ADD COLUMN "openvpnInfoError" TEXT;
