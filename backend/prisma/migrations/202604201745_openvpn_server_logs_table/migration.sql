CREATE TABLE "OpenvpnServerLog" (
  "id" TEXT NOT NULL,
  "agentNodeId" TEXT NOT NULL,
  "occurredAt" TIMESTAMP(3) NOT NULL,
  "occurredRaw" TEXT,
  "event" TEXT NOT NULL,
  "username" TEXT,
  "ipAddress" TEXT,
  "rawLine" TEXT NOT NULL,
  "fingerprint" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "OpenvpnServerLog_pkey" PRIMARY KEY ("id")
);

ALTER TABLE "OpenvpnServerLog"
ADD CONSTRAINT "OpenvpnServerLog_agentNodeId_fkey" FOREIGN KEY ("agentNodeId") REFERENCES "AgentNode"("id") ON DELETE CASCADE ON UPDATE CASCADE;

CREATE UNIQUE INDEX "OpenvpnServerLog_fingerprint_key" ON "OpenvpnServerLog"("fingerprint");
CREATE INDEX "OpenvpnServerLog_agentNodeId_occurredAt_idx" ON "OpenvpnServerLog"("agentNodeId", "occurredAt");
CREATE INDEX "OpenvpnServerLog_createdAt_idx" ON "OpenvpnServerLog"("createdAt");
CREATE INDEX "OpenvpnServerLog_username_idx" ON "OpenvpnServerLog"("username");
CREATE INDEX "OpenvpnServerLog_ipAddress_idx" ON "OpenvpnServerLog"("ipAddress");
