CREATE TABLE "Admin" (
    "id" TEXT NOT NULL,
    "username" TEXT NOT NULL,
    "passwordHash" TEXT NOT NULL,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "Admin_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "Admin_username_key" ON "Admin"("username");

CREATE TABLE "AgentNode" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "host" TEXT NOT NULL,
    "port" INTEGER NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'UNKNOWN',
    "cpuPercent" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "memoryPercent" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "diskPercent" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "networkInBps" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "networkOutBps" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "activeClients" INTEGER NOT NULL DEFAULT 0,
    "lastSeenAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "AgentNode_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "Certificate" (
    "id" TEXT NOT NULL,
    "commonName" TEXT NOT NULL,
    "serialNumber" TEXT NOT NULL,
    "issuedBy" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "revokedAt" TIMESTAMP(3),
    "revokedReason" TEXT,
    CONSTRAINT "Certificate_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "Certificate_commonName_key" ON "Certificate"("commonName");
CREATE UNIQUE INDEX "Certificate_serialNumber_key" ON "Certificate"("serialNumber");
