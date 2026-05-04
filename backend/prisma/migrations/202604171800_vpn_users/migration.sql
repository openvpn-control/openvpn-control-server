-- CreateTable
CREATE TABLE "VpnUser" (
    "id" TEXT NOT NULL,
    "commonName" TEXT NOT NULL,
    "displayName" TEXT,
    "email" TEXT,
    "notes" TEXT,
    "organizationId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "VpnUser_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "VpnUser_commonName_key" ON "VpnUser"("commonName");

-- CreateIndex
CREATE INDEX "VpnUser_organizationId_idx" ON "VpnUser"("organizationId");

-- AddForeignKey
ALTER TABLE "VpnUser" ADD CONSTRAINT "VpnUser_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AlterTable
ALTER TABLE "Certificate" ADD COLUMN "vpnUserId" TEXT;

-- CreateIndex
CREATE INDEX "Certificate_vpnUserId_idx" ON "Certificate"("vpnUserId");

-- AddForeignKey
ALTER TABLE "Certificate" ADD CONSTRAINT "Certificate_vpnUserId_fkey" FOREIGN KEY ("vpnUserId") REFERENCES "VpnUser"("id") ON DELETE SET NULL ON UPDATE CASCADE;
