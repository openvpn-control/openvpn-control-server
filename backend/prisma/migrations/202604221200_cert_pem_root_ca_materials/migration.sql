-- AlterTable
ALTER TABLE "Certificate" ADD COLUMN IF NOT EXISTS "certPem" TEXT;
ALTER TABLE "Certificate" ADD COLUMN IF NOT EXISTS "keyPem" TEXT;

-- CreateTable
CREATE TABLE "RootCaOpenvpnMaterial" (
    "id" TEXT NOT NULL,
    "rootCaId" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "label" TEXT,
    "pem" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "RootCaOpenvpnMaterial_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "RootCaOpenvpnMaterial_rootCaId_kind_idx" ON "RootCaOpenvpnMaterial"("rootCaId", "kind");

ALTER TABLE "RootCaOpenvpnMaterial" ADD CONSTRAINT "RootCaOpenvpnMaterial_rootCaId_fkey" FOREIGN KEY ("rootCaId") REFERENCES "RootCertificateAuthority"("id") ON DELETE CASCADE ON UPDATE CASCADE;
