CREATE TABLE "RootCertificateAuthority" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "commonName" TEXT NOT NULL,
    "certPem" TEXT NOT NULL,
    "keyPem" TEXT NOT NULL,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "RootCertificateAuthority_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "RootCertificateAuthority_name_key"
ON "RootCertificateAuthority"("name");

ALTER TABLE "Certificate"
ADD COLUMN "rootCaId" TEXT;

ALTER TABLE "Certificate"
ADD CONSTRAINT "Certificate_rootCaId_fkey"
FOREIGN KEY ("rootCaId") REFERENCES "RootCertificateAuthority"("id")
ON DELETE SET NULL ON UPDATE CASCADE;
