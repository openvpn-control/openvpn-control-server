CREATE TABLE "AdminTotpRecoveryCode" (
    "id" TEXT NOT NULL,
    "adminId" TEXT NOT NULL,
    "codeHash" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "usedAt" TIMESTAMP(3),

    CONSTRAINT "AdminTotpRecoveryCode_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "AdminTotpRecoveryCode_adminId_usedAt_idx" ON "AdminTotpRecoveryCode"("adminId", "usedAt");

ALTER TABLE "AdminTotpRecoveryCode" ADD CONSTRAINT "AdminTotpRecoveryCode_adminId_fkey" FOREIGN KEY ("adminId") REFERENCES "Admin"("id") ON DELETE CASCADE ON UPDATE CASCADE;
