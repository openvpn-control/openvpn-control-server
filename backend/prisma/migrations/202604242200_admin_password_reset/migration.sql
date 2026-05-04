-- AlterTable
ALTER TABLE "Admin" ADD COLUMN "passwordResetToken" TEXT;
ALTER TABLE "Admin" ADD COLUMN "passwordResetExpiresAt" TIMESTAMP(3);

CREATE UNIQUE INDEX "Admin_passwordResetToken_key" ON "Admin"("passwordResetToken");
