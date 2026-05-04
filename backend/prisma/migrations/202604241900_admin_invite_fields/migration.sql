-- AlterTable
ALTER TABLE "Admin" ADD COLUMN     "fullName" TEXT NOT NULL DEFAULT '';
ALTER TABLE "Admin" ADD COLUMN     "email" TEXT;
ALTER TABLE "Admin" ADD COLUMN     "inviteToken" TEXT;
ALTER TABLE "Admin" ADD COLUMN     "inviteExpiresAt" TIMESTAMP(3);

CREATE UNIQUE INDEX "Admin_email_key" ON "Admin"("email");
CREATE UNIQUE INDEX "Admin_inviteToken_key" ON "Admin"("inviteToken");
