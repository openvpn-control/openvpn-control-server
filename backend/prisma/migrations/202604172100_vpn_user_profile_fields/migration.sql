-- VpnUser: профиль без привязки к CN; обязательные организация, должность, email, телефон.

ALTER TABLE "VpnUser" ADD COLUMN IF NOT EXISTS "fullName" TEXT;
ALTER TABLE "VpnUser" ADD COLUMN IF NOT EXISTS "position" TEXT;
ALTER TABLE "VpnUser" ADD COLUMN IF NOT EXISTS "phone" TEXT;

UPDATE "VpnUser" SET
  "fullName" = COALESCE(NULLIF(TRIM("displayName"), ''), "commonName", 'Пользователь'),
  "position" = '-',
  "phone" = '-',
  "email" = COALESCE(NULLIF(TRIM("email"), ''), 'user-' || "id" || '@migrated.local')
WHERE "fullName" IS NULL OR TRIM("fullName") = '';

UPDATE "VpnUser" u
SET "organizationId" = (SELECT o.id FROM "Organization" o ORDER BY o."createdAt" ASC LIMIT 1)
WHERE u."organizationId" IS NULL;

ALTER TABLE "VpnUser" DROP CONSTRAINT IF EXISTS "VpnUser_commonName_key";
ALTER TABLE "VpnUser" DROP COLUMN IF EXISTS "commonName";
ALTER TABLE "VpnUser" DROP COLUMN IF EXISTS "displayName";

ALTER TABLE "VpnUser" ALTER COLUMN "fullName" SET NOT NULL;
ALTER TABLE "VpnUser" ALTER COLUMN "position" SET NOT NULL;
ALTER TABLE "VpnUser" ALTER COLUMN "phone" SET NOT NULL;
ALTER TABLE "VpnUser" ALTER COLUMN "email" SET NOT NULL;
ALTER TABLE "VpnUser" ALTER COLUMN "organizationId" SET NOT NULL;

ALTER TABLE "VpnUser" DROP CONSTRAINT IF EXISTS "VpnUser_organizationId_fkey";

ALTER TABLE "VpnUser" ADD CONSTRAINT "VpnUser_organizationId_fkey"
  FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

CREATE UNIQUE INDEX "VpnUser_email_key" ON "VpnUser"("email");
