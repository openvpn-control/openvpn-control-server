ALTER TABLE "Organization"
ADD COLUMN IF NOT EXISTS "firewallRules" JSONB;
