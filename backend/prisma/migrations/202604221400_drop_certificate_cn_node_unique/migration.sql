-- Разрешаем несколько записей с одной парой (commonName, agentNodeId): различаем по серийному номеру.
DROP INDEX IF EXISTS "Certificate_commonName_agentNodeId_key";

CREATE INDEX "Certificate_commonName_agentNodeId_idx" ON "Certificate"("commonName", "agentNodeId");
