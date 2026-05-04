import crypto from "node:crypto";
import { authenticator } from "otplib";
import QRCode from "qrcode";
import { config } from "../config.js";

const TOTP_PENDING_TTL_MS = 10 * 60 * 1000;

function encryptionKey() {
  return crypto.createHash("sha256").update(String(config.jwtSecret || "")).digest();
}

export function encryptSecret(secret) {
  const iv = crypto.randomBytes(12);
  const key = encryptionKey();
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(String(secret), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString("base64")}:${tag.toString("base64")}:${encrypted.toString("base64")}`;
}

export function decryptSecret(payload) {
  const [ivB64, tagB64, dataB64] = String(payload || "").split(":");
  if (!ivB64 || !tagB64 || !dataB64) return "";
  const iv = Buffer.from(ivB64, "base64");
  const tag = Buffer.from(tagB64, "base64");
  const data = Buffer.from(dataB64, "base64");
  const key = encryptionKey();
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([decipher.update(data), decipher.final()]);
  return decrypted.toString("utf8");
}

export function generatePendingTotpSetup({ accountName, issuer }) {
  const secret = authenticator.generateSecret();
  const otpAuthUrl = authenticator.keyuri(String(accountName || ""), String(issuer || "OpenVPN Control"), secret);
  return {
    secret,
    encryptedSecret: encryptSecret(secret),
    otpAuthUrl,
    expiresAt: new Date(Date.now() + TOTP_PENDING_TTL_MS),
  };
}

export async function generateTotpQrDataUrl(otpAuthUrl) {
  return QRCode.toDataURL(String(otpAuthUrl || ""), {
    errorCorrectionLevel: "M",
    margin: 1,
    scale: 6,
  });
}

export function verifyTotpToken(secret, token) {
  const normalized = String(token || "").replace(/\s+/g, "");
  if (!normalized) return false;
  return authenticator.verify({ token: normalized, secret: String(secret || "") });
}

