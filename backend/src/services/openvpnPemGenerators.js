import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export function firstTlsAuthPath(tlsAuthLine) {
  const s = String(tlsAuthLine || "").trim();
  if (!s) return "";
  const parts = s.split(/\s+/);
  return parts[0] || "";
}

export function generateDhPem2048() {
  return execFileSync("openssl", ["dhparam", "-outform", "PEM", "2048"], {
    encoding: "utf8",
    maxBuffer: 32 * 1024 * 1024,
    timeout: 180000,
  });
}

function generateTlsAuthStaticKeyFallback() {
  const buf = crypto.randomBytes(256);
  const lines = [];
  for (let i = 0; i < 16; i++) {
    lines.push(buf.subarray(i * 16, (i + 1) * 16).toString("hex"));
  }
  return `#\n# 2048 bit OpenVPN static key\n#\n-----BEGIN OpenVPN Static key V1-----\n${lines.join("\n")}\n-----END OpenVPN Static key V1-----\n`;
}

export function generateTlsAuthKeyPem() {
  const tmp = path.join(os.tmpdir(), `ov-ta-${process.pid}-${Date.now()}.key`);
  try {
    execFileSync("openvpn", ["--genkey", "secret", tmp], { timeout: 15000 });
    return fs.readFileSync(tmp, "utf8");
  } catch {
    return generateTlsAuthStaticKeyFallback();
  } finally {
    try {
      fs.unlinkSync(tmp);
    } catch {
      /* ignore */
    }
  }
}
