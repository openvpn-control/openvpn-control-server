import { execFileSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";

function toOpensslUtc(d) {
  const x = new Date(d);
  if (Number.isNaN(x.getTime())) return "00000000000000Z";
  const p = (n) => String(n).padStart(2, "0");
  const y = String(x.getUTCFullYear()).slice(-2);
  return `${y}${p(x.getUTCMonth() + 1)}${p(x.getUTCDate())}${p(x.getUTCHours())}${p(x.getUTCMinutes())}${p(x.getUTCSeconds())}Z`;
}

function serialToOpenSSLHex(serial) {
  const s = String(serial || "")
    .trim()
    .replace(/^0x/i, "");
  if (/^[0-9a-fA-F]+$/.test(s) && s.length > 0) return s.toUpperCase();
  try {
    return BigInt(s).toString(16).toUpperCase();
  } catch {
    return s.toUpperCase();
  }
}

/**
 * Генерация CRL в PEM через OpenSSL `ca -gencrl` (нужен openssl в PATH на хосте панели).
 * @param {{ certPem: string, keyPem: string }} rootCa
 * @param {Array<{ serialNumber: string, commonName: string, expiresAt: Date, revokedAt: Date }>} revokedRows
 */
export function generateCrlPem(rootCa, revokedRows) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "ovpn-crl-"));
  try {
    fs.writeFileSync(path.join(tmp, "ca.crt"), rootCa.certPem, "utf8");
    fs.writeFileSync(path.join(tmp, "ca.key"), rootCa.keyPem, "utf8");

    const indexLines = [];
    for (const c of revokedRows) {
      const serialHex = serialToOpenSSLHex(c.serialNumber);
      const exp = toOpensslUtc(c.expiresAt);
      const rev = toOpensslUtc(c.revokedAt);
      const cn = String(c.commonName || "unknown").replace(/[\t\n\r]/g, " ");
      indexLines.push(`R\t${exp}\t${rev}\t${serialHex}\tunknown\t/CN=${cn}`);
    }
    fs.writeFileSync(path.join(tmp, "index.txt"), indexLines.length ? `${indexLines.join("\n")}\n` : "", "utf8");
    fs.writeFileSync(path.join(tmp, "index.txt.attr"), "unique_subject = no\n", "utf8");
    fs.writeFileSync(path.join(tmp, "serial"), "01\n", "utf8");
    fs.writeFileSync(path.join(tmp, "crlnumber"), "01\n", "utf8");

    const dirUnix = tmp.replace(/\\/g, "/");
    const cnf = `[ ca ]
default_ca = CA_default

[ CA_default ]
database = ${dirUnix}/index.txt
certificate = ${dirUnix}/ca.crt
serial = ${dirUnix}/serial
crlnumber = ${dirUnix}/crlnumber
private_key = ${dirUnix}/ca.key
default_md = sha256
default_crl_days = 30
unique_subject = no
`;
    fs.writeFileSync(path.join(tmp, "openssl.cnf"), cnf, "utf8");

    execFileSync("openssl", ["ca", "-config", "openssl.cnf", "-gencrl", "-out", "crl.pem"], {
      cwd: tmp,
      stdio: "pipe",
      encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024,
    });
    return fs.readFileSync(path.join(tmp, "crl.pem"), "utf8");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}
