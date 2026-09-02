// ACA Registry — content hashing + Ed25519 signing (node built-ins only)
import { generateKeyPairSync, createHash, sign as cryptoSign, verify as cryptoVerify } from "node:crypto";
import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";

/** Generate an Ed25519 keypair (PEM). */
export function generateKeypair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
}

async function listFiles(dir) {
  const out = [];
  async function walk(d, base) {
    for (const name of (await readdir(d)).sort()) {
      const full = path.join(d, name);
      const rel = base ? `${base}/${name}` : name;
      const s = await stat(full);
      if (s.isDirectory()) await walk(full, rel);
      else out.push({ rel, full });
    }
  }
  await walk(dir, "");
  return out.sort((a, b) => a.rel.localeCompare(b.rel));
}

/**
 * Deterministic content hash of a package directory + a per-file map (SBOM-ish).
 * @returns {Promise<{ hash: string, files: Record<string,string> }>}
 */
export async function packageHash(dir) {
  const files = await listFiles(dir);
  const map = {};
  for (const f of files) map[f.rel] = createHash("sha256").update(await readFile(f.full)).digest("hex");
  const hash = createHash("sha256").update(JSON.stringify(map)).digest("hex");
  return { hash, files: map };
}

export function signHash(hashHex, privateKeyPem) {
  return cryptoSign(null, Buffer.from(hashHex), privateKeyPem).toString("base64");
}

export function verifyHash(hashHex, signatureB64, publicKeyPem) {
  try {
    return cryptoVerify(null, Buffer.from(hashHex), publicKeyPem, Buffer.from(signatureB64, "base64"));
  } catch {
    return false;
  }
}
