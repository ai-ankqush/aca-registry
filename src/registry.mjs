// ACA Registry — file-backed index with two tracks, signing + integrity checks.
// Zero dependencies. The index is the "app store" catalog: manifests + metadata
// + signatures. Serves self-hosted and hosted cores identically.
import { readFile, writeFile, mkdir, cp } from "node:fs/promises";
import path from "node:path";
import { packageHash, signHash, verifyHash } from "./sign.mjs";

async function readManifest(dir) {
  const m = JSON.parse(await readFile(path.join(dir, "aca-plugin.json"), "utf8"));
  if (!m.name || !m.version || !m.type) throw new Error("invalid manifest: name/version/type required");
  return m;
}

export class Registry {
  constructor(indexPath) { this.indexPath = indexPath; }

  async #read() {
    try { return JSON.parse(await readFile(this.indexPath, "utf8")); }
    catch { return { entries: [] }; }
  }
  async #write(idx) {
    await mkdir(path.dirname(this.indexPath), { recursive: true });
    await writeFile(this.indexPath, JSON.stringify(idx, null, 2) + "\n");
  }

  /**
   * Publish an add-on into a track. Open track = ACA-Compatible (unvetted);
   * curated track requires review before it reaches ACA-Verified/Certified.
   */
  async publish(pluginDir, { track = "open", privateKeyPem = null, publisher = "unknown", source = pluginDir } = {}) {
    if (!["open", "curated"].includes(track)) throw new Error("track must be 'open' or 'curated'");
    const manifest = await readManifest(pluginDir);
    const { hash, files } = await packageHash(pluginDir);
    const entry = {
      name: manifest.name,
      version: manifest.version,
      type: manifest.type,
      track,
      cert: track === "curated" ? "ACA-Verified" : "ACA-Compatible",
      license: manifest.license,
      pricing: manifest.pricing || "free",
      publisher,
      integrity: { algorithm: "sha256", hash },
      signature: privateKeyPem ? signHash(hash, privateKeyPem) : null,
      files,
      source: path.resolve(source),
      manifest,
      publishedAt: new Date().toISOString(),
    };
    const idx = await this.#read();
    idx.entries = idx.entries.filter((e) => !(e.name === entry.name && e.version === entry.version));
    idx.entries.push(entry);
    await this.#write(idx);
    return entry;
  }

  async list({ track, type, pricing } = {}) {
    const idx = await this.#read();
    return idx.entries.filter((e) =>
      (!track || e.track === track) && (!type || e.type === type) && (!pricing || e.pricing === pricing));
  }

  async get(name, version) {
    const idx = await this.#read();
    return idx.entries.find((e) => e.name === name && (!version || e.version === version));
  }

  /** Verify the publisher signature over the package hash. */
  verify(entry, publicKeyPem) {
    return !!entry.signature && verifyHash(entry.integrity.hash, entry.signature, publicKeyPem);
  }

  /**
   * Install an add-on: verify signature (if a key is given), re-check integrity
   * against the recorded hash (tamper detection), then copy into destDir.
   */
  async install(name, version, destDir, { publicKeyPem = null } = {}) {
    const entry = await this.get(name, version);
    if (!entry) throw new Error(`not found: ${name}${version ? "@" + version : ""}`);
    if (publicKeyPem && !this.verify(entry, publicKeyPem)) throw new Error("signature verification failed");
    const { hash } = await packageHash(entry.source);
    if (hash !== entry.integrity.hash) throw new Error("integrity check failed: package changed since publish");
    const dest = path.join(destDir, entry.name.replace("/", "__"));
    await cp(entry.source, dest, { recursive: true });
    return dest;
  }
}
