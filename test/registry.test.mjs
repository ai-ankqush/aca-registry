import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, cp, appendFile, access } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Registry } from "../src/registry.mjs";
import { generateKeypair } from "../src/sign.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PLUGINS = path.join(__dirname, "..", "..", "aca-core", "plugins");

test("publish (open + curated), list, verify, install, and tamper detection", async () => {
  const work = await mkdtemp(path.join(tmpdir(), "aca-reg-"));
  const reg = new Registry(path.join(work, "registry.json"));
  const { publicKeyPem, privateKeyPem } = generateKeypair();

  // copy a collector into a mutable dir, publish to the open track (signed)
  const collectorSrc = path.join(work, "collector");
  await cp(path.join(PLUGINS, "example-collector"), collectorSrc, { recursive: true });
  const e1 = await reg.publish(collectorSrc, { track: "open", privateKeyPem, publisher: "acme" });
  assert.equal(e1.cert, "ACA-Compatible");
  assert.equal(e1.type, "collector");
  assert.ok(e1.signature, "should be signed");

  // publish a framework to the curated track
  const e2 = await reg.publish(path.join(PLUGINS, "example-framework"), { track: "curated", privateKeyPem });
  assert.equal(e2.cert, "ACA-Verified");

  // list + filters
  assert.equal((await reg.list()).length, 2);
  assert.equal((await reg.list({ type: "collector" })).length, 1);
  assert.equal((await reg.list({ track: "curated" })).length, 1);

  // signature verifies with the right key, fails with a wrong key
  assert.equal(reg.verify(e1, publicKeyPem), true);
  assert.equal(reg.verify(e1, generateKeypair().publicKeyPem), false);

  // install verifies signature + integrity and copies the package
  const dest = await reg.install("aca.example/hello-collector", "0.1.0", path.join(work, "installed"), { publicKeyPem });
  await access(path.join(dest, "aca-plugin.json"));

  // tamper the source after publish -> install must fail the integrity check
  await appendFile(path.join(collectorSrc, "index.mjs"), "\n// tampered\n");
  await assert.rejects(
    () => reg.install("aca.example/hello-collector", "0.1.0", path.join(work, "installed2"), { publicKeyPem }),
    /integrity check failed/,
  );
});
