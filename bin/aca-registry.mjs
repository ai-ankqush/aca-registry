#!/usr/bin/env node
// ACA Registry CLI — keygen, publish, list, install, verify. Zero dependencies.
import { writeFile, readFile } from "node:fs/promises";
import { Registry } from "../src/registry.mjs";
import { generateKeypair } from "../src/sign.mjs";

const rest = process.argv.slice(2);
const [cmd, ...args] = rest;
const flag = (n, d) => { const i = args.indexOf("--" + n); return i >= 0 ? args[i + 1] : d; };
const pos = args.filter((a, i) => !a.startsWith("--") && !(i > 0 && args[i - 1].startsWith("--")));

function usage() {
  console.log(`aca-registry <command> [--index registry.json]

  keygen [--out aca-key]
  publish <dir> [--track open|curated] [--key key.pem] [--publisher name]
  list [--track t] [--type t] [--pricing p]
  install <name> [--version v] [--dest ./installed] [--key pub.pem]
  verify <name> --key pub.pem [--version v]
`);
}

async function main() {
  const reg = new Registry(flag("index", "registry.json"));

  if (cmd === "keygen") {
    const { publicKeyPem, privateKeyPem } = generateKeypair();
    const out = flag("out", "aca-key");
    await writeFile(`${out}.pub.pem`, publicKeyPem);
    await writeFile(`${out}.key.pem`, privateKeyPem);
    console.log(`wrote ${out}.pub.pem and ${out}.key.pem`);
  } else if (cmd === "publish") {
    const dir = pos[0];
    if (!dir) throw new Error("usage: publish <dir>");
    const keyPath = flag("key");
    const privateKeyPem = keyPath ? await readFile(keyPath, "utf8") : null;
    const e = await reg.publish(dir, { track: flag("track", "open"), privateKeyPem, publisher: flag("publisher", "unknown") });
    console.log(`published ${e.name}@${e.version}  [${e.track}/${e.cert}]${e.signature ? " signed" : " UNSIGNED"}`);
  } else if (cmd === "list") {
    const entries = await reg.list({ track: flag("track"), type: flag("type"), pricing: flag("pricing") });
    if (!entries.length) console.log("(empty)");
    for (const e of entries) console.log(`${e.name}@${e.version}\t${e.type}\t${e.track}/${e.cert}\t${e.pricing}\t${e.publisher}`);
  } else if (cmd === "install") {
    const name = pos[0];
    if (!name) throw new Error("usage: install <name>");
    const keyPath = flag("key");
    const publicKeyPem = keyPath ? await readFile(keyPath, "utf8") : null;
    const dest = await reg.install(name, flag("version"), flag("dest", "./installed"), { publicKeyPem });
    console.log(`installed to ${dest}`);
  } else if (cmd === "verify") {
    const name = pos[0];
    const e = await reg.get(name, flag("version"));
    if (!e) throw new Error(`not found: ${name}`);
    const publicKeyPem = await readFile(flag("key"), "utf8");
    console.log(reg.verify(e, publicKeyPem) ? "OK: signature valid" : "FAIL: invalid signature");
  } else {
    usage();
    process.exit(cmd ? 1 : 0);
  }
}

main().catch((e) => { console.error("Error:", e.message); process.exit(1); });
