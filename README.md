# @aca/registry

The add-on registry for the **AI Control Architecture** — a two-track index with Ed25519 package signing and integrity verification. Zero dependencies.

## Two tracks

- **open** — permissionless, unvetted, `ACA-Compatible`. Velocity + the long tail. Always sandboxed by the consuming core.
- **curated** — reviewed, `ACA-Verified` / `ACA-Certified`. Enterprise-safe; where paid add-ons live.

Deployment-neutral: the same registry serves a self-hosted core and a hosted one.

## Trust model

- Every package gets a deterministic **content hash** (+ a per-file map, SBOM-style).
- Publishers **sign** the hash (Ed25519). Consumers **verify** the signature and **re-check integrity** on install — a package changed since publish is rejected.

## CLI

```
aca-registry keygen --out mykey
aca-registry publish ./my-plugin --track open --key mykey.key.pem --publisher me
aca-registry list
aca-registry verify my.org/my-plugin --key mykey.pub.pem
aca-registry install my.org/my-plugin --key mykey.pub.pem --dest ./installed
```

## API

```js
import { Registry } from "@aca/registry";
const reg = new Registry("registry.json");
await reg.publish(dir, { track: "curated", privateKeyPem, publisher });
await reg.list({ track: "curated", type: "connector" });
await reg.install(name, version, dest, { publicKeyPem }); // verifies + integrity-checks
```

## Run the tests

```
node --test
```

## Status

v0.1. A file-backed index today; the same shape grows into the hosted registry with the curated review flow (see the Marketplace design). Curated promotion (Verified/Certified) is a review process, not an automatic upgrade.
