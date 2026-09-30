#!/usr/bin/env node
// Issue a sandbox API key to a user, as the organization's administrator
// would: the key goes into <dir>/<user>.key (mode 0600), and only its SHA-256
// into <dir>/registry.json, which is what the service reads. Nothing is
// printed but the file names; the key is never shown. Give the user the key
// file through a secret manager, and have them run
//   <command> sandbox login < <user>.key
// so it never reaches shell history or argv.
//
//   node scripts/generate-key.mjs --user alice --dir ./sandbox-keys [--force]
import { createHash, randomBytes } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";

const REGISTRY_SCHEMA = "piship-reference-sandbox-registry/v1";

const { values } = parseArgs({
  options: {
    user: { type: "string" },
    dir: { type: "string" },
    force: { type: "boolean", default: false },
  },
});
if (
  !values.user ||
  !/^[a-z0-9][a-z0-9_.-]{0,40}$/.test(values.user) ||
  !values.dir
) {
  process.stderr.write(
    "usage: generate-key.mjs --user <lowercase name> --dir <directory> [--force]\n",
  );
  process.exit(2);
}

const directory = resolve(values.dir);
mkdirSync(directory, { recursive: true, mode: 0o700 });
chmodSync(directory, 0o700);
const keyFile = join(directory, `${values.user}.key`);
const registryFile = join(directory, "registry.json");
if (existsSync(keyFile) && !values.force) {
  process.stderr.write(`${keyFile} exists; --force replaces the user's key\n`);
  process.exit(1);
}

const key = `sbxk_${randomBytes(32).toString("base64url")}`;
const sha256 = createHash("sha256").update(key, "utf8").digest("hex");
const registry = existsSync(registryFile)
  ? JSON.parse(readFileSync(registryFile, "utf8"))
  : { schema: REGISTRY_SCHEMA, keys: [] };
registry.keys = [
  ...registry.keys.filter((entry) => entry.id !== values.user),
  { id: values.user, sha256 },
];
writeFileSync(keyFile, `${key}\n`, { mode: 0o600 });
chmodSync(keyFile, 0o600);
const staging = `${registryFile}.${process.pid}`;
writeFileSync(staging, `${JSON.stringify(registry, null, 2)}\n`, {
  mode: 0o600,
});
renameSync(staging, registryFile);
process.stdout.write(`wrote ${keyFile} and ${registryFile}\n`);
