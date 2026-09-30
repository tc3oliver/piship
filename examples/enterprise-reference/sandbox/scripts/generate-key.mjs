#!/usr/bin/env node
// Issue a sandbox API key to a user, as the organization's administrator
// would: the key goes into <dir>/<user>.key (mode 0600), and only its SHA-256
// into <dir>/registry.json, which is what the service reads. Nothing is
// printed but the file names; the key is never shown. Give the user the key
// file through a secret manager, and have them run
//   <command> sandbox login < <user>.key
// so it never reaches shell history or argv.
//
// A key is bound to the host user whose projects it may mount, because the
// service runs commands as the owner of the project: --uid names that user
// (default: the user running this script). --root narrows the directories
// further (repeatable). --unbound is the explicit opt-in for a single-user
// setup, where the key may mount any project of any non-root owner under the
// service's roots.
//
//   node scripts/generate-key.mjs --user alice --dir ./sandbox-keys \
//     [--uid 501 | --unbound] [--root /srv/src/alice ...] [--force]
import { createHash, randomBytes } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { isAbsolute, join, resolve } from "node:path";
import { parseArgs } from "node:util";

const REGISTRY_SCHEMA = "piship-reference-sandbox-registry/v1";

const { values } = parseArgs({
  options: {
    user: { type: "string" },
    dir: { type: "string" },
    uid: { type: "string" },
    unbound: { type: "boolean", default: false },
    root: { type: "string", multiple: true },
    force: { type: "boolean", default: false },
  },
});
const usage = (problem) => {
  process.stderr.write(
    `${problem}\nusage: generate-key.mjs --user <lowercase name> --dir <directory> [--uid <host user ID> | --unbound] [--root <directory> ...] [--force]\n`,
  );
  process.exit(2);
};
if (!values.user || !/^[a-z0-9][a-z0-9_.-]{0,40}$/.test(values.user))
  usage("--user must be a short lowercase name");
if (!values.dir) usage("--dir is required");
if (values.unbound && values.uid !== undefined)
  usage("--uid and --unbound are exclusive");
let uid;
if (!values.unbound) {
  uid = values.uid === undefined ? process.getuid?.() : Number(values.uid);
  if (!(Number.isInteger(uid) && uid >= 1 && uid <= 4_294_967_294))
    usage(
      "--uid must be a non-root host user ID (run as that user, or pass --uid, or --unbound)",
    );
}
for (const root of values.root ?? [])
  if (!isAbsolute(root)) usage("--root must be an absolute path");

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
  {
    id: values.user,
    sha256,
    ...(values.unbound ? { unbound: true } : { uid }),
    ...(values.root?.length
      ? { roots: values.root.map((r) => resolve(r)) }
      : {}),
  },
];
writeFileSync(keyFile, `${key}\n`, { mode: 0o600 });
chmodSync(keyFile, 0o600);
const staging = `${registryFile}.${process.pid}`;
writeFileSync(staging, `${JSON.stringify(registry, null, 2)}\n`, {
  mode: 0o600,
});
renameSync(staging, registryFile);
process.stdout.write(`wrote ${keyFile} and ${registryFile}\n`);
