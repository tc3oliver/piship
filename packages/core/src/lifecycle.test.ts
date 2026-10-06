import { spawn, spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  chmodSync,
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  unlinkSync,
  watch,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { PiShipError, type SecretStore, SecretValue } from "@piship/contracts";
import type { UpdateRoot } from "@piship/schema";
import {
  MemorySecretStore,
  RestrictedFileSecretStore,
} from "@piship/credentials";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { deadPid } from "../../../tests/helpers/processes.js";
import * as archiveModule from "./archive.js";
import { PISHIP_VERSION } from "./compatibility.js";
import {
  currentTarget,
  EVIDENCED_TARGETS,
  formatInspection,
  inspection,
  isTestCreatedState,
  lockManifest,
  payloadInventory,
  type requireCurrentLock,
  testStateMarker,
  verifyPayload,
  withTestState,
} from "./index.js";
import * as copyModule from "./install/copy.js";
import * as filesModule from "./install/files.js";
import {
  describeReclaimed,
  holdRuntimeLease,
  installDistribution,
  lifecycleStatus,
  purgeDistributionState,
  RECEIPT_SCHEMA,
  readInstallReceipt,
  reclaimObsoleteVersions,
  recoverInstallation,
  runtimeLeases,
  uninstallAndPurgeDistribution,
  uninstallDistribution,
} from "./install/index.js";
import { readStateMarker } from "./migration.js";
import { acquireLock } from "./install/receipt.js";
import { readTrustState, trustStatePath } from "./install/trust-state.js";
import {
  buildRelease,
  type CommandResult,
  hostedRootText,
  signChannel,
} from "./release/index.js";
import {
  buildSignatureEnvelope,
  generateSigningKey,
  keyFingerprint,
  pemSigner,
  signBytes,
  signVerified,
} from "./signing.js";
import {
  repairDistribution,
  rollbackDistribution,
  selectChannel,
  type UpdateOptions,
  updateDistribution,
} from "./update/index.js";

// ------------------------------------------------------------------ fixtures

const BUILD_INPUT = process.env.PISHIP_BUILD_INPUT as string;
const KEY = generateSigningKey("test-release");
const ID = "acmepi";
const SENTINEL = "sentinel-secret-7f3a9c1e5b";
const SENTINEL_V2 = "sentinel-secret-v2-44d0e2a1";
const HOST_EVIDENCED = EVIDENCED_TARGETS.includes(currentTarget());

const roots: string[] = [];
const ENV_KEYS = [
  "PISHIP_INSTALL_HOME",
  "PISHIP_BIN_HOME",
  "PISHIP_STATE_HOME",
  "SOURCE_DATE_EPOCH",
];
let savedEnv: Record<string, string | undefined> = {};

beforeEach(() => {
  savedEnv = Object.fromEntries(ENV_KEYS.map((key) => [key, process.env[key]]));
  process.env.SOURCE_DATE_EPOCH = "1767225600";
  const home = temp("piship-home-");
  process.env.PISHIP_INSTALL_HOME = join(home, "install");
  process.env.PISHIP_BIN_HOME = join(home, "bin");
  process.env.PISHIP_STATE_HOME = join(home, "state");
});
afterEach(() => {
  for (const [key, value] of Object.entries(savedEnv))
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

function temp(prefix = "piship-lifecycle-"): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  roots.push(dir);
  return dir;
}
function write(path: string, content: string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content);
}

type Key = { readonly id: string; readonly publicKey: string };

function manifestSource(
  version: string,
  rollback: boolean,
  storage?: "file" | "system",
  keys: readonly Key[] = [KEY],
  rootKeys: readonly Key[] = keys,
): string {
  // With a storage provider, a personal access section whose runtime
  // credential (a local secret) lives in that store.
  const accessSection = storage
    ? `identity:
  mode: none
credential:
  provider: local-secret
  storage:
    provider: ${storage}
inference:
  provider: openai-compatible
  baseUrl: https://llm.acmepi.example/v1
models:
  allowed: [acme/coder]
  catalog:
    acme/coder:
      name: Acme Coder
      contextWindow: 128000
      maxOutputTokens: 8192
      tools: true
`
    : "";
  const ids = keys.map((key) => key.id).join(", ");
  const rootIds = rootKeys.map((key) => key.id).join(", ");
  const listed = [
    ...keys,
    ...rootKeys.filter((key) => !keys.some((other) => other.id === key.id)),
  ];
  return `schema: piship/v1alpha5
app:
  id: ${ID}
  name: AcmePi
  command: ${ID}
  version: ${version}
runtime:
  pi: "1.0.3"
deployment:
  mode: personal
variables:
  - ACMEPI_UPDATE_SOURCE
${accessSection}resources:
  instructions:
    user: [./resources/AGENTS.md]
updates:
  channel: stable
  channels: [stable, candidate]
  source: \${ACMEPI_UPDATE_SOURCE}
  rollback: ${rollback}
  trust:
    bootstrap:
      version: 1
      expires: 2099-01-01T00:00:00Z
      keys:
${listed.map((key) => `        - id: ${key.id}\n          publicKey: ${key.publicKey}\n`).join("")}      roles:
        root: { keyIds: [${rootIds}], threshold: 1 }
        channel: { keyIds: [${ids}], threshold: 1 }
`;
}

function project(
  version: string,
  rollback = true,
  storage?: "file" | "system",
  keys?: readonly Key[],
  rootKeys?: readonly Key[],
): string {
  const dir = temp("piship-project-");
  write(join(dir, "resources", "AGENTS.md"), `# AcmePi ${version}\n`);
  const path = join(dir, "piship.yaml");
  writeFileSync(
    path,
    manifestSource(version, rollback, storage, keys, rootKeys),
  );
  lockManifest(path);
  return path;
}

function fakeAssemble(manifestPath: string, outputRoot: string): string {
  const base = dirname(resolve(manifestPath));
  const lock = JSON.parse(readFileSync(join(base, "piship.lock"), "utf8")) as {
    app: { id: string; command: string };
    resources: { path: string }[];
  };
  const out = join(outputRoot, lock.app.id);
  mkdirSync(out, { recursive: true });
  cpSync(manifestPath, join(out, "piship.yaml"));
  cpSync(join(base, "piship.lock"), join(out, "piship.lock"));
  cpSync(
    join(BUILD_INPUT, "package-lock.json"),
    join(out, "package-lock.json"),
  );
  for (const resource of lock.resources)
    write(
      join(out, "resources", resource.path),
      readFileSync(join(base, resource.path), "utf8"),
    );
  write(
    join(out, "metadata", "target.json"),
    `${JSON.stringify({ platform: process.platform, arch: process.arch }, null, 2)}\n`,
  );
  write(
    join(out, "bin", lock.app.command),
    "#!/usr/bin/env node\nconsole.log('payload');\n",
  );
  write(
    join(out, "node_modules", "alpha", "package.json"),
    JSON.stringify({ name: "alpha", version: "1.0.0", license: "MIT" }),
  );
  write(
    join(out, "node_modules", "@piship", "core", "dist", "index.js"),
    `export { holdRuntimeLease } from ${JSON.stringify(pathToFileURL(resolve("packages/core/dist/index.js")).href)};\n`,
  );
  write(
    join(out, "node_modules", "@piship", "core", "package.json"),
    '{"type":"module"}\n',
  );
  write(
    join(out, "metadata", "inventory.json"),
    `${JSON.stringify(payloadInventory(out), null, 2)}\n`,
  );
  return out;
}

const checked: string[] = [];
function fakeRun(
  payload: string,
  _command: string,
  args: readonly string[],
): CommandResult {
  checked.push(payload);
  const lock = JSON.parse(
    readFileSync(join(payload, "piship.lock"), "utf8"),
  ) as {
    app: { name: string; version: string };
    runtime: { version: string };
  };
  if (args[0] === "version")
    return {
      status: 0,
      stdout: `${lock.app.name} ${lock.app.version}\nPi ${lock.runtime.version} (PiShip 0.1.0)\n`,
      stderr: "",
    };
  if (args[0] === "--smoke")
    return { status: 0, stdout: '{"initialized":true}\n', stderr: "" };
  if (args[0] === "capabilities")
    return { status: 0, stdout: "[]\n", stderr: "" };
  return { status: 2, stdout: "", stderr: `unexpected ${args.join(" ")}` };
}

// What \`npm audit signatures\` answers for the fake payload, whose one
// package the npm lock does not list. The default auditor spawns npm for
// every release, which costs a process start (seconds on Windows) and shows
// nothing these tests check; release.test.ts covers the signature policy.
const signatureAuditor = () => ({
  status: 1,
  stdout: JSON.stringify({
    error: { summary: "found no installed dependencies to audit", detail: "" },
  }),
  stderr: "",
});

async function release(
  version: string,
  rollback = true,
  storage?: "file" | "system",
  keys?: readonly Key[],
  rootKeys?: readonly Key[],
) {
  const path = project(version, rollback, storage, keys, rootKeys);
  return buildRelease(path, {
    outputRoot: join(dirname(path), "dist"),
    assemble: fakeAssemble,
    runTest: fakeRun,
    scanner: () => ({ auditReportVersion: 2, vulnerabilities: {} }),
    signatureAuditor,
  });
}

function sign(
  directory: string,
  archives: string[],
  channel = "stable",
  key: typeof KEY = KEY,
  previous?: typeof KEY,
) {
  return signChannel({
    directory,
    channel,
    archives,
    privateKeyPem: key.privateKeyPem,
    keyId: key.id,
    ...(previous
      ? {
          previousKeys: [{ id: previous.id, publicKey: previous.publicKey }],
        }
      : {}),
  });
}

/** Releases A (1.0.0) and B (1.1.0); the channel offered A at sequence 1 and now offers B at sequence 2. */
async function fixture(
  options: {
    rollbackB?: boolean;
    storageA?: "file" | "system";
    storageB?: "file" | "system";
  } = {},
) {
  const a = await release("1.0.0", true, options.storageA);
  const b = await release("1.1.0", options.rollbackB ?? true, options.storageB);
  const channelDir = temp("piship-channel-");
  await sign(channelDir, [a.archive]);
  const old = temp("piship-old-channel-");
  cpSync(join(channelDir, "stable.json"), join(old, "stable.json"));
  cpSync(join(channelDir, "stable.json.sig"), join(old, "stable.json.sig"));
  await sign(channelDir, [b.archive]);
  const opts: UpdateOptions = { source: channelDir, runCheck: fakeRun };
  return { a, b, channelDir, old, opts };
}

const PARTIAL_FILE = join("node_modules", "alpha", "package.json");

/** Make the archive extraction leave a partly written tree where it writes, and throw, as a process killed during it would. */
function killArchiveExtraction() {
  return vi
    .spyOn(archiveModule, "extractArchive")
    .mockImplementation(async (_archive, destination) => {
      write(join(destination, "x", "partial", PARTIAL_FILE), '{"name":"al');
      throw new Error("killed");
    });
}

/** Make the copy of a release directory leave a partial copy at its destination, and throw. */
function killDirectoryCopy() {
  return vi
    .spyOn(copyModule, "copyTree")
    .mockImplementation(async (_source, destination) => {
      write(join(destination, PARTIAL_FILE), '{"name":"al');
      throw new Error("killed");
    });
}

/** A version directory no receipt references, partly written: what an earlier PiShip left when killed during an extraction. */
function strandCandidate(version: string): string {
  const directory = join(appsDir(), version);
  write(join(directory, PARTIAL_FILE), '{"name":"al');
  return directory;
}

/** Make every directory rename fail as it does on Windows while a scanner holds a file in it. */
function busyRenames() {
  const real = filesModule.renameWithRetry;
  return vi
    .spyOn(filesModule, "renameWithRetry")
    .mockImplementation((from, to) =>
      real(from, to, {
        platform: "win32",
        sleep: () => {},
        rename: () => {
          throw Object.assign(new Error("EBUSY: resource busy or locked"), {
            code: "EBUSY",
          });
        },
      }),
    );
}

function receiptFile(): string {
  return join(
    process.env.PISHIP_INSTALL_HOME as string,
    "receipts",
    `${ID}.json`,
  );
}

function stateDir(): string {
  return join(process.env.PISHIP_STATE_HOME as string, ID);
}
function appsDir(): string {
  return join(process.env.PISHIP_INSTALL_HOME as string, "apps", ID);
}
function apps(): string[] {
  return existsSync(appsDir()) ? readdirSync(appsDir()).sort() : [];
}

function seedState(): void {
  const state = stateDir();
  write(
    join(state, "identity", "session.json"),
    JSON.stringify({
      schema: "piship-identity-metadata/v1",
      subject: "user-1",
      credential_ref: "file:identity",
    }),
  );
  write(
    join(state, "credentials-metadata", "inference.json"),
    JSON.stringify({
      schema: "piship-credential-metadata/v1",
      credential_ref: "file:inference",
    }),
  );
  write(join(state, "secrets", "inference"), `${SENTINEL}\n`);
  write(
    join(state, "config", "preferences.json"),
    JSON.stringify({ schema: "piship-preferences/v1", theme: "dark" }),
  );
  write(join(state, "sessions", "s1.jsonl"), '{"type":"message"}\n');
}

function files(root: string): string[] {
  if (!existsSync(root)) return [];
  const out: string[] = [];
  const visit = (dir: string) => {
    for (const name of readdirSync(dir)) {
      const path = join(dir, name);
      if (statSync(path).isDirectory()) visit(path);
      else out.push(path);
    }
  };
  visit(root);
  return out.sort();
}
function treeHash(root: string): Record<string, string> {
  return Object.fromEntries(
    files(root).map((path) => [
      relative(root, path),
      createHash("sha256").update(readFileSync(path)).digest("hex"),
    ]),
  );
}
function containing(needle: string): string[] {
  return [
    ...files(process.env.PISHIP_INSTALL_HOME as string),
    ...files(process.env.PISHIP_STATE_HOME as string),
    ...files(process.env.PISHIP_BIN_HOME as string),
  ].filter((path) => readFileSync(path).includes(needle));
}

async function rejection(
  promise: Promise<unknown>,
): Promise<Error & { code?: string; retryable?: boolean }> {
  try {
    await promise;
  } catch (error) {
    return error as Error & { code?: string; retryable?: boolean };
  }
  throw new Error("expected a rejection");
}

/**
 * A memory secret store that records deletions. While `locked` answers true
 * for a reference, `get` and `delete` throw SECRET_STORE_UNAVAILABLE, as a
 * locked keyring does.
 */
function testStore(locked: (ref: string) => boolean = () => false) {
  const memory = new MemorySecretStore();
  const deleted: string[] = [];
  const refuse = () =>
    new PiShipError("SECRET_STORE_UNAVAILABLE", "The keychain is locked", {
      component: "credential",
    });
  const store: SecretStore = {
    kind: memory.kind,
    description: "test store",
    put: (ref, value) => memory.put(ref, value),
    async get(ref) {
      if (locked(ref)) throw refuse();
      return memory.get(ref);
    },
    async delete(ref) {
      deleted.push(ref);
      if (locked(ref)) throw refuse();
      await memory.delete(ref);
    },
  };
  return { store, memory, deleted };
}

function flipByte(path: string): void {
  const bytes = readFileSync(path);
  const at = Math.floor(bytes.length / 2);
  bytes[at] = (bytes[at] as number) ^ 0xff;
  writeFileSync(path, bytes);
}

// ----------------------------------------------------------------- install

describe.runIf(HOST_EVIDENCED)("install", () => {
  it("installs a release archive with a v1 receipt, launcher, and shim", async () => {
    const a = await release("1.0.0");
    const receipt = await installDistribution(a.archive);
    const payload = join(appsDir(), "1.0.0");
    const launcher = join(appsDir(), "launch.mjs");
    const commandPath = join(
      process.env.PISHIP_BIN_HOME as string,
      process.platform === "win32" ? `${ID}.cmd` : ID,
    );
    expect(receipt).toMatchObject({
      schema: RECEIPT_SCHEMA,
      app: { id: ID, command: ID, version: "1.0.0", name: "AcmePi" },
      payload,
      commandPath,
      launcher,
      active: "1.0.0",
      channel: "stable",
      releases: [
        {
          version: "1.0.0",
          payload,
          release: {
            target: currentTarget(),
            channel: "stable",
            pi: "1.0.3",
            piship: PISHIP_VERSION,
            lockSha256: a.metadata.lockSha256,
            archiveSha256: a.sha256,
          },
        },
      ],
    });
    expect(receipt).not.toHaveProperty("previous");
    expect(
      Date.parse(receipt.releases[0]?.installedAt as string),
    ).not.toBeNaN();
    expect(readInstallReceipt(ID)).toEqual(receipt);
    expect(verifyPayload(payload).app.version).toBe("1.0.0");
    expect(apps()).toEqual(["1.0.0", "launch.mjs"]);
    const launcherSource = readFileSync(launcher, "utf8");
    expect(launcherSource).toContain('"acmepi.json"');
    expect(launcherSource).toContain("receipt.active");
    const shim = readFileSync(commandPath, "utf8");
    expect(shim).toContain(launcher);
    if (process.platform !== "win32")
      expect(statSync(commandPath).mode & 0o111).not.toBe(0);
    // Staging is gone; the state directory is not created by install.
    expect(
      readdirSync(process.env.PISHIP_INSTALL_HOME as string).sort(),
    ).toEqual(["apps", "receipts", "trust"]);
    expect(lifecycleStatus(ID, verifyPayload(payload))).toEqual({
      installed: true,
      tracked: true,
      active: "1.0.0",
      channel: "stable",
      channels: ["stable", "candidate"],
      source: `\${ACMEPI_UPDATE_SOURCE}`,
      trustedKeys: 1,
      keys: [{ id: KEY.id, fingerprint: keyFingerprint(KEY.publicKey) }],
      updateRoot: {
        version: 1,
        expires: "2099-01-01T00:00:00Z",
        origin: "bootstrap",
        channelThreshold: 1,
      },
      rollback: true,
      fromRelease: true,
      leftovers: [],
    });
    // doctor runs inside a launcher that holds a lease: its own lease is
    // not another live session.
    const releaseLease = holdRuntimeLease(ID, "1.0.0");
    try {
      expect(runtimeLeases(ID).map((lease) => lease.self)).toEqual([true]);
      expect(
        lifecycleStatus(ID, verifyPayload(payload)).runtimeLeases,
      ).toBeUndefined();
    } finally {
      releaseLease();
    }
  });

  it("installs a release directory without an archive digest", async () => {
    const a = await release("1.0.0");
    const receipt = await installDistribution(a.directory);
    expect(receipt.releases[0]?.release).toBeDefined();
    expect(receipt.releases[0]?.release).not.toHaveProperty("archiveSha256");
    // The release directory is left untouched.
    expect(existsSync(join(a.directory, "payload", "piship.lock"))).toBe(true);
  });

  it("installs an archive whose SHA-256 matches the expected digest", async () => {
    const a = await release("1.0.0");
    const receipt = await installDistribution(a.archive, false, {
      expectedSha256: a.sha256.toUpperCase(),
    });
    expect(receipt.releases[0]?.release?.archiveSha256).toBe(a.sha256);
  });

  it("reads an installed archive once, hashing it and every payload file as they are written", async () => {
    const a = await release("1.0.0");
    const hashed = vi.spyOn(archiveModule, "sha256File");
    const extracted = vi.spyOn(archiveModule, "extractArchive");
    try {
      const receipt = await installDistribution(a.archive);
      // The receipt records the digest of the bytes that were extracted.
      expect(receipt.releases[0]?.release?.archiveSha256).toBe(a.sha256);
      expect(hashed).not.toHaveBeenCalled();
      expect(extracted).toHaveBeenCalledTimes(1);
      expect(extracted.mock.calls[0]?.[2]).toMatchObject({ digests: true });
      expect(extracted.mock.calls[0]?.[2]?.hash).not.toBe(false);
    } finally {
      hashed.mockRestore();
      extracted.mockRestore();
    }
  });

  it("checks an expected digest against the bytes it read, never a second read of the file", async () => {
    const a = await release("1.0.0");
    const hashed = vi.spyOn(archiveModule, "sha256File");
    const extracted = vi.spyOn(archiveModule, "extractArchive");
    try {
      await installDistribution(a.archive, false, { expectedSha256: a.sha256 });
      expect(hashed).not.toHaveBeenCalled();
      expect(extracted).toHaveBeenCalledTimes(1);
    } finally {
      hashed.mockRestore();
      extracted.mockRestore();
    }
  });

  it("refuses an archive swapped for another release after its digest was published", async () => {
    const a = await release("1.0.0");
    // The same release built again with another timestamp: another archive
    // under the same root name.
    process.env.SOURCE_DATE_EPOCH = "1767312000";
    const other = await release("1.0.0");
    expect(other.sha256).not.toBe(a.sha256);
    // The swap happens just before the one read: whatever is read is what is
    // hashed, so the swapped bytes cannot pass for the published digest.
    const real = archiveModule.extractArchive;
    const extracted = vi
      .spyOn(archiveModule, "extractArchive")
      .mockImplementation(async (archive, destination, options) => {
        cpSync(other.archive, archive);
        return real(archive, destination, options);
      });
    try {
      const error = await rejection(
        installDistribution(a.archive, false, { expectedSha256: a.sha256 }),
      );
      expect(error.code).toBe("INTEGRITY_FAILED");
      expect(error.message).toContain("does not match the expected");
    } finally {
      extracted.mockRestore();
    }
    expect(apps()).toEqual([]);
    expect(existsSync(receiptFile())).toBe(false);
  });

  it("refuses a corrupted file inside an otherwise valid archive, installing nothing", async () => {
    const a = await release("1.0.0");
    const dir = temp();
    cpSync(a.directory, join(dir, a.name), { recursive: true });
    write(
      join(dir, a.name, "payload", "resources", "resources", "AGENTS.md"),
      "# corrupted after the inventory was written\n",
    );
    const archive = join(dir, `${a.name}.tar.gz`);
    await archiveModule.createArchive(join(dir, a.name), a.name, archive);
    const error = await rejection(installDistribution(archive));
    expect(error.code).toBe("INTEGRITY_FAILED");
    expect(error.message).toContain("modified: resources/resources/AGENTS.md");
    expect(apps()).toEqual([]);
    expect(existsSync(receiptFile())).toBe(false);
    // Nothing of the extraction is left in the install home.
    expect(
      readdirSync(process.env.PISHIP_INSTALL_HOME as string).filter(
        (name) => name !== "receipts" && name !== "apps",
      ),
    ).toEqual([]);
  });

  it.runIf(process.platform !== "win32")(
    "copies a release directory's files rather than linking them off Windows",
    async () => {
      const a = await release("1.0.0");
      const receipt = await installDistribution(a.directory);
      const installed = statSync(join(receipt.payload, "piship.lock"));
      expect(installed.nlink).toBe(1);
      expect(installed.ino).not.toBe(
        statSync(join(a.directory, "payload", "piship.lock")).ino,
      );
    },
  );

  it("refuses a truncated file in a release directory, removing the partial copy", async () => {
    const a = await release("1.0.0");
    const file = join(
      a.directory,
      "payload",
      "resources",
      "resources",
      "AGENTS.md",
    );
    const original = readFileSync(file);
    writeFileSync(file, original.subarray(0, 4));
    const error = await rejection(installDistribution(a.directory));
    expect(error.code).toBe("INTEGRITY_FAILED");
    expect(error.message).toMatch(
      /modified: resources\/resources\/AGENTS\.md \(expected [0-9a-f]{16}, actual [0-9a-f]{16}\)/,
    );
    expect(existsSync(join(appsDir(), "1.0.0"))).toBe(false);
    expect(existsSync(receiptFile())).toBe(false);
    // Restored, the same directory installs.
    writeFileSync(file, original);
    expect((await installDistribution(a.directory)).active).toBe("1.0.0");
  });

  it("reports the phases of an install under PISHIP_DEBUG_TIMING", async () => {
    const a = await release("1.0.0");
    const written: string[] = [];
    const stderr = vi
      .spyOn(process.stderr, "write")
      .mockImplementation((chunk: string | Uint8Array) => {
        written.push(String(chunk));
        return true;
      });
    process.env.PISHIP_DEBUG_TIMING = "1";
    try {
      await installDistribution(a.archive);
    } finally {
      delete process.env.PISHIP_DEBUG_TIMING;
      stderr.mockRestore();
    }
    const labels = written
      .join("")
      .split("\n")
      .filter((line) => line.startsWith("install "))
      .map((line) => line.slice(0, line.indexOf(":")));
    expect(labels).toEqual([
      "install verify release",
      "install preflight",
      "install place payload",
      "install launcher and trust state",
      "install receipt",
      "install command shim",
      "install cleanup",
    ]);
  });

  it("refuses an archive whose SHA-256 differs from the expected digest, installing nothing", async () => {
    const a = await release("1.0.0");
    const error = await rejection(
      installDistribution(a.archive, false, { expectedSha256: "f".repeat(64) }),
    );
    expect(error.code).toBe("INTEGRITY_FAILED");
    expect(error.message).toContain(
      `does not match the expected ${"f".repeat(64)}`,
    );
    expect(apps()).toEqual([]);
    expect(files(process.env.PISHIP_BIN_HOME as string)).toEqual([]);
    expect(
      existsSync(
        join(
          process.env.PISHIP_INSTALL_HOME as string,
          "receipts",
          `${ID}.json`,
        ),
      ),
    ).toBe(false);
  });

  it("refuses an expected digest for a directory or in the wrong format", async () => {
    const a = await release("1.0.0");
    const directory = await rejection(
      installDistribution(a.directory, false, { expectedSha256: a.sha256 }),
    );
    expect(directory).toBeInstanceOf(PiShipError);
    expect(directory.code).toBe("CONFIG_INVALID");
    expect(directory.message).toContain("is a directory");
    expect((directory as PiShipError).userAction).toContain(".tar.gz");
    const malformed = await rejection(
      installDistribution(a.archive, false, { expectedSha256: "abc" }),
    );
    expect(malformed.code).toBe("CONFIG_INVALID");
    expect(malformed.message).toContain("64 hexadecimal characters");
    expect(apps()).toEqual([]);
  });

  it("installs when every expected key fingerprint is pinned", async () => {
    const backup = generateSigningKey("test-backup");
    const a = await release("1.0.0", true, undefined, [KEY, backup]);
    const receipt = await installDistribution(a.archive, false, {
      expectedKeys: [keyFingerprint(backup.publicKey)],
    });
    expect(receipt.active).toBe("1.0.0");
    // inspect reports the pinned keys by fingerprint.
    const info = inspection(verifyPayload(receipt.payload), stateDir());
    expect(info.trust).toEqual({
      keys: [
        { id: KEY.id, fingerprint: keyFingerprint(KEY.publicKey) },
        { id: backup.id, fingerprint: keyFingerprint(backup.publicKey) },
      ],
    });
    expect(formatInspection(info)).toContain(
      `${backup.id} ${keyFingerprint(backup.publicKey)}`,
    );
  });

  it("refuses a release that does not pin an expected key, installing nothing", async () => {
    const other = generateSigningKey("test-other");
    const a = await release("1.0.0");
    const missing = keyFingerprint(other.publicKey);
    const error = await rejection(
      installDistribution(a.archive, false, {
        expectedKeys: [keyFingerprint(KEY.publicKey), missing],
      }),
    );
    expect(error).toBeInstanceOf(PiShipError);
    expect(error.code).toBe("INTEGRITY_FAILED");
    expect(error.message).toContain(missing);
    expect(error.message).not.toContain(keyFingerprint(KEY.publicKey));
    expect(apps()).toEqual([]);
    expect(files(process.env.PISHIP_BIN_HOME as string)).toEqual([]);
    expect(
      readdirSync(process.env.PISHIP_INSTALL_HOME as string).filter(
        (name) => name !== "receipts" && name !== "apps",
      ),
    ).toEqual([]);
    const malformed = await rejection(
      installDistribution(a.archive, false, { expectedKeys: ["abc"] }),
    );
    expect(malformed.code).toBe("CONFIG_INVALID");
  });

  it("refuses collisions and unowned state, leaving nothing behind", async () => {
    const a = await release("1.0.0");
    await installDistribution(a.archive);
    const before = treeHash(process.env.PISHIP_INSTALL_HOME as string);
    const collision = await rejection(installDistribution(a.archive));
    expect(collision.message).toBe(
      "Install collision for acmepi/acmepi; 1.0.0 is already installed. To restore it from a release you trust, run piship repair acmepi <release archive or directory>; to start over, run piship uninstall acmepi (state is kept) and install again with --use-existing-state. acmepi update --from <signed update source> only upgrades to a newer version",
    );
    expect(treeHash(process.env.PISHIP_INSTALL_HOME as string)).toEqual(before);
    uninstallDistribution(ID);
    mkdirSync(stateDir(), { recursive: true });
    await expect(installDistribution(a.archive)).rejects.toThrow(
      /State already exists for acmepi/,
    );
    expect(apps()).toEqual([]);
    await expect(installDistribution(a.archive, true)).resolves.toMatchObject({
      active: "1.0.0",
    });
  });

  it("adopts state that a pre-install test launch created, once", async () => {
    const a = await release("1.0.0");
    // `piship test` launches the payload, which creates the state.
    withTestState({ value: ID }, () =>
      mkdirSync(stateDir(), { recursive: true }),
    );
    expect(isTestCreatedState({ value: ID })).toBe(true);
    await expect(installDistribution(a.archive)).resolves.toMatchObject({
      active: "1.0.0",
    });
    // The install owns the state now; it is not test-created any more.
    expect(existsSync(testStateMarker({ value: ID }))).toBe(false);
    uninstallDistribution(ID);
    await expect(installDistribution(a.archive)).rejects.toThrow(
      /State already exists for acmepi/,
    );
  });

  it("still refuses state that existed before a test launch", async () => {
    const a = await release("1.0.0");
    mkdirSync(stateDir(), { recursive: true });
    withTestState({ value: ID }, () => undefined);
    expect(existsSync(testStateMarker({ value: ID }))).toBe(false);
    await expect(installDistribution(a.archive)).rejects.toThrow(
      /State already exists for acmepi/,
    );
    // A marker naming another distribution is not this one's.
    writeFileSync(
      testStateMarker({ value: ID }),
      JSON.stringify({ schema: "piship-test-state/v1", id: "other" }),
    );
    await expect(installDistribution(a.archive)).rejects.toThrow(
      /State already exists for acmepi/,
    );
    expect(apps()).toEqual([]);
  });

  it("recovers a marked first install interrupted before its receipt", async () => {
    const a = await release("1.0.0");
    mkdirSync(appsDir(), { recursive: true });
    writeFileSync(
      join(appsDir(), ".initial-install.json"),
      JSON.stringify({
        schema: "piship-initial-install/v1",
        id: ID,
        command: ID,
      }),
    );
    writeFileSync(join(appsDir(), "launch.mjs"), "partial launcher");
    const receipt = await installDistribution(a.archive);
    expect(receipt.active).toBe("1.0.0");
    expect(apps()).toEqual(["1.0.0", "launch.mjs"]);
  });

  it("reinstalls after an archive extraction was killed partway", async () => {
    const a = await release("1.0.0");
    const killed = killArchiveExtraction();
    try {
      await expect(installDistribution(a.archive)).rejects.toThrow("killed");
    } finally {
      killed.mockRestore();
    }
    // The archive is extracted into a staging directory, so nothing of it is
    // at the version path and no receipt was written.
    expect(apps()).toEqual([]);
    expect(existsSync(receiptFile())).toBe(false);
    const receipt = await installDistribution(a.archive);
    expect(receipt.active).toBe("1.0.0");
    expect(apps()).toEqual(["1.0.0", "launch.mjs"]);
    expect(() => verifyPayload(receipt.payload)).not.toThrow();
  });

  it("reinstalls after a directory copy was killed partway, with no manual cleanup", async () => {
    const a = await release("1.0.0");
    const killed = killDirectoryCopy();
    try {
      await expect(installDistribution(a.directory)).rejects.toThrow("killed");
    } finally {
      killed.mockRestore();
    }
    // The killed install leaves its marked, partly copied directory and no receipt.
    expect(existsSync(join(appsDir(), ".initial-install.json"))).toBe(true);
    expect(existsSync(join(appsDir(), "1.0.0", PARTIAL_FILE))).toBe(true);
    expect(existsSync(receiptFile())).toBe(false);
    const receipt = await installDistribution(a.directory);
    expect(receipt.active).toBe("1.0.0");
    expect(apps()).toEqual(["1.0.0", "launch.mjs"]);
    expect(() => verifyPayload(receipt.payload)).not.toThrow();
  });

  it("reports a retryable error, changing nothing, when a scanner holds the abandoned install", async () => {
    const a = await release("1.0.0");
    const killed = killDirectoryCopy();
    try {
      await expect(installDistribution(a.directory)).rejects.toThrow("killed");
    } finally {
      killed.mockRestore();
    }
    const busy = busyRenames();
    let error: Awaited<ReturnType<typeof rejection>>;
    try {
      error = await rejection(installDistribution(a.directory));
    } finally {
      busy.mockRestore();
    }
    expect(error).toBeInstanceOf(PiShipError);
    expect(error.code).toBe("UPDATE_FAILED");
    expect(error.retryable).toBe(true);
    expect(error.message).toContain("EBUSY");
    expect((error as PiShipError).userAction).toContain("nothing was changed");
    expect(existsSync(join(appsDir(), "1.0.0", PARTIAL_FILE))).toBe(true);
    expect(existsSync(receiptFile())).toBe(false);
    expect((await installDistribution(a.directory)).active).toBe("1.0.0");
  });

  it("repairs a committed first install whose shim was not written", async () => {
    const a = await release("1.0.0");
    const receipt = await installDistribution(a.archive);
    rmSync(receipt.commandPath);
    writeFileSync(
      join(appsDir(), ".initial-install.json"),
      JSON.stringify({
        schema: "piship-initial-install/v1",
        id: ID,
        command: ID,
      }),
    );
    const repaired = await installDistribution(a.archive);
    expect(repaired).toEqual(receipt);
    expect(existsSync(receipt.commandPath)).toBe(true);
    expect(apps()).toEqual(["1.0.0", "launch.mjs"]);
  });

  // A first install in a child process that is killed (SIGKILL, so no
  // cleanup runs) just before one file operation; the built core is used.
  const INSTALL_CHILD = `import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
const [core, artifact, operation, pattern] = process.argv.slice(2);
const original = fs[operation];
if (original)
  fs[operation] = function (path, ...rest) {
    if (typeof path === "string" && new RegExp(pattern).test(path))
      process.kill(process.pid, "SIGKILL");
    return original.call(this, path, ...rest);
  };
syncBuiltinESMExports();
const { installDistribution } = await import(core);
await installDistribution(artifact);
`;
  function installChild(operation: string, pattern: RegExp, payload: string) {
    const script = join(temp("piship-install-child-"), "install.mjs");
    writeFileSync(script, INSTALL_CHILD);
    return [
      script,
      pathToFileURL(resolve("packages/core/dist/index.js")).href,
      payload,
      operation,
      pattern.source,
    ];
  }

  for (const [phase, operation, pattern] of [
    [
      "the app directory is staged",
      "writeFileSync",
      /\.initial-install\.json$/,
    ],
    ["the payload is installed", "writeFileSync", /launch\.mjs$/],
    ["the launcher is written", "openSync", /receipts[/\\]acmepi\.json/],
    ["the receipt is written", "writeFileSync", /bin[/\\]acmepi(\.cmd)?$/],
    ["the shim is written", "rmSync", /\.initial-install\.json$/],
  ] as const)
    it(`a first install killed after ${phase} is completed by the next install`, async () => {
      const payload = fakeAssemble(project("1.0.0"), temp("piship-payload-"));
      const killed = spawnSync(
        process.execPath,
        installChild(operation, pattern, payload),
        { encoding: "utf8" },
      );
      expect(killed.status, killed.stderr).not.toBe(0);
      expect(killed.stderr).not.toContain("Error");
      const receipt = await installDistribution(payload);
      expect(receipt.active).toBe("1.0.0");
      expect(apps()).toEqual(["1.0.0", "launch.mjs"]);
      expect(readInstallReceipt(ID)).toEqual(receipt);
      expect(existsSync(receipt.commandPath)).toBe(true);
      // Install ignores abandoned staging rather than recursively deleting it.
      const homeEntries = readdirSync(
        process.env.PISHIP_INSTALL_HOME as string,
      ).sort();
      expect(
        homeEntries.filter((name) => !name.startsWith(".staging-")),
      ).toEqual(["apps", "receipts", "trust"]);
      const stagingCount = homeEntries.filter((name) =>
        name.startsWith(".staging-"),
      ).length;
      expect(stagingCount).toBe(
        phase === "the payload is installed" ||
          phase === "the launcher is written"
          ? 2
          : 1,
      );
      uninstallDistribution(ID);
      expect(existsSync(appsDir())).toBe(false);
      expect(existsSync(receipt.commandPath)).toBe(false);
    });

  it("names the directory in the way when no installation is recorded", async () => {
    const payload = fakeAssemble(project("1.0.0"), temp("piship-payload-"));
    mkdirSync(appsDir(), { recursive: true });
    writeFileSync(join(appsDir(), "notes.txt"), "not PiShip's\n");
    await expect(installDistribution(payload)).rejects.toThrow(
      `${appsDir()} exists but no PiShip installation of ${ID} is recorded; move it aside`,
    );
    // Never removed: PiShip did not create it.
    expect(readFileSync(join(appsDir(), "notes.txt"), "utf8")).toBe(
      "not PiShip's\n",
    );
  });

  it("lets exactly one of two concurrent first installs of a distribution win", async () => {
    const payload = fakeAssemble(project("1.0.0"), temp("piship-payload-"));
    const run = () =>
      new Promise<{ status: number | null; stderr: string }>((done) => {
        const child = spawn(
          process.execPath,
          installChild("none", /$^/, payload),
          { stdio: ["ignore", "ignore", "pipe"] },
        );
        let stderr = "";
        child.stderr.on("data", (chunk) => {
          stderr += chunk;
        });
        child.on("close", (status) => done({ status, stderr }));
      });
    const outcomes = await Promise.all([run(), run()]);
    expect(outcomes.filter((item) => item.status === 0)).toHaveLength(1);
    const loser = outcomes.find((item) => item.status !== 0);
    expect(loser?.stderr).toMatch(
      /Another (initial install of acmepi|operation owns command acmepi)|Install collision for acmepi\/acmepi/,
    );
    const receipt = readInstallReceipt(ID);
    expect(apps()).toEqual(["1.0.0", "launch.mjs"]);
    expect(existsSync(receipt.commandPath)).toBe(true);
    uninstallDistribution(ID);
  });

  it("serializes different distributions claiming the same command", async () => {
    const first = fakeAssemble(project("1.0.0"), temp("piship-first-"));
    const otherProject = temp("piship-other-project-");
    const otherManifest = join(otherProject, "piship.yaml");
    write(join(otherProject, "resources", "AGENTS.md"), "# other\n");
    writeFileSync(
      otherManifest,
      manifestSource("1.0.0", true).replace("id: acmepi", "id: otherpi"),
    );
    lockManifest(otherManifest);
    const second = fakeAssemble(otherManifest, temp("piship-second-"));
    const outcomes = await Promise.allSettled([
      installDistribution(first),
      installDistribution(second),
    ]);
    expect(
      outcomes.filter((result) => result.status === "fulfilled"),
    ).toHaveLength(1);
    const winner = outcomes.find((result) => result.status === "fulfilled");
    if (winner?.status !== "fulfilled") throw new Error("No winner");
    const loser = winner.value.app.id === ID ? "otherpi" : ID;
    expect(
      existsSync(
        join(
          process.env.PISHIP_INSTALL_HOME as string,
          "receipts",
          `${loser}.json`,
        ),
      ),
    ).toBe(false);
    const shim = readFileSync(winner.value.commandPath, "utf8");
    expect(() => uninstallDistribution(loser)).toThrow(
      /No PiShip installation/,
    );
    expect(readFileSync(winner.value.commandPath, "utf8")).toBe(shim);
    uninstallDistribution(winner.value.app.id);
  });

  it("keeps a leased payload after it leaves the receipt and reclaims it when the runtime exits", async () => {
    const a = await release("1.0.0");
    const receipt = await installDistribution(a.archive);
    const old = receipt.payload;
    const next = join(appsDir(), "1.1.0");
    mkdirSync(next);
    const releaseLease = holdRuntimeLease(ID, "1.0.0");
    try {
      writeFileSync(
        join(
          process.env.PISHIP_INSTALL_HOME as string,
          "receipts",
          `${ID}.json`,
        ),
        JSON.stringify({
          ...receipt,
          active: "1.1.0",
          payload: next,
          releases: [
            {
              version: "1.1.0",
              payload: next,
              installedAt: new Date().toISOString(),
            },
          ],
        }),
      );
      expect(
        runtimeLeases(ID)
          .filter((item) => item.live)
          .map((item) => item.version),
      ).toContain("1.0.0");
      recoverInstallation(ID);
      expect(existsSync(old)).toBe(true);
      expect(() => uninstallDistribution(ID)).toThrow(/runtime session/);
    } finally {
      releaseLease();
    }
    recoverInstallation(ID);
    expect(existsSync(old)).toBe(false);
    expect(() => uninstallDistribution(ID)).not.toThrow();
  });

  it("installs a local release directory without its release scans, and verifies every payload file as it is copied", async () => {
    const a = await release("1.0.0");
    rmSync(join(a.directory, "sbom.spdx.json"));
    rmSync(join(a.directory, "vulnerabilities.json"));
    rmSync(join(a.directory, "checksums.txt"));
    const receipt = await installDistribution(a.directory);
    expect(receipt.active).toBe("1.0.0");
    expect(() => verifyPayload(receipt.payload)).not.toThrow();
    // A file changed after the inventory was written is refused.
    uninstallDistribution(ID);
    write(
      join(a.directory, "payload", "resources", "resources", "AGENTS.md"),
      "# local resource change\n",
    );
    const error = await rejection(installDistribution(a.directory, true));
    expect(error.code).toBe("INTEGRITY_FAILED");
    expect(error.message).toContain("modified: resources/resources/AGENTS.md");
  });

  it("refuses a tampered release before installing", async () => {
    const a = await release("1.0.0");
    flipByte(a.archive);
    await expect(installDistribution(a.archive)).rejects.toThrow(
      /Release verification/,
    );
    expect(apps()).toEqual([]);
    expect(
      existsSync(
        join(
          process.env.PISHIP_INSTALL_HOME as string,
          "receipts",
          `${ID}.json`,
        ),
      ),
    ).toBe(false);
  });

  it("reads a legacy receipt, and update and rollback ask for a reinstall", async () => {
    const a = await release("1.0.0");
    const payload = join(appsDir(), "1.0.0");
    cpSync(join(a.directory, "payload"), payload, { recursive: true });
    const lock = verifyPayload(payload);
    const commandPath = join(
      process.env.PISHIP_BIN_HOME as string,
      process.platform === "win32" ? `${ID}.cmd` : ID,
    );
    write(
      join(process.env.PISHIP_INSTALL_HOME as string, "receipts", `${ID}.json`),
      JSON.stringify({ app: lock.app, payload, commandPath }),
    );
    expect(readInstallReceipt(ID)).toEqual({
      app: lock.app,
      payload,
      commandPath,
      active: "1.0.0",
      releases: [{ version: "1.0.0", payload, installedAt: "" }],
    });
    const update = await rejection(updateDistribution(ID, { source: temp() }));
    expect(update.code).toBe("UPDATE_FAILED");
    expect(update.message).toMatch(
      /installed by an earlier PiShip without release tracking; reinstall it/,
    );
    await expect(rollbackDistribution(ID)).rejects.toThrow(
      /reinstall it to enable update and rollback/,
    );
    expect(lifecycleStatus(ID, lock)).toMatchObject({
      installed: true,
      tracked: false,
      fromRelease: false,
    });
    // A legacy receipt pointing outside the install home is unsafe.
    write(
      join(process.env.PISHIP_INSTALL_HOME as string, "receipts", `${ID}.json`),
      JSON.stringify({ app: lock.app, payload: temp(), commandPath }),
    );
    expect(() => readInstallReceipt(ID)).toThrow(/Unsafe installation receipt/);
  });

  it("uninstalls a legacy receipt whose shim runs the payload's command script", async () => {
    const a = await release("1.0.0");
    const payload = join(appsDir(), "1.0.0");
    cpSync(join(a.directory, "payload"), payload, { recursive: true });
    const lock = verifyPayload(payload);
    const commandPath = join(
      process.env.PISHIP_BIN_HOME as string,
      process.platform === "win32"
        ? `${lock.app.command}.cmd`
        : lock.app.command,
    );
    const script = join(payload, "bin", lock.app.command);
    // The shim an earlier PiShip wrote, without a launcher.
    write(
      commandPath,
      process.platform === "win32"
        ? `@echo off\r\nwhere node >nul 2>nul || (echo Node.js 22.19.0 or newer is required. Install Node separately. 1>&2 & exit /b 1)\r\nnode "${script}" %*\r\n`
        : `#!/bin/sh\ncommand -v node >/dev/null 2>&1 || { echo 'Node.js 22.19.0 or newer is required. Install Node separately.' >&2; exit 1; }\nexec node '${script.replaceAll("'", "'\"'\"'")}' "$@"\n`,
    );
    const receiptFile = join(
      process.env.PISHIP_INSTALL_HOME as string,
      "receipts",
      `${ID}.json`,
    );
    write(receiptFile, JSON.stringify({ app: lock.app, payload, commandPath }));
    // A shim that runs something else is not this distribution's.
    const owned = readFileSync(commandPath, "utf8");
    writeFileSync(commandPath, owned.replace(script, `${script}-other`));
    expect(() => uninstallDistribution(ID)).toThrow(/not owned/);
    writeFileSync(commandPath, owned);
    uninstallDistribution(ID);
    expect(existsSync(commandPath)).toBe(false);
    expect(existsSync(payload)).toBe(false);
    expect(existsSync(receiptFile)).toBe(false);
  });

  it("recovers an edited command shim only when asked, and never removes a foreign file (#158)", async () => {
    const a = await release("1.0.0");
    const receipt = await installDistribution(a.archive);
    const shim = readFileSync(receipt.commandPath, "utf8");
    // The user added a line to the shim PiShip wrote: it still runs this
    // install's launcher, so it is recognized as PiShip's, edited.
    const edited =
      process.platform === "win32"
        ? shim.replace("@echo off\r\n", "@echo off\r\nset FOO=1\r\n")
        : shim.replace("#!/bin/sh\n", "#!/bin/sh\nexport FOO=1\n");
    writeFileSync(receipt.commandPath, edited);
    const refusal = (() => {
      try {
        uninstallDistribution(ID);
      } catch (error) {
        return (error as Error).message;
      }
      return undefined;
    })();
    expect(refusal).toMatch(/was changed after/);
    expect(refusal).toContain("--remove-edited-shim");
    // Refused before anything was removed.
    expect(readFileSync(receipt.commandPath, "utf8")).toBe(edited);
    expect(existsSync(receipt.payload)).toBe(true);
    uninstallDistribution(ID, { removeEditedShim: true });
    expect(existsSync(receipt.commandPath)).toBe(false);
    expect(existsSync(receipt.payload)).toBe(false);
    // And it installs again.
    const again = await installDistribution(a.archive, true);
    expect(readFileSync(again.commandPath, "utf8")).toBe(shim);
    // A file that does not run this install's launcher is not PiShip's: the
    // flag does not remove it, and the error says how to proceed.
    const foreign =
      process.platform === "win32"
        ? "@echo off\r\necho mine\r\n"
        : "#!/bin/sh\necho mine\n";
    writeFileSync(again.commandPath, foreign);
    expect(() => uninstallDistribution(ID, { removeEditedShim: true })).toThrow(
      /does not run .*launcher.*move it aside/i,
    );
    expect(readFileSync(again.commandPath, "utf8")).toBe(foreign);
    expect(existsSync(again.payload)).toBe(true);
    // Moved aside by the user: the uninstall goes through and leaves it.
    rmSync(again.commandPath);
    uninstallDistribution(ID);
    expect(existsSync(again.payload)).toBe(false);
  });

  it("rejects receipts from a newer PiShip and receipts with foreign paths", async () => {
    const a = await release("1.0.0");
    await installDistribution(a.archive);
    const path = join(
      process.env.PISHIP_INSTALL_HOME as string,
      "receipts",
      `${ID}.json`,
    );
    const receipt = JSON.parse(readFileSync(path, "utf8"));
    writeFileSync(
      path,
      JSON.stringify({ ...receipt, schema: "piship-install/v2" }),
    );
    expect(() => readInstallReceipt(ID)).toThrow(/written by a newer PiShip/);
    // Uninstall leaves that receipt to the PiShip that wrote it.
    expect(() => uninstallDistribution(ID)).toThrow(
      /written by a newer PiShip/,
    );
    expect(existsSync(appsDir())).toBe(true);
    writeFileSync(
      path,
      JSON.stringify({
        ...receipt,
        releases: [{ ...receipt.releases[0], payload: "/tmp/elsewhere" }],
      }),
    );
    expect(() => readInstallReceipt(ID)).toThrow(/Unsafe installation receipt/);
    writeFileSync(path, JSON.stringify({ ...receipt, previous: "0.9.0" }));
    expect(() => readInstallReceipt(ID)).toThrow(/Unsafe installation receipt/);
  });
});

// ------------------------------------------------------------------ update

describe.runIf(HOST_EVIDENCED)("update", () => {
  it("updates A to B with a non-secret snapshot and a state marker", async () => {
    const { a, b, opts } = await fixture();
    seedState();
    await installDistribution(a.archive, true);
    const credentialsBefore = treeHash(
      join(stateDir(), "credentials-metadata"),
    );
    checked.length = 0;
    const result = await updateDistribution(ID, opts);
    expect(result).toMatchObject({
      status: "updated",
      id: ID,
      from: "1.0.0",
      to: "1.1.0",
      channel: "stable",
      keyId: KEY.id,
      notices: [],
    });
    expect(result.migration?.verdict).toBe("safe");
    // Installation never boots the candidate; the first user launch does.
    expect(checked).toEqual([]);
    const receipt = readInstallReceipt(ID);
    expect(receipt).toMatchObject({
      active: "1.1.0",
      previous: "1.0.0",
      payload: join(appsDir(), "1.1.0"),
      app: { version: "1.1.0" },
      channel: "stable",
      channelSequences: { stable: 2 },
      lastCheck: { channel: "stable", result: "updated 1.0.0 -> 1.1.0" },
    });
    expect(receipt.releases.map((item) => item.version)).toEqual([
      "1.1.0",
      "1.0.0",
    ]);
    expect(receipt.releases[0]?.release).toMatchObject({
      archiveSha256: b.sha256,
      lockSha256: b.metadata.lockSha256,
    });
    expect(apps()).toEqual(["1.0.0", "1.1.0", "launch.mjs"]);
    expect(verifyPayload(join(appsDir(), "1.1.0")).app.version).toBe("1.1.0");
    expect(verifyPayload(join(appsDir(), "1.0.0")).app.version).toBe("1.0.0");
    // Snapshot: preferences only, never credentials.
    const snapshot = result.snapshot as string;
    expect(
      snapshot.startsWith(join(stateDir(), "migration", "snapshots")),
    ).toBe(true);
    expect(files(snapshot).map((path) => relative(snapshot, path))).toEqual([
      join("config", "preferences.json"),
      "snapshot.json",
    ]);
    const meta = JSON.parse(
      readFileSync(join(snapshot, "snapshot.json"), "utf8"),
    );
    expect(meta).toMatchObject({
      schema: "piship-snapshot/v1",
      from: "1.0.0",
      to: "1.1.0",
      files: ["config/preferences.json"],
    });
    expect(meta.excluded).toEqual(
      expect.arrayContaining([
        "identity/session.json",
        "credentials-metadata/inference.json",
        "secrets",
        "agent",
      ]),
    );
    expect(containing(SENTINEL)).toEqual([
      join(stateDir(), "secrets", "inference"),
    ]);
    // Readable credentials stay in place.
    expect(treeHash(join(stateDir(), "credentials-metadata"))).toEqual(
      credentialsBefore,
    );
    expect(readStateMarker(stateDir())).toEqual({
      schema: "piship-state/v1",
      distribution: ID,
      version: "1.1.0",
      pi: "1.0.3",
      piship: PISHIP_VERSION,
    });
    expect(existsSync(join(appsDir(), ".lifecycle.lock"))).toBe(false);
  });

  it("reports each long step of update and rollback to a progress callback", async () => {
    const { a, opts } = await fixture();
    await installDistribution(a.archive, true);
    const steps: string[] = [];
    await updateDistribution(ID, {
      ...opts,
      progress: (step) => steps.push(step),
    });
    await rollbackDistribution(ID, {
      runCheck: fakeRun,
      progress: (step) => steps.push(step),
    });
    expect(steps.map((step) => step.replace(/\(.*\)/, "(size)"))).toEqual([
      "Checking the stable channel",
      "Downloading 1.1.0 (size)",
      "Verifying the 1.1.0 release",
      "Switching to 1.1.0",
      "Verifying the retained 1.0.0 release",
      "Switching to 1.0.0",
    ]);
  });

  it("reactivates unchanged retained bytes even while a runtime session uses them", async () => {
    const { a, opts } = await fixture();
    await installDistribution(a.archive, true);
    await updateDistribution(ID, opts);
    await rollbackDistribution(ID, { runCheck: fakeRun });
    // A session started on 1.1.0 before the rollback is still running.
    const retained = join(appsDir(), "1.1.0");
    const marker = join(retained, "in-use-by-session");
    writeFileSync(marker, "running");
    const releaseLease = holdRuntimeLease(ID, "1.1.0");
    try {
      expect(await updateDistribution(ID, opts)).toMatchObject({
        status: "updated",
        to: "1.1.0",
      });
      expect(readFileSync(marker, "utf8")).toBe("running");
      expect(readInstallReceipt(ID).active).toBe("1.1.0");
    } finally {
      releaseLease();
    }
    expect(await updateDistribution(ID, opts)).toMatchObject({
      status: "up-to-date",
    });
  });

  it("retries an update that failed during extraction: the partial candidate is set aside", async () => {
    const { a, opts } = await fixture();
    await installDistribution(a.archive);
    const killed = killArchiveExtraction();
    try {
      await expect(updateDistribution(ID, opts)).rejects.toThrow("killed");
    } finally {
      killed.mockRestore();
    }
    // The extraction writes into the version directory itself, which nothing
    // references: the receipt is unchanged.
    expect(readInstallReceipt(ID).active).toBe("1.0.0");
    expect(
      existsSync(join(appsDir(), "1.1.0", "x", "partial", PARTIAL_FILE)),
    ).toBe(true);
    expect((await updateDistribution(ID, opts)).status).toBe("updated");
    expect(() => verifyPayload(join(appsDir(), "1.1.0"))).not.toThrow();
    expect(
      apps().filter((name) => name.startsWith(".retained-1.1.0-")),
    ).toHaveLength(1);
  });

  it("replaces an unreferenced candidate stranded at the version path", async () => {
    const { a, opts } = await fixture();
    await installDistribution(a.archive);
    strandCandidate("1.1.0");
    expect((await updateDistribution(ID, opts)).status).toBe("updated");
    expect(readInstallReceipt(ID).active).toBe("1.1.0");
    expect(() => verifyPayload(join(appsDir(), "1.1.0"))).not.toThrow();
    // The stranded tree was moved aside in one rename; recovery removes it.
    const aside = apps().filter((name) => name.startsWith(".retained-1.1.0-"));
    expect(aside).toHaveLength(1);
    expect(recoverInstallation(ID)).toEqual(aside);
  });

  it("does not move aside a candidate a running session holds", async () => {
    const { a, opts } = await fixture();
    await installDistribution(a.archive);
    strandCandidate("1.1.0");
    const releaseLease = holdRuntimeLease(ID, "1.1.0");
    try {
      const error = await rejection(updateDistribution(ID, opts));
      expect(error.code).toBe("UPDATE_FAILED");
      expect(error.retryable).toBe(true);
      expect(error.message).toContain("running session");
      expect(existsSync(join(appsDir(), "1.1.0", PARTIAL_FILE))).toBe(true);
      expect(readInstallReceipt(ID).active).toBe("1.0.0");
    } finally {
      releaseLease();
    }
    expect((await updateDistribution(ID, opts)).status).toBe("updated");
  });

  it("reports a retryable error and keeps the active release when a scanner holds the stale candidate", async () => {
    const { a, opts } = await fixture();
    await installDistribution(a.archive);
    strandCandidate("1.1.0");
    const busy = busyRenames();
    let error: Awaited<ReturnType<typeof rejection>>;
    try {
      error = await rejection(updateDistribution(ID, opts));
    } finally {
      busy.mockRestore();
    }
    expect(error).toBeInstanceOf(PiShipError);
    expect(error.code).toBe("UPDATE_FAILED");
    expect(error.retryable).toBe(true);
    expect(error.message).toContain("EBUSY");
    expect(error.message).toContain(join(appsDir(), "1.1.0"));
    expect(readInstallReceipt(ID).active).toBe("1.0.0");
    expect(existsSync(join(appsDir(), "1.1.0", PARTIAL_FILE))).toBe(true);
    expect((await updateDistribution(ID, opts)).status).toBe("updated");
  });

  it("replaces a retained release the channel has re-signed with other archive bytes", async () => {
    const { a, b, channelDir, opts } = await fixture();
    await installDistribution(a.archive);
    await updateDistribution(ID, opts);
    await rollbackDistribution(ID, { runCheck: fakeRun });
    expect(readInstallReceipt(ID)).toMatchObject({
      active: "1.0.0",
      previous: "1.1.0",
    });
    // The same version built again with another timestamp: other archive bytes.
    process.env.SOURCE_DATE_EPOCH = "1767312000";
    const other = await release("1.1.0");
    expect(other.sha256).not.toBe(b.sha256);
    await sign(channelDir, [other.archive]);
    const result = await updateDistribution(ID, opts);
    expect(result.status).toBe("updated");
    expect(result.notices.join("\n")).toContain(
      "built from other archive bytes than the channel now offers",
    );
    const receipt = readInstallReceipt(ID);
    // Rollback now returns to the release that was active, which is intact.
    expect(receipt).toMatchObject({ active: "1.1.0", previous: "1.0.0" });
    expect(receipt.releases[0]?.release?.archiveSha256).toBe(other.sha256);
    expect(() => verifyPayload(join(appsDir(), "1.1.0"))).not.toThrow();
    expect(() => verifyPayload(join(appsDir(), "1.0.0"))).not.toThrow();
    expect(
      apps().filter((name) => name.startsWith(".retained-1.1.0-")),
    ).toHaveLength(1);
  });

  it("puts back a replaced retained release when the update fails before its commit", async () => {
    const { a, b, channelDir, opts } = await fixture();
    await installDistribution(a.archive);
    await updateDistribution(ID, opts);
    await rollbackDistribution(ID, { runCheck: fakeRun });
    const retained = join(appsDir(), "1.1.0");
    const before = treeHash(retained);
    process.env.SOURCE_DATE_EPOCH = "1767312000";
    const other = await release("1.1.0");
    expect(other.sha256).not.toBe(b.sha256);
    await sign(channelDir, [other.archive]);
    const error = await rejection(
      updateDistribution(ID, {
        ...opts,
        faults: (phase) => {
          if (phase === "verified") throw new Error("interrupted");
        },
      }),
    );
    expect(error.message).toBe("interrupted");
    // The rollback target is the release it was: same files, same receipt.
    expect(treeHash(retained)).toEqual(before);
    expect(readInstallReceipt(ID)).toMatchObject({
      active: "1.0.0",
      previous: "1.1.0",
    });
    expect(() => verifyPayload(retained)).not.toThrow();
    expect(
      apps().filter((name) => name.startsWith(".retained-1.1.0-")),
    ).toHaveLength(1);
  });

  it("does not replace a retained release a running session holds", async () => {
    const { a, b, channelDir, opts } = await fixture();
    await installDistribution(a.archive);
    await updateDistribution(ID, opts);
    await rollbackDistribution(ID, { runCheck: fakeRun });
    const retained = join(appsDir(), "1.1.0");
    const before = treeHash(retained);
    process.env.SOURCE_DATE_EPOCH = "1767312000";
    const other = await release("1.1.0");
    expect(other.sha256).not.toBe(b.sha256);
    await sign(channelDir, [other.archive]);
    const releaseLease = holdRuntimeLease(ID, "1.1.0");
    try {
      const error = await rejection(updateDistribution(ID, opts));
      expect(error.code).toBe("UPDATE_FAILED");
      expect(error.retryable).toBe(true);
    } finally {
      releaseLease();
    }
    expect(treeHash(retained)).toEqual(before);
    expect(readInstallReceipt(ID).active).toBe("1.0.0");
  });

  it("keeps receipt-retained bytes intact when reactivation is interrupted", async () => {
    const { a, opts } = await fixture();
    await installDistribution(a.archive);
    await updateDistribution(ID, opts);
    await rollbackDistribution(ID);
    const retained = join(appsDir(), "1.1.0");
    const before = treeHash(retained);
    await expect(
      updateDistribution(ID, {
        ...opts,
        faults: (phase) => {
          if (phase === "installed")
            throw new Error("interrupted reactivation");
        },
      }),
    ).rejects.toThrow("interrupted reactivation");
    expect(readInstallReceipt(ID).active).toBe("1.0.0");
    expect(treeHash(retained)).toEqual(before);
    expect(apps()).toEqual(["1.0.0", "1.1.0", "launch.mjs"]);
    expect((await updateDistribution(ID, opts)).status).toBe("updated");
  });

  it("reports up-to-date on the next run", async () => {
    const { a, opts } = await fixture();
    await installDistribution(a.archive);
    await updateDistribution(ID, opts);
    const result = await updateDistribution(ID, opts);
    expect(result).toMatchObject({
      status: "up-to-date",
      from: "1.1.0",
      channel: "stable",
    });
    expect(readInstallReceipt(ID).lastCheck?.result).toBe("up-to-date");
    expect(apps()).toEqual(["1.0.0", "1.1.0", "launch.mjs"]);
  });

  it("check mode records the check and changes nothing else", async () => {
    const { a, opts } = await fixture();
    seedState();
    await installDistribution(a.archive, true);
    const before = readInstallReceipt(ID);
    const state = treeHash(stateDir());
    const result = await updateDistribution(ID, { ...opts, check: true });
    expect(result).toMatchObject({
      status: "available",
      from: "1.0.0",
      to: "1.1.0",
    });
    const after = readInstallReceipt(ID);
    expect(after.lastCheck).toMatchObject({
      channel: "stable",
      result: "available 1.1.0",
    });
    const { lastCheck: _l, channelSequences: _c, ...rest } = after;
    expect(rest).toEqual(before);
    expect(apps()).toEqual(["1.0.0", "launch.mjs"]);
    expect(treeHash(stateDir())).toEqual(state);
  });

  it("refuses a channel the distribution does not allow", async () => {
    const { a, opts } = await fixture();
    await installDistribution(a.archive);
    const error = await rejection(
      updateDistribution(ID, { ...opts, channel: "dev" }),
    );
    expect(error.code).toBe("POLICY_DENIED");
    expect(error.message).toMatch(
      /Channel dev is not allowed by this distribution \(allowed: stable, candidate\)/,
    );
    expect(readInstallReceipt(ID).active).toBe("1.0.0");
  });

  it("falls back from a saved channel that is no longer allowed", async () => {
    const { a, opts } = await fixture();
    await installDistribution(a.archive);
    const path = join(
      process.env.PISHIP_INSTALL_HOME as string,
      "receipts",
      `${ID}.json`,
    );
    writeFileSync(
      path,
      JSON.stringify({
        ...JSON.parse(readFileSync(path, "utf8")),
        channel: "dev",
      }),
    );
    const result = await updateDistribution(ID, opts);
    expect(result.status).toBe("updated");
    expect(result.channel).toBe("stable");
    expect(result.notices).toEqual([
      "Channel dev is no longer allowed; using stable",
    ]);
    expect(readInstallReceipt(ID).channel).toBe("stable");
  });

  it("uses an allowed requested channel", async () => {
    const { a, b, opts } = await fixture();
    await installDistribution(a.archive);
    const candidate = temp("piship-candidate-");
    await sign(candidate, [b.archive], "candidate");
    const check = await updateDistribution(ID, {
      ...opts,
      source: candidate,
      channel: "candidate",
      check: true,
    });
    expect(check).toMatchObject({ status: "available", channel: "candidate" });
    // A check does not switch the remembered channel.
    expect(readInstallReceipt(ID).channel).toBe("stable");
    const result = await updateDistribution(ID, {
      ...opts,
      source: candidate,
      channel: "candidate",
    });
    expect(result).toMatchObject({ status: "updated", channel: "candidate" });
    expect(readInstallReceipt(ID)).toMatchObject({
      channel: "candidate",
      channelSequences: { candidate: 1 },
    });
  });

  it("refuses a downgrade offered by the channel", async () => {
    const { a, b, opts } = await fixture();
    await installDistribution(b.archive);
    const older = temp("piship-older-");
    await sign(older, [a.archive]);
    const error = await rejection(
      updateDistribution(ID, { ...opts, source: older }),
    );
    expect(error.code).toBe("UPDATE_FAILED");
    expect(error.message).toMatch(
      /offers 1.0.0, older than the active 1.1.0; downgrades are refused/,
    );
    expect(readInstallReceipt(ID).active).toBe("1.1.0");
    expect(apps()).toEqual(["1.1.0", "launch.mjs"]);
  });

  it("refuses a tampered archive in the channel directory", async () => {
    const { a, b, channelDir, opts } = await fixture();
    await installDistribution(a.archive);
    flipByte(join(channelDir, `${b.name}.tar.gz`));
    const error = await rejection(updateDistribution(ID, opts));
    expect(error.code).toBe("INTEGRITY_FAILED");
    const receipt = readInstallReceipt(ID);
    expect(receipt.active).toBe("1.0.0");
    expect(receipt.releases.map((item) => item.version)).toEqual(["1.0.0"]);
    expect(apps()).toEqual(["1.0.0", "launch.mjs"]);
  });

  it("refuses replayed older channel metadata", async () => {
    const { a, channelDir, old, opts } = await fixture();
    await installDistribution(a.archive);
    await updateDistribution(ID, opts);
    cpSync(join(old, "stable.json"), join(channelDir, "stable.json"));
    cpSync(join(old, "stable.json.sig"), join(channelDir, "stable.json.sig"));
    const error = await rejection(updateDistribution(ID, opts));
    expect(error.code).toBe("INTEGRITY_FAILED");
    expect(error.message).toMatch(
      /sequence 1 is older than the 2 already seen/,
    );
    expect(readInstallReceipt(ID).channelSequences).toEqual({ stable: 2 });
  });

  // Update trust is installation state: a verified root refresh changes it;
  // activating a release, rolling back, or a release lock never does.
  const ROOT = generateSigningKey("test-root");
  function rootBody(
    version: number,
    channel: readonly Key[],
    rootKeys: readonly Key[] = [ROOT],
    expires = "2099-01-01T00:00:00Z",
  ): UpdateRoot {
    const keys = [
      ...rootKeys,
      ...channel.filter(
        (key) => !rootKeys.some((other) => other.id === key.id),
      ),
    ];
    return {
      version,
      expires,
      keys: keys.map((key) => ({ id: key.id, publicKey: key.publicKey })),
      roles: {
        root: { keyIds: rootKeys.map((key) => key.id), threshold: 1 },
        channel: { keyIds: channel.map((key) => key.id), threshold: 1 },
      },
    };
  }
  /** Publish `root/<version>.json` and its signature as trust-root next does. */
  async function publishRoot(
    dir: string,
    body: UpdateRoot,
    signers: readonly (typeof KEY)[],
  ): Promise<void> {
    const text = Buffer.from(hostedRootText(ID, body));
    const entries = [];
    for (const key of signers)
      entries.push(
        await signVerified(
          pemSigner({ keyId: key.id, privateKeyPem: key.privateKeyPem }),
          text,
        ),
      );
    write(join(dir, "root", `${body.version}.json`), text.toString());
    write(
      join(dir, "root", `${body.version}.json.sig`),
      JSON.stringify(buildSignatureEnvelope(entries)),
    );
  }
  /** Re-sign the published channel at the next sequence, as a holder of `key` could. */
  function forgeChannel(dir: string, key: typeof KEY): void {
    const path = join(dir, "stable.json");
    const metadata = JSON.parse(readFileSync(path, "utf8"));
    metadata.sequence += 1;
    const text = `${JSON.stringify(metadata, null, 2)}\n`;
    writeFileSync(path, text);
    writeFileSync(
      `${path}.sig`,
      JSON.stringify(signBytes(Buffer.from(text), key.privateKeyPem, key.id)),
    );
  }
  /** An https update source served from `dir`, recording each request path. */
  function served(dir: string, requested: string[]): UpdateOptions {
    const fetcher = (async (input: URL | string) => {
      const url = new URL(String(input));
      requested.push(url.pathname);
      const file = join(dir, ...url.pathname.split("/").slice(2));
      return existsSync(file)
        ? new Response(readFileSync(file))
        : new Response("", { status: 404 });
    }) as typeof fetch;
    return {
      runCheck: fakeRun,
      fetcher,
      env: { ACMEPI_UPDATE_SOURCE: "https://updates.example.test/acmepi" },
    };
  }

  it("rotates the channel key only through a signed root; a release lock never widens trust", async () => {
    const next = generateSigningKey("test-release-next");
    const a = await release("1.0.0", true, undefined, [KEY], [ROOT]);
    // B's lock also trusts the next key, as any channel signer's release could.
    const b = await release("1.1.0", true, undefined, [KEY, next], [ROOT]);
    const c = await release("1.2.0", true, undefined, [next], [ROOT]);
    const channelDir = temp("piship-channel-");
    const opts: UpdateOptions = { source: channelDir, runCheck: fakeRun };
    await installDistribution(a.archive);
    expect(readTrustState(ID)).toMatchObject({
      origin: "bootstrap",
      root: { version: 1, roles: { channel: { keyIds: [KEY.id] } } },
    });
    await sign(channelDir, [b.archive], "stable", next);
    const early = await rejection(updateDistribution(ID, opts));
    expect(early.code).toBe("INTEGRITY_FAILED");
    expect(early.message).toMatch(
      /Signature key test-release-next is not trusted; trusted keys: test-release$/,
    );
    await sign(channelDir, [b.archive]);
    expect(await updateDistribution(ID, opts)).toMatchObject({
      status: "updated",
      to: "1.1.0",
      keyId: KEY.id,
    });
    // Activating B, whose lock trusts the next key, did not trust it here.
    expect(readTrustState(ID)?.root.roles.channel.keyIds).toEqual([KEY.id]);
    await sign(channelDir, [c.archive], "stable", next, KEY);
    const stillOld = await rejection(updateDistribution(ID, opts));
    expect(stillOld.message).toMatch(/test-release-next is not trusted/);
    // The owner's root 2 moves the channel role to the next key.
    await publishRoot(channelDir, rootBody(2, [next]), [ROOT]);
    const rotated = await updateDistribution(ID, opts);
    expect(rotated).toMatchObject({
      status: "updated",
      to: "1.2.0",
      keyId: next.id,
    });
    expect(rotated.notices).toContain(
      "Update trust advanced to root version 2",
    );
    expect(readTrustState(ID)).toMatchObject({
      origin: "remote",
      root: { version: 2 },
      removedKeys: [
        {
          id: KEY.id,
          fingerprint: keyFingerprint(KEY.publicKey),
          role: "channel",
          version: 2,
        },
      ],
    });
    // The receipt retires the removed channel key too, so a PiShip v0.7 CLI
    // (which trusts its lock keys minus the retired keys) never trusts it
    // again after a rollback to a release it installed.
    const retired = readInstallReceipt(ID).retiredKeys ?? [];
    expect(retired).toEqual([
      {
        id: KEY.id,
        fingerprint: keyFingerprint(KEY.publicKey),
        release: "root 2",
      },
    ]);
    expect(
      [KEY, next]
        .filter(
          (key) =>
            !retired.some(
              (item) => item.fingerprint === keyFingerprint(key.publicKey),
            ),
        )
        .map((key) => key.id),
    ).toEqual([next.id]);
    // The removed key no longer counts, even at a higher sequence.
    forgeChannel(channelDir, KEY);
    expect((await rejection(updateDistribution(ID, opts))).message).toMatch(
      /Signature key test-release is not trusted; trusted keys: test-release-next$/,
    );
    // Rolling back to B, whose lock trusts the old key, does not restore it.
    await rollbackDistribution(ID, { runCheck: fakeRun });
    expect(readInstallReceipt(ID).active).toBe("1.1.0");
    expect(readTrustState(ID)?.root.version).toBe(2);
    forgeChannel(channelDir, KEY);
    expect((await rejection(updateDistribution(ID, opts))).message).toMatch(
      /Signature key test-release is not trusted/,
    );
    expect(
      lifecycleStatus(ID, verifyPayload(join(appsDir(), "1.1.0"))),
    ).toMatchObject({
      trustedKeys: 1,
      updateRoot: { version: 2, origin: "remote", channelThreshold: 1 },
      keys: [
        { id: next.id, fingerprint: keyFingerprint(next.publicKey) },
        {
          id: KEY.id,
          fingerprint: keyFingerprint(KEY.publicKey),
          retiredBy: "root 2",
        },
      ],
    });
  });

  it("an emergency root removes a compromised channel key before anything is downloaded", async () => {
    const backup = generateSigningKey("test-release-backup");
    const a = await release("1.0.0", true, undefined, [KEY], [ROOT]);
    const b = await release("1.1.0", true, undefined, [KEY], [ROOT]);
    const channelDir = temp("piship-channel-");
    await installDistribution(a.archive);
    // Whoever holds KEY publishes B under it ...
    await sign(channelDir, [b.archive]);
    // ... after the owner's emergency root 2 took KEY out.
    await publishRoot(channelDir, rootBody(2, [backup]), [ROOT]);
    const requested: string[] = [];
    const error = await rejection(
      updateDistribution(ID, served(channelDir, requested)),
    );
    expect(error.code).toBe("INTEGRITY_FAILED");
    expect(error.message).toMatch(
      /Signature key test-release is not trusted; trusted keys: test-release-backup$/,
    );
    // Root first, then the channel; the archive is never fetched.
    expect(requested).toEqual([
      "/acmepi/root/2.json",
      "/acmepi/root/2.json.sig",
      "/acmepi/root/3.json",
      "/acmepi/stable.json",
      "/acmepi/stable.json.sig",
    ]);
    expect(readInstallReceipt(ID).active).toBe("1.0.0");
    expect(apps()).toEqual(["1.0.0", "launch.mjs"]);
    // The failed update still persisted the newer root.
    expect(readTrustState(ID)?.root.version).toBe(2);
    await sign(channelDir, [b.archive], "stable", backup, KEY);
    expect(await updateDistribution(ID, served(channelDir, []))).toMatchObject({
      status: "updated",
      to: "1.1.0",
      keyId: backup.id,
    });
  });

  it("an expired final root cannot authorize the channel; an expired intermediate root still advances", async () => {
    const { a, channelDir, opts } = await fixture();
    await installDistribution(a.archive);
    // The fixture's bootstrap has KEY in both roles.
    await publishRoot(
      channelDir,
      rootBody(2, [KEY], [KEY], "2026-01-01T00:00:00Z"),
      [KEY],
    );
    const now = () => new Date("2026-06-01T00:00:00Z");
    const expired = await rejection(updateDistribution(ID, { ...opts, now }));
    expect(expired.code).toBe("INTEGRITY_FAILED");
    expect(expired.message).toMatch(
      /Update root version 2 expired at 2026-01-01T00:00:00Z/,
    );
    expect(readInstallReceipt(ID).active).toBe("1.0.0");
    await publishRoot(channelDir, rootBody(3, [KEY], [KEY]), [KEY]);
    expect(await updateDistribution(ID, { ...opts, now })).toMatchObject({
      status: "updated",
    });
    expect(readTrustState(ID)?.root.version).toBe(3);
  });

  it("a failed root fetch stops the update before the channel", async () => {
    const { a, channelDir } = await fixture();
    await installDistribution(a.archive);
    for (const failure of ["HTTP 500", "fetch failed"]) {
      const requested: string[] = [];
      const options = served(channelDir, requested);
      const fetcher = options.fetcher as typeof fetch;
      const error = await rejection(
        updateDistribution(ID, {
          ...options,
          fetcher: (async (input: URL | string, init?: RequestInit) => {
            if (String(input).includes("/root/")) {
              requested.push(new URL(String(input)).pathname);
              if (failure === "fetch failed") throw new TypeError(failure);
              return new Response("", { status: 500 });
            }
            return fetcher(input, init);
          }) as typeof fetch,
        }),
      );
      expect(error.message).toContain(failure);
      expect(requested).toEqual(["/acmepi/root/2.json"]);
      expect(readInstallReceipt(ID).active).toBe("1.0.0");
    }
  });

  it("a damaged or missing trust state fails closed until a verified reinstall", async () => {
    const { a, opts } = await fixture();
    await installDistribution(a.archive, true);
    const path = trustStatePath(ID);
    writeFileSync(path, "{");
    const damaged = await rejection(updateDistribution(ID, opts));
    expect(damaged.code).toBe("INTEGRITY_FAILED");
    expect(damaged.message).toMatch(/is damaged/);
    expect(readFileSync(path, "utf8")).toBe("{");
    // Deleting it does not reset trust to the active release lock.
    rmSync(path);
    const missing = await rejection(updateDistribution(ID, opts));
    expect(missing.code).toBe("INTEGRITY_FAILED");
    expect(missing.message).toMatch(/is missing/);
    expect(existsSync(path)).toBe(false);
    expect(
      lifecycleStatus(ID, verifyPayload(join(appsDir(), "1.0.0"))).trustProblem,
    ).toBe("missing");
    // The recovery: uninstall (state kept), then a verified reinstall.
    uninstallDistribution(ID);
    expect(existsSync(path)).toBe(false);
    await installDistribution(a.archive, true, { expectedSha256: a.sha256 });
    expect(readTrustState(ID)).toMatchObject({
      origin: "bootstrap",
      root: { version: 1 },
    });
    expect((await updateDistribution(ID, opts)).status).toBe("updated");
  });

  it("takes an installation from before v0.8 onto trust state once", async () => {
    const { a, opts } = await fixture();
    await installDistribution(a.archive);
    // As PiShip v0.7 left it: no trust state, no marker in the receipt.
    rmSync(trustStatePath(ID));
    const { trustState: _marker, ...earlier } = readInstallReceipt(ID);
    writeFileSync(
      join(process.env.PISHIP_INSTALL_HOME as string, "receipts", `${ID}.json`),
      JSON.stringify(earlier),
    );
    expect((await updateDistribution(ID, opts)).status).toBe("updated");
    expect(readInstallReceipt(ID).trustState).toBe(true);
    expect(readTrustState(ID)).toMatchObject({
      origin: "bootstrap",
      root: { version: 1 },
    });
  });

  /** Replace the lock's update trust bootstrap behind a rewritten inventory. */
  function corruptBootstrap(payload: string): void {
    const path = join(payload, "piship.lock");
    const lock = JSON.parse(readFileSync(path, "utf8"));
    lock.updates.trust.bootstrap.roles.channel.keyIds = ["nobody"];
    writeFileSync(path, `${JSON.stringify(lock, null, 2)}\n`);
    write(
      join(payload, "metadata", "inventory.json"),
      `${JSON.stringify(payloadInventory(payload), null, 2)}\n`,
    );
  }

  it("refuses to install a lock whose update trust bootstrap is malformed", async () => {
    const payload = fakeAssemble(project("1.0.0"), temp("piship-payload-"));
    corruptBootstrap(payload);
    const error = await rejection(installDistribution(payload));
    expect(error.code).toBe("LOCK_INVALID");
    expect(error.message).toMatch(
      /invalid update trust: .*updates\.trust\.bootstrap\.roles\.channel/,
    );
    expect(existsSync(trustStatePath(ID))).toBe(false);
    expect(existsSync(appsDir())).toBe(false);
  });

  it("refuses to migrate an installation from before v0.8 onto a malformed bootstrap", async () => {
    const { a, opts } = await fixture();
    await installDistribution(a.archive);
    rmSync(trustStatePath(ID));
    const { trustState: _marker, ...earlier } = readInstallReceipt(ID);
    writeFileSync(
      join(process.env.PISHIP_INSTALL_HOME as string, "receipts", `${ID}.json`),
      JSON.stringify(earlier),
    );
    corruptBootstrap(join(appsDir(), "1.0.0"));
    const error = await rejection(updateDistribution(ID, opts));
    expect(error.code).toBe("LOCK_INVALID");
    expect(existsSync(trustStatePath(ID))).toBe(false);
    expect(readInstallReceipt(ID).trustState).toBeUndefined();
    expect(readInstallReceipt(ID).active).toBe("1.0.0");
  });

  it("an update interrupted between root versions keeps each accepted root whole", async () => {
    const { a, channelDir, opts } = await fixture();
    await installDistribution(a.archive);
    await publishRoot(channelDir, rootBody(2, [KEY], [KEY]), [KEY]);
    await publishRoot(channelDir, rootBody(3, [KEY], [KEY]), [KEY]);
    let accepted = 0;
    const killed = await rejection(
      updateDistribution(ID, {
        ...opts,
        faults: (phase) => {
          if (phase === "root-accepted" && ++accepted === 1)
            throw new Error("killed after root 2");
        },
      }),
    );
    expect(killed.message).toBe("killed after root 2");
    expect(readTrustState(ID)?.root.version).toBe(2);
    expect(readInstallReceipt(ID).active).toBe("1.0.0");
    // A write that fails before its rename keeps the accepted root.
    const trustDir = dirname(trustStatePath(ID));
    if (process.platform !== "win32" && process.getuid?.() !== 0) {
      chmodSync(trustDir, 0o500);
      try {
        const denied = await rejection(updateDistribution(ID, opts));
        expect(denied.message).toMatch(/EACCES|permission/i);
      } finally {
        chmodSync(trustDir, 0o700);
      }
      expect(readTrustState(ID)?.root.version).toBe(2);
    }
    expect(await updateDistribution(ID, opts)).toMatchObject({
      status: "updated",
    });
    expect(readTrustState(ID)?.root.version).toBe(3);
  });

  it("activates without spawning a redundant launch check", async () => {
    const { a, opts } = await fixture();
    await installDistribution(a.archive);
    const runCheck = vi.fn(() => ({
      status: 1,
      stdout: "",
      stderr: "cannot start",
    }));
    const result = await updateDistribution(ID, { ...opts, runCheck });
    expect(result.status).toBe("updated");
    expect(runCheck).not.toHaveBeenCalled();
    expect(readInstallReceipt(ID).active).toBe("1.1.0");
  });

  it("refuses local data the target would reinterpret", async () => {
    const { a, opts } = await fixture();
    seedState();
    write(
      join(stateDir(), "config", "preferences.json"),
      JSON.stringify({ schema: "piship-preferences/v9" }),
    );
    await installDistribution(a.archive, true);
    const state = treeHash(stateDir());
    const error = await rejection(updateDistribution(ID, opts));
    expect(error.code).toBe("UPDATE_FAILED");
    expect(error.message).toMatch(
      /cannot use this distribution's local data: preferences/,
    );
    expect(readInstallReceipt(ID).active).toBe("1.0.0");
    expect(treeHash(stateDir())).toEqual(state);
  });

  it("treats a change of secret store as a credential transition in update and rollback", async () => {
    const { a, opts } = await fixture({ storageA: "file", storageB: "system" });
    // Signed in under 1.0.0, whose file store holds the local secret.
    const state = stateDir();
    const metadata = {
      schema: "piship-credential-metadata/v1",
      mode: "local-secret",
      credential_ref: `piship:${ID}:inference#1`,
      generation: 1,
      kind: "api_key",
      acquired_at: "2026-01-01T00:00:00.000Z",
      secret_store: "file",
    };
    write(
      join(state, "credentials-metadata", "inference.json"),
      JSON.stringify(metadata),
    );
    const fileStore = new RestrictedFileSecretStore(join(state, "secrets"));
    await fileStore.put(`piship:${ID}:inference#1`, new SecretValue(SENTINEL));
    await installDistribution(a.archive, true);
    // file -> system: the switching release (1.0.0) deletes it from the
    // file store; 1.1.0 never looks it up in the platform store.
    const check = await updateDistribution(ID, { ...opts, check: true });
    expect(
      check.migration?.items.find(
        (item) => item.name === "runtime credential metadata",
      ),
    ).toMatchObject({
      action: "clear-and-reacquire",
      storageTransition: { from: "file", to: "system" },
    });
    const platform = testStore();
    const updated = await updateDistribution(ID, {
      ...opts,
      secretStore: fileStore,
    });
    expect(updated.status).toBe("updated");
    expect(updated.notices).toEqual([
      "runtime credential metadata was cleared because the secret store changes from file to system: its secrets were deleted from the file store; sign in again",
    ]);
    expect(
      existsSync(join(state, "credentials-metadata", "inference.json")),
    ).toBe(false);
    expect(existsSync(join(state, "secrets"))).toBe(false);
    expect(platform.deleted).toEqual([]);
    // Signed in again under 1.1.0, whose platform store holds it now.
    write(
      join(state, "credentials-metadata", "inference.json"),
      JSON.stringify({ ...metadata, secret_store: "system" }),
    );
    await platform.memory.put(
      `piship:${ID}:inference#1`,
      new SecretValue(SENTINEL_V2),
    );
    // system -> file: the switching release (1.1.0) deletes it from the
    // platform store before 1.0.0 is active again.
    const rolled = await rollbackDistribution(ID, {
      runCheck: fakeRun,
      secretStore: platform.store,
    });
    expect(rolled.notices).toEqual([
      "runtime credential metadata was cleared because the secret store changes from system to file: its secrets were deleted from the system store; sign in again",
    ]);
    expect(platform.deleted).toEqual([
      `piship:${ID}:inference#1`,
      `piship:${ID}:inference#2`,
    ]);
    expect(platform.memory.refs()).toEqual([]);
    expect(
      existsSync(join(state, "credentials-metadata", "inference.json")),
    ).toBe(false);
  });

  it("stops before activation when a credential the target cannot read cannot be deleted", async () => {
    const { a, opts } = await fixture();
    seedState();
    // Credential metadata in a format the 1.1.0 target cannot read.
    write(
      join(stateDir(), "credentials-metadata", "inference.json"),
      JSON.stringify({
        schema: "piship-credential-metadata/v2",
        credential_ref: `piship:${ID}:inference#1`,
        generation: 1,
      }),
    );
    await installDistribution(a.archive, true);
    const lock = { on: true };
    const { store, memory } = testStore(() => lock.on);
    await memory.put(`piship:${ID}:inference#1`, new SecretValue(SENTINEL_V2));
    const credentials = treeHash(join(stateDir(), "credentials-metadata"));
    const error = await rejection(
      updateDistribution(ID, { ...opts, secretStore: store }),
    );
    expect(error.code).toBe("SECRET_STORE_UNAVAILABLE");
    expect(error.message).toMatch(
      /piship:acmepi:inference#1: SECRET_STORE_UNAVAILABLE: The keychain is locked.*so the switch stopped before activation/,
    );
    // The inactive candidate is kept for explicit maintenance; the receipt and credentials remain unchanged.
    expect(readInstallReceipt(ID).active).toBe("1.0.0");
    expect(apps()).toEqual(["1.0.0", "1.1.0", "launch.mjs"]);
    expect(treeHash(join(stateDir(), "credentials-metadata"))).toEqual(
      credentials,
    );
    expect(memory.refs()).toEqual([`piship:${ID}:inference#1`]);
    // Unlocked, the update deletes it and activates.
    lock.on = false;
    const result = await updateDistribution(ID, {
      ...opts,
      secretStore: store,
    });
    expect(result.status).toBe("updated");
    expect(result.notices).toEqual([
      "runtime credential metadata was cleared because the target cannot read it; sign in again",
    ]);
    expect(memory.refs()).toEqual([]);
    expect(containing(SENTINEL_V2)).toEqual([]);
    // The identity session is kept, so the file store it may use is kept
    // too: only the cleared class's own references were deleted.
    expect(existsSync(join(stateDir(), "identity", "session.json"))).toBe(true);
    expect(existsSync(join(stateDir(), "secrets"))).toBe(true);
  });

  it("fetches through the declared https source", async () => {
    const { a, channelDir } = await fixture();
    await installDistribution(a.archive);
    const requested: string[] = [];
    const fetcher = (async (input: URL | string) => {
      const url = new URL(String(input));
      requested.push(url.pathname);
      const file = join(channelDir, url.pathname.split("/").pop() as string);
      return existsSync(file)
        ? new Response(readFileSync(file))
        : new Response("", { status: 404 });
    }) as typeof fetch;
    const result = await updateDistribution(ID, {
      runCheck: fakeRun,
      fetcher,
      env: { ACMEPI_UPDATE_SOURCE: "https://updates.example.test/acmepi" },
    });
    expect(result.status).toBe("updated");
    expect(requested).toEqual([
      "/acmepi/root/2.json",
      "/acmepi/stable.json",
      "/acmepi/stable.json.sig",
      `/acmepi/acmepi-1.1.0-${currentTarget()}.tar.gz`,
    ]);
    // An unresolved source template is a configuration error, not a network call.
    const error = await rejection(
      updateDistribution(ID, { runCheck: fakeRun, fetcher, env: {} }),
    );
    expect(error.code).toBe("CONFIG_UNAVAILABLE");
  });

  it("reads a downloaded update archive once, hashing it and every payload file as they are written", async () => {
    const { a, b, channelDir } = await fixture();
    await installDistribution(a.archive);
    const hashed = vi.spyOn(archiveModule, "sha256File");
    const extracted = vi.spyOn(archiveModule, "extractArchive");
    try {
      const fetcher = (async (input: URL | string) => {
        const file = join(
          channelDir,
          new URL(String(input)).pathname.split("/").pop() as string,
        );
        return existsSync(file)
          ? new Response(readFileSync(file))
          : new Response("", { status: 404 });
      }) as typeof fetch;
      const result = await updateDistribution(ID, {
        runCheck: fakeRun,
        fetcher,
        env: { ACMEPI_UPDATE_SOURCE: "https://updates.example.test/acmepi" },
      });
      expect(result.status).toBe("updated");
      // The download is hashed as it streams, so no read of the file hashes
      // it; the one extraction hashes the bytes it reads and every file.
      expect(hashed).not.toHaveBeenCalled();
      expect(extracted).toHaveBeenCalledTimes(1);
      expect(extracted.mock.calls[0]?.[2]).toMatchObject({ digests: true });
      expect(extracted.mock.calls[0]?.[2]?.hash).not.toBe(false);
      expect(readInstallReceipt(ID).releases[0]?.release?.archiveSha256).toBe(
        b.sha256,
      );
    } finally {
      hashed.mockRestore();
      extracted.mockRestore();
    }
  });

  it("hashes an update archive copied from a directory once, and reads it once to extract", async () => {
    const { a, b, opts } = await fixture();
    await installDistribution(a.archive);
    const hashed = vi.spyOn(archiveModule, "sha256File");
    const extracted = vi.spyOn(archiveModule, "extractArchive");
    try {
      expect((await updateDistribution(ID, opts)).status).toBe("updated");
      expect(hashed).toHaveBeenCalledTimes(1);
      expect(extracted).toHaveBeenCalledTimes(1);
      expect(readInstallReceipt(ID).releases[0]?.release?.archiveSha256).toBe(
        b.sha256,
      );
    } finally {
      hashed.mockRestore();
      extracted.mockRestore();
    }
  });

  it("applies the manifest source rules to the resolved updates.source", async () => {
    const { a, channelDir } = await fixture();
    await installDistribution(a.archive);
    let requests = 0;
    const fetcher = (async () => {
      requests += 1;
      return new Response("", { status: 404 });
    }) as typeof fetch;
    const attempt = (source: string) =>
      rejection(
        updateDistribution(ID, {
          runCheck: fakeRun,
          fetcher,
          env: { ACMEPI_UPDATE_SOURCE: source },
        }),
      );
    for (const source of [
      "http://updates.example.test/acmepi",
      "ftp://updates.example.test/acmepi",
      "file:///srv/acmepi",
    ])
      expect((await attempt(source)).code).toBe("NETWORK_DENIED");
    expect(
      (await attempt("https://updates.example.test/acmepi?x=1")).message,
    ).toMatch(/query string or fragment/);
    const relative = await attempt("channel");
    expect(relative.code).toBe("CONFIG_INVALID");
    expect(relative.message).toMatch(/absolute local directory/);
    expect(requests).toBe(0);
    // An absolute local directory is accepted after resolution.
    const result = await updateDistribution(ID, {
      runCheck: fakeRun,
      env: { ACMEPI_UPDATE_SOURCE: channelDir },
    });
    expect(result.status).toBe("updated");
  });

  it("accepts a relative --from directory but not an unsupported scheme", async () => {
    const { a, channelDir } = await fixture();
    await installDistribution(a.archive);
    const denied = await rejection(
      updateDistribution(ID, {
        runCheck: fakeRun,
        source: "ftp://updates.example.test/acmepi",
      }),
    );
    expect(denied.code).toBe("NETWORK_DENIED");
    const missing = await rejection(
      updateDistribution(ID, { runCheck: fakeRun, source: join(temp(), "x") }),
    );
    expect(missing.message).toMatch(/does not exist/);
    const cwd = process.cwd();
    process.chdir(dirname(channelDir));
    try {
      const result = await updateDistribution(ID, {
        runCheck: fakeRun,
        source: basename(channelDir),
      });
      expect(result.status).toBe("updated");
    } finally {
      process.chdir(cwd);
    }
  });

  it("drops the previous release when the new release disables rollback", async () => {
    const { a, opts } = await fixture({ rollbackB: false });
    await installDistribution(a.archive);
    await updateDistribution(ID, opts);
    const receipt = readInstallReceipt(ID);
    expect(receipt).not.toHaveProperty("previous");
    expect(receipt.releases.map((item) => item.version)).toEqual(["1.1.0"]);
    expect(apps()).toEqual(["1.0.0", "1.1.0", "launch.mjs"]);
    expect(recoverInstallation(ID)).toEqual(["1.0.0"]);
    const error = await rejection(
      rollbackDistribution(ID, { runCheck: fakeRun }),
    );
    expect(error.code).toBe("ROLLBACK_FAILED");
    expect(error.message).toMatch(/no retained release to roll back to/);
  });
});

// ------------------------------------------------------------ interruption

describe.runIf(HOST_EVIDENCED)("interrupted update", () => {
  it.each(["staged", "verified", "installed", "committed"] as const)(
    "leaves one consistent release after an interruption at %s, and a retry completes",
    async (phase) => {
      const { a, opts } = await fixture();
      seedState();
      await installDistribution(a.archive, true);
      const error = await rejection(
        updateDistribution(ID, {
          ...opts,
          faults: (at) => {
            if (at === phase) throw new Error(`interrupted at ${at}`);
          },
        }),
      );
      expect(error.message).toBe(`interrupted at ${phase}`);
      const receipt = readInstallReceipt(ID);
      const expected = phase === "committed" ? "1.1.0" : "1.0.0";
      expect(receipt.active).toBe(expected);
      expect(verifyPayload(receipt.payload).app.version).toBe(expected);
      // The payload is extracted straight into the version directory before
      // the release is checked against the signed entry, so from "verified"
      // on an interrupted update leaves it there, unreferenced.
      expect(apps()).toEqual(
        phase === "verified" || phase === "installed"
          ? ["1.0.0", "1.1.0", "launch.mjs"]
          : [
              ...receipt.releases.map((item) => item.version),
              "launch.mjs",
            ].sort(),
      );
      const retry = await updateDistribution(ID, opts);
      expect(retry.status).toBe(
        phase === "committed" ? "up-to-date" : "updated",
      );
      const final = readInstallReceipt(ID);
      expect(final.active).toBe("1.1.0");
      expect(final.previous).toBe("1.0.0");
      expect(final.releases.map((item) => item.version)).toEqual([
        "1.1.0",
        "1.0.0",
      ]);
      if (phase === "verified" || phase === "installed") {
        const leftovers = apps().filter((name) =>
          name.startsWith(".retained-"),
        );
        expect(leftovers).toHaveLength(1);
        expect(recoverInstallation(ID)).toEqual(leftovers);
      }
      expect(apps()).toEqual(["1.0.0", "1.1.0", "launch.mjs"]);
      for (const item of final.releases) verifyPayload(item.payload);
      expect(recoverInstallation(ID)).toEqual([]);
      expect(recoverInstallation(ID)).toEqual([]);
      expect(containing(SENTINEL)).toEqual([
        join(stateDir(), "secrets", "inference"),
      ]);
    },
  );

  it("leaves cleanup of killed operations to explicit maintenance", async () => {
    const { a, opts } = await fixture();
    await installDistribution(a.archive);
    write(join(appsDir(), ".staging-killed", "partial.tar.gz"), "partial");
    cpSync(join(appsDir(), "1.0.0"), join(appsDir(), "1.1.0"), {
      recursive: true,
    });
    expect(
      lifecycleStatus(ID, verifyPayload(join(appsDir(), "1.0.0")))
        .leftovers.slice()
        .sort(),
    ).toEqual([".staging-killed", "1.1.0"]);
    expect(recoverInstallation(ID).sort()).toEqual([
      ".staging-killed",
      "1.1.0",
    ]);
    expect(recoverInstallation(ID)).toEqual([]);
    expect(apps()).toEqual(["1.0.0", "launch.mjs"]);
    write(join(appsDir(), ".staging-killed", "partial.tar.gz"), "partial");
    const result = await updateDistribution(ID, opts);
    expect(result.status).toBe("updated");
    expect(apps()).toEqual([".staging-killed", "1.0.0", "1.1.0", "launch.mjs"]);
    expect(recoverInstallation(ID)).toEqual([".staging-killed"]);
  });
  // up-to-date path never rewrites it, so an interruption between the two
  // leaves the marker naming the old release forever.
  it("rewrites the state marker for the active release after an interrupted commit", async () => {
    const { a, opts } = await fixture();
    seedState();
    await installDistribution(a.archive, true);
    await rejection(
      updateDistribution(ID, {
        ...opts,
        faults: (at) => {
          if (at === "committed") throw new Error("interrupted");
        },
      }),
    );
    await updateDistribution(ID, opts);
    expect(readInstallReceipt(ID).active).toBe("1.1.0");
    expect(readStateMarker(stateDir())?.version).toBe("1.1.0");
  });
});

// ------------------------------------------------------------ concurrency

describe.runIf(HOST_EVIDENCED)("lifecycle lock", () => {
  it("blocks while a live process holds the lock", async () => {
    const { a, opts } = await fixture();
    await installDistribution(a.archive);
    const lock = join(appsDir(), ".lifecycle.lock");
    writeFileSync(lock, String(process.pid));
    const error = await rejection(updateDistribution(ID, opts));
    expect(error.code).toBe("UPDATE_FAILED");
    expect(error.retryable).toBe(true);
    expect(error.message).toMatch(
      `Another update, rollback, or uninstall of acmepi is running (process ${process.pid})`,
    );
    const rollback = await rejection(
      rollbackDistribution(ID, { runCheck: fakeRun }),
    );
    expect(rollback.code).toBe("ROLLBACK_FAILED");
    expect(rollback.message).toMatch(/Another update, rollback, or uninstall/);
    expect(() => uninstallDistribution(ID)).toThrow(
      /Another update, rollback, or uninstall/,
    );
    expect(readFileSync(lock, "utf8")).toBe(String(process.pid));
    expect(readInstallReceipt(ID).active).toBe("1.0.0");
  });

  it("removes a stale lock left by a dead process", async () => {
    const { a, opts } = await fixture();
    await installDistribution(a.archive);
    const lock = join(appsDir(), ".lifecycle.lock");
    writeFileSync(lock, "999999999");
    const result = await updateDistribution(ID, opts);
    expect(result.status).toBe("updated");
    expect(existsSync(lock)).toBe(false);
    writeFileSync(lock, "garbage");
    await expect(updateDistribution(ID, opts)).resolves.toMatchObject({
      status: "up-to-date",
    });
    expect(existsSync(lock)).toBe(false);
  });
});

// ---------------------------------------------------------------- rollback

describe.runIf(HOST_EVIDENCED)("rollback", () => {
  async function updated() {
    const f = await fixture();
    seedState();
    await installDistribution(f.a.archive, true);
    await updateDistribution(ID, f.opts);
    return f;
  }

  it("returns to the retained release and leaves sessions and settings untouched", async () => {
    await updated();
    const sessions = treeHash(join(stateDir(), "sessions"));
    const config = treeHash(join(stateDir(), "config"));
    const credentials = treeHash(join(stateDir(), "credentials-metadata"));
    checked.length = 0;
    const result = await rollbackDistribution(ID, { runCheck: fakeRun });
    expect(result).toMatchObject({
      id: ID,
      from: "1.1.0",
      to: "1.0.0",
      notices: [],
    });
    expect(result.migration.verdict).toBe("safe");
    expect(checked).toEqual([]);
    expect(treeHash(join(stateDir(), "sessions"))).toEqual(sessions);
    expect(treeHash(join(stateDir(), "config"))).toEqual(config);
    expect(treeHash(join(stateDir(), "credentials-metadata"))).toEqual(
      credentials,
    );
    const receipt = readInstallReceipt(ID);
    expect(receipt).toMatchObject({
      active: "1.0.0",
      previous: "1.1.0",
      payload: join(appsDir(), "1.0.0"),
      app: { version: "1.0.0" },
      lastCheck: { result: "rolled back 1.1.0 -> 1.0.0" },
    });
    expect(receipt.releases.map((item) => item.version)).toEqual([
      "1.1.0",
      "1.0.0",
    ]);
    expect(readStateMarker(stateDir())?.version).toBe("1.0.0");
    expect(apps()).toEqual(["1.0.0", "1.1.0", "launch.mjs"]);
    // The retained release is now newer: rollback refuses, update returns to it.
    const again = await rejection(
      rollbackDistribution(ID, { runCheck: fakeRun }),
    );
    expect(again.code).toBe("ROLLBACK_FAILED");
    expect(again.message).toMatch(
      /1.1.0 is newer than the active 1.0.0; use update instead/,
    );
  });

  it("deletes the secrets a damaged credential file still names before clearing it", async () => {
    await updated();
    // A newer format, cut short: no longer JSON, but it still names #3.
    write(
      join(stateDir(), "credentials-metadata", "inference.json"),
      `{"schema": "piship-credential-metadata/v2", "credential_ref": "piship:${ID}:inference#3", "generation": 3`,
    );
    const { store, memory, deleted } = testStore();
    await memory.put(`piship:${ID}:inference#3`, new SecretValue(SENTINEL_V2));
    const result = await rollbackDistribution(ID, {
      runCheck: fakeRun,
      secretStore: store,
    });
    expect(deleted).toEqual([
      `piship:${ID}:inference#3`,
      `piship:${ID}:inference#4`,
    ]);
    expect(memory.refs()).toEqual([]);
    expect(result.notices).toEqual([
      "runtime credential metadata was cleared because the target cannot read it; sign in again",
    ]);
  });

  it("fails when there is no retained release", async () => {
    const a = await release("1.0.0");
    await installDistribution(a.archive);
    const error = await rejection(
      rollbackDistribution(ID, { runCheck: fakeRun }),
    );
    expect(error.code).toBe("ROLLBACK_FAILED");
    expect(error.message).toMatch(/has no retained release/);
  });

  it("leaves retained-file auditing to explicit verification", async () => {
    await updated();
    const payload = join(appsDir(), "1.0.0");
    write(
      join(payload, "resources", "resources", "AGENTS.md"),
      "# changed locally\n",
    );
    expect(() => verifyPayload(payload)).toThrow(/integrity mismatch/);
    expect((await rollbackDistribution(ID)).to).toBe("1.0.0");
  });

  it("rolls back without a redundant launch check", async () => {
    await updated();
    const runCheck = vi.fn(() => ({ status: 1, stdout: "", stderr: "broken" }));
    expect((await rollbackDistribution(ID, { runCheck })).to).toBe("1.0.0");
    expect(runCheck).not.toHaveBeenCalled();
  });

  it("clears credentials the target cannot read and never restores the secret", async () => {
    await updated();
    // Written by the newer release in a format the retained release cannot read.
    write(
      join(stateDir(), "credentials-metadata", "inference.json"),
      JSON.stringify({
        schema: "piship-credential-metadata/v2",
        credential_ref: `piship:${ID}:inference#2`,
      }),
    );
    const identity = readFileSync(
      join(stateDir(), "identity", "session.json"),
      "utf8",
    );
    const { store, memory, deleted } = testStore();
    await memory.put(`piship:${ID}:inference#2`, new SecretValue(SENTINEL_V2));
    const result = await rollbackDistribution(ID, {
      runCheck: fakeRun,
      secretStore: store,
    });
    // Only references in this distribution's own namespace are deleted.
    expect(deleted).toEqual([`piship:${ID}:inference#2`]);
    expect(memory.refs()).toEqual([]);
    expect(result.notices).toEqual([
      "runtime credential metadata was cleared because the target cannot read it; sign in again",
    ]);
    expect(
      result.migration.items.find(
        (item) => item.name === "runtime credential metadata",
      ),
    ).toMatchObject({
      action: "clear-and-reacquire",
      current: "piship-credential-metadata/v2",
    });
    expect(
      existsSync(join(stateDir(), "credentials-metadata", "inference.json")),
    ).toBe(false);
    // The identity session is kept, and with it the file store it may use:
    // the cleared credential's own reference was deleted above.
    expect(existsSync(join(stateDir(), "secrets"))).toBe(true);
    expect(
      readFileSync(join(stateDir(), "identity", "session.json"), "utf8"),
    ).toBe(identity);
    expect(containing(SENTINEL_V2)).toEqual([]);
    expect(readInstallReceipt(ID).active).toBe("1.0.0");
  });

  it("stops before activation while the secret store is locked, and keeps every secret tracked", async () => {
    await updated();
    const identityPath = join(stateDir(), "identity", "session.json");
    const credentialPath = join(
      stateDir(),
      "credentials-metadata",
      "inference.json",
    );
    write(
      identityPath,
      JSON.stringify({
        schema: "piship-identity-metadata/v7",
        secretRef: `piship:${ID}:identity#1`,
      }),
    );
    write(
      credentialPath,
      JSON.stringify({
        schema: "piship-credential-metadata/v2",
        credential_ref: `piship:${ID}:inference#1`,
        generation: 1,
      }),
    );
    const lock = { on: true };
    const { store, memory } = testStore(() => lock.on);
    await memory.put(`piship:${ID}:identity#1`, new SecretValue(SENTINEL));
    await memory.put(`piship:${ID}:inference#1`, new SecretValue(SENTINEL_V2));
    const revokeCredential = vi.fn(async () => ({ outcome: "failed" }));
    const receipt = readInstallReceipt(ID);
    const marker = readStateMarker(stateDir());
    const metadata = {
      identity: readFileSync(identityPath, "utf8"),
      credential: readFileSync(credentialPath, "utf8"),
    };
    const error = await rejection(
      rollbackDistribution(ID, {
        runCheck: fakeRun,
        secretStore: store,
        revokeCredential,
      }),
    );
    expect(error.code).toBe("SECRET_STORE_UNAVAILABLE");
    expect(error.message).toMatch(
      /could not be deleted from the secret store \(piship:acmepi:identity#1: SECRET_STORE_UNAVAILABLE: The keychain is locked; .*\), so the switch stopped before activation/,
    );
    // Nothing was activated, and the metadata still names both secrets.
    expect(readInstallReceipt(ID)).toEqual(receipt);
    expect(readStateMarker(stateDir())).toEqual(marker);
    expect(readFileSync(identityPath, "utf8")).toBe(metadata.identity);
    expect(readFileSync(credentialPath, "utf8")).toBe(metadata.credential);
    expect(memory.refs()).toEqual([
      `piship:${ID}:identity#1`,
      `piship:${ID}:inference#1`,
    ]);
    // Once the store is unlocked, the same rollback deletes them and switches.
    lock.on = false;
    const result = await rollbackDistribution(ID, {
      runCheck: fakeRun,
      secretStore: store,
    });
    expect(result.to).toBe("1.0.0");
    expect(memory.refs()).toEqual([]);
    expect(existsSync(identityPath)).toBe(false);
    expect(existsSync(credentialPath)).toBe(false);
    expect(containing(SENTINEL)).toEqual([]);
    expect(containing(SENTINEL_V2)).toEqual([]);
  });

  it("stops rather than dropping secret references when no secret store is available", async () => {
    await updated();
    const credentialPath = join(
      stateDir(),
      "credentials-metadata",
      "inference.json",
    );
    write(
      credentialPath,
      JSON.stringify({
        schema: "piship-credential-metadata/v2",
        credential_ref: `piship:${ID}:inference#4`,
        generation: 4,
      }),
    );
    const error = await rejection(
      rollbackDistribution(ID, { runCheck: fakeRun }),
    );
    expect(error.code).toBe("SECRET_STORE_UNAVAILABLE");
    expect(error.message).toContain(
      `piship:${ID}:inference#4: no secret store is available to delete it`,
    );
    expect(existsSync(credentialPath)).toBe(true);
    expect(readInstallReceipt(ID).active).toBe("1.1.0");
  });

  it("clears every credential class the target cannot read and keeps the non-secret revocation record", async () => {
    await updated();
    const path = (...parts: string[]) => join(stateDir(), ...parts);
    // Identity tokens in a newer format, a discarded credential whose secrets
    // are still to be deleted, and a pending revocation (no secret).
    write(
      path("identity", "session.json"),
      JSON.stringify({
        schema: "piship-identity-metadata/v7",
        secretRef: `piship:${ID}:identity#2`,
      }),
    );
    write(
      path("credentials-metadata", "inference.json"),
      JSON.stringify({
        schema: "piship-credential-discarded/v1",
        orphans: [`piship:${ID}:inference#3`, `piship:${ID}:inference#4`],
        discarded_at: "2026-09-29T00:00:00.000Z",
      }),
    );
    const retry = JSON.stringify({
      schema: "piship-revocation-retry/v1",
      entries: [
        {
          credential_id: "vk_retry",
          mode: "http-broker",
          generation: 2,
          reason: "logout",
          failed_at: "2026-09-29T00:00:00.000Z",
          checks: 0,
        },
      ],
    });
    write(path("credentials-metadata", "revocation-retry.json"), retry);
    const principal = JSON.stringify({
      schema: "piship-principal-binding/v1",
      issuer: "https://idp.example",
      subject: "user-1",
    });
    write(path("identity", "principal.json"), principal);
    const { store, memory } = testStore();
    const sentinels = {
      [`piship:${ID}:identity#2`]: "sentinel-identity-tokens-51c0",
      [`piship:${ID}:identity#3`]: "sentinel-identity-next-9a1d",
      [`piship:${ID}:inference#3`]: "sentinel-discarded-3-77e2",
      [`piship:${ID}:inference#4`]: "sentinel-discarded-4-0b4f",
      "piship:another-app:inference#1": "sentinel-other-app-6d39",
    };
    for (const [ref, value] of Object.entries(sentinels))
      await memory.put(ref, new SecretValue(value));
    const result = await rollbackDistribution(ID, {
      runCheck: fakeRun,
      secretStore: store,
    });
    expect(
      result.migration.items
        .filter((item) => item.action === "clear-and-reacquire")
        .map((item) => [item.name, item.current]),
    ).toEqual([
      ["identity session", "piship-identity-metadata/v7"],
      ["runtime credential metadata", "piship-credential-discarded/v1"],
    ]);
    // Every secret of this distribution is gone; another app's is untouched.
    expect(memory.refs()).toEqual(["piship:another-app:inference#1"]);
    expect(existsSync(path("identity", "session.json"))).toBe(false);
    expect(existsSync(path("credentials-metadata", "inference.json"))).toBe(
      false,
    );
    // The pending revocation and the principal binding hold no secret and stay.
    expect(
      readFileSync(
        path("credentials-metadata", "revocation-retry.json"),
        "utf8",
      ),
    ).toBe(retry);
    expect(readFileSync(path("identity", "principal.json"), "utf8")).toBe(
      principal,
    );
    for (const value of Object.values(sentinels))
      expect(containing(value)).toEqual([]);
    expect(containing(SENTINEL)).toEqual([]);
  });

  it("deletes every secret reference, including orphans and the next generation", async () => {
    await updated();
    write(
      join(stateDir(), "credentials-metadata", "inference.json"),
      JSON.stringify({
        schema: "piship-credential-metadata/v2",
        credential_ref: `piship:${ID}:inference#5`,
        generation: 5,
        orphans: [
          `piship:${ID}:inference#3`,
          `piship:${ID}:inference#4`,
          "piship:another-app:inference#1",
        ],
      }),
    );
    write(
      join(stateDir(), "identity", "session.json"),
      JSON.stringify({
        schema: "piship-identity-metadata/v7",
        secretRef: `piship:${ID}:identity#4`,
      }),
    );
    const { store, deleted } = testStore();
    const revokeCredential = vi.fn(async () => ({ outcome: "revoked" }));
    const result = await rollbackDistribution(ID, {
      runCheck: fakeRun,
      secretStore: store,
      revokeCredential,
    });
    expect(revokeCredential).toHaveBeenCalledTimes(1);
    expect(deleted.sort()).toEqual([
      `piship:${ID}:identity#3`,
      `piship:${ID}:identity#4`,
      `piship:${ID}:identity#5`,
      `piship:${ID}:inference#3`,
      `piship:${ID}:inference#4`,
      `piship:${ID}:inference#5`,
      `piship:${ID}:inference#6`,
    ]);
    expect(result.notices).toEqual([
      "identity session was cleared because the target cannot read it; sign in again",
      "runtime credential metadata was cleared because the target cannot read it; sign in again",
    ]);
    expect(existsSync(join(stateDir(), "identity", "session.json"))).toBe(
      false,
    );
    expect(
      existsSync(join(stateDir(), "credentials-metadata", "inference.json")),
    ).toBe(false);
  });

  it("revokes before deleting and still clears locally when revocation fails", async () => {
    await updated();
    write(
      join(stateDir(), "credentials-metadata", "inference.json"),
      JSON.stringify({
        schema: "piship-credential-metadata/v2",
        credential_ref: `piship:${ID}:inference#2`,
        generation: 2,
      }),
    );
    const order: string[] = [];
    const { store } = testStore();
    const result = await rollbackDistribution(ID, {
      runCheck: fakeRun,
      secretStore: {
        ...store,
        delete: async (ref) => {
          order.push(`delete ${ref}`);
          await store.delete(ref);
        },
      },
      revokeCredential: async () => {
        order.push("revoke");
        return {
          outcome: "failed",
          problem: "Credential revocation returned HTTP 503",
        };
      },
    });
    expect(order).toEqual([
      "revoke",
      `delete piship:${ID}:inference#2`,
      `delete piship:${ID}:inference#3`,
    ]);
    expect(result.notices).toEqual([
      "The runtime credential could not be revoked remotely (Credential revocation returned HTTP 503); it was cleared locally",
      "runtime credential metadata was cleared because the target cannot read it; sign in again",
    ]);
    expect(
      existsSync(join(stateDir(), "credentials-metadata", "inference.json")),
    ).toBe(false);
    expect(readInstallReceipt(ID).active).toBe("1.0.0");
  });

  it("continues clearing when the revocation hook throws", async () => {
    await updated();
    write(
      join(stateDir(), "credentials-metadata", "inference.json"),
      JSON.stringify({
        schema: "piship-credential-metadata/v2",
        credential_ref: `piship:${ID}:inference#2`,
        generation: 2,
      }),
    );
    const { store, deleted } = testStore();
    const result = await rollbackDistribution(ID, {
      runCheck: fakeRun,
      secretStore: store,
      revokeCredential: async () => {
        throw new Error("broker unreachable");
      },
    });
    expect(deleted).toEqual([
      `piship:${ID}:inference#2`,
      `piship:${ID}:inference#3`,
    ]);
    expect(result.notices[0]).toBe(
      "The runtime credential could not be revoked remotely (broker unreachable); it was cleared locally",
    );
    expect(
      existsSync(join(stateDir(), "credentials-metadata", "inference.json")),
    ).toBe(false);
  });

  it("does not bring back credentials revoked by logout", async () => {
    await updated();
    rmSync(join(stateDir(), "identity"), { recursive: true });
    rmSync(join(stateDir(), "credentials-metadata"), { recursive: true });
    rmSync(join(stateDir(), "secrets"), { recursive: true });
    await rollbackDistribution(ID, { runCheck: fakeRun });
    expect(existsSync(join(stateDir(), "identity"))).toBe(false);
    expect(existsSync(join(stateDir(), "credentials-metadata"))).toBe(false);
    expect(existsSync(join(stateDir(), "secrets"))).toBe(false);
    expect(containing(SENTINEL)).toEqual([]);
    expect(containing("file:inference")).toEqual([]);
    expect(containing("user-1")).toEqual([]);
  });
});

// ------------------------------------------------------------------ repair

describe.runIf(HOST_EVIDENCED)("obsolete release directories", () => {
  /** Active 1.1.0 with rollback target 1.0.0, plus directories nothing records. */
  async function strewn() {
    const { a, opts } = await fixture();
    await installDistribution(a.archive);
    await updateDistribution(ID, opts);
    const aside = `.retained-1.1.0-${randomUUID()}`;
    write(join(appsDir(), "0.9.0", "bin", "run.js"), "o".repeat(1000));
    write(
      join(appsDir(), "0.9.0", "node_modules", "a", "index.js"),
      "a".repeat(500),
    );
    write(join(appsDir(), aside, "payload.js"), "r".repeat(2000));
    return { aside, opts };
  }

  it("keeps the active release and the rollback target, removes the rest, and says what it freed", async () => {
    const { aside } = await strewn();
    const before = readInstallReceipt(ID);
    const result = reclaimObsoleteVersions(ID);
    expect([...result.removed].sort()).toEqual([aside, "0.9.0"].sort());
    expect(result.freedBytes).toBe(3500);
    expect(result.skipped).toEqual([]);
    expect(apps()).toEqual(["1.0.0", "1.1.0", "launch.mjs"]);
    expect(readInstallReceipt(ID)).toEqual(before);
    expect(describeReclaimed(result)).toMatch(
      /^Removed 2 obsolete release directories \(.*0\.9\.0.*\) and freed 0\.0 MiB\.$/,
    );
    // Rollback still works, and a second run has nothing to do.
    expect(reclaimObsoleteVersions(ID)).toMatchObject({
      removed: [],
      freedBytes: 0,
    });
    expect((await rollbackDistribution(ID, { runCheck: fakeRun })).to).toBe(
      "1.0.0",
    );
  });

  it("never touches a directory a live runtime lease holds", async () => {
    const { aside } = await strewn();
    const releaseLease = holdRuntimeLease(ID, "0.9.0");
    try {
      const result = reclaimObsoleteVersions(ID);
      expect(result.removed).toEqual([aside]);
      expect(result.skipped).toEqual([
        { name: "0.9.0", reason: "a running session holds it" },
      ]);
      expect(existsSync(join(appsDir(), "0.9.0", "bin", "run.js"))).toBe(true);
      expect(describeReclaimed(result)).toContain(
        "Left 0.9.0 in place (a running session holds it).",
      );
    } finally {
      releaseLease();
    }
    expect(reclaimObsoleteVersions(ID).removed).toEqual(["0.9.0"]);
  });

  it("leaves a directory a scanner holds in place and reports it, removing the others", async () => {
    const { aside } = await strewn();
    write(join(appsDir(), "0.9.0", "locked.node"), "x");
    const result = reclaimObsoleteVersions(ID, {
      unlink: (path) => {
        if (path.endsWith("locked.node"))
          throw Object.assign(new Error("EBUSY: resource busy or locked"), {
            code: "EBUSY",
          });
        unlinkSync(path);
      },
    });
    expect(result.removed).toEqual([aside]);
    expect(result.skipped).toEqual([
      { name: "0.9.0", reason: "in use: locked.node (EBUSY)" },
    ]);
    expect(existsSync(join(appsDir(), "0.9.0", "locked.node"))).toBe(true);
    // Once nothing holds it, the next run finishes.
    expect(reclaimObsoleteVersions(ID).removed).toEqual(["0.9.0"]);
  });

  it("stops at its budget between directories, and the next run continues", async () => {
    await strewn();
    for (let version = 1; version <= 6; version++)
      write(join(appsDir(), `0.${version}.0`, "file.js"), "v");
    let time = 0;
    // Deadline 6: the checks before each directory read 2, 3, 4, 5, 6, then 7.
    const result = reclaimObsoleteVersions(ID, {
      budgetMs: 5,
      now: () => ++time,
    });
    expect(result.removed).toHaveLength(5);
    expect(result.remaining).toHaveLength(3);
    expect(describeReclaimed(result)).toContain(
      "Stopped at the 0.005 s budget with 3 obsolete directories left; run doctor again to continue.",
    );
    const next = reclaimObsoleteVersions(ID);
    expect(next.removed).toHaveLength(3);
    expect(next.remaining).toEqual([]);
    expect(apps()).toEqual(["1.0.0", "1.1.0", "launch.mjs"]);
  });

  it("stops at its budget inside a large directory, leaving it for the next run", async () => {
    await strewn();
    for (let file = 0; file < 200; file++)
      write(join(appsDir(), "0.8.0", `f${file}.js`), "z");
    // The deadline, then the checks before the two first directories read 0;
    // after that the budget is spent, which the 64th deletion notices.
    const reads = [0, 0, 0];
    const result = reclaimObsoleteVersions(ID, {
      budgetMs: 1,
      now: () => reads.shift() ?? 100,
    });
    expect(result.remaining).toContain("0.8.0");
    const left = readdirSync(join(appsDir(), "0.8.0")).length;
    expect(left).toBeGreaterThan(0);
    expect(left).toBeLessThan(200);
    expect(reclaimObsoleteVersions(ID).remaining).toEqual([]);
    expect(existsSync(join(appsDir(), "0.8.0"))).toBe(false);
  });

  it("does nothing while an update, rollback, or uninstall holds the installation", async () => {
    await strewn();
    const hold = acquireLock(ID);
    try {
      const result = reclaimObsoleteVersions(ID);
      expect(result).toMatchObject({ busy: true, removed: [] });
      expect(describeReclaimed(result)).toContain(
        "another update, rollback, or uninstall is running",
      );
      expect(existsSync(join(appsDir(), "0.9.0"))).toBe(true);
    } finally {
      hold.release();
    }
  });

  it("does nothing for a distribution that is not installed", () => {
    expect(reclaimObsoleteVersions(ID)).toMatchObject({
      removed: [],
      busy: false,
    });
  });

  it("is never part of an update, which only sets directories aside", async () => {
    const { opts } = await strewn();
    await rollbackDistribution(ID, { runCheck: fakeRun });
    await updateDistribution(ID, opts);
    expect(existsSync(join(appsDir(), "0.9.0"))).toBe(true);
  });
});

describe.runIf(HOST_EVIDENCED)("repair", () => {
  /** A installed, updated to B: B active, A retained. */
  async function updated() {
    const f = await fixture();
    seedState();
    await installDistribution(f.a.archive, true);
    await updateDistribution(ID, f.opts);
    return f;
  }

  it("restores an active release with a stray file, so rollback and update work again", async () => {
    const f = await updated();
    const active = join(appsDir(), "1.1.0");
    write(join(active, ".DS_Store"), "finder metadata");
    // Still refused, naming the file and the command that repairs it.
    const refused = (() => {
      try {
        verifyPayload(active);
      } catch (error) {
        return error as PiShipError;
      }
      throw new Error("expected a throw");
    })();
    expect(refused.code).toBe("INTEGRITY_FAILED");
    expect(refused.message).toContain(
      "unexpected (not in the inventory): .DS_Store",
    );
    expect(refused.userAction).toContain(
      `piship repair ${ID} <release archive>`,
    );
    const receipt = readInstallReceipt(ID);

    const result = await repairDistribution(ID, f.b.archive);
    expect(result).toMatchObject({
      status: "repaired",
      id: ID,
      version: "1.1.0",
    });
    expect(result.problem).toContain(".DS_Store");
    expect(existsSync(join(active, ".DS_Store"))).toBe(false);
    expect(verifyPayload(active).app.version).toBe("1.1.0");
    expect(readInstallReceipt(ID)).toEqual(receipt);
    expect(apps()).toEqual(["1.0.0", "1.1.0", "launch.mjs"]);

    // Neither is blocked any longer.
    expect((await rollbackDistribution(ID, { runCheck: fakeRun })).to).toBe(
      "1.0.0",
    );
    expect((await updateDistribution(ID, f.opts)).status).toBe("updated");
    expect(readInstallReceipt(ID).active).toBe("1.1.0");
  });

  it("restores a modified file in the retained release, so rollback works again", async () => {
    const f = await updated();
    write(
      join(appsDir(), "1.0.0", "resources", "resources", "AGENTS.md"),
      "# tampered\n",
    );
    expect(() => verifyPayload(join(appsDir(), "1.0.0"))).toThrow(
      /modified: resources\/resources\/AGENTS.md/,
    );
    const result = await repairDistribution(ID, f.a.archive);
    expect(result).toMatchObject({ status: "repaired", version: "1.0.0" });
    expect((await rollbackDistribution(ID, { runCheck: fakeRun })).to).toBe(
      "1.0.0",
    );
  });

  it("restores a release whose directory is missing", async () => {
    const f = await updated();
    rmSync(join(appsDir(), "1.1.0"), { recursive: true, force: true });
    const result = await repairDistribution(ID, f.b.archive);
    expect(result.status).toBe("repaired");
    expect(verifyPayload(join(appsDir(), "1.1.0")).app.version).toBe("1.1.0");
  });

  it("reports an intact release and changes nothing", async () => {
    const f = await updated();
    const before = treeHash(appsDir());
    const result = await repairDistribution(ID, f.b.archive);
    expect(result).toMatchObject({ status: "intact", version: "1.1.0" });
    expect(treeHash(appsDir())).toEqual(before);
  });

  it("refuses a source that is not the recorded release, and changes nothing", async () => {
    const a = await release("1.0.0");
    const b = await release("1.1.0");
    await installDistribution(a.archive);
    const active = join(appsDir(), "1.0.0");
    write(join(active, ".DS_Store"), "finder metadata");
    const before = treeHash(appsDir());
    const receipt = readInstallReceipt(ID);

    // A version this installation does not record.
    const other = await rejection(repairDistribution(ID, b.archive));
    expect(other.code).toBe("UPDATE_FAILED");
    expect(other.message).toMatch(
      /acmepi 1.1.0, which is not a release of acmepi this installation records \(1.0.0\)/,
    );

    // The same version built from different content.
    const path = project("1.0.0");
    write(join(dirname(path), "resources", "AGENTS.md"), "# impostor\n");
    lockManifest(path);
    const impostor = await buildRelease(path, {
      outputRoot: join(dirname(path), "dist"),
      assemble: fakeAssemble,
      runTest: fakeRun,
      scanner: () => ({ auditReportVersion: 2, vulnerabilities: {} }),
      signatureAuditor,
    });
    const mismatch = await rejection(repairDistribution(ID, impostor.archive));
    expect(mismatch.code).toBe("INTEGRITY_FAILED");
    expect(mismatch.message).toMatch(/does not match the 1.0.0 release/);

    // A damaged archive.
    const copy = join(temp(), basename(a.archive));
    cpSync(a.archive, copy);
    flipByte(copy);
    expect((await rejection(repairDistribution(ID, copy))).code).toBe(
      "INTEGRITY_FAILED",
    );

    expect(treeHash(appsDir())).toEqual(before);
    expect(readInstallReceipt(ID)).toEqual(receipt);
  });

  it("does not replace a release a running session still uses", async () => {
    const f = await updated();
    write(join(appsDir(), "1.1.0", ".DS_Store"), "finder metadata");
    const release = holdRuntimeLease(ID, "1.1.0");
    try {
      const error = await rejection(repairDistribution(ID, f.b.archive));
      expect(error.code).toBe("UPDATE_FAILED");
      expect(error.message).toMatch(/runtime session/);
      expect(existsSync(join(appsDir(), "1.1.0", ".DS_Store"))).toBe(true);
    } finally {
      release();
    }
  });
});

// --------------------------------------------------------------- uninstall

describe.runIf(HOST_EVIDENCED)("uninstall and purge", () => {
  it("removes every retained release, the launcher, shim, and receipt, and keeps state", async () => {
    const { a, opts } = await fixture();
    seedState();
    const receipt = await installDistribution(a.archive, true);
    await updateDistribution(ID, opts);
    const state = treeHash(stateDir());
    await expect(purgeDistributionState(ID)).rejects.toThrow(
      /Uninstall acmepi before purging its state/,
    );
    expect(uninstallDistribution(ID)).toBe(stateDir());
    expect(existsSync(appsDir())).toBe(false);
    expect(existsSync(receipt.commandPath)).toBe(false);
    expect(
      existsSync(
        join(
          process.env.PISHIP_INSTALL_HOME as string,
          "receipts",
          `${ID}.json`,
        ),
      ),
    ).toBe(false);
    expect(treeHash(stateDir())).toEqual(state);
    expect(() => readInstallReceipt(ID)).toThrow(
      /No PiShip installation recorded/,
    );
    expect(lifecycleStatus(ID, requireCurrentLockFor(a.directory))).toEqual({
      installed: false,
      tracked: false,
      leftovers: [],
    });
    // Still signed in: purge revokes nothing, so it refuses and deletes
    // nothing until logout has run.
    await expect(purgeDistributionState(ID)).rejects.toThrow(
      /acmepi is still signed in \(an identity session, a runtime credential\)\. .* Run logout with the release's own command .* first, then purge again; .* add --without-logout/,
    );
    expect(treeHash(stateDir())).toEqual(state);
    // What logout leaves: no identity session and no credential.
    rmSync(join(stateDir(), "identity", "session.json"));
    rmSync(join(stateDir(), "credentials-metadata", "inference.json"));
    // The seeded state uses the file fallback, which goes with the directory.
    expect(await purgeDistributionState(ID)).toEqual({
      state: stateDir(),
      deletedSecrets: [],
    });
    expect(existsSync(stateDir())).toBe(false);
  });

  it("purge deletes the secrets a truncated credential file still names", async () => {
    const state = stateDir();
    write(
      join(state, "credentials-metadata", "inference.json"),
      `{"schema": "piship-credential-metadata/v1", "credential_ref": "piship:${ID}:inference#4", "generation": 4, "orphans": ["piship:${ID}:inference#2"`,
    );
    const { store, memory, deleted } = testStore();
    for (const generation of [2, 4, 5])
      await memory.put(
        `piship:${ID}:inference#${generation}`,
        new SecretValue(SENTINEL),
      );
    await purgeDistributionState(ID, { secretStore: store });
    expect(deleted).toEqual([
      `piship:${ID}:inference#2`,
      `piship:${ID}:inference#4`,
      `piship:${ID}:inference#5`,
    ]);
    expect(memory.refs()).toEqual([]);
  });

  it("purge deletes the platform secret-store entries the metadata references", async () => {
    const state = stateDir();
    write(
      join(state, "identity", "session.json"),
      JSON.stringify({
        schema: "piship-identity-metadata/v1",
        subject: "user-1",
        secretRef: `piship:${ID}:identity#2`,
      }),
    );
    write(
      join(state, "credentials-metadata", "inference.json"),
      JSON.stringify({
        schema: "piship-credential-metadata/v1",
        credential_ref: `piship:${ID}:inference#3`,
        orphans: [`piship:${ID}:inference#1`, "piship:other:inference#1"],
      }),
    );
    const lock = { on: true };
    const { store, memory, deleted } = testStore(
      (ref) => lock.on && ref.endsWith("identity#3"),
    );
    const refs = [
      `piship:${ID}:identity#2`,
      `piship:${ID}:identity#3`,
      `piship:${ID}:inference#1`,
      `piship:${ID}:inference#3`,
      "piship:other:inference#1",
    ];
    for (const ref of refs) await memory.put(ref, new SecretValue("s3cret-v"));
    // A secret that cannot be deleted fails the purge and removes no state,
    // so the metadata still names it.
    const error = await rejection(
      purgeDistributionState(ID, { secretStore: store, withoutLogout: true }),
    );
    expect(error.code).toBe("SECRET_STORE_UNAVAILABLE");
    expect(error.message).toBe(
      `Could not delete piship:${ID}:identity#3 from the test store (SECRET_STORE_UNAVAILABLE: The keychain is locked); no state was removed, so the metadata still names this secret`,
    );
    expect(existsSync(join(state, "identity", "session.json"))).toBe(true);
    expect(memory.refs()).toEqual([
      `piship:${ID}:identity#3`,
      "piship:other:inference#1",
    ]);
    lock.on = false;
    deleted.length = 0;
    const result = await purgeDistributionState(ID, {
      secretStore: store,
      withoutLogout: true,
    });
    // Current, adjacent, and orphaned generations of this distribution only.
    expect(deleted).toEqual([
      `piship:${ID}:identity#1`,
      `piship:${ID}:identity#2`,
      `piship:${ID}:identity#3`,
      `piship:${ID}:inference#1`,
      `piship:${ID}:inference#3`,
    ]);
    expect(memory.refs()).toEqual(["piship:other:inference#1"]);
    expect(result).toEqual({
      state,
      deletedSecrets: deleted,
      notRevoked: ["an identity session", "a runtime credential"],
    });
    expect(existsSync(state)).toBe(false);
  });

  it("refuses install, uninstall, and purge when the roots overlap, deleting nothing", async () => {
    const payload = fakeAssemble(project("1.0.0"), temp("piship-payload-"));
    const install = process.env.PISHIP_INSTALL_HOME as string;
    const state = process.env.PISHIP_STATE_HOME as string;
    const bin = process.env.PISHIP_BIN_HOME as string;
    // State inside <install-home>/apps: the payload and state of acmepi
    // would be the same directory.
    process.env.PISHIP_STATE_HOME = join(install, "apps");
    await expect(installDistribution(payload)).rejects.toThrow(
      /PISHIP_STATE_HOME .* and PISHIP_INSTALL_HOME .* overlap/,
    );
    expect(existsSync(join(install, "apps", ID))).toBe(false);
    expect(existsSync(join(install, "receipts", `${ID}.json`))).toBe(false);
    // Installed with separate roots, then the state home is moved over the
    // install: uninstall refuses and keeps everything.
    process.env.PISHIP_STATE_HOME = state;
    const receipt = await installDistribution(payload);
    write(join(stateDir(), "sessions", "s1.jsonl"), "{}\n");
    process.env.PISHIP_STATE_HOME = join(install, "apps");
    expect(() => uninstallDistribution(ID)).toThrow(/overlap/);
    expect(existsSync(receipt.payload)).toBe(true);
    process.env.PISHIP_STATE_HOME = state;
    expect(uninstallDistribution(ID)).toBe(stateDir());
    expect(existsSync(join(stateDir(), "sessions", "s1.jsonl"))).toBe(true);
    // A bin home inside acmepi's state holds another distribution's shim:
    // purging acmepi refuses rather than deleting it.
    process.env.PISHIP_BIN_HOME = join(stateDir(), "bin");
    write(join(stateDir(), "bin", "otherpi"), "#!/bin/sh\n");
    await expect(purgeDistributionState(ID)).rejects.toThrow(/overlap/);
    expect(existsSync(join(stateDir(), "bin", "otherpi"))).toBe(true);
    process.env.PISHIP_BIN_HOME = bin;
  });

  it("refuses update when the roots overlap, changing nothing", async () => {
    const { a, opts } = await fixture();
    await installDistribution(a.archive, true);
    const before = readInstallReceipt(ID);
    const state = process.env.PISHIP_STATE_HOME as string;
    // A state home inside the install home. The receipt records the payload
    // and command paths, not the state home, so only the overlap check can
    // refuse this layout.
    const nested = join(process.env.PISHIP_INSTALL_HOME as string, "state");
    process.env.PISHIP_STATE_HOME = nested;
    const error = await rejection(updateDistribution(ID, opts));
    expect(error.message).toMatch(
      /PISHIP_STATE_HOME .* and PISHIP_INSTALL_HOME .* overlap/,
    );
    expect(readInstallReceipt(ID)).toEqual(before);
    expect(apps()).toEqual(["1.0.0", "launch.mjs"]);
    expect(existsSync(nested)).toBe(false);
    // With separate roots again the same update goes through.
    process.env.PISHIP_STATE_HOME = state;
    await updateDistribution(ID, opts);
    expect(readInstallReceipt(ID).active).toBe("1.1.0");
  });

  it("refuses rollback when the roots overlap, changing nothing", async () => {
    const { a, opts } = await fixture();
    await installDistribution(a.archive, true);
    await updateDistribution(ID, opts);
    const before = readInstallReceipt(ID);
    const state = process.env.PISHIP_STATE_HOME as string;
    const nested = join(process.env.PISHIP_INSTALL_HOME as string, "state");
    process.env.PISHIP_STATE_HOME = nested;
    const error = await rejection(
      rollbackDistribution(ID, { runCheck: fakeRun }),
    );
    expect(error.message).toMatch(
      /PISHIP_STATE_HOME .* and PISHIP_INSTALL_HOME .* overlap/,
    );
    expect(readInstallReceipt(ID)).toEqual(before);
    expect(apps()).toEqual(["1.0.0", "1.1.0", "launch.mjs"]);
    expect(existsSync(nested)).toBe(false);
    process.env.PISHIP_STATE_HOME = state;
    await rollbackDistribution(ID, { runCheck: fakeRun });
    expect(readInstallReceipt(ID).active).toBe("1.0.0");
  });

  it("uninstall with purge removes the install, the secrets, and the state in one operation, or nothing", async () => {
    const a = await release("1.0.0");
    const receipt = await installDistribution(a.archive);
    const state = stateDir();
    write(
      join(state, "credentials-metadata", "inference.json"),
      JSON.stringify({
        schema: "piship-credential-metadata/v1",
        credential_ref: `piship:${ID}:inference#1`,
      }),
    );
    write(join(state, "sessions", "s1.jsonl"), '{"type":"message"}\n');
    const lock = { on: true };
    const { store, memory } = testStore(
      (ref) => lock.on && ref.endsWith("inference#1"),
    );
    await memory.put(`piship:${ID}:inference#1`, new SecretValue(SENTINEL));
    await memory.put("piship:other:inference#1", new SecretValue(SENTINEL));
    // A live runtime refuses it before any secret is touched.
    const releaseLease = holdRuntimeLease(ID, "1.0.0");
    try {
      await expect(
        uninstallAndPurgeDistribution(ID, {
          secretStore: store,
          withoutLogout: true,
        }),
      ).rejects.toThrow(/runtime session/);
    } finally {
      releaseLease();
    }
    // A secret that cannot be deleted leaves the installed manager, the
    // receipt, and the state in place, so the same command can be retried.
    const before = treeHash(state);
    const error = await rejection(
      uninstallAndPurgeDistribution(ID, {
        secretStore: store,
        withoutLogout: true,
      }),
    );
    expect(error.code).toBe("SECRET_STORE_UNAVAILABLE");
    expect(readInstallReceipt(ID)).toEqual(receipt);
    expect(existsSync(receipt.payload)).toBe(true);
    expect(existsSync(receipt.commandPath)).toBe(true);
    expect(treeHash(state)).toEqual(before);
    expect(memory.refs()).toContain(`piship:${ID}:inference#1`);
    lock.on = false;
    const result = await uninstallAndPurgeDistribution(ID, {
      secretStore: store,
      withoutLogout: true,
    });
    expect(result.state).toBe(state);
    expect(result.deletedSecrets).toContain(`piship:${ID}:inference#1`);
    expect(memory.refs()).toEqual(["piship:other:inference#1"]);
    expect(existsSync(receipt.commandPath)).toBe(false);
    expect(existsSync(appsDir())).toBe(false);
    expect(() => readInstallReceipt(ID)).toThrow(
      /No PiShip installation recorded/,
    );
    expect(existsSync(state)).toBe(false);
  });

  it("uninstall with purge refuses a signed-in distribution until logout, deleting nothing", async () => {
    const a = await release("1.0.0");
    const receipt = await installDistribution(a.archive);
    const state = stateDir();
    const metadata = join(state, "credentials-metadata", "inference.json");
    write(
      metadata,
      JSON.stringify({
        schema: "piship-credential-metadata/v1",
        credential_ref: `piship:${ID}:inference#1`,
      }),
    );
    const { store, memory } = testStore(() => false);
    await memory.put(`piship:${ID}:inference#1`, new SecretValue(SENTINEL));
    const before = treeHash(state);
    await expect(
      uninstallAndPurgeDistribution(ID, { secretStore: store }),
    ).rejects.toThrow(
      /acmepi is still signed in \(a runtime credential\)\. .* Run acmepi logout first, then purge again/,
    );
    expect(readInstallReceipt(ID)).toEqual(receipt);
    expect(existsSync(receipt.payload)).toBe(true);
    expect(existsSync(receipt.commandPath)).toBe(true);
    expect(treeHash(state)).toEqual(before);
    expect(memory.refs()).toEqual([`piship:${ID}:inference#1`]);
    // A discarded marker is signed out: purge deletes what it still names.
    write(
      metadata,
      JSON.stringify({
        schema: "piship-credential-discarded/v1",
        orphans: [`piship:${ID}:inference#1`],
      }),
    );
    const result = await uninstallAndPurgeDistribution(ID, {
      secretStore: store,
    });
    expect(result.notRevoked).toBeUndefined();
    expect(memory.refs()).toEqual([]);
    expect(existsSync(receipt.commandPath)).toBe(false);
    expect(existsSync(state)).toBe(false);
  });

  it("names sandbox logout when only a stored sandbox credential is signed in", async () => {
    await installDistribution((await release("1.0.0")).archive);
    write(
      join(stateDir(), "credentials-metadata", "sandbox.json"),
      JSON.stringify({
        schema: "piship-sandbox-credential-metadata/v1",
        credential_ref: `piship:${ID}:sandbox#1`,
      }),
    );
    await expect(uninstallAndPurgeDistribution(ID, {})).rejects.toThrow(
      /\(a sandbox credential\)\. .* Run acmepi sandbox logout first/,
    );
  });

  it("uninstall with purge refuses a rewritten command shim before it deletes a secret", async () => {
    const a = await release("1.0.0");
    const receipt = await installDistribution(a.archive);
    const state = stateDir();
    write(
      join(state, "credentials-metadata", "inference.json"),
      JSON.stringify({
        schema: "piship-credential-metadata/v1",
        credential_ref: `piship:${ID}:inference#1`,
      }),
    );
    const { store, memory } = testStore(() => false);
    await memory.put(`piship:${ID}:inference#1`, new SecretValue(SENTINEL));
    // Another tool rewrote the command: the uninstall refuses, and because it
    // checks before deleting, the state still names credentials that exist.
    const shim = readFileSync(receipt.commandPath, "utf8");
    writeFileSync(receipt.commandPath, `${shim}\n# rewritten`);
    await expect(
      uninstallAndPurgeDistribution(ID, {
        secretStore: store,
        withoutLogout: true,
      }),
    ).rejects.toThrow(/was changed after/);
    expect(memory.refs()).toEqual([`piship:${ID}:inference#1`]);
    expect(existsSync(state)).toBe(true);
    expect(existsSync(receipt.payload)).toBe(true);
    writeFileSync(receipt.commandPath, shim);
    const result = await uninstallAndPurgeDistribution(ID, {
      secretStore: store,
      withoutLogout: true,
    });
    expect(result.deletedSecrets).toContain(`piship:${ID}:inference#1`);
    expect(memory.refs()).toEqual([]);
    expect(existsSync(state)).toBe(false);
  });
});

describe.runIf(HOST_EVIDENCED)("uninstall after an interrupted update", () => {
  it("removes an orphan release directory left by a killed update", async () => {
    const a = await release("1.0.0");
    const receipt = await installDistribution(a.archive);
    cpSync(join(appsDir(), "1.0.0"), join(appsDir(), "1.1.0"), {
      recursive: true,
    });
    expect(() => uninstallDistribution(ID)).not.toThrow();
    expect(existsSync(appsDir())).toBe(false);
    expect(existsSync(receipt.commandPath)).toBe(false);
    expect(() => readInstallReceipt(ID)).toThrow(
      /No PiShip installation recorded/,
    );
  });
});

describe.runIf(HOST_EVIDENCED)("a damaged install receipt", () => {
  const receiptFile = () =>
    join(process.env.PISHIP_INSTALL_HOME as string, "receipts", `${ID}.json`);
  /** A payload of another distribution, `otherpi`, with its own command. */
  function otherPayload(command: string): string {
    const dir = temp("piship-other-project-");
    const manifest = join(dir, "piship.yaml");
    write(join(dir, "resources", "AGENTS.md"), "# other\n");
    writeFileSync(
      manifest,
      manifestSource("1.0.0", true)
        .replace(`id: ${ID}`, "id: otherpi")
        .replace(`command: ${ID}`, `command: ${command}`),
    );
    lockManifest(manifest);
    return fakeAssemble(manifest, temp("piship-other-"));
  }

  for (const [kind, damage] of [
    ["truncated", (text: string) => text.slice(0, 120)],
    ["empty", () => ""],
  ] as const)
    it(`uninstalls and purges a distribution whose receipt is ${kind}`, async () => {
      const a = await release("1.0.0");
      const receipt = await installDistribution(a.archive);
      seedState();
      const bin = process.env.PISHIP_BIN_HOME as string;
      writeFileSync(join(bin, "unrelated"), "#!/bin/sh\necho unrelated\n");
      writeFileSync(receiptFile(), damage(readFileSync(receiptFile(), "utf8")));
      const error = (() => {
        try {
          readInstallReceipt(ID);
        } catch (caught) {
          return caught;
        }
      })();
      expect(error).toBeInstanceOf(PiShipError);
      expect(error).toMatchObject({ code: "CONFIG_INVALID" });
      expect((error as Error).message).toContain(receiptFile());
      expect((error as PiShipError).userAction).toBe(
        `Run piship uninstall ${ID}, then install ${ID} again`,
      );
      // Reinstalling still refuses while the receipt exists.
      await expect(installDistribution(a.archive)).rejects.toThrow(
        /uninstall the existing distribution first/,
      );
      expect(uninstallDistribution(ID)).toBe(stateDir());
      expect(existsSync(appsDir())).toBe(false);
      expect(existsSync(receiptFile())).toBe(false);
      expect(existsSync(receipt.commandPath)).toBe(false);
      expect(readFileSync(join(bin, "unrelated"), "utf8")).toContain(
        "unrelated",
      );
      expect(existsSync(stateDir())).toBe(true);
      // Still signed in: purge refuses until the release's own logout ran,
      // which removes what this does.
      await expect(purgeDistributionState(ID)).rejects.toThrow(
        /still signed in .*payload\/bin\/<command> logout/,
      );
      rmSync(join(stateDir(), "identity"), { recursive: true, force: true });
      rmSync(join(stateDir(), "credentials-metadata"), {
        recursive: true,
        force: true,
      });
      await expect(purgeDistributionState(ID)).resolves.toMatchObject({
        state: stateDir(),
      });
      expect(existsSync(stateDir())).toBe(false);
      await expect(installDistribution(a.archive)).resolves.toMatchObject({
        active: "1.0.0",
      });
    });

  it("names PISHIP_BIN_HOME for a command path under another bin home and removes nothing", async () => {
    const a = await release("1.0.0");
    const receipt = await installDistribution(a.archive);
    const original = process.env.PISHIP_BIN_HOME as string;
    const before = treeHash(process.env.PISHIP_INSTALL_HOME as string);
    process.env.PISHIP_BIN_HOME = temp("piship-other-bin-");
    let error: unknown;
    try {
      uninstallDistribution(ID);
    } catch (caught) {
      error = caught;
    }
    expect(error).toBeInstanceOf(PiShipError);
    expect((error as PiShipError).message).toContain(receiptFile());
    expect((error as PiShipError).userAction).toBe(
      `Set PISHIP_BIN_HOME=${original} and run the command again`,
    );
    expect(treeHash(process.env.PISHIP_INSTALL_HOME as string)).toEqual(before);
    expect(existsSync(receipt.commandPath)).toBe(true);
    process.env.PISHIP_BIN_HOME = original;
    uninstallDistribution(ID);
    expect(existsSync(receipt.commandPath)).toBe(false);
  });

  it("removes only the current install home's paths when the receipt names another install home", async () => {
    const a = await release("1.0.0");
    const receipt = await installDistribution(a.archive);
    const home = process.env.PISHIP_INSTALL_HOME as string;
    // The receipt names an install home that exists and holds files.
    const decoy = join(temp("piship-decoy-"), "install");
    cpSync(home, decoy, { recursive: true });
    const decoyTree = treeHash(decoy);
    writeFileSync(
      receiptFile(),
      readFileSync(receiptFile(), "utf8").replaceAll(
        JSON.stringify(home).slice(1, -1),
        JSON.stringify(decoy).slice(1, -1),
      ),
    );
    expect(() => readInstallReceipt(ID)).toThrow(
      `it was written with PISHIP_INSTALL_HOME=${decoy}`,
    );
    uninstallDistribution(ID);
    expect(existsSync(appsDir())).toBe(false);
    expect(existsSync(receiptFile())).toBe(false);
    expect(existsSync(receipt.commandPath)).toBe(false);
    expect(treeHash(decoy)).toEqual(decoyTree);
  });

  it("installs another distribution while this one's receipt is damaged", async () => {
    const a = await release("1.0.0");
    const receipt = await installDistribution(a.archive);
    writeFileSync(receiptFile(), "");
    const shim = readFileSync(receipt.commandPath, "utf8");
    const other = await installDistribution(otherPayload("otherpi"));
    expect(other.app.id).toBe("otherpi");
    expect(readFileSync(receipt.commandPath, "utf8")).toBe(shim);
    // A damaged receipt whose text still names the command keeps it, even
    // before its shim was written.
    uninstallDistribution("otherpi");
    rmSync(receipt.commandPath);
    writeFileSync(
      receiptFile(),
      `{"app": {"id": "${ID}", "command": "otherpi"`,
    );
    await expect(installDistribution(otherPayload("otherpi"))).rejects.toThrow(
      `Install collision: command otherpi is owned by ${ID}`,
    );
    uninstallDistribution(ID);
    expect(existsSync(appsDir())).toBe(false);
  });
});

function requireCurrentLockFor(releaseDir: string) {
  return JSON.parse(
    readFileSync(join(releaseDir, "payload", "piship.lock"), "utf8"),
  ) as ReturnType<typeof requireCurrentLock>;
}

// ---------------------------------------------------------- channel policy

describe("selectChannel", () => {
  const updates = {
    channel: "stable" as const,
    channels: ["stable" as const, "candidate" as const],
    rollback: true,
    trust: { keys: [] },
  };
  it("honours requested, saved, and default channels", () => {
    expect(selectChannel(updates, "candidate", "stable")).toEqual({
      channel: "candidate",
      notices: [],
    });
    expect(selectChannel(updates, undefined, "candidate")).toEqual({
      channel: "candidate",
      notices: [],
    });
    expect(selectChannel(updates, undefined, undefined)).toEqual({
      channel: "stable",
      notices: [],
    });
    expect(selectChannel(updates, undefined, "dev")).toEqual({
      channel: "stable",
      notices: ["Channel dev is no longer allowed; using stable"],
    });
    expect(() => selectChannel(updates, "dev", undefined)).toThrow(
      /Channel dev is not allowed/,
    );
  });
});

// ------------------------------------------------------- update hardening

describe.runIf(HOST_EVIDENCED)("update hardening", () => {
  it("starts an install of a candidate-built archive on the default channel", async () => {
    const path = project("1.0.0");
    const built = await buildRelease(path, {
      outputRoot: join(dirname(path), "dist"),
      channel: "candidate",
      assemble: fakeAssemble,
      runTest: fakeRun,
      scanner: () => ({ auditReportVersion: 2, vulnerabilities: {} }),
    });
    expect(built.metadata.channel).toBe("candidate");
    const receipt = await installDistribution(built.archive);
    expect(receipt.channel).toBe("stable");
    expect(readInstallReceipt(ID).channel).toBe("stable");
  });

  it("does not boot the candidate or create throwaway runtime state", async () => {
    const { a, opts } = await fixture();
    seedState();
    await installDistribution(a.archive, true);
    const homes: (string | undefined)[] = [];
    const result = await updateDistribution(ID, {
      ...opts,
      runCheck: (payload, command, args, env) => {
        homes.push(env.PISHIP_STATE_HOME);
        return fakeRun(payload, command, args);
      },
    });
    expect(result.status).toBe("updated");
    expect(homes).toEqual([]);
  });

  it("stops a download that grows past the signed size", async () => {
    const { a, channelDir } = await fixture();
    await installDistribution(a.archive);
    const serve = (padArchive: number, padMetadata: number) =>
      (async (input: URL | string) => {
        const name = new URL(String(input)).pathname.split("/").pop() as string;
        const file = join(channelDir, name);
        if (!existsSync(file)) return new Response("", { status: 404 });
        const bytes = readFileSync(file);
        const pad = name.endsWith(".tar.gz")
          ? padArchive
          : name === "stable.json"
            ? padMetadata
            : 0;
        return new Response(Buffer.concat([bytes, Buffer.alloc(pad)]));
      }) as typeof fetch;
    const env = { ACMEPI_UPDATE_SOURCE: "https://updates.example.test/acmepi" };
    const archive = await rejection(
      updateDistribution(ID, {
        runCheck: fakeRun,
        fetcher: serve(4096, 0),
        env,
      }),
    );
    expect(archive.code).toBe("INTEGRITY_FAILED");
    expect(archive.message).toMatch(/exceeds \d+ bytes/);
    const metadata = await rejection(
      updateDistribution(ID, {
        runCheck: fakeRun,
        fetcher: serve(0, 2 * 1024 * 1024),
        env,
      }),
    );
    expect(metadata.code).toBe("INTEGRITY_FAILED");
    expect(metadata.message).toMatch(/stable\.json .*exceeds/);
    expect(readInstallReceipt(ID).active).toBe("1.0.0");
    expect(apps()).toEqual(["1.0.0", "launch.mjs"]);
  });

  it("gives up on an update source that does not answer", async () => {
    const { a } = await fixture();
    await installDistribution(a.archive);
    const signals: (AbortSignal | null | undefined)[] = [];
    // Every request carries a deadline; a timed-out request is a retryable failure.
    const fetcher = (async (_input: URL | string, init?: RequestInit) => {
      signals.push(init?.signal);
      throw new DOMException("The operation timed out", "TimeoutError");
    }) as typeof fetch;
    const error = await rejection(
      updateDistribution(ID, {
        runCheck: fakeRun,
        fetcher,
        env: { ACMEPI_UPDATE_SOURCE: "https://updates.example.test/acmepi" },
      }),
    );
    expect(signals[0]).toBeInstanceOf(AbortSignal);
    expect(error.code).toBe("UPDATE_FAILED");
    expect(error.retryable).toBe(true);
    expect(error.message).toMatch(
      /did not answer for root\/2\.json within 30 s/,
    );
    expect(existsSync(join(appsDir(), ".lifecycle.lock"))).toBe(false);
  });
});

// ------------------------------------------------------- installed launcher

describe.runIf(HOST_EVIDENCED)("installed launcher", () => {
  const launch = (launcher: string) =>
    spawnSync(process.execPath, [launcher], { encoding: "utf8" });
  const waitForFile = (path: string): Promise<void> =>
    new Promise((resolvePromise) => {
      if (existsSync(path)) return resolvePromise();
      const watcher = watch(dirname(path), () => {
        if (existsSync(path)) {
          watcher.close();
          resolvePromise();
        }
      });
      if (existsSync(path)) {
        watcher.close();
        resolvePromise();
      }
    });

  // A release whose command is a long-running session: it reports that it
  // started, waits for a signal, then reads a packaged resource of its own
  // release on demand, as Pi reads a skill file, and exits.
  const SESSION = `#!/usr/bin/env node
const { existsSync, readFileSync, writeFileSync } = require("node:fs");
const { join } = require("node:path");
const dir = process.env.ACMEPI_SESSION;
const root = join(__dirname, "..");
writeFileSync(join(dir, "ready"), "");
const lock = JSON.parse(readFileSync(join(root, "piship.lock"), "utf8"));
const wait = () => {
  if (!existsSync(join(dir, "go"))) return setTimeout(wait, 20);
  writeFileSync(join(dir, "read"), readFileSync(join(root, "resources", lock.resources[0].path), "utf8"));
};
wait();
`;
  const sessionAssemble = (manifest: string, outputRoot: string) => {
    const out = fakeAssemble(manifest, outputRoot);
    const lock = JSON.parse(readFileSync(join(out, "piship.lock"), "utf8")) as {
      app: { command: string };
    };
    writeFileSync(join(out, "bin", lock.app.command), SESSION);
    const inventory = join(out, "metadata", "inventory.json");
    rmSync(inventory);
    writeFileSync(
      inventory,
      `${JSON.stringify(payloadInventory(out), null, 2)}\n`,
    );
    return out;
  };
  const sessionRelease = (version: string, rollback = true) =>
    buildRelease(project(version, rollback), {
      outputRoot: temp("piship-session-dist-"),
      assemble: sessionAssemble,
      runTest: fakeRun,
      scanner: () => ({ auditReportVersion: 2, vulnerabilities: {} }),
      signatureAuditor,
    });
  const startSession = async (launcher: string) => {
    const dir = temp("piship-session-");
    const child = spawn(process.execPath, [launcher], {
      env: { ...process.env, ACMEPI_SESSION: dir },
      stdio: ["ignore", "ignore", "pipe"],
    });
    let stderr = "";
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    const exited = new Promise<number | null>((done) =>
      child.once("exit", done),
    );
    await Promise.race([
      waitForFile(join(dir, "ready")),
      exited.then(() => {
        throw new Error(`The session exited early: ${stderr}`);
      }),
    ]);
    return {
      child,
      /** Ask the session for its resource and wait for it to exit. */
      async finish(): Promise<string> {
        writeFileSync(join(dir, "go"), "");
        expect(await exited, stderr).toBe(0);
        return readFileSync(join(dir, "read"), "utf8");
      },
    };
  };
  const releaseDirs = () => apps().filter((name) => /^\d/.test(name));

  it("keeps a running session's release through two updates, then reclaims it after the session exits", async () => {
    const [v1, v2, v3] = [
      await sessionRelease("1.0.0"),
      await sessionRelease("1.1.0"),
      await sessionRelease("1.2.0"),
    ];
    const channel = temp("piship-channel-");
    const options: UpdateOptions = { source: channel, runCheck: fakeRun };
    const receipt = await installDistribution(v1.archive);
    const session = await startSession(receipt.launcher as string);
    try {
      await sign(channel, [v2.archive]);
      await updateDistribution(ID, options);
      await sign(channel, [v3.archive]);
      await updateDistribution(ID, options);
      const current = readInstallReceipt(ID);
      expect(current.active).toBe("1.2.0");
      expect(current.releases.map((item) => item.version)).not.toContain(
        "1.0.0",
      );
      // The receipt no longer names 1.0.0, but its session still runs it.
      expect(releaseDirs()).toEqual(["1.0.0", "1.1.0", "1.2.0"]);
      recoverInstallation(ID);
      expect(releaseDirs()).toEqual(["1.0.0", "1.1.0", "1.2.0"]);
      expect(() => uninstallDistribution(ID)).toThrow(
        /while 1 runtime session\(s\) still use its payload/,
      );
      expect(await session.finish()).toBe("# AcmePi 1.0.0\n");
    } finally {
      session.child.kill();
    }
    recoverInstallation(ID);
    expect(releaseDirs()).toEqual(["1.1.0", "1.2.0"]);
    uninstallDistribution(ID);
    expect(existsSync(appsDir())).toBe(false);
  }, 60_000);

  it("keeps a running session's release through an update that disables rollback", async () => {
    const v1 = await sessionRelease("1.0.0");
    const v2 = await sessionRelease("1.1.0", false);
    const channel = temp("piship-channel-");
    const receipt = await installDistribution(v1.archive);
    const session = await startSession(receipt.launcher as string);
    try {
      await sign(channel, [v2.archive]);
      await updateDistribution(ID, { source: channel, runCheck: fakeRun });
      expect(
        readInstallReceipt(ID).releases.map((item) => item.version),
      ).toEqual(["1.1.0"]);
      expect(releaseDirs()).toEqual(["1.0.0", "1.1.0"]);
      expect(await session.finish()).toBe("# AcmePi 1.0.0\n");
    } finally {
      session.child.kill();
    }
    recoverInstallation(ID);
    expect(releaseDirs()).toEqual(["1.1.0"]);
  }, 60_000);

  it("holds the release against uninstall while the runtime loads, and holds the gate only while the launch registers", async () => {
    const { a } = await fixture();
    const receipt = await installDistribution(a.archive);
    const ready = join(temp("piship-launch-race-"), "ready");
    const release = join(dirname(ready), "release");
    const gate = join(
      process.env.PISHIP_INSTALL_HOME as string,
      "receipts",
      `.${ID}.launch.lock`,
    );
    // A release whose launcher takes as long as a cold load of the runtime:
    // the first launch writes `ready` and waits; a launch that finds `ready`
    // is the second, and returns at once.
    writeFileSync(
      join(receipt.payload, "bin", receipt.app.command),
      `import { writeFileSync, watch, existsSync } from "node:fs";
import { dirname } from "node:path";
if (existsSync(${JSON.stringify(ready)})) console.log("second launch ran");
else {
  writeFileSync(${JSON.stringify(ready)}, "ready");
  await new Promise((resolve) => {
    const watcher = watch(dirname(${JSON.stringify(release)}), () => {
      if (existsSync(${JSON.stringify(release)})) { watcher.close(); resolve(); }
    });
    if (existsSync(${JSON.stringify(release)})) { watcher.close(); resolve(); }
  });
}
`,
    );
    const child = spawn(process.execPath, [receipt.launcher as string], {
      stdio: "ignore",
    });
    try {
      await waitForFile(ready);
      // The gate is free: a second launch is not held up by the load.
      expect(existsSync(gate)).toBe(false);
      const second = spawnSync(process.execPath, [receipt.launcher as string], {
        encoding: "utf8",
      });
      expect(second.status, second.stderr).toBe(0);
      expect(second.stdout).toContain("second launch ran");
      // What keeps the release is the lease, not the gate.
      expect(() => uninstallDistribution(ID)).toThrow(
        /while 1 runtime session\(s\) still use its payload/,
      );
      expect(existsSync(receipt.payload)).toBe(true);
      writeFileSync(release, "continue");
      const code = await new Promise<number | null>((resolvePromise) =>
        child.once("exit", resolvePromise),
      );
      expect(code).toBe(0);
      uninstallDistribution(ID);
    } finally {
      child.kill();
    }
  }, 30_000);

  it("reclaims a registration gate a killed launcher left, and waits only briefly for a live one", async () => {
    const { a } = await fixture();
    const receipt = await installDistribution(a.archive);
    const gate = join(
      process.env.PISHIP_INSTALL_HOME as string,
      "receipts",
      `.${ID}.launch.lock`,
    );
    const holder = (pid: number) =>
      `${JSON.stringify({ schema: "piship-lifecycle-lock/v1", pid, instance: "left-behind" })}\n`;
    writeFileSync(gate, holder(deadPid()));
    const launched = spawnSync(process.execPath, [receipt.launcher as string], {
      encoding: "utf8",
    });
    expect(launched.status, launched.stderr).toBe(0);
    expect(launched.stdout).toContain("payload");
    expect(existsSync(gate)).toBe(false);
    // A live holder (this process) is waited for, then reported.
    writeFileSync(gate, holder(process.pid));
    const started = Date.now();
    const busy = spawnSync(process.execPath, [receipt.launcher as string], {
      encoding: "utf8",
    });
    expect(busy.status).toBe(1);
    // The launcher names the gate by its real path, which can differ from
    // the configured one (/private/var on macOS).
    expect(busy.stderr).toContain(join("receipts", `.${ID}.launch.lock`));
    expect(busy.stderr).toContain(`is held by process ${process.pid}. Retry`);
    expect(Date.now() - started).toBeLessThan(10_000);
    rmSync(gate);
  }, 30_000);

  it("launches a release whose PiShip predates runtime leases", async () => {
    const { a } = await fixture();
    const receipt = await installDistribution(a.archive);
    writeFileSync(
      join(
        receipt.payload,
        "node_modules",
        "@piship",
        "core",
        "dist",
        "index.js",
      ),
      "export {};\n",
    );
    const launched = spawnSync(process.execPath, [receipt.launcher as string], {
      encoding: "utf8",
    });
    expect(launched.status, launched.stderr).toBe(0);
    expect(launched.stdout).toContain("payload");
  });

  it.runIf(process.platform !== "win32")(
    "launches when the receipt records a symlinked install path",
    async () => {
      // The receipt records the configured (alias) path; Node resolves the
      // launcher to its real path, as with macOS /var -> /private/var.
      const real = temp("piship-real-home-");
      const alias = join(temp("piship-alias-"), "home");
      symlinkSync(real, alias);
      process.env.PISHIP_INSTALL_HOME = join(alias, "install");
      process.env.PISHIP_BIN_HOME = join(alias, "bin");
      const { a } = await fixture();
      const receipt = await installDistribution(a.archive);
      const launcher = receipt.launcher as string;
      expect(receipt.payload.startsWith(alias)).toBe(true);
      expect(realpathSync(launcher)).not.toBe(launcher);
      for (const path of [launcher, realpathSync(launcher)]) {
        const result = launch(path);
        expect(result.status, result.stderr).toBe(0);
        expect(result.stdout).toContain("payload");
      }
    },
  );

  it("fails closed for a payload outside the install tree or a missing payload", async () => {
    const { a } = await fixture();
    const receipt = await installDistribution(a.archive);
    const launcher = receipt.launcher as string;
    expect(launch(launcher).status).toBe(0);
    const path = join(
      process.env.PISHIP_INSTALL_HOME as string,
      "receipts",
      `${ID}.json`,
    );
    const original = readFileSync(path, "utf8");
    // A payload elsewhere, even a valid copy, is not this installation's.
    const outside = join(temp("piship-outside-"), "1.0.0");
    cpSync(receipt.payload, outside, { recursive: true });
    const moved = JSON.parse(original);
    moved.releases[0].payload = outside;
    writeFileSync(path, JSON.stringify(moved));
    const escaped = launch(launcher);
    expect(escaped.status).toBe(1);
    expect(escaped.stderr).toContain("install receipt is missing or damaged");
    expect(escaped.stdout).not.toContain("payload");
    // A missing payload fails the same way.
    writeFileSync(path, original);
    rmSync(receipt.payload, { recursive: true, force: true });
    const missing = launch(launcher);
    expect(missing.status).toBe(1);
    expect(missing.stderr).toContain("install receipt is missing or damaged");
  });
});

describe("launch-time payload verification", () => {
  function payload(): string {
    return fakeAssemble(project("1.0.0"), temp("piship-payload-"));
  }
  function thrown(action: () => unknown): Error & { code?: string } {
    try {
      action();
    } catch (error) {
      return error as Error & { code?: string };
    }
    throw new Error("expected a throw");
  }
  function reinventory(directory: string): void {
    write(
      join(directory, "metadata", "inventory.json"),
      `${JSON.stringify(payloadInventory(directory), null, 2)}\n`,
    );
  }

  it("verifies an untouched payload", () => {
    expect(verifyPayload(payload()).app.id).toBe(ID);
  });

  it("reports a modified payload file as INTEGRITY_FAILED", () => {
    const directory = payload();
    write(join(directory, "resources", "resources", "AGENTS.md"), "# evil\n");
    const error = thrown(() => verifyPayload(directory));
    expect(error).toBeInstanceOf(PiShipError);
    expect(error.code).toBe("INTEGRITY_FAILED");
    expect(error.message).toMatch(/payload integrity mismatch/);
    expect(error.message).toContain("modified: resources/resources/AGENTS.md");
    expect((error as PiShipError).sanitizedDetail).toMatchObject({
      added: [],
      modified: ["resources/resources/AGENTS.md"],
      missing: [],
    });
  });

  it("names an unexpected added file, still refusing the payload", () => {
    const directory = payload();
    write(join(directory, ".DS_Store"), "finder metadata");
    write(join(directory, "resources", "._AGENTS.md"), "resource fork");
    const error = thrown(() => verifyPayload(directory)) as PiShipError;
    expect(error).toBeInstanceOf(PiShipError);
    expect(error.code).toBe("INTEGRITY_FAILED");
    expect(error.message).toContain(
      "unexpected (not in the inventory): .DS_Store, resources/._AGENTS.md",
    );
    expect(error.message).not.toContain("modified:");
    expect(error.sanitizedDetail).toMatchObject({
      added: [".DS_Store", "resources/._AGENTS.md"],
      modified: [],
      missing: [],
    });
    expect(error.userAction).toContain("piship repair <id> <release archive>");
    expect(error.userAction).toContain(
      "Remove the unexpected files it names, or restore it",
    );
    expect(error.userAction).toContain(
      "without a PiShip CLI: node <extracted release>/payload/piship.mjs repair <id> <extracted release>",
    );
  });

  it("names a missing file and caps a long list", () => {
    const directory = payload();
    rmSync(join(directory, "bin", ID));
    for (let index = 0; index < 12; index += 1)
      write(join(directory, "extra", `file-${index}`), "x");
    const error = thrown(() => verifyPayload(directory)) as PiShipError;
    expect(error.code).toBe("INTEGRITY_FAILED");
    expect(error.message).toContain(`missing: bin/${ID}`);
    expect(error.message).toContain("and 7 more");
    expect(error.sanitizedDetail).toMatchObject({ missing: [`bin/${ID}`] });
    expect(error.sanitizedDetail?.added).toHaveLength(12);
    expect(error.userAction).toMatch(/^Do not run it\. Restore it from/);
  });

  it("reports a lock tampered behind a rewritten inventory as LOCK_INVALID", () => {
    const directory = payload();
    const path = join(directory, "piship.lock");
    const lock = JSON.parse(readFileSync(path, "utf8"));
    lock.manifest.sha256 = "0".repeat(64);
    writeFileSync(path, `${JSON.stringify(lock, null, 2)}\n`);
    reinventory(directory);
    const error = thrown(() => verifyPayload(directory));
    expect(error).toBeInstanceOf(PiShipError);
    expect(error.code).toBe("LOCK_INVALID");
    expect(error.message).toMatch(/manifest and lock mismatch/);
  });

  it("reports an npm lock that the lock does not record as LOCK_INVALID", () => {
    const directory = payload();
    writeFileSync(join(directory, "package-lock.json"), "{}\n");
    reinventory(directory);
    const error = thrown(() => verifyPayload(directory));
    expect(error.code).toBe("LOCK_INVALID");
    expect(error.message).toMatch(/npm lock mismatch/);
    expect((error as PiShipError).userAction).toContain("piship repair <id>");
  });
});
