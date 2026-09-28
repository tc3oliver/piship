import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, relative, resolve } from "node:path";
import { SecretValue } from "@piship/contracts";
import { MemorySecretStore } from "@piship/credentials";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  EVIDENCED_TARGETS,
  currentTarget,
  lockManifest,
  payloadInventory,
  type requireCurrentLock,
  verifyPayload,
} from "./index.js";
import {
  RECEIPT_SCHEMA,
  type UpdateOptions,
  installDistribution,
  lifecycleStatus,
  purgeDistributionState,
  readInstallReceipt,
  recoverInstallation,
  rollbackDistribution,
  selectChannel,
  uninstallDistribution,
  updateDistribution,
} from "./lifecycle.js";
import { readStateMarker } from "./migration.js";
import { type CommandResult, buildRelease, signChannel } from "./release.js";
import { generateSigningKey } from "./signing.js";

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

function manifestSource(version: string, rollback: boolean): string {
  return `schema: piship/v1alpha4
app:
  id: ${ID}
  name: AcmePi
  command: ${ID}
  version: ${version}
runtime:
  pi: "0.87.1"
deployment:
  mode: personal
variables:
  - ACMEPI_UPDATE_SOURCE
resources:
  instructions:
    user: [./resources/AGENTS.md]
updates:
  channel: stable
  channels: [stable, candidate]
  source: \${ACMEPI_UPDATE_SOURCE}
  rollback: ${rollback}
  trust:
    keys:
      - id: ${KEY.id}
        publicKey: ${KEY.publicKey}
`;
}

function project(version: string, rollback = true): string {
  const dir = temp("piship-project-");
  write(join(dir, "resources", "AGENTS.md"), `# AcmePi ${version}\n`);
  const path = join(dir, "piship.yaml");
  writeFileSync(path, manifestSource(version, rollback));
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

async function release(version: string, rollback = true) {
  const path = project(version, rollback);
  return buildRelease(path, {
    outputRoot: join(dirname(path), "dist"),
    assemble: fakeAssemble,
    runTest: fakeRun,
    scanner: () => ({ auditReportVersion: 2, vulnerabilities: {} }),
  });
}

function sign(directory: string, archives: string[], channel = "stable") {
  return signChannel({
    directory,
    channel,
    archives,
    privateKeyPem: KEY.privateKeyPem,
    keyId: KEY.id,
  });
}

/** Releases A (1.0.0) and B (1.1.0); the channel offered A at sequence 1 and now offers B at sequence 2. */
async function fixture(options: { rollbackB?: boolean } = {}) {
  const a = await release("1.0.0");
  const b = await release("1.1.0", options.rollbackB ?? true);
  const channelDir = temp("piship-channel-");
  await sign(channelDir, [a.archive]);
  const old = temp("piship-old-channel-");
  cpSync(join(channelDir, "stable.json"), join(old, "stable.json"));
  cpSync(join(channelDir, "stable.json.sig"), join(old, "stable.json.sig"));
  await sign(channelDir, [b.archive]);
  const opts: UpdateOptions = { source: channelDir, runCheck: fakeRun };
  return { a, b, channelDir, old, opts };
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
            pi: "0.87.1",
            piship: "0.1.0",
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
    ).toEqual(["apps", "receipts"]);
    expect(lifecycleStatus(ID, verifyPayload(payload))).toEqual({
      installed: true,
      tracked: true,
      active: "1.0.0",
      channel: "stable",
      channels: ["stable", "candidate"],
      source: `\${ACMEPI_UPDATE_SOURCE}`,
      trustedKeys: 1,
      rollback: true,
      fromRelease: true,
      leftovers: [],
    });
  });

  it("installs a release directory without an archive digest", async () => {
    const a = await release("1.0.0");
    const receipt = await installDistribution(a.directory);
    expect(receipt.releases[0]?.release).toBeDefined();
    expect(receipt.releases[0]?.release).not.toHaveProperty("archiveSha256");
    // The release directory is left untouched.
    expect(existsSync(join(a.directory, "payload", "piship.lock"))).toBe(true);
  });

  it("refuses collisions and unowned state, leaving nothing behind", async () => {
    const a = await release("1.0.0");
    await installDistribution(a.archive);
    const before = treeHash(process.env.PISHIP_INSTALL_HOME as string);
    await expect(installDistribution(a.archive)).rejects.toThrow(
      /Install collision for acmepi\/acmepi/,
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
    // The candidate was launch-checked before activation, from staging.
    expect(checked).toHaveLength(1);
    expect(checked[0]).toContain(".staging-");
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
      pi: "0.87.1",
      piship: "0.1.0",
    });
    expect(existsSync(join(appsDir(), ".lifecycle.lock"))).toBe(false);
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

  it("refuses a release whose launch check fails", async () => {
    const { a, opts } = await fixture();
    await installDistribution(a.archive);
    const error = await rejection(
      updateDistribution(ID, {
        ...opts,
        runCheck: () => ({ status: 1, stdout: "", stderr: "cannot start" }),
      }),
    );
    expect(error.code).toBe("UPDATE_FAILED");
    expect(error.message).toMatch(
      /The 1.1.0 release failed its launch check: cannot start/,
    );
    expect(readInstallReceipt(ID).active).toBe("1.0.0");
    expect(apps()).toEqual(["1.0.0", "launch.mjs"]);
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
    expect(apps()).toEqual(["1.1.0", "launch.mjs"]);
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
      expect(apps()).toEqual(
        [...receipt.releases.map((item) => item.version), "launch.mjs"].sort(),
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
      expect(apps()).toEqual(["1.0.0", "1.1.0", "launch.mjs"]);
      for (const item of final.releases) verifyPayload(item.payload);
      expect(recoverInstallation(ID)).toEqual([]);
      expect(recoverInstallation(ID)).toEqual([]);
      expect(containing(SENTINEL)).toEqual([
        join(stateDir(), "secrets", "inference"),
      ]);
    },
  );

  it("removes leftovers of a killed process before the next operation", async () => {
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
    expect(apps()).toEqual(["1.0.0", "1.1.0", "launch.mjs"]);
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
    expect(checked).toEqual([join(appsDir(), "1.0.0")]);
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

  it("fails when there is no retained release", async () => {
    const a = await release("1.0.0");
    await installDistribution(a.archive);
    const error = await rejection(
      rollbackDistribution(ID, { runCheck: fakeRun }),
    );
    expect(error.code).toBe("ROLLBACK_FAILED");
    expect(error.message).toMatch(/has no retained release/);
  });

  it("refuses a tampered retained release and switches nothing", async () => {
    await updated();
    write(
      join(appsDir(), "1.0.0", "resources", "resources", "AGENTS.md"),
      "# tampered\n",
    );
    const receipt = readInstallReceipt(ID);
    const marker = readStateMarker(stateDir());
    const error = await rejection(
      rollbackDistribution(ID, { runCheck: fakeRun }),
    );
    expect(error.code).toBe("ROLLBACK_FAILED");
    expect(error.message).toMatch(
      /The retained release 1.0.0 failed verification: .*integrity mismatch/,
    );
    expect(readInstallReceipt(ID)).toEqual(receipt);
    expect(readStateMarker(stateDir())).toEqual(marker);
  });

  it("refuses when the retained release fails its launch check", async () => {
    await updated();
    const error = await rejection(
      rollbackDistribution(ID, {
        runCheck: () => ({ status: 1, stdout: "", stderr: "broken" }),
      }),
    );
    expect(error.code).toBe("ROLLBACK_FAILED");
    expect(readInstallReceipt(ID).active).toBe("1.1.0");
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
    write(join(stateDir(), "secrets", "inference-v2"), `${SENTINEL_V2}\n`);
    const identity = readFileSync(
      join(stateDir(), "identity", "session.json"),
      "utf8",
    );
    const deleted: string[] = [];
    const deleteSecret = vi.fn(async (ref: string) => {
      deleted.push(ref);
    });
    const result = await rollbackDistribution(ID, {
      runCheck: fakeRun,
      deleteSecret,
    });
    // Only references in this distribution's own namespace are deleted.
    expect(deleted).toEqual([`piship:${ID}:inference#2`]);
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
    expect(existsSync(join(stateDir(), "secrets"))).toBe(false);
    expect(
      readFileSync(join(stateDir(), "identity", "session.json"), "utf8"),
    ).toBe(identity);
    expect(containing(SENTINEL_V2)).toEqual([]);
    expect(containing(SENTINEL)).toEqual([]);
    expect(readInstallReceipt(ID).active).toBe("1.0.0");
  });

  it("reports a secret that could not be deleted and still clears the metadata", async () => {
    await updated();
    write(
      join(stateDir(), "identity", "session.json"),
      JSON.stringify({
        schema: "piship-identity-metadata/v7",
        secretRef: `piship:${ID}:identity#1`,
      }),
    );
    const result = await rollbackDistribution(ID, {
      runCheck: fakeRun,
      deleteSecret: async () => {
        throw new Error("keychain locked");
      },
    });
    // The current and the possibly pending next generation both fail.
    expect(result.notices).toEqual([
      "Could not delete a stored secret: keychain locked",
      "Could not delete a stored secret: keychain locked",
      "identity session was cleared because the target cannot read it; sign in again",
    ]);
    expect(existsSync(join(stateDir(), "identity", "session.json"))).toBe(
      false,
    );
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
    const deleted: string[] = [];
    const revokeCredential = vi.fn(async () => ({ outcome: "revoked" }));
    const result = await rollbackDistribution(ID, {
      runCheck: fakeRun,
      deleteSecret: async (ref) => {
        deleted.push(ref);
      },
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
    const result = await rollbackDistribution(ID, {
      runCheck: fakeRun,
      deleteSecret: async (ref) => {
        order.push(`delete ${ref}`);
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
    const deleted: string[] = [];
    const result = await rollbackDistribution(ID, {
      runCheck: fakeRun,
      deleteSecret: async (ref) => {
        deleted.push(ref);
      },
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
    // The seeded state uses the file fallback, which goes with the directory.
    expect(await purgeDistributionState(ID)).toEqual({
      state: stateDir(),
      deletedSecrets: [],
      problems: [],
    });
    expect(existsSync(stateDir())).toBe(false);
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
    const store = new MemorySecretStore();
    const refs = [
      `piship:${ID}:identity#2`,
      `piship:${ID}:inference#1`,
      `piship:${ID}:inference#3`,
      "piship:other:inference#1",
    ];
    for (const ref of refs) await store.put(ref, new SecretValue("s3cret-v"));
    const deleted: string[] = [];
    const tracking = {
      kind: store.kind,
      description: "test store",
      put: store.put.bind(store),
      get: store.get.bind(store),
      async delete(ref: string) {
        deleted.push(ref);
        if (ref.endsWith("identity#3")) throw new Error("locked keychain");
        await store.delete(ref);
      },
    };
    const result = await purgeDistributionState(ID, { secretStore: tracking });
    // Current, adjacent, and orphaned generations of this distribution only.
    expect(deleted).toEqual([
      `piship:${ID}:identity#1`,
      `piship:${ID}:identity#2`,
      `piship:${ID}:identity#3`,
      `piship:${ID}:inference#1`,
      `piship:${ID}:inference#3`,
    ]);
    expect(store.refs()).toEqual(["piship:other:inference#1"]);
    expect(result.problems).toEqual([
      `Could not delete piship:${ID}:identity#3 from the test store: locked keychain`,
    ]);
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

  it("runs the candidate's launch check against throwaway state", async () => {
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
    expect(homes).toHaveLength(1);
    expect(homes[0]).not.toBe(process.env.PISHIP_STATE_HOME);
    expect(existsSync(homes[0] as string)).toBe(false);
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
      /did not answer for stable\.json within 30 s/,
    );
    expect(existsSync(join(appsDir(), ".lifecycle.lock"))).toBe(false);
  });
});

// ------------------------------------------------------- installed launcher

describe.runIf(HOST_EVIDENCED)("installed launcher", () => {
  const launch = (launcher: string) =>
    spawnSync(process.execPath, [launcher], { encoding: "utf8" });

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
