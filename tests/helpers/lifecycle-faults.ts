// Shared fixture of the lifecycle fault tests (packages/core/src/lifecycle-*
// .test.ts): a personal v1alpha4 distribution with releases 1.0.0 and 1.1.0,
// installed under temporary homes, and helpers that report what the
// installed launcher starts and what temporaries were left. Each test file
// mocks node:fs with tests/helpers/fs-faults.ts and arms faults only around
// the operation under test; the releases and the install are built through
// @piship/core before that.
import { spawnSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, beforeEach, expect } from "vitest";
import {
  type CommandResult,
  EVIDENCED_TARGETS,
  type UpdateOptions,
  buildRelease,
  currentTarget,
  generateSigningKey,
  installDistribution,
  lockManifest,
  payloadInventory,
  readInstallReceipt,
  signChannel,
} from "@piship/core";
import { clearFaults } from "./fs-faults.js";
import { deadPid, livePid, stopLiveProcesses } from "./processes.js";

const BUILD_INPUT = process.env.PISHIP_BUILD_INPUT as string;
const KEY = generateSigningKey("test-release");
export const ID = "acmepi";
export const HOST_EVIDENCED = EVIDENCED_TARGETS.includes(currentTarget());
/** Fault-matching patterns for the receipt and the state marker. */
export const RECEIPT = /[/\\]receipts[/\\]acmepi\.json/;
export const MARKER = /[/\\]acmepi[/\\]state\.json/;

const roots: string[] = [];
const ENV_KEYS = [
  "PISHIP_INSTALL_HOME",
  "PISHIP_BIN_HOME",
  "PISHIP_STATE_HOME",
  "SOURCE_DATE_EPOCH",
  "ACMEPI_UPDATE_SOURCE",
  "ACMEPI_GATEWAY_URL",
];

/** Give each test its own install, bin, and state homes, and clean up. */
export function useLifecycleHomes(): void {
  let savedEnv: Record<string, string | undefined> = {};
  beforeEach(() => {
    savedEnv = Object.fromEntries(
      ENV_KEYS.map((key) => [key, process.env[key]]),
    );
    process.env.SOURCE_DATE_EPOCH = "1767225600";
    const home = temp("piship-home-");
    process.env.PISHIP_INSTALL_HOME = join(home, "install");
    process.env.PISHIP_BIN_HOME = join(home, "bin");
    process.env.PISHIP_STATE_HOME = join(home, "state");
  });
  afterEach(() => {
    clearFaults();
    stopLiveProcesses();
    for (const [key, value] of Object.entries(savedEnv))
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    for (const root of roots.splice(0))
      rmSync(root, { recursive: true, force: true });
  });
}

function temp(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  roots.push(dir);
  return dir;
}
export function write(path: string, content: string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content);
}

/**
 * With `access`, the distribution also declares a gateway on
 * `ACMEPI_GATEWAY_URL` and a private-only network.
 */
const ACCESS = `identity:
  mode: none
credential:
  provider: none
inference:
  provider: openai-compatible
  baseUrl: \${ACMEPI_GATEWAY_URL}
models:
  default: acme/coder
  allowed: [acme/coder]
  catalog:
    acme/coder:
      name: Coder
      contextWindow: 32000
      maxOutputTokens: 2048
network:
  privateOnly: true
`;

function manifestSource(version: string, access: boolean): string {
  return `schema: piship/v1alpha4
app:
  id: ${ID}
  name: AcmePi
  command: ${ID}
  version: ${version}
runtime:
  pi: "1.0.0"
deployment:
  mode: personal
variables:
  - ACMEPI_UPDATE_SOURCE
${access ? `  - ACMEPI_GATEWAY_URL\n${ACCESS}` : ""}resources:
  instructions:
    user: [./resources/AGENTS.md]
updates:
  channel: stable
  channels: [stable]
  source: \${ACMEPI_UPDATE_SOURCE}
  rollback: true
  trust:
    keys:
      - id: ${KEY.id}
        publicKey: ${KEY.publicKey}
`;
}

function project(version: string, access: boolean): string {
  const dir = temp("piship-project-");
  write(join(dir, "resources", "AGENTS.md"), `# AcmePi ${version}\n`);
  const path = join(dir, "piship.yaml");
  writeFileSync(path, manifestSource(version, access));
  lockManifest(path);
  return path;
}

/**
 * A payload whose command answers `version` like a real one (so the default
 * launch check passes) and otherwise prints `payload <version>`, so a launch
 * shows which release the receipt selected.
 */
function fakeAssemble(manifestPath: string, outputRoot: string): string {
  const base = dirname(resolve(manifestPath));
  const lock = JSON.parse(readFileSync(join(base, "piship.lock"), "utf8")) as {
    app: { id: string; command: string; version: string };
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
  const version = lock.app.version;
  write(
    join(out, "bin", lock.app.command),
    `#!/usr/bin/env node\nconsole.log(process.argv[2] === "version" ? "AcmePi ${version}\\nPi 1.0.0" : "payload ${version}");\n`,
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

/** The launch check and release tests, answered without spawning. */
export function fakeRun(
  payload: string,
  _command: string,
  args: readonly string[],
): CommandResult {
  const lock = JSON.parse(
    readFileSync(join(payload, "piship.lock"), "utf8"),
  ) as { app: { name: string; version: string }; runtime: { version: string } };
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

async function release(version: string, access = false) {
  const path = project(version, access);
  return buildRelease(path, {
    outputRoot: join(dirname(path), "dist"),
    assemble: fakeAssemble,
    runTest: fakeRun,
    scanner: () => ({ auditReportVersion: 2, vulnerabilities: {} }),
    signatureAuditor,
  });
}

/**
 * 1.0.0 installed over seeded state, and a signed channel offering 1.1.0;
 * with `access`, both declare a gateway and a private-only network.
 */
export async function installed(access = false) {
  const a = await release("1.0.0", access);
  const b = await release("1.1.0", access);
  const channelDir = temp("piship-channel-");
  await signChannel({
    directory: channelDir,
    channel: "stable",
    archives: [b.archive],
    privateKeyPem: KEY.privateKeyPem,
    keyId: KEY.id,
  });
  write(
    join(stateDir(), "config", "preferences.json"),
    JSON.stringify({ schema: "piship-preferences/v1", theme: "dark" }),
  );
  write(join(stateDir(), "config", "policy.json"), JSON.stringify({}));
  write(join(stateDir(), "sessions", "s1.jsonl"), '{"type":"message"}\n');
  await installDistribution(a.archive, true);
  process.env.ACMEPI_UPDATE_SOURCE = channelDir;
  const opts: UpdateOptions = { source: channelDir, runCheck: fakeRun };
  return { a, b, channelDir, opts };
}

export function stateDir(): string {
  return join(process.env.PISHIP_STATE_HOME as string, ID);
}
export function appsDir(): string {
  return join(process.env.PISHIP_INSTALL_HOME as string, "apps", ID);
}
export function receiptFile(): string {
  return join(
    process.env.PISHIP_INSTALL_HOME as string,
    "receipts",
    `${ID}.json`,
  );
}
export function markerFile(): string {
  return join(stateDir(), "state.json");
}
export function snapshotsDir(): string {
  return join(stateDir(), "migration", "snapshots");
}

/** Every atomic-write temporary left under the install and state homes. */
export function temporaries(): string[] {
  const out: string[] = [];
  const visit = (dir: string) => {
    if (!existsSync(dir)) return;
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) visit(path);
      else if (entry.name.endsWith(".tmp")) out.push(path);
    }
  };
  visit(process.env.PISHIP_INSTALL_HOME as string);
  visit(process.env.PISHIP_STATE_HOME as string);
  return out;
}

/** What the installed launcher starts: `payload <version>`. */
export function launch(): string {
  const result = spawnSync(
    process.execPath,
    [readInstallReceipt(ID).launcher as string],
    { encoding: "utf8" },
  );
  expect(result.status, result.stderr).toBe(0);
  return result.stdout.trim();
}

export async function rejection(promise: Promise<unknown>) {
  try {
    await promise;
  } catch (error) {
    return error as Error & { code?: string; retryable?: boolean };
  }
  throw new Error("expected a rejection");
}

/** A process ID no process has, and a live one (stopped after each test). */
export { deadPid, livePid };

/** Set a file's modification time `ms` into the past. */
export function age(path: string, ms: number): void {
  const then = new Date(Date.now() - ms);
  utimesSync(path, then, then);
}
