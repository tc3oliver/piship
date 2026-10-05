import { spawn } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { readManifest } from "@piship/schema";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  deadPid,
  livePid,
  stopLiveProcesses,
} from "../../../tests/helpers/processes.js";
import { plantTemporary } from "../../../tests/helpers/temporaries.js";
import {
  buildDistribution,
  currentTarget,
  EVIDENCED_TARGETS,
  LOCK_SCHEMA_V1ALPHA3,
  LOCK_SCHEMA_V1ALPHA5,
  lockManifest,
  PI_COMPATIBILITY,
  payloadInventory,
  requireCurrentLock,
  resolveLock,
} from "./index.js";
import { STATE_SCHEMAS } from "./migration.js";
import {
  buildRelease,
  CHANNEL_SCHEMA,
  type CommandResult,
  checkReleaseInputs,
  checkSourceUrl,
  compareReleases,
  downloadArchive,
  evaluateSignatures,
  evaluateVulnerabilities,
  npmAuditScanner,
  piCompatibility,
  piCompatibilitySurfaces,
  RELEASE_FILES,
  readChannel,
  signChannel,
  verifyRelease,
} from "./release/index.js";
import { generateSigningKey, pemSigner, signBytes } from "./signing.js";
import { formatChecksums } from "./supply-chain.js";

// ------------------------------------------------------------------ fixtures

const BUILD_INPUT = process.env.PISHIP_BUILD_INPUT as string;
const KEY = generateSigningKey("test-release");
const TRUSTED = [{ id: KEY.id, publicKey: KEY.publicKey }];
const EPOCH = "1767225600"; // 2026-01-01T00:00:00Z
const ADVISORY = "GHSA-aaaa-bbbb-cccc";
const HOST_EVIDENCED = EVIDENCED_TARGETS.includes(currentTarget());

const roots: string[] = [];
const ENV_KEYS = [
  "PISHIP_INSTALL_HOME",
  "PISHIP_BIN_HOME",
  "PISHIP_STATE_HOME",
  "PISHIP_BUILD_INPUT",
  "SOURCE_DATE_EPOCH",
  "ACMEPI_UPDATE_SOURCE",
];
let savedEnv: Record<string, string | undefined> = {};

beforeEach(() => {
  savedEnv = Object.fromEntries(ENV_KEYS.map((key) => [key, process.env[key]]));
  process.env.SOURCE_DATE_EPOCH = EPOCH;
});
afterEach(() => {
  stopLiveProcesses();
  for (const [key, value] of Object.entries(savedEnv))
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

function temp(prefix = "piship-release-"): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  roots.push(dir);
  return dir;
}

interface ProjectOptions {
  readonly id?: string;
  readonly version?: string;
  readonly schema?: string;
  /** Extra top-level YAML appended to the manifest. */
  readonly extra?: string;
  /** Replaces the default `release:` section. */
  readonly release?: string;
  /** Replaces the default `resources:` section. */
  readonly resources?: string;
  readonly lock?: boolean;
  /** A managed distribution with plain https access endpoints. */
  readonly managed?: boolean;
  /** Replaces the v1alpha5 `updates.trust` body (indented four spaces). */
  readonly trust?: string;
}

const COMPANY_RESOURCES = `resources:
  instructions:
    company: [./resources/AGENTS.md]
`;
const MANAGED_ACCESS = `identity:
  mode: oidc
  oidc:
    issuer: https://login.acme.example
    clientId: acmepi
    redirectUri: http://127.0.0.1:8765/callback
credential:
  provider: http-broker
  broker: { endpoint: https://broker.acme.example/token }
inference:
  provider: openai-compatible
  baseUrl: https://gateway.acme.example/v1
models:
  default: acme/coder
  allowed: [acme/coder]
  catalog:
    acme/coder: { name: Acme Coder, contextWindow: 128000, maxOutputTokens: 8192 }
`;

const DEFAULT_RELEASE = `release:
  vulnerabilities:
    failOn: high
    allow:
      - id: ${ADVISORY}
        reason: not reachable from the packaged runtime
        expires: 2026-12-31
`;

/** `updates.trust` YAML whose root and channel roles are `keys` at threshold 1. */
function bootstrapTrust(
  keys: readonly { id: string; publicKey: string }[],
): string {
  const ids = keys.map((key) => key.id).join(", ");
  return `    bootstrap:
      version: 1
      expires: 2099-01-01T00:00:00Z
      keys:
${keys.map((key) => `        - id: ${key.id}\n          publicKey: ${key.publicKey}\n`).join("")}      roles:
        root: { keyIds: [${ids}], threshold: 1 }
        channel: { keyIds: [${ids}], threshold: 1 }
`;
}

function manifestSource(options: ProjectOptions = {}): string {
  const id = options.id ?? "acmepi";
  const schema = options.schema ?? "piship/v1alpha5";
  const v5 = schema === "piship/v1alpha5" || schema === "piship/v1alpha6";
  const v4 = schema === "piship/v1alpha4" || v5;
  return `schema: ${schema}
app:
  id: ${id}
  name: AcmePi
  command: ${id}
  version: ${options.version ?? "1.0.0"}
runtime:
  pi: "1.0.3"
deployment:
  mode: ${options.managed ? "managed" : "personal"}
${options.managed ? MANAGED_ACCESS : ""}${v4 ? "variables:\n  - ACMEPI_UPDATE_SOURCE\n" : ""}${
  options.resources ??
  `resources:
  instructions:
    user: [./resources/AGENTS.md]
`
}${
  v4
    ? `updates:
  channel: stable
  channels: [stable, candidate]
  source: \${ACMEPI_UPDATE_SOURCE}
  rollback: true
  trust:
${
  options.trust !== undefined
    ? options.trust
    : v5
      ? `    bootstrap:
      version: 1
      expires: 2099-01-01T00:00:00Z
      keys:
        - id: ${KEY.id}
          publicKey: ${KEY.publicKey}
      roles:
        root: { keyIds: [${KEY.id}], threshold: 1 }
        channel: { keyIds: [${KEY.id}], threshold: 1 }
`
      : `    keys:
      - id: ${KEY.id}
        publicKey: ${KEY.publicKey}
`
}${options.release ?? DEFAULT_RELEASE}`
    : ""
}${options.extra ?? ""}`;
}

function project(options: ProjectOptions = {}): { dir: string; path: string } {
  const dir = temp("piship-project-");
  mkdirSync(join(dir, "resources"));
  writeFileSync(join(dir, "resources", "AGENTS.md"), "# AcmePi\n");
  const path = join(dir, "piship.yaml");
  writeFileSync(path, manifestSource(options));
  if (options.lock !== false) lockManifest(path);
  return { dir, path };
}

function write(path: string, content: string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content);
}

/** Canonical payload layout without npm: what buildDistribution produces, minus the real runtime. */
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
    join(process.env.PISHIP_BUILD_INPUT ?? BUILD_INPUT, "package-lock.json"),
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
  write(join(out, "node_modules", "alpha", "LICENSE"), "MIT License\nalpha\n");
  write(
    join(out, "node_modules", "@scope", "beta", "package.json"),
    JSON.stringify({ name: "@scope/beta", version: "2.0.0", license: "ISC" }),
  );
  write(
    join(out, "metadata", "inventory.json"),
    `${JSON.stringify(payloadInventory(out), null, 2)}\n`,
  );
  return out;
}

function fakeRun(
  payload: string,
  _command: string,
  args: readonly string[],
): CommandResult {
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

const cleanScanner = () => ({ auditReportVersion: 2, vulnerabilities: {} });

/** `npm audit signatures --json` output. */
function signatureOutput(
  invalid: readonly object[] = [],
  missing: readonly object[] = [],
  status = invalid.length || missing.length ? 1 : 0,
): CommandResult {
  return { status, stdout: JSON.stringify({ invalid, missing }), stderr: "" };
}
const cleanSignatures = () => signatureOutput();

function advisory(severity: string, id = ADVISORY) {
  return {
    auditReportVersion: 2,
    vulnerabilities: {
      alpha: {
        severity,
        via: [
          {
            source: 1234,
            title: "Prototype pollution",
            url: `https://github.com/advisories/${id}`,
            severity,
          },
        ],
      },
    },
  };
}

function build(path: string, options: Parameters<typeof buildRelease>[1] = {}) {
  return buildRelease(path, {
    outputRoot: join(dirname(path), "dist"),
    assemble: fakeAssemble,
    runTest: fakeRun,
    scanner: cleanScanner,
    signatureAuditor: cleanSignatures,
    now: () => new Date("2026-06-01T00:00:00Z"),
    ...options,
  });
}

function caught(fn: () => unknown): Error & { code?: string } {
  try {
    fn();
  } catch (error) {
    return error as Error & { code?: string };
  }
  throw new Error("expected a throw");
}
async function rejection(
  promise: Promise<unknown>,
): Promise<Error & { code?: string; userAction?: string }> {
  try {
    await promise;
  } catch (error) {
    return error as Error & { code?: string; userAction?: string };
  }
  throw new Error("expected a rejection");
}

function flipByte(path: string, offset?: number): void {
  const bytes = readFileSync(path);
  const at = offset ?? Math.floor(bytes.length / 2);
  bytes[at] = (bytes[at] as number) ^ 0xff;
  writeFileSync(path, bytes);
}

/**
 * Lock and check a project against a copy of the build input whose npm lock
 * `edit` changed, with fresh module instances that read that input.
 */
async function withNpmLock<T>(
  edit: (packages: Record<string, Record<string, unknown>>) => void,
  run: (
    core: typeof import("./index.js"),
    release: typeof import("./release/index.js"),
  ) => T,
): Promise<T> {
  const input = temp("piship-build-input-");
  const npmLock = JSON.parse(
    readFileSync(join(BUILD_INPUT, "package-lock.json"), "utf8"),
  ) as { packages: Record<string, Record<string, unknown>> };
  edit(npmLock.packages);
  writeFileSync(
    join(input, "package-lock.json"),
    JSON.stringify(npmLock, null, 2),
  );
  process.env.PISHIP_BUILD_INPUT = input;
  vi.resetModules();
  try {
    return run(await import("./index.js"), await import("./release/index.js"));
  } finally {
    process.env.PISHIP_BUILD_INPUT = BUILD_INPUT;
    vi.resetModules();
  }
}

// --------------------------------------------------------------------- lock

describe("lock piship-lock/v1alpha5", () => {
  it("is deterministic and records sources, digests, updates, release, and state schemas", () => {
    const { path } = project({ lock: false });
    const first = readFileSync(lockManifest(path), "utf8");
    const second = readFileSync(lockManifest(path), "utf8");
    expect(second).toBe(first);
    const lock = requireCurrentLock(path);
    expect(lock.schema).toBe(LOCK_SCHEMA_V1ALPHA5);
    expect(lock.manifest.sha256).toMatch(/^sha256-[0-9a-f]{64}$/);
    expect(lock.runtime.stateSchemas).toEqual(STATE_SCHEMAS);
    for (const item of lock.runtime.packages) {
      expect(item.resolved).toMatch(/^https:\/\//);
      expect(item.integrity).toMatch(/^sha512-/);
    }
    expect(
      lock.runtime.packages
        .filter((item) => item.installScript)
        .map((item) => item.path),
    ).toEqual([
      "node_modules/@google/genai",
      "node_modules/esbuild",
      "node_modules/protobufjs",
    ]);
    expect(Object.keys(lock.digests ?? {}).sort()).toEqual([
      "access",
      "audit",
      "capabilities",
      "mcp",
      "policy",
      "resources",
      "sandbox",
    ]);
    for (const value of Object.values(lock.digests ?? {}))
      expect(value).toMatch(/^sha256-[0-9a-f]{64}$/);
    expect(lock.updates).toEqual({
      channel: "stable",
      channels: ["stable", "candidate"],
      source: `\${ACMEPI_UPDATE_SOURCE}`,
      rollback: true,
      trust: {
        bootstrap: {
          version: 1,
          expires: "2099-01-01T00:00:00Z",
          keys: TRUSTED,
          roles: {
            root: { keyIds: [KEY.id], threshold: 1 },
            channel: { keyIds: [KEY.id], threshold: 1 },
          },
        },
      },
    });
    expect(lock.release).toEqual({
      targets: ["linux-x64", "darwin-arm64", "win32-x64"],
      sources: ["https://registry.npmjs.org"],
      vulnerabilities: {
        failOn: "high",
        allow: [
          {
            id: ADVISORY,
            reason: "not reachable from the packaged runtime",
            expires: "2026-12-31",
          },
        ],
      },
    });
  });

  it("keeps every registry package and leaves out only workspace links", () => {
    const npmLock = JSON.parse(
      readFileSync(join(BUILD_INPUT, "package-lock.json"), "utf8"),
    ) as { packages: Record<string, { dev?: boolean; link?: boolean }> };
    const entries = Object.entries(npmLock.packages).filter(
      ([path, value]) => path.startsWith("node_modules/") && !value.dev,
    );
    const links = entries.filter(([, value]) => value.link);
    expect(links.map(([path]) => path).sort()).toEqual(
      [
        "adapter-conformance",
        "adapter-sdk",
        "audit",
        "cli",
        "contracts",
        "core",
        "credentials",
        "identity",
        "inference",
        "mcp",
        "pi",
        "policy",
        "sandbox",
        "schema",
      ].map((name) => `node_modules/@piship/${name}`),
    );
    const { path } = project();
    const locked = resolveLock(path).runtime.packages;
    expect(locked.map((item) => item.path)).toEqual(
      entries
        .filter(([, value]) => !value.link)
        .map(([path]) => path)
        .sort((a, b) => a.localeCompare(b)),
    );
    expect(
      locked.some((item) => item.path.startsWith("node_modules/@piship/")),
    ).toBe(false);
    // Pi and its sibling packages are hoisted (Pi 1.0.1+ ships no
    // shrinkwrap) and carry registry integrity.
    const prefix = "node_modules/@earendil-works/";
    const pi = locked.filter(
      (item) =>
        item.path.startsWith(prefix) &&
        !item.path.slice(prefix.length).includes("/"),
    );
    expect(pi.map((item) => item.path.split("/").pop())).toEqual([
      "chord",
      "pi-agent-core",
      "pi-ai",
      "pi-codemode",
      "pi-coding-agent",
      "pi-mcp",
      "pi-telemetry",
      "pi-tui",
    ]);
    for (const item of pi) expect(item.integrity).toMatch(/^sha512-/);
  });

  it("changes the resource digest when a resource changes", () => {
    const { dir, path } = project();
    const before = resolveLock(path).digests?.resources;
    writeFileSync(join(dir, "resources", "AGENTS.md"), "# changed\n");
    const after = resolveLock(path).digests?.resources;
    expect(after).not.toBe(before);
  });

  it("keeps templates and never resolved variable values or secret material", () => {
    process.env.ACMEPI_UPDATE_SOURCE =
      "https://resolved-host.example/secret-path";
    const { path } = project({ lock: false });
    const text = readFileSync(lockManifest(path), "utf8");
    expect(text).toContain(`\${ACMEPI_UPDATE_SOURCE}`);
    expect(text).not.toContain("resolved-host.example");
    expect(text).not.toContain("PRIVATE KEY");
    const privateBody = KEY.privateKeyPem
      .split("\n")
      .filter((line) => line && !line.startsWith("-----"))
      .join("");
    expect(text).not.toContain(privateBody);
    expect(text).not.toMatch(/password|bearer|api_?key|"token"/i);
  });

  it("leaves the v1alpha3 lock shape unchanged", () => {
    const { path } = project({ schema: "piship/v1alpha3" });
    const lock = requireCurrentLock(path);
    expect(lock.schema).toBe(LOCK_SCHEMA_V1ALPHA3);
    expect(lock).not.toHaveProperty("digests");
    expect(lock).not.toHaveProperty("updates");
    expect(lock).not.toHaveProperty("release");
    expect(lock.runtime).not.toHaveProperty("stateSchemas");
    for (const item of lock.runtime.packages) {
      expect(item).not.toHaveProperty("resolved");
      expect(item).not.toHaveProperty("installScript");
      expect(Object.keys(item).sort()).toEqual([
        "integrity",
        "path",
        "version",
      ]);
    }
  });
});

// ------------------------------------------------------------------- gates

// The release and lifecycle suites run only on an evidenced target. Every CI
// runner (ubuntu-latest, macos-latest, windows-latest) is one, so there a
// target that is not must fail rather than silently skip those suites.
it.runIf(process.env.CI === "true")(
  "runs the evidenced-target suites on every CI runner",
  () => {
    expect(EVIDENCED_TARGETS, currentTarget()).toContain(currentTarget());
  },
);

describe.runIf(HOST_EVIDENCED)("release gates", () => {
  it("accepts a current v1alpha5 lock with only reviewed install scripts", () => {
    const { path } = project();
    expect(checkReleaseInputs(path).schema).toBe(LOCK_SCHEMA_V1ALPHA5);
  });

  it("lock: refuses a stale lock after a resource edit", () => {
    const { dir, path } = project();
    writeFileSync(join(dir, "resources", "AGENTS.md"), "# edited\n");
    const error = caught(() => checkReleaseInputs(path));
    expect(error.code).toBe("LOCK_INVALID");
    expect(error.message).toMatch(/Release gate lock: .*stale/);
  });

  it("lock: refuses a tampered lock file", () => {
    const { dir, path } = project();
    const lockPath = join(dir, "piship.lock");
    const lock = JSON.parse(readFileSync(lockPath, "utf8"));
    lock.release.sources = ["https://evil.example"];
    writeFileSync(lockPath, `${JSON.stringify(lock, null, 2)}\n`);
    const error = caught(() => checkReleaseInputs(path));
    expect(error.code).toBe("LOCK_INVALID");
    expect(error.message).toMatch(/Release gate lock/);
  });

  it("lock: refuses a missing lock", () => {
    const { path } = project({ lock: false });
    expect(caught(() => checkReleaseInputs(path)).message).toMatch(
      /Release gate lock: Lockfile missing/,
    );
  });

  it("schema: refuses a v1alpha3 manifest", () => {
    const { path } = project({ schema: "piship/v1alpha3" });
    const error = caught(() => checkReleaseInputs(path));
    expect(error.code).toBe("CONFIG_INVALID");
    expect(error.message).toMatch(/Release gate schema: .*piship\/v1alpha3/);
  });

  it("schema: refuses a v1alpha4 manifest; releases need v1alpha5 or later", () => {
    const { path } = project({ schema: "piship/v1alpha4" });
    const error = caught(() => checkReleaseInputs(path));
    expect(error.code).toBe("CONFIG_INVALID");
    expect(error.message).toMatch(
      /Release gate schema: production releases need a piship\/v1alpha5 or piship\/v1alpha6 manifest \(found piship\/v1alpha4\)/,
    );
  });

  it("trust: builds an update-disabled release from a source without bootstrap trust", () => {
    // Nothing can verify an update for it, so update fails closed; the
    // release itself is no less trustworthy than one with no source.
    const { path } = project({ trust: "    {}\n" });
    expect(checkReleaseInputs(path).updates?.trust).not.toHaveProperty(
      "bootstrap",
    );
  });

  it("trust: refuses a managed distribution whose root and channel roles share a key", () => {
    // What piship migrate makes of a v1alpha4 key set: the legacy key in
    // both roles. The owner must split the roles before a managed release.
    const { path } = project({ managed: true, resources: COMPANY_RESOURCES });
    const error = caught(() => checkReleaseInputs(path));
    expect(error.code).toBe("POLICY_DENIED");
    expect(error.message).toMatch(
      new RegExp(
        `Release gate trust: the update root and channel roles share ${KEY.id}`,
      ),
    );
  });

  it("trust: accepts a managed distribution with distinct root and channel keys", () => {
    const root = generateKeyPairSync("ed25519")
      .publicKey.export({ type: "spki", format: "der" })
      .toString("base64");
    const { path } = project({
      managed: true,
      resources: COMPANY_RESOURCES,
      trust: `    bootstrap:
      version: 1
      expires: 2099-01-01T00:00:00Z
      keys:
        - id: acme-root
          publicKey: ${root}
        - id: ${KEY.id}
          publicKey: ${KEY.publicKey}
      roles:
        root: { keyIds: [acme-root], threshold: 1 }
        channel: { keyIds: [${KEY.id}], threshold: 1 }
`,
    });
    expect(checkReleaseInputs(path).schema).toBe(LOCK_SCHEMA_V1ALPHA5);
  });

  it("trust: accepts a personal distribution whose roles share a key", () => {
    const { path } = project();
    expect(checkReleaseInputs(path).deployment.mode).toBe("personal");
  });

  it("target: refuses a target outside release.targets", () => {
    const { path } = project();
    const error = caught(() => checkReleaseInputs(path, "linux-arm64"));
    expect(error.code).toBe("CONFIG_INVALID");
    expect(error.message).toMatch(
      /Release gate target: linux-arm64 is not in release.targets/,
    );
  });

  it("target: refuses a declared target without lifecycle evidence", () => {
    const { path } = project({
      release:
        "release:\n  targets: [linux-x64, linux-arm64, darwin-arm64, win32-x64]\n",
    });
    expect(
      caught(() => checkReleaseInputs(path, "linux-arm64")).message,
    ).toMatch(
      /Release gate target: linux-arm64 has no installed lifecycle evidence/,
    );
  });

  it("target: refuses cross-target builds", () => {
    const { path } = project();
    const other = EVIDENCED_TARGETS.find(
      (target) => target !== currentTarget(),
    ) as string;
    expect(caught(() => checkReleaseInputs(path, other)).message).toMatch(
      /Release gate target: releases are built on their target/,
    );
  });

  it("pi: refuses a pinned Pi this PiShip records as unsupported", () => {
    const { path } = project();
    const known = PI_COMPATIBILITY["1.0.3"] as Record<string, string>;
    const saved = { ...known };
    try {
      for (const surface of Object.keys(known)) known[surface] = "unsupported";
      const error = caught(() => checkReleaseInputs(path));
      expect(error.message).toMatch(/Release gate pi: /);
      expect(error.message).toMatch(/1\.0\.3/);
    } finally {
      Object.assign(known, saved);
    }
    expect(() => checkReleaseInputs(path)).not.toThrow();
  });

  it("pi: an unpinned Pi cannot reach the compatibility gate; locking and the lock gate reject it", () => {
    const { dir, path } = project();
    // The schema-valid manifest pins Pi; changing it fails the build-pin check first.
    writeFileSync(
      path,
      readFileSync(path, "utf8").replace('pi: "1.0.3"', 'pi: "0.86.0"'),
    );
    expect(() => lockManifest(path)).toThrow(/Pi 0.86.0 is not available/);
    const error = caught(() => checkReleaseInputs(path));
    expect(error.message).toMatch(/Pi 0.86.0 is not available/);
    // Editing the locked runtime version is a stale lock, not a compatibility result.
    writeFileSync(path, manifestSource());
    lockManifest(path);
    const lockPath = join(dir, "piship.lock");
    writeFileSync(
      lockPath,
      readFileSync(lockPath, "utf8").replace(
        '"version": "1.0.3"',
        '"version": "0.86.0"',
      ),
    );
    expect(caught(() => checkReleaseInputs(path)).message).toMatch(
      /Release gate lock: .*stale/,
    );
  });

  it("source: refuses packages from an unapproved origin", () => {
    const { path } = project({
      release: "release:\n  sources: [https://npm.internal.example]\n",
    });
    const error = caught(() => checkReleaseInputs(path));
    expect(error.code).toBe("POLICY_DENIED");
    expect(error.message).toMatch(
      /Release gate source: .* comes from https:\/\/registry.npmjs.org, which is not in release.sources \(https:\/\/npm.internal.example\)/,
    );
    // `piship build` runs the same gate before assembling anything.
    const out = temp("piship-build-out-");
    const built = caught(() => buildDistribution(path, out));
    expect(built.code).toBe("POLICY_DENIED");
    expect(built.message).toMatch(
      /Build gate source: .* comes from https:\/\/registry.npmjs.org, which is not in release.sources/,
    );
    expect(readdirSync(out)).toEqual([]);
  });

  it("source: refuses a registry package the npm lock records without integrity", async () => {
    let victim = "";
    const error = await withNpmLock(
      (packages) => {
        const entry = Object.entries(packages).find(
          ([path, value]) =>
            path.startsWith("node_modules/") && !value.dev && !value.link,
        ) as [string, Record<string, unknown>];
        victim = `${entry[0]}@${String(entry[1].version)}`;
        delete entry[1].integrity;
      },
      (core, release) => {
        const { path } = project({ lock: false });
        core.lockManifest(path);
        // The entry is kept in the lock, so the gate can see it.
        expect(
          core
            .requireCurrentLock(path)
            .runtime.packages.map((item) => `${item.path}@${item.version}`),
        ).toContain(victim);
        return caught(() => release.checkReleaseInputs(path));
      },
    );
    expect(error.code).toBe("INTEGRITY_FAILED");
    expect(error.message).toContain(
      `Release gate source: ${victim} is missing integrity`,
    );
  });

  it("source: a link outside the workspace packages is not treated as a workspace package", async () => {
    const error = await withNpmLock(
      (packages) => {
        packages["node_modules/@piship/extra"] = {
          resolved: "../elsewhere/extra",
          link: true,
        };
      },
      (core, release) => {
        const { path } = project({ lock: false });
        core.lockManifest(path);
        expect(
          core
            .requireCurrentLock(path)
            .runtime.packages.map((item) => item.path),
        ).toContain("node_modules/@piship/extra");
        return caught(() => release.checkReleaseInputs(path));
      },
    );
    expect(error.code).toBe("INTEGRITY_FAILED");
    expect(error.message).toMatch(
      /Release gate source: node_modules\/@piship\/extra@ is missing integrity/,
    );
  });

  it("install-script: refuses an unreviewed npm lifecycle script", async () => {
    const input = temp("piship-build-input-");
    const npmLock = JSON.parse(
      readFileSync(join(BUILD_INPUT, "package-lock.json"), "utf8"),
    ) as { packages: Record<string, Record<string, unknown>> };
    const victim = Object.entries(npmLock.packages).find(
      ([path, value]) =>
        path.startsWith("node_modules/") &&
        !value.dev &&
        value.integrity &&
        !value.hasInstallScript,
    ) as [string, Record<string, unknown>];
    victim[1].hasInstallScript = true;
    writeFileSync(
      join(input, "package-lock.json"),
      JSON.stringify(npmLock, null, 2),
    );
    process.env.PISHIP_BUILD_INPUT = input;
    vi.resetModules();
    try {
      const core = await import("./index.js");
      const release = await import("./release/index.js");
      const { path } = project({ lock: false });
      core.lockManifest(path);
      const lock = core.requireCurrentLock(path);
      expect(
        lock.runtime.packages.find((item) => item.path === victim[0])
          ?.installScript,
      ).toBe(true);
      const error = caught(() => release.checkReleaseInputs(path));
      expect(error.code).toBe("POLICY_DENIED");
      expect(error.message).toContain(
        `Release gate install-script: ${victim[0]}@${String(victim[1].version)} runs npm lifecycle scripts`,
      );
      // `piship build` refuses it too, before npm could run the script.
      const built = caught(() =>
        core.buildDistribution(path, temp("piship-build-out-")),
      );
      expect(built.code).toBe("POLICY_DENIED");
      expect(built.message).toContain(
        `Build gate install-script: ${victim[0]}@${String(victim[1].version)}`,
      );
    } finally {
      process.env.PISHIP_BUILD_INPUT = BUILD_INPUT;
      vi.resetModules();
    }
  });

  it("policy: refuses enforced rules that disagree on one action and resource", () => {
    const { path } = project({
      extra: `policy:
  enforced:
    - id: acme.read.deny
      action: filesystem.read
      resource: "~/.ssh/**"
      effect: deny
    - id: acme.read.allow
      action: filesystem.read
      resource: "~/.ssh/**"
      effect: allow
`,
    });
    const error = caught(() => checkReleaseInputs(path));
    expect(error.code).toBe("POLICY_DENIED");
    expect(error.message).toMatch(
      /Release gate policy: enforced rules for filesystem.read ~\/.ssh\/\*\* disagree \(deny and allow\)/,
    );
  });

  it("policy: refuses a managed deny on an unsupported action (POLICY_UNENFORCEABLE)", async () => {
    const root = generateKeyPairSync("ed25519")
      .publicKey.export({ type: "spki", format: "der" })
      .toString("base64");
    const managed = (extra: string, schema?: string) =>
      project({
        managed: true,
        ...(schema ? { schema } : {}),
        resources: COMPANY_RESOURCES,
        trust: `    bootstrap:
      version: 1
      expires: 2099-01-01T00:00:00Z
      keys:
        - id: acme-root
          publicKey: ${root}
        - id: ${KEY.id}
          publicKey: ${KEY.publicKey}
      roles:
        root: { keyIds: [acme-root], threshold: 1 }
        channel: { keyIds: [${KEY.id}], threshold: 1 }
`,
        extra,
      }).path;
    const rules = `policy:
  enforced:
    - id: acme.web.deny
      action: web.request
      effect: deny
`;
    const error = caught(() => checkReleaseInputs(managed(rules)));
    expect(error.code).toBe("POLICY_UNENFORCEABLE");
    expect(error.message).toMatch(
      /^Release gate policy: policy.enforced rule acme.web.deny \(deny web.request:\*\*\)/,
    );
    // An acknowledged rule passes; the acknowledgement is in the lock.
    const acknowledged = checkReleaseInputs(
      managed(
        `${rules}  acknowledgeUnenforced: ["web.request:**"]\n`,
        "piship/v1alpha6",
      ),
    );
    expect(
      acknowledged.governance?.manifest.policy.acknowledgeUnenforced,
    ).toEqual(["web.request:**"]);
    // Acknowledging another resource does not cover the rule.
    expect(
      caught(() =>
        checkReleaseInputs(
          managed(
            `${rules}  acknowledgeUnenforced: ["web.request:example.com"]\n`,
            "piship/v1alpha6",
          ),
        ),
      ).code,
    ).toBe("POLICY_UNENFORCEABLE");
    // Wildcard and prefix rules never trigger it.
    expect(
      checkReleaseInputs(
        managed(`policy:
  enforced:
    - id: acme.web.all
      action: web.*
      effect: deny
`),
      ).deployment.mode,
    ).toBe("managed");
    // A personal distribution only warns at validate.
    expect(
      checkReleaseInputs(project({ extra: rules }).path).deployment.mode,
    ).toBe("personal");
    // A required sandbox contains the network only when it denies it. Build
    // on a (simulated) linux-x64 host, which has a sandbox adapter, so the
    // policy gate decides on every host, win32 included.
    const network = (mode: "deny" | "allow") => `sandbox:
  required: true
  network:
    mode: ${mode}
policy:
  enforced:
    - id: acme.net.deny
      action: network.connect
      effect: deny
`;
    vi.resetModules();
    vi.doMock("./index.js", async (original) => ({
      ...(await original<typeof import("./index.js")>()),
      currentTarget: () => "linux-x64",
    }));
    try {
      const release = await import("./release/index.js");
      const open = caught(() =>
        release.checkReleaseInputs(managed(network("allow")), "linux-x64"),
      );
      expect(open.code).toBe("POLICY_UNENFORCEABLE");
      expect(open.message).toContain("acme.net.deny (deny network.connect:**)");
      expect(
        release.checkReleaseInputs(managed(network("deny")), "linux-x64")
          .deployment.mode,
      ).toBe("managed");
    } finally {
      vi.doUnmock("./index.js");
      vi.resetModules();
    }
  });

  it("policy: duplicate rule ids are already rejected by the manifest schema", () => {
    const { path } = project({
      lock: false,
      extra: `policy:
  enforced:
    - id: acme.rule
      action: tool.execute
      effect: deny
  defaults:
    - id: acme.rule
      action: tool.execute
      effect: allow
`,
    });
    expect(() => readManifest(path)).toThrow(/already used in policy.enforced/);
    expect(caught(() => checkReleaseInputs(path)).message).toMatch(
      /already used/,
    );
  });

  it("policy: refuses a declared resource whose trust class policy denies", () => {
    const { path } = project({
      extra: "policy:\n  resourceTrust:\n    user: deny\n",
    });
    const error = caught(() => checkReleaseInputs(path));
    expect(error.code).toBe("POLICY_DENIED");
    expect(error.message).toMatch(
      /Release gate policy: instructions .*AGENTS.md is declared user, which policy.resourceTrust denies/,
    );
  });

  it("policy: refuses a declared MCP server whose trust class policy denies", () => {
    const server = (cls: string) => `mcp:
  servers:
    docs: { transport: streamable-http, url: "https://mcp.example.com/mcp", class: ${cls} }
policy:
  resourceTrust:
    company: deny
`;
    const error = caught(() =>
      checkReleaseInputs(
        project({ schema: "piship/v1alpha6", extra: server("company") }).path,
      ),
    );
    expect(error.code).toBe("POLICY_DENIED");
    expect(error.message).toContain(
      "MCP server docs is declared company, which policy.resourceTrust denies",
    );
    expect(
      checkReleaseInputs(
        project({ schema: "piship/v1alpha6", extra: server("user") }).path,
      ).deployment.mode,
    ).toBe("personal");
  });

  it("policy: refuses an enabled capability whose provider class policy.providerTrust denies", () => {
    const { path } = project({
      extra: `capabilities:
  workflow:
    enabled: true
    provider: { id: builtin/workflow }
policy:
  providerTrust:
    builtin: deny
`,
    });
    const error = caught(() => checkReleaseInputs(path));
    expect(error.code).toBe("POLICY_DENIED");
    expect(error.message).toMatch(/^Release gate policy: /);
    expect(error.message).toContain(
      "capability workflow is enabled with a builtin provider, which policy.providerTrust denies",
    );
  });

  it("certification: certified evidence is enforced when locking (the gate is a second layer)", () => {
    const { dir, path } = project({
      lock: false,
      resources: `resources:
  instructions:
    user: [./resources/AGENTS.md]
  skills:
    certified:
      - path: ./resources/certified/notes
        id: notes
        version: 1.0.0
        source: https://example.org/notes
        integrity: sha256-${"0".repeat(64)}
        license: MIT
        pi: ["1.0.3"]
`,
    });
    write(
      join(dir, "resources", "certified", "notes", "SKILL.md"),
      "# notes\n",
    );
    expect(() => lockManifest(path)).toThrow(/integrity/i);
    expect(caught(() => checkReleaseInputs(path)).message).toMatch(
      /Release gate lock|integrity/i,
    );
  });

  it.runIf(process.platform !== "win32")(
    "sandbox: a required sandbox passes on a supported host target",
    () => {
      const { path } = project({ extra: "sandbox:\n  required: true\n" });
      expect(
        checkReleaseInputs(path).governance?.manifest.sandbox.required,
      ).toBe(true);
    },
  );

  it.runIf(process.platform !== "win32")(
    "sandbox: win32 cannot be reached from this host; the target gate refuses first",
    () => {
      const { path } = project({ extra: "sandbox:\n  required: true\n" });
      expect(
        caught(() => checkReleaseInputs(path, "win32-x64")).message,
      ).toMatch(/Release gate target: releases are built on their target/);
    },
  );

  it("sandbox: refuses a required sandbox for win32-x64, which has no adapter", async () => {
    // Build on a (simulated) win32-x64 host so the target gate passes and the
    // sandbox gate is the one that decides, on every host.
    vi.resetModules();
    vi.doMock("./index.js", async (original) => ({
      ...(await original<typeof import("./index.js")>()),
      currentTarget: () => "win32-x64",
    }));
    try {
      const release = await import("./release/index.js");
      const { path } = project({ extra: "sandbox:\n  required: true\n" });
      const error = caught(() => release.checkReleaseInputs(path, "win32-x64"));
      expect(error.code).toBe("SANDBOX_UNAVAILABLE");
      expect(error.message).toBe(
        "Release gate sandbox: the distribution requires an OS sandbox and PiShip has no sandbox adapter for win32-x64",
      );
      const optional = project({ extra: "sandbox:\n  required: false\n" });
      expect(
        release.checkReleaseInputs(optional.path, "win32-x64").app.id,
      ).toBe("acmepi");
      // A remote backend does not depend on the target's OS sandbox.
      const remote = project({
        extra:
          "sandbox:\n  required: true\n  provider: e2b-compatible\n  endpoint: https://sandbox.example.com\n",
      });
      expect(release.checkReleaseInputs(remote.path, "win32-x64").app.id).toBe(
        "acmepi",
      );
    } finally {
      vi.doUnmock("./index.js");
      vi.resetModules();
    }
  });

  it.runIf(process.platform === "win32")(
    "sandbox: refuses a required sandbox on win32",
    () => {
      const { path } = project({ extra: "sandbox:\n  required: true\n" });
      const error = caught(() => checkReleaseInputs(path));
      expect(error.code).toBe("SANDBOX_UNAVAILABLE");
      expect(error.message).toMatch(/Release gate sandbox/);
    },
  );

  it("test: a failing required test stops the build and leaves no output", async () => {
    const { dir, path } = project();
    const error = await rejection(
      build(path, {
        runTest: (payload, command, args) =>
          args[0] === "--smoke"
            ? { status: 1, stdout: "", stderr: "smoke failed: boom" }
            : fakeRun(payload, command, args),
      }),
    );
    expect(error.code).toBe("UPDATE_FAILED");
    expect(error.message).toMatch(
      /Release gate test: required test offline-smoke failed: smoke failed: boom/,
    );
    expect(readdirSync(join(dir, "dist", "releases"))).toEqual([]);
  });

  it("test: a version check that does not name the pinned Pi fails", async () => {
    const { path } = project();
    const error = await rejection(
      build(path, {
        runTest: () => ({
          status: 0,
          stdout: "AcmePi 1.0.0\nPi 0.1.0\n",
          stderr: "",
        }),
      }),
    );
    expect(error.message).toMatch(/required test launch-version failed/);
  });

  it("vulnerability: a high advisory fails the build", async () => {
    const { dir, path } = project();
    const error = await rejection(
      build(path, { scanner: () => advisory("high", "GHSA-zzzz-yyyy-xxxx") }),
    );
    expect(error.code).toBe("POLICY_DENIED");
    expect(error.message).toMatch(
      /Release gate vulnerability: blocking advisories at or above high: GHSA-zzzz-yyyy-xxxx \(alpha, high\)/,
    );
    expect(readdirSync(join(dir, "dist", "releases"))).toEqual([]);
  });

  it("vulnerability: an allowlisted advisory with a future expiry passes", async () => {
    const { path } = project();
    const built = await build(path, { scanner: () => advisory("critical") });
    const report = JSON.parse(
      readFileSync(join(built.directory, "vulnerabilities.json"), "utf8"),
    );
    expect(report.verdict).toBe("passed");
    expect(report.findings).toEqual([
      expect.objectContaining({
        id: ADVISORY,
        status: "allowed",
        severity: "critical",
      }),
    ]);
    expect(built.metadata.vulnerabilities.counts.critical).toBe(1);
  });

  it("vulnerability: an expired exception fails", async () => {
    const { path } = project();
    const error = await rejection(
      build(path, {
        scanner: () => advisory("high"),
        now: () => new Date("2027-01-01T00:00:00Z"),
      }),
    );
    expect(error.message).toMatch(
      /blocking advisories at or above high: GHSA-aaaa-bbbb-cccc/,
    );
  });

  it.each([
    ["undefined", undefined],
    ["a string", "npm ERR! network"],
    ["an audit v1 report", { auditReportVersion: 1, advisories: {} }],
    ["an error object", { error: { code: "ENOAUDIT" } }],
    ["a report without vulnerabilities", { auditReportVersion: 2 }],
  ])("vulnerability: a scanner returning %s fails", async (_label, output) => {
    const { path } = project();
    const error = await rejection(build(path, { scanner: () => output }));
    expect(error.code).toBe("UPDATE_FAILED");
    expect(error.message).toMatch(
      /Release gate vulnerability: the dependency scan returned no npm audit v2 report/,
    );
  });

  it("vulnerability: a throwing scanner fails the build", async () => {
    const { path } = project();
    await expect(
      build(path, {
        scanner: () => {
          throw new Error("registry unreachable");
        },
      }),
    ).rejects.toThrow("registry unreachable");
  });

  it("vulnerability: npm audit fails on a high advisory for a nested runtime package", async () => {
    // A local registry stub answers npm's bulk advisory request with a high
    // advisory for a package Pi pulls in. It runs in a child process because
    // the scanner blocks this one while npm audit runs.
    const stub = spawn(
      process.execPath,
      [
        "--input-type=module",
        "-e",
        `import { createServer } from "node:http";
const advisory = { id: 1, url: "https://github.com/advisories/GHSA-hhhh-iiii-jjjj", title: "ReDoS", severity: "high", vulnerable_versions: "*", cwe: [], cvss: { score: 7.5, vectorString: null } };
const server = createServer((request, response) => {
  request.resume().on("end", () => {
    const bulk = request.method === "POST" && request.url.endsWith("/-/npm/v1/security/advisories/bulk");
    response.writeHead(bulk ? 200 : 404, { "content-type": "application/json" });
    response.end(bulk ? JSON.stringify({ "@earendil-works/pi-coding-agent": [advisory] }) : "{}");
  });
});
server.listen(0, "127.0.0.1", () => console.log(server.address().port));`,
      ],
      { stdio: ["ignore", "pipe", "inherit"] },
    );
    const saved = process.env.npm_config_registry;
    try {
      const port = await new Promise<string>((done, fail) => {
        stub.stdout.once("data", (chunk) => done(String(chunk).trim()));
        stub.once("error", fail);
      });
      process.env.npm_config_registry = `http://127.0.0.1:${port}/`;
      const { path } = project();
      const error = await rejection(
        build(path, {
          // The payload carries the workspace build input as buildDistribution
          // installs it: the root manifest and each workspace manifest.
          assemble: (manifestPath, outputRoot) => {
            const out = fakeAssemble(manifestPath, outputRoot);
            const input = join(
              out,
              "node_modules",
              "@piship",
              "core",
              "dist",
              "build-input",
            );
            for (const file of readdirSync(join(BUILD_INPUT, "packages")))
              cpSync(
                join(BUILD_INPUT, "packages", file, "package.json"),
                join(input, "packages", file, "package.json"),
              );
            cpSync(
              join(BUILD_INPUT, "package.json"),
              join(input, "package.json"),
            );
            return out;
          },
          scanner: npmAuditScanner,
        }),
      );
      expect(error.code).toBe("POLICY_DENIED");
      expect(error.message).toMatch(
        /GHSA-hhhh-iiii-jjjj \(@earendil-works\/pi-coding-agent, high\)/,
      );
    } finally {
      if (saved === undefined) delete process.env.npm_config_registry;
      else process.env.npm_config_registry = saved;
      stub.kill();
    }
  });

  it("signature: records a passing check and the packages without a registry signature", async () => {
    const { path } = project();
    const built = await build(path, {
      signatureAuditor: () =>
        signatureOutput(
          [],
          [
            {
              name: "zeta",
              version: "1.0.0",
              registry: "https://registry.npmjs.org/",
            },
            {
              name: "alpha",
              version: "1.0.0",
              registry: "https://registry.npmjs.org/",
            },
          ],
        ),
    });
    expect(built.metadata.signatures).toEqual({
      tool: "npm audit signatures --omit=dev",
      verdict: "passed",
      missing: ["alpha@1.0.0", "zeta@1.0.0"],
    });
    const verified = await verifyRelease(built.archive);
    expect(verified.metadata.signatures?.verdict).toBe("passed");
    verified.cleanup();
  });

  it("signature: runs over the assembled payload", async () => {
    const { path } = project();
    const seen: string[] = [];
    await build(path, {
      signatureAuditor: (payload) => {
        seen.push(payload);
        expect(existsSync(join(payload, "node_modules", "alpha"))).toBe(true);
        expect(existsSync(join(payload, "package-lock.json"))).toBe(true);
        return signatureOutput();
      },
    });
    expect(seen).toHaveLength(1);
  });

  it("signature: an invalid registry signature fails the build and leaves no output", async () => {
    const { dir, path } = project();
    const error = await rejection(
      build(path, {
        signatureAuditor: () =>
          signatureOutput([
            {
              name: "alpha",
              version: "1.0.0",
              code: "EINTEGRITYSIGNATURE",
              message: "alpha@1.0.0 has an invalid registry signature",
            },
          ]),
      }),
    );
    expect(error.code).toBe("INTEGRITY_FAILED");
    expect(error.message).toBe(
      "Release gate signature: invalid registry signatures or attestations: alpha@1.0.0 (EINTEGRITYSIGNATURE)",
    );
    expect(readdirSync(join(dir, "dist", "releases"))).toEqual([]);
  });

  it("signature: an invalid attestation fails the build", async () => {
    const { path } = project();
    const error = await rejection(
      build(path, {
        signatureAuditor: () =>
          signatureOutput(
            [
              {
                name: "@scope/beta",
                version: "2.0.0",
                code: "EATTESTATIONVERIFY",
              },
            ],
            [{ name: "alpha", version: "1.0.0" }],
          ),
      }),
    );
    expect(error.message).toMatch(
      /Release gate signature: .*@scope\/beta@2\.0\.0 \(EATTESTATIONVERIFY\)/,
    );
  });

  it("signature: a check npm reports it could not run is recorded as unavailable", async () => {
    const { path } = project();
    const built = await build(path, {
      signatureAuditor: () => ({
        status: 1,
        stdout: JSON.stringify({
          error: { summary: "Failed to download", detail: "" },
        }),
        stderr: "npm error Failed to download\n",
      }),
    });
    expect(built.metadata.signatures).toEqual({
      tool: "npm audit signatures --omit=dev",
      verdict: "unavailable",
      missing: [],
      reason: "Failed to download",
    });
  });

  it.each([
    [
      "no output (npm could not start)",
      { status: null, stdout: "", stderr: "spawn npm ENOENT" },
    ],
    ["plain text", { status: 1, stdout: "npm ERR! something", stderr: "" }],
    [
      "a report without missing",
      { status: 0, stdout: '{"invalid":[]}', stderr: "" },
    ],
    [
      "malformed entries",
      { status: 1, stdout: '{"invalid":[1],"missing":[]}', stderr: "" },
    ],
    [
      "an error without a summary",
      { status: 1, stdout: '{"error":{}}', stderr: "" },
    ],
  ])("signature: %s fails closed", async (_label, output) => {
    const { dir, path } = project();
    const error = await rejection(
      build(path, { signatureAuditor: () => output }),
    );
    expect(error.code).toBe("UPDATE_FAILED");
    expect(error.message).toMatch(
      /^Release gate signature: the registry signature check returned no report/,
    );
    expect(readdirSync(join(dir, "dist", "releases"))).toEqual([]);
  });

  it("channel: refuses an unknown channel", async () => {
    const { path } = project();
    await expect(build(path, { channel: "nightly" })).rejects.toThrow(
      /Release gate channel: unknown channel nightly/,
    );
  });
});

describe("release Pi compatibility", () => {
  const lockFor = (
    mode: "personal" | "managed",
    version = "1.0.3",
    governance = false,
  ) => ({
    deployment: { mode },
    runtime: { version } as never,
    ...(governance ? { governance: {} as never } : {}),
  });

  it("records the weakest of the deployment and lifecycle surfaces", () => {
    const known = PI_COMPATIBILITY["1.0.3"] as Record<string, string>;
    const saved = { ...known };
    try {
      const cases: [Record<string, string>, string, string][] = [
        [
          { personal: "supported", lifecycle: "supported" },
          "personal",
          "supported",
        ],
        [
          { personal: "supported", lifecycle: "candidate" },
          "personal",
          "candidate",
        ],
        [
          { personal: "candidate", lifecycle: "supported" },
          "personal",
          "candidate",
        ],
        [
          { managed: "supported", lifecycle: "unsupported" },
          "managed",
          "unsupported",
        ],
        [
          { managed: "unsupported", lifecycle: "supported" },
          "managed",
          "unsupported",
        ],
        [
          { managed: "candidate", lifecycle: "candidate" },
          "managed",
          "candidate",
        ],
        [
          { managed: "retired", lifecycle: "supported" },
          "managed",
          "unsupported",
        ],
      ];
      for (const [statuses, mode, expected] of cases) {
        Object.assign(known, saved, statuses);
        const lock = lockFor(mode as "personal" | "managed");
        expect(piCompatibility(lock)).toBe(expected);
        expect(piCompatibilitySurfaces(lock)).toEqual({
          [mode]: statuses[mode],
          lifecycle: statuses.lifecycle,
        });
      }
    } finally {
      Object.assign(known, saved);
    }
  });

  it("includes the governance surface when the distribution declares governance", () => {
    const known = PI_COMPATIBILITY["1.0.3"] as Record<string, string>;
    const saved = { ...known };
    try {
      const cases: [Record<string, string>, string, string][] = [
        [
          {
            personal: "supported",
            governance: "supported",
            lifecycle: "supported",
          },
          "personal",
          "supported",
        ],
        [
          {
            personal: "supported",
            governance: "candidate",
            lifecycle: "supported",
          },
          "personal",
          "candidate",
        ],
        [
          {
            managed: "supported",
            governance: "unsupported",
            lifecycle: "supported",
          },
          "managed",
          "unsupported",
        ],
        [
          {
            managed: "candidate",
            governance: "supported",
            lifecycle: "supported",
          },
          "managed",
          "candidate",
        ],
      ];
      for (const [statuses, mode, expected] of cases) {
        Object.assign(known, saved, statuses);
        const lock = lockFor(mode as "personal" | "managed", "1.0.3", true);
        expect(piCompatibility(lock)).toBe(expected);
        expect(piCompatibilitySurfaces(lock)).toEqual({
          [mode]: statuses[mode],
          governance: statuses.governance,
          lifecycle: statuses.lifecycle,
        });
        // Without governance the governance surface does not count.
        const plain = lockFor(mode as "personal" | "managed");
        expect(piCompatibilitySurfaces(plain)).not.toHaveProperty("governance");
      }
    } finally {
      Object.assign(known, saved);
    }
  });

  it("records an unknown Pi version as unsupported on every surface", () => {
    const lock = lockFor("personal", "0.0.0");
    expect(piCompatibility(lock)).toBe("unsupported");
    expect(piCompatibilitySurfaces(lock)).toEqual({
      personal: "unsupported",
      lifecycle: "unsupported",
    });
    expect(piCompatibilitySurfaces(lockFor("managed", "0.0.0", true))).toEqual({
      managed: "unsupported",
      governance: "unsupported",
      lifecycle: "unsupported",
    });
  });

  it.runIf(HOST_EVIDENCED)(
    "pi: refuses a release when only the governance surface is unsupported",
    () => {
      const { path } = project();
      const known = PI_COMPATIBILITY["1.0.3"] as Record<string, string>;
      const saved = { ...known };
      try {
        for (const surface of Object.keys(known)) known[surface] = "supported";
        known.governance = "unsupported";
        const error = caught(() => checkReleaseInputs(path));
        expect(error.message).toMatch(/Release gate pi: Pi 1\.0\.3/);
      } finally {
        Object.assign(known, saved);
      }
    },
  );

  it.runIf(HOST_EVIDENCED)(
    "pi: refuses a release when only the lifecycle surface is unsupported",
    () => {
      const { path } = project();
      const known = PI_COMPATIBILITY["1.0.3"] as Record<string, string>;
      const saved = { ...known };
      try {
        known.personal = "supported";
        known.lifecycle = "unsupported";
        const error = caught(() => checkReleaseInputs(path));
        expect(error.message).toMatch(/Release gate pi: Pi 1\.0\.3/);
      } finally {
        Object.assign(known, saved);
      }
    },
  );
});

describe("evaluateSignatures", () => {
  it("passes a clean report and sorts missing signatures", () => {
    expect(
      evaluateSignatures(
        signatureOutput(
          [],
          [
            { name: "b", version: "1.0.0" },
            { name: "a", version: "2.0.0" },
          ],
        ),
      ),
    ).toEqual({
      tool: "npm audit signatures --omit=dev",
      verdict: "passed",
      missing: ["a@2.0.0", "b@1.0.0"],
    });
  });

  it("never records content beyond package names, versions, and npm's summary", () => {
    const report = evaluateSignatures({
      status: 1,
      stdout: JSON.stringify({
        error: {
          summary: "  found no dependencies\n  to audit  ",
          detail: "secret-ish detail",
        },
      }),
      stderr: "",
    });
    expect(report).toEqual({
      tool: "npm audit signatures --omit=dev",
      verdict: "unavailable",
      missing: [],
      reason: "found no dependencies to audit",
    });
  });

  it("fails on invalid entries even when npm exits 0", () => {
    expect(() =>
      evaluateSignatures(
        signatureOutput(
          [{ name: "a", version: "1.0.0", code: "EINTEGRITYSIGNATURE" }],
          [],
          0,
        ),
      ),
    ).toThrow(/Release gate signature: invalid registry signatures/);
  });
});

describe("evaluateVulnerabilities", () => {
  const policy = {
    failOn: "high" as const,
    allow: [{ id: ADVISORY, reason: "reviewed", expires: "2026-12-31" }],
  };
  it("classifies below-threshold, allowed, and blocking findings", () => {
    const low = evaluateVulnerabilities(
      advisory("moderate", "GHSA-1111-2222-3333"),
      policy,
      new Date("2026-06-01"),
    );
    expect(low.verdict).toBe("passed");
    expect(low.findings[0]?.status).toBe("below-threshold");
    const allowed = evaluateVulnerabilities(
      advisory("high"),
      policy,
      new Date("2026-12-31T23:00:00Z"),
    );
    expect(allowed.findings[0]?.status).toBe("allowed");
    expect(allowed.verdict).toBe("passed");
    const expired = evaluateVulnerabilities(
      advisory("high"),
      policy,
      new Date("2027-01-01T00:00:00Z"),
    );
    expect(expired.findings[0]?.status).toBe("blocking");
    expect(expired.verdict).toBe("failed");
  });
  it("uses the package severity when the advisory has none and ids from npm sources", () => {
    const report = evaluateVulnerabilities(
      {
        auditReportVersion: 2,
        vulnerabilities: {
          beta: { severity: "critical", via: [{ source: 42 }, "alpha"] },
        },
      },
      policy,
      new Date("2026-06-01"),
    );
    expect(report.findings).toEqual([
      expect.objectContaining({
        id: "npm-42",
        package: "beta",
        severity: "critical",
        status: "blocking",
      }),
    ]);
    expect(report.counts).toMatchObject({ critical: 1, high: 0 });
  });
  it.each([
    ["null", null],
    ["an array", []],
  ])(
    "rejects a v2 report whose vulnerabilities are %s",
    (_label, vulnerabilities) => {
      expect(() =>
        evaluateVulnerabilities(
          { auditReportVersion: 2, vulnerabilities },
          policy,
          new Date("2026-06-01"),
        ),
      ).toThrow(/no npm audit v2 report/);
    },
  );
  it("does not let an unrecognised severity pass as below-threshold", () => {
    const report = evaluateVulnerabilities(
      advisory("CRITICAL", "GHSA-9999-8888-7777"),
      policy,
      new Date("2026-06-01"),
    );
    expect(report.verdict).toBe("failed");
  });
});

// ------------------------------------------------------------ build output

describe.runIf(HOST_EVIDENCED)("staging a killed release build left", () => {
  const staging = (releases: string) => {
    const name = ".piship-release-acmepi-";
    const stale = plantTemporary(
      releases,
      `${name}aaaaaa`,
      "release",
      deadPid(),
    );
    const live = plantTemporary(
      releases,
      `${name}bbbbbb`,
      "release",
      livePid(),
    );
    const user = join(releases, `${name}notes`);
    mkdirSync(user);
    writeFileSync(join(user, "keep.txt"), "user data");
    return { name, stale, live, user };
  };

  it("is reported, not removed: the output directory may be one sandboxed commands write", async () => {
    const { dir, path } = project();
    const releases = join(dir, "dist", "releases");
    const { name, stale, live, user } = staging(releases);
    const found: { directory: string; count: number; attempted: boolean }[] =
      [];
    const built = await build(path, {
      abandonedStaging: (report) => found.push(report),
    });
    expect(found).toEqual([
      { directory: releases, count: 1, attempted: false },
    ]);
    expect(existsSync(join(stale, "x", "output.txt"))).toBe(true);
    expect(existsSync(join(live, "x", "output.txt"))).toBe(true);
    expect(readFileSync(join(user, "keep.txt"), "utf8")).toBe("user data");
    // The build's own staging is gone, and it left no release-test state.
    expect(readdirSync(releases).sort()).toEqual(
      [
        `${name}aaaaaa`,
        `${name}bbbbbb`,
        `${name}notes`,
        built.name,
        `${built.name}.tar.gz`,
        `${built.name}.tar.gz.sha256`,
      ].sort(),
    );
  });

  it("is removed when the build is asked to, and a live build's is kept", async () => {
    const { dir, path } = project();
    const releases = join(dir, "dist", "releases");
    const { name, stale, live, user } = staging(releases);
    const found: unknown[] = [];
    const built = await build(path, {
      reclaimStaging: true,
      abandonedStaging: (report) => found.push(report),
    });
    expect(found).toEqual([]);
    expect(existsSync(stale)).toBe(false);
    expect(existsSync(join(live, "x", "output.txt"))).toBe(true);
    expect(readFileSync(join(user, "keep.txt"), "utf8")).toBe("user data");
    expect(readdirSync(releases).sort()).toEqual(
      [
        `${name}bbbbbb`,
        `${name}notes`,
        built.name,
        `${built.name}.tar.gz`,
        `${built.name}.tar.gz.sha256`,
      ].sort(),
    );
  });

  it("is removed on request even when that build fails", async () => {
    const { dir, path } = project();
    const releases = join(dir, "dist", "releases");
    const stale = plantTemporary(
      releases,
      ".piship-release-acmepi-aaaaaa",
      "release",
      deadPid(),
    );
    await rejection(
      build(path, {
        reclaimStaging: true,
        runTest: () => ({ status: 1, stdout: "", stderr: "no" }),
      }),
    );
    expect(existsSync(stale)).toBe(false);
    expect(readdirSync(releases)).toEqual([]);
  });
});

describe.runIf(HOST_EVIDENCED)("release staging paths", () => {
  // On Windows npm cannot run an install script in a directory longer than 260
  // characters; the deepest is inside the build's staging directory, below the
  // release staging directory. Every character of the staging path counts.
  it("are at least 20 characters shorter than the layout that named the release and nested the build", async () => {
    const { dir, path } = project();
    const releases = join(dir, "dist", "releases");
    let outputRoot = "";
    await build(path, {
      assemble: (manifest, root) => {
        outputRoot = root;
        return fakeAssemble(manifest, root);
      },
    });
    // The build is assembled straight into the staging directory, which is
    // named for the distribution and lies directly in the releases directory.
    expect(dirname(outputRoot)).toBe(releases);
    expect(basename(outputRoot)).toMatch(
      /^\.piship-release-acmepi-[A-Za-z0-9]{6}$/,
    );
    // The longest staging directory is the build's own, inside it.
    const longest = join(outputRoot, ".piship-acmepi-XXXXXX", "payload");
    // What a typical Windows release named its staging directory and where it
    // nested the build before: the release name, and a `build` directory.
    const before = join(
      releases,
      ".piship-release-acmepi-1.0.0-win32-x64-XXXXXX",
      "build",
      ".piship-acmepi-XXXXXX",
      "payload",
    );
    expect(before.length - longest.length).toBeGreaterThanOrEqual(20);
  });

  it("do not collide with a distribution whose ID is one of the fixed names", async () => {
    for (const id of ["release", "audit"]) {
      const { dir, path } = project({ id });
      const built = await build(path);
      expect(readdirSync(built.directory)).toContain("payload");
      expect(readdirSync(join(dir, "dist", "releases"))).toEqual(
        expect.arrayContaining([built.name, `${built.name}.tar.gz`]),
      );
    }
  });
});

describe.runIf(HOST_EVIDENCED)("buildRelease output", () => {
  it("writes the release layout, checksums, and a deterministic archive", async () => {
    const { dir, path } = project();
    const first = await build(path);
    const target = currentTarget();
    expect(first.name).toBe(`acmepi-1.0.0-${target}`);
    expect(first.archive).toBe(
      join(dir, "dist", "releases", `acmepi-1.0.0-${target}.tar.gz`),
    );
    expect(readFileSync(`${first.archive}.sha256`, "utf8")).toBe(
      `${first.sha256}  acmepi-1.0.0-${target}.tar.gz\n`,
    );
    expect(readdirSync(first.directory).sort()).toEqual([
      "checksums.txt",
      "install.ps1",
      "install.sh",
      "licenses",
      "payload",
      "release.json",
      "sbom.spdx.json",
      "vulnerabilities.json",
    ]);
    expect(readdirSync(join(dir, "dist", "releases")).sort()).toEqual([
      `acmepi-1.0.0-${target}`,
      `acmepi-1.0.0-${target}.tar.gz`,
      `acmepi-1.0.0-${target}.tar.gz.sha256`,
    ]);
    const checksums = readFileSync(
      join(first.directory, "checksums.txt"),
      "utf8",
    );
    expect(
      checksums
        .trimEnd()
        .split("\n")
        .map((line) => line.slice(66)),
    ).toEqual([...RELEASE_FILES]);
    expect(first.metadata).toMatchObject({
      schema: "piship-release/v1",
      distribution: {
        id: "acmepi",
        name: "AcmePi",
        version: "1.0.0",
        command: "acmepi",
        mode: "personal",
      },
      // The weakest of the personal, governance, and lifecycle surfaces.
      pi: {
        version: "1.0.3",
        compatibility: piCompatibility({
          deployment: { mode: "personal" },
          runtime: { version: "1.0.3" } as never,
          governance: {} as never,
        }),
        surfaces: {
          personal: PI_COMPATIBILITY["1.0.3"]?.personal,
          governance: PI_COMPATIBILITY["1.0.3"]?.governance,
          lifecycle: PI_COMPATIBILITY["1.0.3"]?.lifecycle,
        },
      },
      manifestSchema: "piship/v1alpha5",
      lockSchema: LOCK_SCHEMA_V1ALPHA5,
      target,
      channel: "stable",
      created: "2026-01-01T00:00:00Z",
      stateSchemas: STATE_SCHEMAS,
      tests: [
        { name: "launch-version", result: "passed" },
        { name: "offline-smoke", result: "passed" },
        { name: "governance-inspection", result: "passed" },
      ],
      sbom: { packages: 2 },
    });
    const sbom = JSON.parse(
      readFileSync(join(first.directory, "sbom.spdx.json"), "utf8"),
    );
    expect(sbom.packages.map((item: { name: string }) => item.name)).toEqual([
      "AcmePi",
      "@scope/beta",
      "alpha",
    ]);
    // Same source, lock, and SOURCE_DATE_EPOCH: byte-identical archive.
    const second = await build(path, { outputRoot: join(dir, "second") });
    expect(second.sha256).toBe(first.sha256);
    const verified = await verifyRelease(first.directory, {
      requireTarget: true,
    });
    expect(verified.metadata.distribution.version).toBe("1.0.0");
    verified.cleanup();
    const fromArchive = await verifyRelease(first.archive, {
      expectedSha256: first.sha256,
    });
    expect(fromArchive.lock.app.id).toBe("acmepi");
    expect(existsSync(fromArchive.directory)).toBe(true);
    fromArchive.cleanup();
    expect(existsSync(fromArchive.directory)).toBe(false);
    const report = await compareReleases(first.archive, second.archive);
    expect(report).toMatchObject({
      payloadEqual: true,
      archiveEqual: true,
      payloadDifferences: [],
    });
    expect(Object.values(report.wrapper).every(Boolean)).toBe(true);
  });

  it("changes the archive digest with SOURCE_DATE_EPOCH but not the payload", async () => {
    const { dir, path } = project();
    const first = await build(path);
    process.env.SOURCE_DATE_EPOCH = "1767312000";
    const second = await build(path, { outputRoot: join(dir, "later") });
    expect(second.sha256).not.toBe(first.sha256);
    const report = await compareReleases(first.archive, second.archive);
    expect(report.payloadEqual).toBe(true);
    expect(report.archiveEqual).toBe(false);
    expect(report.wrapper["release.json"]).toBe(false);
  });

  it("compareReleases refuses different versions", async () => {
    const a = project();
    const b = project({ version: "1.1.0" });
    const first = await build(a.path);
    const second = await build(b.path);
    await expect(
      compareReleases(first.directory, second.directory),
    ).rejects.toThrow(/one distribution version on one target/);
  });

  describe("tampering is rejected", () => {
    async function fresh() {
      const { path } = project();
      return build(path);
    }
    it("a modified payload file", async () => {
      const built = await fresh();
      writeFileSync(
        join(built.directory, "payload", "resources", "resources", "AGENTS.md"),
        "# evil\n",
      );
      const error = await rejection(verifyRelease(built.directory));
      expect(error.code).toBe("INTEGRITY_FAILED");
      expect(error.message).toMatch(/integrity mismatch/);
    });
    it("an added payload file", async () => {
      const built = await fresh();
      writeFileSync(join(built.directory, "payload", "bin", "extra"), "evil\n");
      await expect(verifyRelease(built.directory)).rejects.toThrow(
        /integrity mismatch/,
      );
    });
    it("a modified release.json", async () => {
      const built = await fresh();
      const path = join(built.directory, "release.json");
      writeFileSync(
        path,
        readFileSync(path, "utf8").replace(
          '"version": "1.0.0"',
          '"version": "9.0.0"',
        ),
      );
      await expect(verifyRelease(built.directory)).rejects.toThrow(
        /Checksum mismatch for release.json/,
      );
      // Even with checksums recomputed, metadata must match the payload.
      writeFileSync(
        join(built.directory, "checksums.txt"),
        formatChecksums(built.directory, [...RELEASE_FILES]),
      );
      await expect(verifyRelease(built.directory)).rejects.toThrow(
        /release.json does not match the payload: distribution version/,
      );
    });
    it("release metadata missing a required field", async () => {
      const built = await fresh();
      const path = join(built.directory, "release.json");
      const metadata = JSON.parse(readFileSync(path, "utf8"));
      delete metadata.tests;
      writeFileSync(path, `${JSON.stringify(metadata, null, 2)}\n`);
      writeFileSync(
        join(built.directory, "checksums.txt"),
        formatChecksums(built.directory, [...RELEASE_FILES]),
      );
      const error = await rejection(verifyRelease(built.directory));
      expect(error.code).toBe("INTEGRITY_FAILED");
      expect(error.message).toMatch(/malformed release metadata/);
    });
    it("an SBOM entry removed", async () => {
      const built = await fresh();
      const path = join(built.directory, "sbom.spdx.json");
      const sbom = JSON.parse(readFileSync(path, "utf8"));
      sbom.packages = sbom.packages.filter(
        (item: { name: string }) => item.name !== "alpha",
      );
      writeFileSync(path, `${JSON.stringify(sbom, null, 2)}\n`);
      await expect(verifyRelease(built.directory)).rejects.toThrow(
        /Checksum mismatch for sbom.spdx.json/,
      );
      writeFileSync(
        join(built.directory, "checksums.txt"),
        formatChecksums(built.directory, [...RELEASE_FILES]),
      );
      await expect(verifyRelease(built.directory)).rejects.toThrow(
        /SBOM is missing alpha@1.0.0/,
      );
    });
    it("a changed checksums line", async () => {
      const built = await fresh();
      const path = join(built.directory, "checksums.txt");
      const lines = readFileSync(path, "utf8").split("\n");
      lines[0] = `${"0".repeat(64)}${(lines[0] as string).slice(64)}`;
      writeFileSync(path, lines.join("\n"));
      await expect(verifyRelease(built.directory)).rejects.toThrow(
        /Checksum mismatch for install.ps1/,
      );
    });
    it("a checksums line removed", async () => {
      const built = await fresh();
      const path = join(built.directory, "checksums.txt");
      writeFileSync(
        path,
        readFileSync(path, "utf8")
          .split("\n")
          .filter((line) => !line.endsWith("vulnerabilities.json"))
          .join("\n"),
      );
      await expect(verifyRelease(built.directory)).rejects.toThrow(
        /do not cover required file vulnerabilities.json/,
      );
    });
    it("a failed vulnerability verdict with recomputed checksums", async () => {
      const built = await fresh();
      const path = join(built.directory, "vulnerabilities.json");
      writeFileSync(
        path,
        readFileSync(path, "utf8").replace(
          '"verdict": "passed"',
          '"verdict": "failed"',
        ),
      );
      writeFileSync(
        join(built.directory, "checksums.txt"),
        formatChecksums(built.directory, [...RELEASE_FILES]),
      );
      await expect(verifyRelease(built.directory)).rejects.toThrow(
        /vulnerability scan did not pass/,
      );
    });
    it("an archive byte flipped with its .sha256 sidecar", async () => {
      const built = await fresh();
      flipByte(built.archive);
      const error = await rejection(verifyRelease(built.archive));
      expect(error.code).toBe("INTEGRITY_FAILED");
      expect(error.message).toMatch(/does not match .*\.tar\.gz\.sha256/);
    });
    it("an archive byte flipped without a sidecar", async () => {
      const built = await fresh();
      rmSync(`${built.archive}.sha256`);
      flipByte(built.archive);
      await expect(verifyRelease(built.archive)).rejects.toThrow();
    });
    it("an expectedSha256 mismatch", async () => {
      const built = await fresh();
      await expect(
        verifyRelease(built.archive, { expectedSha256: "f".repeat(64) }),
      ).rejects.toThrow(/does not match the expected/);
    });
  });
});

// ---------------------------------------------------------------- channels

describe.runIf(HOST_EVIDENCED)("signed channels", () => {
  async function channel(sequence?: number) {
    const { dir, path } = project();
    const built = await build(path);
    const channelDir = join(dir, "channel");
    const signed = await signChannel({
      directory: channelDir,
      channel: "stable",
      archives: [built.archive],
      privateKeyPem: KEY.privateKeyPem,
      keyId: KEY.id,
      now: () => new Date("2026-06-01T00:00:00Z"),
      ...(sequence === undefined ? {} : { sequence }),
    });
    return { dir, channelDir, built, signed };
  }
  const options = {
    distribution: "acmepi",
    trusted: TRUSTED,
    now: () => new Date("2026-06-02T00:00:00Z"),
  };

  it("verifies a valid signature and lists the archive", async () => {
    const { channelDir, built, signed } = await channel();
    const { metadata, keyId } = await readChannel(
      channelDir,
      "stable",
      options,
    );
    expect(keyId).toBe(KEY.id);
    expect(metadata).toEqual(signed.metadata);
    expect(metadata).toMatchObject({
      schema: CHANNEL_SCHEMA,
      distribution: "acmepi",
      channel: "stable",
      sequence: 1,
      expires: "2026-07-01T00:00:00.000Z",
    });
    expect(metadata.releases).toEqual([
      expect.objectContaining({
        version: "1.0.0",
        target: currentTarget(),
        archive: `acmepi-1.0.0-${currentTarget()}.tar.gz`,
        sha256: built.sha256,
        pi: "1.0.3",
        lockSha256: built.metadata.lockSha256,
      }),
    ]);
    expect(
      existsSync(join(channelDir, metadata.releases[0]?.archive as string)),
    ).toBe(true);
  });

  it("rejects the wrong key and an unknown key id", async () => {
    const { channelDir } = await channel();
    const other = generateSigningKey("test-release");
    await expect(
      readChannel(channelDir, "stable", {
        ...options,
        trusted: [{ id: KEY.id, publicKey: other.publicKey }],
      }),
    ).rejects.toThrow(/does not verify/);
    await expect(
      readChannel(channelDir, "stable", {
        ...options,
        trusted: [{ id: "someone-else", publicKey: KEY.publicKey }],
      }),
    ).rejects.toThrow(/Signature key test-release is not trusted/);
    await expect(
      readChannel(channelDir, "stable", { ...options, trusted: [] }),
    ).rejects.toThrow(/no trusted release keys/);
  });

  it("rejects tampered channel metadata and a damaged signature file", async () => {
    const { channelDir } = await channel();
    const path = join(channelDir, "stable.json");
    const original = readFileSync(path, "utf8");
    writeFileSync(path, original.replace('"sequence": 1', '"sequence": 99'));
    const error = await rejection(readChannel(channelDir, "stable", options));
    expect(error.code).toBe("INTEGRITY_FAILED");
    expect(error.message).toMatch(/does not verify/);
    writeFileSync(path, original);
    writeFileSync(`${path}.sig`, "not json");
    await expect(readChannel(channelDir, "stable", options)).rejects.toThrow(
      /not valid JSON/,
    );
  });

  it.each([
    [
      "null releases",
      (doc: Record<string, unknown>) => ({ ...doc, releases: null }),
    ],
    [
      "negative bytes",
      (doc: Record<string, unknown>) => ({
        ...doc,
        releases: [
          { ...(doc.releases as Record<string, unknown>[])[0], bytes: -1 },
        ],
      }),
    ],
    [
      "fractional bytes",
      (doc: Record<string, unknown>) => ({
        ...doc,
        releases: [
          { ...(doc.releases as Record<string, unknown>[])[0], bytes: 1.5 },
        ],
      }),
    ],
    [
      "bad hash",
      (doc: Record<string, unknown>) => ({
        ...doc,
        releases: [
          { ...(doc.releases as Record<string, unknown>[])[0], sha256: "bad" },
        ],
      }),
    ],
    [
      "missing release field",
      (doc: Record<string, unknown>) => ({
        ...doc,
        releases: [{ version: "1.0.0" }],
      }),
    ],
    [
      "unsafe archive",
      (doc: Record<string, unknown>) => ({
        ...doc,
        releases: [
          {
            ...(doc.releases as Record<string, unknown>[])[0],
            archive: "../escape.tar.gz",
          },
        ],
      }),
    ],
  ])(
    "rejects correctly signed malformed channel metadata: %s",
    async (_label, mutate) => {
      const { channelDir } = await channel();
      const path = join(channelDir, "stable.json");
      const original = JSON.parse(readFileSync(path, "utf8")) as Record<
        string,
        unknown
      >;
      const bytes = Buffer.from(`${JSON.stringify(mutate(original))}\n`);
      writeFileSync(path, bytes);
      writeFileSync(
        `${path}.sig`,
        JSON.stringify(signBytes(bytes, KEY.privateKeyPem, KEY.id)),
      );
      const error = await rejection(readChannel(channelDir, "stable", options));
      expect(error.code).toBe("INTEGRITY_FAILED");
    },
  );

  it("rejects expired metadata", async () => {
    const { channelDir } = await channel();
    await expect(
      readChannel(channelDir, "stable", {
        ...options,
        now: () => new Date("2026-07-01T00:00:01Z"),
      }),
    ).rejects.toThrow(/expired at 2026-07-01T00:00:00.000Z/);
  });

  it("rejects a sequence lower than one already seen (replay)", async () => {
    const { channelDir } = await channel();
    await expect(
      readChannel(channelDir, "stable", { ...options, minSequence: 1 }),
    ).resolves.toBeTruthy();
    const error = await rejection(
      readChannel(channelDir, "stable", { ...options, minSequence: 2 }),
    );
    expect(error.code).toBe("INTEGRITY_FAILED");
    expect(error.message).toMatch(/refusing a replayed channel/);
  });

  it("rejects metadata for another distribution or channel", async () => {
    const { channelDir } = await channel();
    await expect(
      readChannel(channelDir, "stable", {
        ...options,
        distribution: "otherpi",
      }),
    ).rejects.toThrow(/is for acmepi\/stable, not otherpi\/stable/);
    cpSync(join(channelDir, "stable.json"), join(channelDir, "candidate.json"));
    cpSync(
      join(channelDir, "stable.json.sig"),
      join(channelDir, "candidate.json.sig"),
    );
    await expect(readChannel(channelDir, "candidate", options)).rejects.toThrow(
      /is for acmepi\/stable, not acmepi\/candidate/,
    );
  });

  it("requires the sequence to increase on re-sign and keeps existing entries", async () => {
    const { dir, channelDir, built } = await channel();
    const sign = (sequence?: number, archives = [built.archive]) =>
      signChannel({
        directory: channelDir,
        channel: "stable",
        archives,
        privateKeyPem: KEY.privateKeyPem,
        keyId: KEY.id,
        ...(sequence === undefined ? {} : { sequence }),
      });
    await expect(sign(1)).rejects.toThrow(
      /Channel sequence must increase \(current 1\)/,
    );
    await expect(sign(0)).rejects.toThrow(/must increase/);
    const b = project({ version: "1.1.0" });
    const next = await build(b.path, { outputRoot: join(dir, "b") });
    const resigned = await sign(undefined, [next.archive]);
    expect(resigned.metadata.sequence).toBe(2);
    expect(resigned.metadata.releases.map((item) => item.version)).toEqual([
      "1.0.0",
      "1.1.0",
    ]);
  });

  it("changes nothing when signing fails, and leaves no temporary files", async () => {
    const { channelDir, built } = await channel();
    const files = () =>
      readdirSync(channelDir)
        .sort()
        .map((name) => [name, readFileSync(join(channelDir, name))]);
    const before = files();
    for (const signer of [
      { privateKeyPem: KEY.privateKeyPem, keyId: "Not A Key Id" },
      { privateKeyPem: "not a pem", keyId: KEY.id },
    ])
      await expect(
        signChannel({
          directory: channelDir,
          channel: "stable",
          archives: [built.archive],
          ...signer,
        }),
      ).rejects.toThrow();
    expect(files()).toEqual(before);
    await signChannel({
      directory: channelDir,
      channel: "stable",
      archives: [built.archive],
      privateKeyPem: KEY.privateKeyPem,
      keyId: KEY.id,
    });
    expect(readdirSync(channelDir).sort()).toEqual([
      basename(built.archive),
      "stable.json",
      "stable.json.sig",
    ]);
    // Published files keep the default mode, not the owner-only state mode.
    if (process.platform !== "win32")
      for (const name of ["stable.json", "stable.json.sig"])
        expect(statSync(join(channelDir, name)).mode & 0o777).toBe(
          0o666 & ~process.umask(),
        );
  });

  it("rejects a faulty signer before publishing and changes no files", async () => {
    const { dir, channelDir, built } = await channel();
    // Every file under the channel directory and the fresh one, with bytes.
    const snapshot = () =>
      [channelDir, join(dir, "fresh")].map((root) =>
        existsSync(root)
          ? readdirSync(root)
              .sort()
              .map((name) => [name, readFileSync(join(root, name))])
          : null,
      );
    const before = snapshot();
    expect(before[1]).toBeNull();
    const next = project({ version: "1.1.0" });
    const added = await build(next.path, { outputRoot: join(dir, "next") });
    const faulty = (sign: () => Promise<Uint8Array>) => ({
      keyId: KEY.id,
      algorithm: "ed25519" as const,
      publicKey: KEY.publicKey,
      sign,
    });
    for (const signer of [
      faulty(async () => new Uint8Array(64)),
      faulty(async () => {
        throw new Error("hardware token unplugged");
      }),
    ])
      for (const directory of [channelDir, join(dir, "fresh")]) {
        const error = await rejection(
          signChannel({
            directory,
            channel: "stable",
            archives: [built.archive, added.archive],
            signer,
          }),
        );
        expect(error.code).toBe("INTEGRITY_FAILED");
        expect(error.message).not.toContain("unplugged");
        expect(snapshot()).toEqual(before);
      }
  });

  it("publishes with an encrypted key through a PEM signer", async () => {
    const encrypted = generateSigningKey(KEY.id, { passphrase: "hunter2" });
    const { dir, path } = project({ trust: bootstrapTrust([encrypted]) });
    const built = await build(path);
    const channelDir = join(dir, "channel");
    const signed = await signChannel({
      directory: channelDir,
      channel: "stable",
      archives: [built.archive],
      signer: pemSigner({
        keyId: KEY.id,
        privateKeyPem: encrypted.privateKeyPem,
        passphrase: "hunter2",
      }),
      now: () => new Date("2026-06-01T00:00:00Z"),
    });
    const read = await readChannel(channelDir, "stable", {
      distribution: "acmepi",
      trusted: [{ id: KEY.id, publicKey: encrypted.publicKey }],
      now: () => new Date("2026-06-02T00:00:00Z"),
    });
    expect(read.metadata).toEqual(signed.metadata);
    expect(
      JSON.parse(readFileSync(join(channelDir, "stable.json.sig"), "utf8")),
    ).not.toHaveProperty("signatures");
  });

  it("extends existing metadata only when its signature verifies", async () => {
    const { channelDir, built: first } = await channel();
    const path = join(channelDir, "stable.json");
    // A release whose channel role also trusts the next key.
    const next = generateSigningKey("test-release-next");
    const overlap = project({ trust: bootstrapTrust([KEY, next]) });
    const both = await build(overlap.path);
    const resign = (key = KEY) =>
      signChannel({
        directory: channelDir,
        channel: "stable",
        archives: [key === KEY ? first.archive : both.archive],
        privateKeyPem: key.privateKeyPem,
        keyId: key.id,
      });
    // Rotation: a new signing key may extend metadata signed by a key the
    // added release pins.
    expect((await resign(next)).metadata.sequence).toBe(2);
    // Metadata signed by a key neither the signer nor the release vouches
    // for is refused.
    const stranger = generateSigningKey("someone-else");
    const valid = readFileSync(`${path}.sig`);
    writeFileSync(
      `${path}.sig`,
      JSON.stringify(
        signBytes(readFileSync(path), stranger.privateKeyPem, stranger.id),
      ),
    );
    const unknown = await rejection(resign());
    expect(unknown.code).toBe("INTEGRITY_FAILED");
    expect(unknown.message).toMatch(
      /Existing channel metadata .*stable\.json does not verify: Signature key someone-else is not trusted/,
    );
    writeFileSync(`${path}.sig`, valid);
    expect((await resign(next)).metadata.sequence).toBe(3);
    // The old key cannot extend it with a release that does not pin the new.
    await expect(resign()).rejects.toThrow(
      /does not verify: Signature key test-release-next is not trusted; trusted keys: test-release;/,
    );
    // ... unless the owner names the key that signed it.
    const back = await signChannel({
      directory: channelDir,
      channel: "stable",
      archives: [first.archive],
      privateKeyPem: KEY.privateKeyPem,
      keyId: KEY.id,
      previousKeys: [{ id: next.id, publicKey: next.publicKey }],
    });
    expect(back.metadata.sequence).toBe(4);
    expect((await resign(next)).metadata.sequence).toBe(5);
    // Metadata changed after it was signed, or without its signature.
    const signed = readFileSync(path, "utf8");
    writeFileSync(path, signed.replace('"sequence": 5', '"sequence": 50'));
    await expect(resign(next)).rejects.toThrow(
      /Existing channel metadata .*stable\.json does not verify: Signature does not verify/,
    );
    writeFileSync(path, signed);
    rmSync(`${path}.sig`);
    await expect(resign(next)).rejects.toThrow(
      /Existing channel metadata .*stable\.json has no signature/,
    );
    writeFileSync(path, "{");
    await expect(resign(next)).rejects.toThrow(
      /Existing channel metadata .*stable\.json is not valid channel metadata/,
    );
  });

  it("refuses archives of another distribution and unverified archives", async () => {
    const { dir, channelDir } = await channel();
    const other = project({ id: "otherpi" });
    const otherBuilt = await build(other.path, {
      outputRoot: join(dir, "other"),
    });
    await expect(
      signChannel({
        directory: channelDir,
        channel: "stable",
        archives: [otherBuilt.archive],
        privateKeyPem: KEY.privateKeyPem,
        keyId: KEY.id,
      }),
    ).rejects.toThrow(/belongs to acmepi, not otherpi/);
    flipByte(otherBuilt.archive);
    await expect(
      signChannel({
        directory: join(dir, "fresh"),
        channel: "stable",
        archives: [otherBuilt.archive],
        privateKeyPem: KEY.privateKeyPem,
        keyId: KEY.id,
      }),
    ).rejects.toThrow(/Release verification/);
    await expect(
      signChannel({
        directory: join(dir, "fresh"),
        channel: "nightly",
        archives: [],
        privateKeyPem: KEY.privateKeyPem,
        keyId: KEY.id,
      }),
    ).rejects.toThrow(/Unknown channel nightly/);
  });

  it("reads through an https fetcher and refuses insecure sources", async () => {
    const { channelDir, signed } = await channel();
    const requested: string[] = [];
    const fetcher = (async (input: URL | string) => {
      const url = new URL(String(input));
      requested.push(url.href);
      const file = join(channelDir, url.pathname.split("/").pop() as string);
      return existsSync(file)
        ? new Response(readFileSync(file))
        : new Response("missing", { status: 404 });
    }) as typeof fetch;
    const { metadata } = await readChannel(
      "https://updates.example.test/acmepi",
      "stable",
      {
        ...options,
        fetcher,
      },
    );
    expect(metadata.sequence).toBe(signed.metadata.sequence);
    expect(requested).toEqual([
      "https://updates.example.test/acmepi/stable.json",
      "https://updates.example.test/acmepi/stable.json.sig",
    ]);
    await expect(
      readChannel("https://updates.example.test/acmepi", "candidate", {
        ...options,
        fetcher,
      }),
    ).rejects.toThrow(/HTTP 404 for candidate.json/);
    const insecure = await rejection(
      readChannel("http://updates.example.test/acmepi", "stable", {
        ...options,
        fetcher,
      }),
    );
    expect(insecure.code).toBe("NETWORK_DENIED");
    expect(() =>
      checkSourceUrl(new URL("http://127.0.0.1:8080/x")),
    ).not.toThrow();
    expect(() =>
      checkSourceUrl(new URL("https://user:pw@updates.example.test/")),
    ).toThrow(/may not carry credentials/);
    // Downloads stream through the fetcher and are checked against the entry.
    const entry = metadata.releases[0] as (typeof metadata.releases)[number];
    const out = join(temp(), entry.archive);
    await downloadArchive(
      "https://updates.example.test/acmepi",
      entry,
      out,
      fetcher,
    );
    expect(readFileSync(out).length).toBe(entry.bytes);
  });

  it("follows redirects only within the source origin, honors 429 Retry-After, and names a clock that is ahead", async () => {
    const { channelDir } = await channel();
    const serve = (url: URL, headers: Record<string, string> = {}) => {
      const file = join(channelDir, url.pathname.split("/").pop() as string);
      return new Response(readFileSync(file), { headers });
    };
    const base = "https://updates.example.test/acmepi";
    const requested: string[] = [];
    // Same origin: /acmepi/x -> /mirror/x is followed.
    const sameOrigin = (async (input: URL | string, init?: RequestInit) => {
      const url = new URL(String(input));
      requested.push(url.href);
      expect(init?.redirect).toBe("manual");
      return url.pathname.startsWith("/acmepi/")
        ? new Response(null, {
            status: 302,
            headers: { location: `/mirror/${url.pathname.split("/").pop()}` },
          })
        : serve(url);
    }) as typeof fetch;
    await expect(
      readChannel(base, "stable", { ...options, fetcher: sameOrigin }),
    ).resolves.toBeTruthy();
    expect(requested).toContain(
      "https://updates.example.test/mirror/stable.json",
    );
    // Another origin is never contacted.
    const contacted: string[] = [];
    const crossOrigin = (async (input: URL | string) => {
      const url = new URL(String(input));
      contacted.push(url.host);
      return url.host === "updates.example.test"
        ? new Response(null, {
            status: 301,
            headers: { location: "https://cdn.example.test/stable.json" },
          })
        : serve(url);
    }) as typeof fetch;
    const redirected = await rejection(
      readChannel(base, "stable", { ...options, fetcher: crossOrigin }),
    );
    expect(redirected.code).toBe("UPDATE_FAILED");
    expect(redirected.message).toContain(
      "redirected stable.json to another origin (https://cdn.example.test)",
    );
    expect(contacted).toEqual(["updates.example.test"]);
    // 429 is retryable and carries Retry-After.
    const limited = (async () =>
      new Response("slow down", {
        status: 429,
        headers: { "retry-after": "120" },
      })) as unknown as typeof fetch;
    const rateLimited = await rejection(
      readChannel(base, "stable", { ...options, fetcher: limited }),
    );
    expect(rateLimited).toMatchObject({
      code: "UPDATE_FAILED",
      retryable: true,
      retryAfterMs: 120_000,
    });
    // The source's clock says the metadata is still valid: this computer's
    // clock is ahead, and the publisher is not blamed.
    const dated = (async (input: URL | string) =>
      serve(new URL(String(input)), {
        date: "Tue, 02 Jun 2026 00:00:00 GMT",
      })) as typeof fetch;
    const ahead = await rejection(
      readChannel(base, "stable", {
        ...options,
        fetcher: dated,
        now: () => new Date("2026-08-01T00:00:00Z"),
      }),
    );
    expect(ahead.code).toBe("UPDATE_FAILED");
    expect(ahead.message).toContain(
      "This computer's clock (2026-08-01T00:00:00.000Z) is ahead of the update source's (2026-06-02T00:00:00.000Z)",
    );
    expect(ahead.userAction).toContain("Correct this computer's date and time");
  });

  it("downloadArchive refuses unsafe names and digest mismatches", async () => {
    const { channelDir, signed } = await channel();
    const entry = signed.metadata
      .releases[0] as (typeof signed.metadata.releases)[number];
    const out = temp();
    await expect(
      downloadArchive(
        channelDir,
        { ...entry, archive: "../escape.tar.gz" },
        join(out, "a.tar.gz"),
      ),
    ).rejects.toThrow(/Unsafe archive name/);
    const error = await rejection(
      downloadArchive(
        channelDir,
        { ...entry, sha256: "0".repeat(64) },
        join(out, "b.tar.gz"),
      ),
    );
    expect(error.code).toBe("INTEGRITY_FAILED");
    expect(error.message).toMatch(/does not match the signed channel metadata/);
    await expect(
      downloadArchive(
        channelDir,
        { ...entry, bytes: entry.bytes + 1 },
        join(out, "c.tar.gz"),
      ),
    ).rejects.toThrow(/does not match the signed channel metadata/);
  });
});

describe("committed example locks", () => {
  // The release lock gate refuses a stale lock, so a dependency or resource
  // change must re-lock the examples in the same change.
  it.each([
    "demo-company",
    "personal",
    "developer",
    "enterprise-reference",
    "enterprise-reference/sandbox",
  ])("keeps examples/%s/piship.lock current", (name) => {
    const manifest = fileURLToPath(
      new URL(`../../../examples/${name}/piship.yaml`, import.meta.url),
    );
    expect(() => requireCurrentLock(manifest)).not.toThrow();
  });
});
