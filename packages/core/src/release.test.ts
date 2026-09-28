import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { readManifest } from "@piship/schema";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  EVIDENCED_TARGETS,
  LOCK_SCHEMA_V1ALPHA3,
  LOCK_SCHEMA_V1ALPHA4,
  PI_COMPATIBILITY,
  currentTarget,
  lockManifest,
  payloadInventory,
  requireCurrentLock,
  resolveLock,
} from "./index.js";
import { STATE_SCHEMAS } from "./migration.js";
import {
  CHANNEL_SCHEMA,
  RELEASE_FILES,
  type CommandResult,
  buildRelease,
  checkReleaseInputs,
  checkSourceUrl,
  compareReleases,
  downloadArchive,
  evaluateVulnerabilities,
  readChannel,
  signChannel,
  verifyRelease,
} from "./release.js";
import { generateSigningKey } from "./signing.js";
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
}

const DEFAULT_RELEASE = `release:
  vulnerabilities:
    failOn: high
    allow:
      - id: ${ADVISORY}
        reason: not reachable from the packaged runtime
        expires: 2026-12-31
`;

function manifestSource(options: ProjectOptions = {}): string {
  const id = options.id ?? "acmepi";
  const schema = options.schema ?? "piship/v1alpha4";
  const v4 = schema === "piship/v1alpha4";
  return `schema: ${schema}
app:
  id: ${id}
  name: AcmePi
  command: ${id}
  version: ${options.version ?? "1.0.0"}
runtime:
  pi: "0.87.1"
deployment:
  mode: personal
${v4 ? "variables:\n  - ACMEPI_UPDATE_SOURCE\n" : ""}${
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
    keys:
      - id: ${KEY.id}
        publicKey: ${KEY.publicKey}
${options.release ?? DEFAULT_RELEASE}`
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
): Promise<Error & { code?: string }> {
  try {
    await promise;
  } catch (error) {
    return error as Error & { code?: string };
  }
  throw new Error("expected a rejection");
}

function flipByte(path: string, offset?: number): void {
  const bytes = readFileSync(path);
  const at = offset ?? Math.floor(bytes.length / 2);
  bytes[at] = (bytes[at] as number) ^ 0xff;
  writeFileSync(path, bytes);
}

// --------------------------------------------------------------------- lock

describe("lock piship-lock/v1alpha4", () => {
  it("is deterministic and records sources, digests, updates, release, and state schemas", () => {
    const { path } = project({ lock: false });
    const first = readFileSync(lockManifest(path), "utf8");
    const second = readFileSync(lockManifest(path), "utf8");
    expect(second).toBe(first);
    const lock = requireCurrentLock(path);
    expect(lock.schema).toBe(LOCK_SCHEMA_V1ALPHA4);
    expect(lock.runtime.stateSchemas).toEqual(STATE_SCHEMAS);
    for (const item of lock.runtime.packages)
      expect(item.resolved).toMatch(/^https:\/\//);
    expect(
      lock.runtime.packages
        .filter((item) => item.installScript)
        .map((item) => item.path),
    ).toEqual([
      "node_modules/@earendil-works/pi-coding-agent/node_modules/@google/genai",
      "node_modules/@earendil-works/pi-coding-agent/node_modules/esbuild",
      "node_modules/@earendil-works/pi-coding-agent/node_modules/protobufjs",
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
      trust: { keys: TRUSTED },
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

describe.runIf(HOST_EVIDENCED)("release gates", () => {
  it("accepts a current v1alpha4 lock with only reviewed install scripts", () => {
    const { path } = project();
    expect(checkReleaseInputs(path).schema).toBe(LOCK_SCHEMA_V1ALPHA4);
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
    const known = PI_COMPATIBILITY["0.87.1"] as Record<string, string>;
    const saved = { ...known };
    try {
      for (const surface of Object.keys(known)) known[surface] = "unsupported";
      const error = caught(() => checkReleaseInputs(path));
      expect(error.message).toMatch(/Release gate pi: /);
      expect(error.message).toMatch(/0\.87\.1/);
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
      readFileSync(path, "utf8").replace('pi: "0.87.1"', 'pi: "0.86.0"'),
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
        '"version": "0.87.1"',
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
      const release = await import("./release.js");
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
        pi: ["0.87.1"]
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

  it("sandbox: a required sandbox passes on a supported host target", () => {
    const { path } = project({ extra: "sandbox:\n  required: true\n" });
    expect(checkReleaseInputs(path).governance?.manifest.sandbox.required).toBe(
      true,
    );
  });

  it.runIf(process.platform !== "win32")(
    "sandbox: win32 cannot be reached from this host; the target gate refuses first",
    () => {
      const { path } = project({ extra: "sandbox:\n  required: true\n" });
      expect(
        caught(() => checkReleaseInputs(path, "win32-x64")).message,
      ).toMatch(/Release gate target: releases are built on their target/);
    },
  );

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

  it("channel: refuses an unknown channel", async () => {
    const { path } = project();
    await expect(build(path, { channel: "nightly" })).rejects.toThrow(
      /Release gate channel: unknown channel nightly/,
    );
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
      pi: { version: "0.87.1", compatibility: "supported" },
      manifestSchema: "piship/v1alpha4",
      lockSchema: LOCK_SCHEMA_V1ALPHA4,
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
        pi: "0.87.1",
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
  it.each(["demo-company", "personal"])(
    "keeps examples/%s/piship.lock current",
    (name) => {
      const manifest = fileURLToPath(
        new URL(`../../../examples/${name}/piship.yaml`, import.meta.url),
      );
      expect(() => requireCurrentLock(manifest)).not.toThrow();
    },
  );
});
