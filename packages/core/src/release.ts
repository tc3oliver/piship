// Production release builds and consumer verification. A release wraps the
// canonical payload from `buildDistribution` unchanged; it never assembles a
// second runtime, resource, or launcher layout.
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  copyFileSync,
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { PiShipError, redact } from "@piship/contracts";
import {
  DEFAULT_RELEASE_TARGETS,
  RELEASE_CHANNELS,
  type ReleaseManifest,
  type UpdatesManifest,
} from "@piship/schema";
import { createArchive, extractArchive, sha256File } from "./archive.js";
import {
  EVIDENCED_TARGETS,
  LOCK_SCHEMA_V1ALPHA4,
  PI_COMPATIBILITY,
  REVIEWED_INSTALL_SCRIPTS,
  buildDistribution,
  currentTarget,
  requireCurrentLock,
  verifyPayloadContents,
  type DistributionLock,
} from "./index.js";
import {
  LEGACY_STATE_SCHEMAS,
  STATE_SCHEMAS,
  type StateSchemaSupport,
} from "./migration.js";
import {
  signBytes,
  verifySignature,
  type SignatureEnvelope,
  type TrustedKey,
} from "./signing.js";
import {
  formatChecksums,
  generateNotices,
  generateSbom,
  listPayloadPackages,
  verifyChecksums,
  verifyNotices,
  verifySbom,
  type SpdxDocument,
} from "./supply-chain.js";

export const RELEASE_SCHEMA = "piship-release/v1";
export const CHANNEL_SCHEMA = "piship-channel/v1";
export const VULNERABILITY_REPORT_SCHEMA = "piship-vulnerabilities/v1";
export const REPRODUCIBILITY_SCHEMA = "piship-reproducibility/v1";

const SEVERITY_ORDER = ["info", "low", "moderate", "high", "critical"];

/** Files every release carries besides the payload, in checksum order. */
export const RELEASE_FILES = [
  "install.ps1",
  "install.sh",
  "licenses/THIRD_PARTY_NOTICES.txt",
  "licenses/index.json",
  "payload/metadata/inventory.json",
  "release.json",
  "sbom.spdx.json",
  "vulnerabilities.json",
] as const;

export interface ReleaseTestResult {
  readonly name: string;
  readonly result: "passed";
}

export interface ReleaseMetadata {
  readonly schema: typeof RELEASE_SCHEMA;
  readonly distribution: {
    readonly id: string;
    readonly name: string;
    readonly version: string;
    readonly command: string;
    readonly mode: string;
  };
  readonly piship: { readonly version: string };
  readonly pi: {
    readonly package: string;
    readonly version: string;
    /**
     * Compatibility status of this Pi version for the release: the weakest of
     * the distribution's deployment surface, the `governance` surface when it
     * declares governance, and the `lifecycle` surface.
     */
    readonly compatibility: string;
    /** Per-surface statuses behind `compatibility` (absent in older releases). */
    readonly surfaces?: Readonly<Record<string, string>>;
  };
  readonly manifestSchema: string;
  readonly lockSchema: string;
  readonly lockSha256: string;
  readonly target: string;
  readonly channel: string;
  /** RFC 3339; SOURCE_DATE_EPOCH when set, so rebuilds stay identical. */
  readonly created: string;
  readonly payload: {
    readonly path: "payload";
    readonly inventorySha256: string;
    readonly files: number;
  };
  readonly stateSchemas: StateSchemaSupport;
  readonly tests: readonly ReleaseTestResult[];
  readonly sbom: {
    readonly path: string;
    readonly sha256: string;
    readonly packages: number;
  };
  readonly notices: { readonly path: string; readonly index: string };
  readonly vulnerabilities: {
    readonly path: string;
    readonly failOn: string;
    readonly verdict: "passed";
    readonly counts: Readonly<Record<string, number>>;
  };
  /** Registry signature check of the payload packages (absent in older releases). */
  readonly signatures?: SignatureReport;
  readonly attribution: string;
}

/**
 * Result of `npm audit signatures` over the installed payload packages.
 * `passed`: no invalid signature or attestation (packages without a registry
 * signature are listed in `missing`). `unavailable`: the check could not run,
 * for example because the Sigstore trust root or the registry keys could not
 * be fetched; `reason` says why. Invalid signatures never produce a release.
 */
export interface SignatureReport {
  readonly tool: string;
  readonly verdict: "passed" | "unavailable";
  /** `name@version` of packages without a registry signature. */
  readonly missing: readonly string[];
  readonly reason?: string;
}

/** Runs the registry signature check in the payload directory. */
export type SignatureAuditor = (
  payloadDirectory: string,
) => Promise<CommandResult> | CommandResult;

export interface VulnerabilityFinding {
  readonly id: string;
  readonly package: string;
  readonly severity: string;
  readonly title: string;
  readonly url: string | null;
  /** `blocking`, `allowed` (reviewed exception), or `below-threshold`. */
  readonly status: "blocking" | "allowed" | "below-threshold";
}

export interface VulnerabilityReport {
  readonly schema: typeof VULNERABILITY_REPORT_SCHEMA;
  readonly scanner: string;
  readonly failOn: string;
  readonly verdict: "passed" | "failed";
  readonly counts: Readonly<Record<string, number>>;
  readonly findings: readonly VulnerabilityFinding[];
}

/** Returns npm-audit-v2-shaped JSON for the given npm lock directory. */
export type VulnerabilityScanner = (
  lockDirectory: string,
) => Promise<unknown> | unknown;

export interface CommandResult {
  readonly status: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

/** Runs a payload command (`version`, `--smoke`, ...) for the release tests. */
export type ReleaseTestRunner = (
  payload: string,
  command: string,
  args: readonly string[],
  env: NodeJS.ProcessEnv,
) => CommandResult;

export interface ReleaseOptions {
  /** Output root; the release lands in `<outputRoot>/releases/`. */
  readonly outputRoot?: string;
  readonly channel?: string;
  /** Build target; defaults to this machine. Cross-target builds are refused. */
  readonly target?: string;
  readonly scanner?: VulnerabilityScanner;
  /** Registry signature check (defaults to `npm audit signatures`). */
  readonly signatureAuditor?: SignatureAuditor;
  readonly runTest?: ReleaseTestRunner;
  /** Injectable clock for vulnerability exception expiry. */
  readonly now?: () => Date;
  /** Test seam: assembles the canonical payload (defaults to buildDistribution). */
  readonly assemble?: (manifestPath: string, outputRoot: string) => string;
}

export interface BuiltRelease {
  readonly name: string;
  readonly directory: string;
  readonly archive: string;
  readonly sha256: string;
  readonly metadata: ReleaseMetadata;
}

function hash(content: string | Buffer): string {
  return createHash("sha256").update(content).digest("hex");
}

function gate(
  code: ConstructorParameters<typeof PiShipError>[0],
  gateName: string,
  message: string,
  userAction?: string,
  stage: "Release" | "Build" = "Release",
): PiShipError {
  return new PiShipError(code, `${stage} gate ${gateName}: ${message}`, {
    component: stage === "Release" ? "release" : "build",
    sanitizedDetail: { gate: gateName },
    ...(userAction ? { userAction } : {}),
  });
}

/** The release name `<id>-<version>-<target>`. */
export function releaseName(lock: DistributionLock, target: string): string {
  return `${lock.app.id}-${lock.app.version}-${target}`;
}

function createdTime(): string {
  const epoch = Number(process.env.SOURCE_DATE_EPOCH);
  const seconds =
    process.env.SOURCE_DATE_EPOCH !== undefined &&
    Number.isSafeInteger(epoch) &&
    epoch >= 0
      ? epoch
      : 0;
  return new Date(seconds * 1000).toISOString().replace(".000Z", "Z");
}

const COMPATIBILITY_ORDER = ["unsupported", "candidate", "supported"];

/**
 * Status of each surface a release depends on: its deployment surface
 * (`personal` or `managed`), the `governance` surface when the distribution
 * declares governance (every piship/v1alpha3 or later manifest does), and
 * the `lifecycle` surface every release uses.
 */
export function piCompatibilitySurfaces(
  lock: Pick<DistributionLock, "deployment" | "runtime" | "governance">,
): Readonly<Record<string, string>> {
  const surface = lock.deployment.mode === "managed" ? "managed" : "personal";
  const known = PI_COMPATIBILITY[lock.runtime.version];
  return {
    [surface]: known?.[surface] ?? "unsupported",
    ...(lock.governance
      ? { governance: known?.governance ?? "unsupported" }
      : {}),
    lifecycle: known?.lifecycle ?? "unsupported",
  };
}

/**
 * The weakest status among the surfaces a release depends on
 * (unsupported < candidate < supported); an unknown status counts as
 * unsupported.
 */
export function piCompatibility(
  lock: Pick<DistributionLock, "deployment" | "runtime" | "governance">,
): string {
  const ranks = Object.values(piCompatibilitySurfaces(lock)).map((status) =>
    Math.max(0, COMPATIBILITY_ORDER.indexOf(status)),
  );
  return COMPATIBILITY_ORDER[Math.min(...ranks)] as string;
}

/** Enforced rules that contradict each other or a declared trust class. */
function policyConflicts(lock: DistributionLock): string[] {
  const governance = lock.governance?.manifest;
  if (!governance) return [];
  const conflicts: string[] = [];
  const { policy } = governance;
  const ids = new Map<string, string>();
  for (const [tier, rules] of [
    ["enforced", policy.enforced],
    ["defaults", policy.defaults],
  ] as const)
    for (const rule of rules) {
      const seen = ids.get(rule.id);
      if (seen)
        conflicts.push(
          `rule id ${rule.id} appears in both ${seen} and ${tier}`,
        );
      ids.set(rule.id, tier);
    }
  const enforced = new Map<string, string>();
  for (const rule of policy.enforced) {
    const key = `${rule.action} ${rule.resource}`;
    const effect = enforced.get(key);
    if (effect && effect !== rule.effect)
      conflicts.push(
        `enforced rules for ${key} disagree (${effect} and ${rule.effect})`,
      );
    enforced.set(key, rule.effect);
  }
  const resourceTrust = policy.resourceTrust as Record<string, string>;
  for (const item of governance.resources.declared)
    if (resourceTrust[item.class] === "deny")
      conflicts.push(
        `${item.kind} ${item.path} is declared ${item.class}, which policy.resourceTrust denies`,
      );
  const providerTrust = policy.providerTrust as Record<string, string>;
  for (const capability of governance.capabilities)
    if (
      capability.enabled &&
      capability.provider &&
      providerTrust[capability.provider.class] === "deny"
    )
      conflicts.push(
        `capability ${capability.name} is enabled with a ${capability.provider.class} provider, which policy.providerTrust denies`,
      );
  return conflicts;
}

/**
 * The `source` and `install-script` gates over the locked npm closure: every
 * package has sha512 integrity and a source in `release.sources`, and every
 * npm lifecycle script was reviewed for this PiShip version. `piship release`
 * and `piship build` both run them; only piship/v1alpha4 locks record
 * sources and install scripts.
 */
export function checkPackageSources(
  lock: DistributionLock,
  stage: "Release" | "Build" = "Release",
): void {
  const release = lock.release;
  if (!release) return;
  for (const item of lock.runtime.packages) {
    // The lock keeps every registry entry, so one the npm lock records
    // without integrity is refused here instead of going unchecked.
    if (!item.integrity)
      throw gate(
        "INTEGRITY_FAILED",
        "source",
        `${item.path}@${item.version} is missing integrity in the npm lock`,
        "Record the registry dist.integrity for this package in package-lock.json and lock again",
        stage,
      );
    if (!item.resolved)
      throw gate(
        "INTEGRITY_FAILED",
        "source",
        `${item.path}@${item.version} has no recorded source`,
        undefined,
        stage,
      );
    let origin: string;
    try {
      origin = new URL(item.resolved).origin;
    } catch {
      throw gate(
        "INTEGRITY_FAILED",
        "source",
        `${item.path}@${item.version} has an unparsable source`,
        undefined,
        stage,
      );
    }
    if (!release.sources.includes(origin))
      throw gate(
        "POLICY_DENIED",
        "source",
        `${item.path}@${item.version} comes from ${origin}, which is not in release.sources (${release.sources.join(", ")})`,
        undefined,
        stage,
      );
    if (!/^sha512-[A-Za-z0-9+/]+=*$/.test(item.integrity))
      throw gate(
        "INTEGRITY_FAILED",
        "source",
        `${item.path}@${item.version} has no sha512 integrity`,
        undefined,
        stage,
      );
    if (
      item.installScript &&
      !REVIEWED_INSTALL_SCRIPTS.includes(`${item.path}@${item.version}`)
    )
      throw gate(
        "POLICY_DENIED",
        "install-script",
        `${item.path}@${item.version} runs npm lifecycle scripts that were not reviewed for this PiShip version`,
        undefined,
        stage,
      );
  }
}

/**
 * Static release gates, checked before anything is assembled. Each failure
 * names its gate: lock, schema, target, pi, source, install-script,
 * policy, certification, or sandbox.
 */
export function checkReleaseInputs(
  manifestPath: string,
  target = currentTarget(),
): DistributionLock {
  let lock: DistributionLock;
  try {
    lock = requireCurrentLock(manifestPath);
  } catch (error) {
    if (error instanceof PiShipError) throw error;
    throw gate(
      "LOCK_INVALID",
      "lock",
      (error as Error).message,
      "Review the manifest and resource changes, then run piship lock",
    );
  }
  if (lock.schema !== LOCK_SCHEMA_V1ALPHA4 || !lock.release || !lock.updates)
    throw gate(
      "CONFIG_INVALID",
      "schema",
      `production releases need a piship/v1alpha4 manifest (found ${lock.manifest.schema})`,
      "Run piship migrate --write, review the updates section, and lock again",
    );
  const release: ReleaseManifest = lock.release;
  if (!release.targets.includes(target as never))
    throw gate(
      "CONFIG_INVALID",
      "target",
      `${target} is not in release.targets (${release.targets.join(", ")})`,
    );
  if (!EVIDENCED_TARGETS.includes(target))
    throw gate(
      "CONFIG_INVALID",
      "target",
      `${target} has no installed lifecycle evidence in this PiShip version (supported: ${EVIDENCED_TARGETS.join(", ")})`,
    );
  if (target !== currentTarget())
    throw gate(
      "CONFIG_INVALID",
      "target",
      `releases are built on their target; this machine is ${currentTarget()}`,
    );
  if (piCompatibility(lock) === "unsupported")
    throw gate(
      "CONFIG_INVALID",
      "pi",
      `Pi ${lock.runtime.version} is not in this PiShip build's compatibility matrix`,
    );
  checkPackageSources(lock);
  const conflicts = policyConflicts(lock);
  if (conflicts.length)
    throw gate("POLICY_DENIED", "policy", conflicts.join("; "));
  for (const provider of lock.governance?.providers ?? [])
    if (provider.class === "certified" && !provider.certified)
      throw gate(
        "POLICY_DENIED",
        "certification",
        `capability ${provider.capability} uses certified provider ${provider.id} without certification evidence`,
      );
  for (const item of lock.governance?.manifest.resources.declared ?? [])
    if (item.class === "certified" && !item.certified)
      throw gate(
        "POLICY_DENIED",
        "certification",
        `${item.kind} ${item.path} is certified without certification evidence`,
      );
  if (
    lock.governance?.manifest.sandbox.required &&
    !["linux", "darwin"].includes(target.split("-")[0] ?? "")
  )
    throw gate(
      "SANDBOX_UNAVAILABLE",
      "sandbox",
      `the distribution requires an OS sandbox and PiShip has no sandbox adapter for ${target}`,
      "Remove the target from release.targets or make the sandbox optional after a security review",
    );
  return lock;
}

/** Default test runner: runs the payload's launcher with Node. */
export function runPayloadCommand(
  payload: string,
  command: string,
  args: readonly string[],
  env: NodeJS.ProcessEnv,
): CommandResult {
  const result = spawnSync(
    process.execPath,
    [join(payload, "bin", command), ...args],
    { encoding: "utf8", env, cwd: payload, timeout: 300_000 },
  );
  return {
    status: result.status,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? result.error?.message ?? "",
  };
}

/**
 * Required release tests on the assembled payload, with a throwaway state
 * directory: launch and version (integrity, target, Node, pinned Pi); the
 * offline smoke session when the distribution needs no sign-in; and the
 * governance inspection when governed.
 */
function runReleaseTests(
  payload: string,
  lock: DistributionLock,
  runTest: ReleaseTestRunner,
): ReleaseTestResult[] {
  const state = mkdtempSync(join(tmpdir(), "piship-release-test-"));
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    PISHIP_STATE_HOME: state,
    PISHIP_NO_BROWSER: "1",
  };
  delete env.PISHIP_BUILD_INPUT;
  const tests: [string, string[], (out: string) => boolean][] = [
    [
      "launch-version",
      ["version"],
      (out) =>
        out.includes(`${lock.app.name} ${lock.app.version}`) &&
        out.includes(`Pi ${lock.runtime.version}`),
    ],
  ];
  const needsSignIn =
    !!lock.access &&
    (lock.access.identity.mode !== "none" ||
      !["pi-native", "none"].includes(lock.access.credential.provider));
  if (!needsSignIn)
    tests.push([
      "offline-smoke",
      ["--smoke"],
      (out) => out.includes('"initialized":true'),
    ]);
  if (lock.governance)
    tests.push([
      "governance-inspection",
      ["capabilities", "--json"],
      (out) => out.trim().startsWith("["),
    ]);
  try {
    return tests.map(([name, args, accept]) => {
      const result = runTest(payload, lock.app.command, args, env);
      if (result.status !== 0 || !accept(result.stdout))
        throw gate(
          "UPDATE_FAILED",
          "test",
          `required test ${name} failed: ${(result.stderr || result.stdout).trim().slice(0, 500)}`,
        );
      return { name, result: "passed" as const };
    });
  } finally {
    rmSync(state, { recursive: true, force: true });
  }
}

/** `npm audit` over the payload npm lock (registry access required). */
export function npmAuditScanner(lockDirectory: string): unknown {
  const args = ["audit", "--omit=dev", "--json"];
  const result =
    process.platform === "win32"
      ? spawnSync("cmd.exe", ["/d", "/s", "/c", `npm ${args.join(" ")}`], {
          cwd: lockDirectory,
          encoding: "utf8",
          maxBuffer: 64 * 1024 * 1024,
        })
      : spawnSync("npm", args, {
          cwd: lockDirectory,
          encoding: "utf8",
          maxBuffer: 64 * 1024 * 1024,
        });
  try {
    return JSON.parse(result.stdout);
  } catch {
    throw gate(
      "UPDATE_FAILED",
      "vulnerability",
      `the dependency scan did not run: ${(result.stderr || result.error?.message || "no output").trim().slice(0, 300)}`,
      "Restore registry access for the build; releases are not produced without a scan",
    );
  }
}

const SIGNATURE_TOOL = "npm audit signatures --omit=dev";

/**
 * `npm audit signatures` over the installed payload. It reads the payload's
 * `node_modules` and needs the registry and the Sigstore trust root.
 */
export function npmSignatureAuditor(payloadDirectory: string): CommandResult {
  const args = ["audit", "signatures", "--omit=dev", "--json"];
  const options = {
    cwd: payloadDirectory,
    encoding: "utf8" as const,
    maxBuffer: 64 * 1024 * 1024,
    timeout: 300_000,
  };
  const result =
    process.platform === "win32"
      ? spawnSync(
          "cmd.exe",
          ["/d", "/s", "/c", `npm ${args.join(" ")}`],
          options,
        )
      : spawnSync("npm", args, options);
  return {
    status: result.status,
    stdout: result.stdout ?? "",
    stderr: result.stderr || result.error?.message || "",
  };
}

interface SignatureEntry {
  readonly name: string;
  readonly version: string;
  readonly code: string;
}

function signatureEntries(value: unknown): SignatureEntry[] | null {
  if (!Array.isArray(value)) return null;
  const entries: SignatureEntry[] = [];
  for (const item of value) {
    if (!item || typeof item !== "object") return null;
    const entry = item as { name?: unknown; version?: unknown; code?: unknown };
    if (typeof entry.name !== "string") return null;
    entries.push({
      name: entry.name,
      version: typeof entry.version === "string" ? entry.version : "",
      code: typeof entry.code === "string" ? entry.code : "",
    });
  }
  return entries;
}

/**
 * Apply the release signature policy to `npm audit signatures --json`
 * output. An invalid registry signature or attestation fails the build. A
 * missing signature is recorded. When npm reports that the check itself
 * could not run, the release records `unavailable` with npm's reason.
 * Output that is neither a report nor an npm error fails closed.
 */
export function evaluateSignatures(result: CommandResult): SignatureReport {
  let parsed: unknown;
  try {
    parsed = JSON.parse(result.stdout);
  } catch {
    parsed = undefined;
  }
  const value = (parsed && typeof parsed === "object" ? parsed : {}) as {
    invalid?: unknown;
    missing?: unknown;
    error?: { summary?: unknown };
  };
  const invalid = signatureEntries(value.invalid);
  const missing = signatureEntries(value.missing);
  if (invalid && missing) {
    if (invalid.length)
      throw gate(
        "INTEGRITY_FAILED",
        "signature",
        `invalid registry signatures or attestations: ${invalid
          .map(
            (item) =>
              `${item.name}@${item.version}${item.code ? ` (${item.code})` : ""}`,
          )
          .join(", ")}`,
        "Do not release this payload; reinstall the dependency from the trusted registry and investigate its source",
      );
    return {
      tool: SIGNATURE_TOOL,
      verdict: "passed",
      missing: missing.map((item) => `${item.name}@${item.version}`).sort(),
    };
  }
  const summary = value.error?.summary;
  if (typeof summary === "string" && summary.trim())
    return {
      tool: SIGNATURE_TOOL,
      verdict: "unavailable",
      missing: [],
      reason: summary.trim().replace(/\s+/g, " ").slice(0, 300),
    };
  throw gate(
    "UPDATE_FAILED",
    "signature",
    `the registry signature check returned no report: ${(result.stderr || result.stdout || "no output").trim().slice(0, 300)}`,
    "Restore npm and registry access for the build; releases are not produced from an unreadable signature check",
  );
}

/** Apply the release vulnerability policy to npm-audit-v2-shaped JSON. */
export function evaluateVulnerabilities(
  audit: unknown,
  policy: ReleaseManifest["vulnerabilities"],
  now: Date,
): VulnerabilityReport {
  const value = audit as {
    auditReportVersion?: unknown;
    vulnerabilities?: Record<
      string,
      { severity?: string; via?: readonly unknown[] }
    >;
    error?: unknown;
  };
  if (
    !value ||
    typeof value !== "object" ||
    value.auditReportVersion !== 2 ||
    !value.vulnerabilities ||
    typeof value.vulnerabilities !== "object" ||
    Array.isArray(value.vulnerabilities)
  )
    throw gate(
      "UPDATE_FAILED",
      "vulnerability",
      "the dependency scan returned no npm audit v2 report",
    );
  const threshold = SEVERITY_ORDER.indexOf(policy.failOn);
  const today = now.toISOString().slice(0, 10);
  const allowed = new Map(
    policy.allow
      .filter((entry) => entry.expires >= today)
      .map((entry) => [entry.id, entry]),
  );
  const findings = new Map<string, VulnerabilityFinding>();
  for (const [name, entry] of Object.entries(value.vulnerabilities))
    for (const via of entry.via ?? []) {
      if (!via || typeof via !== "object") continue;
      const advisory = via as {
        source?: unknown;
        url?: unknown;
        title?: unknown;
        severity?: unknown;
      };
      const url = typeof advisory.url === "string" ? advisory.url : null;
      const id =
        url?.match(/GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}/i)?.[0] ??
        `npm-${String(advisory.source ?? "unknown")}`;
      const severity =
        typeof advisory.severity === "string"
          ? advisory.severity
          : (entry.severity ?? "info");
      // An unrecognised severity cannot be ranked, so it never passes as low.
      const rank = SEVERITY_ORDER.indexOf(severity);
      const status =
        rank !== -1 && rank < threshold
          ? "below-threshold"
          : allowed.has(id)
            ? "allowed"
            : "blocking";
      findings.set(`${id} ${name}`, {
        id,
        package: name,
        severity,
        title: typeof advisory.title === "string" ? advisory.title : "",
        url,
        status,
      });
    }
  const sorted = [...findings.values()].sort((a, b) =>
    `${a.id} ${a.package}`.localeCompare(`${b.id} ${b.package}`),
  );
  const counts: Record<string, number> = {};
  for (const severity of SEVERITY_ORDER) counts[severity] = 0;
  for (const finding of sorted)
    counts[finding.severity] = (counts[finding.severity] ?? 0) + 1;
  return {
    schema: VULNERABILITY_REPORT_SCHEMA,
    scanner: "npm audit --omit=dev",
    failOn: policy.failOn,
    verdict: sorted.some((finding) => finding.status === "blocking")
      ? "failed"
      : "passed",
    counts,
    findings: sorted,
  };
}

function installScripts(name: string): { sh: string; ps1: string } {
  return {
    sh: `#!/bin/sh
# Verifies this release, then installs its payload for the current user.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
command -v node >/dev/null 2>&1 || { echo 'Node.js 22.19.0 or newer is required. Install Node separately.' >&2; exit 1; }
node "$here/payload/piship.mjs" verify-release "$here"
node "$here/payload/piship.mjs" install "$here" "$@"
`,
    ps1: `# Verifies this release, then installs its payload for the current user.
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not (Get-Command node -ErrorAction SilentlyContinue)) { Write-Error 'Node.js 22.19.0 or newer is required. Install Node separately.'; exit 1 }
node "$here\\payload\\piship.mjs" verify-release "$here"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
node "$here\\payload\\piship.mjs" install "$here" @args
exit $LASTEXITCODE
# Release ${name}
`,
  };
}

function writeJson(path: string, value: unknown): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

/**
 * Build a verified release: static gates, the canonical payload, required
 * tests, dependency scan, registry signature check, SBOM, notices,
 * metadata, checksums, and a deterministic archive. Any failure removes
 * the partial output.
 */
export async function buildRelease(
  manifestPath: string,
  options: ReleaseOptions = {},
): Promise<BuiltRelease> {
  const target = options.target ?? currentTarget();
  const lock = checkReleaseInputs(manifestPath, target);
  const updates = lock.updates as UpdatesManifest;
  const channel = options.channel ?? updates.channel;
  if (!(RELEASE_CHANNELS as readonly string[]).includes(channel))
    throw gate("CONFIG_INVALID", "channel", `unknown channel ${channel}`);
  const outputRoot = resolve(options.outputRoot ?? "dist", "releases");
  const name = releaseName(lock, target);
  const directory = join(outputRoot, name);
  const archive = join(outputRoot, `${name}.tar.gz`);
  mkdirSync(outputRoot, { recursive: true });
  const stage = mkdtempSync(join(outputRoot, `.${name}-`));
  try {
    const built = (options.assemble ?? buildDistribution)(
      manifestPath,
      join(stage, "build"),
    );
    const payload = join(stage, "release", "payload");
    mkdirSync(dirname(payload), { recursive: true });
    renameSync(built, payload);
    const root = dirname(payload);
    const tests = runReleaseTests(
      payload,
      lock,
      options.runTest ?? runPayloadCommand,
    );
    const lockDirectory = join(stage, "audit");
    mkdirSync(lockDirectory);
    copyFileSync(
      join(payload, "package-lock.json"),
      join(lockDirectory, "package-lock.json"),
    );
    const buildInputPackage = join(
      payload,
      "node_modules",
      "@piship",
      "core",
      "dist",
      "build-input",
      "package.json",
    );
    if (existsSync(buildInputPackage))
      copyFileSync(buildInputPackage, join(lockDirectory, "package.json"));
    const release = lock.release as ReleaseManifest;
    const report = evaluateVulnerabilities(
      await (options.scanner ?? npmAuditScanner)(lockDirectory),
      release.vulnerabilities,
      (options.now ?? (() => new Date()))(),
    );
    writeJson(join(root, "vulnerabilities.json"), report);
    if (report.verdict !== "passed")
      throw gate(
        "POLICY_DENIED",
        "vulnerability",
        `blocking advisories at or above ${release.vulnerabilities.failOn}: ${report.findings
          .filter((item) => item.status === "blocking")
          .map((item) => `${item.id} (${item.package}, ${item.severity})`)
          .join(", ")}`,
        "Update the dependency, or record a reviewed exception with an expiry in release.vulnerabilities.allow",
      );
    const signatures = evaluateSignatures(
      await (options.signatureAuditor ?? npmSignatureAuditor)(payload),
    );
    const created = createdTime();
    const packages = listPayloadPackages(payload);
    const sbom = generateSbom({
      payloadDir: payload,
      distribution: lock.app,
      target,
      created,
      lockPackages: lock.runtime.packages,
    });
    verifySbom(payload, sbom);
    writeJson(join(root, "sbom.spdx.json"), sbom);
    const notices = generateNotices(payload, packages);
    mkdirSync(join(root, "licenses"), { recursive: true });
    writeFileSync(
      join(root, "licenses", "THIRD_PARTY_NOTICES.txt"),
      notices.text,
    );
    writeJson(join(root, "licenses", "index.json"), notices.index);
    const scripts = installScripts(name);
    writeFileSync(join(root, "install.sh"), scripts.sh);
    if (process.platform !== "win32")
      chmodSync(join(root, "install.sh"), 0o755);
    writeFileSync(join(root, "install.ps1"), scripts.ps1);
    const inventory = readFileSync(join(payload, "metadata", "inventory.json"));
    const metadata: ReleaseMetadata = {
      schema: RELEASE_SCHEMA,
      distribution: {
        id: lock.app.id,
        name: lock.app.name,
        version: lock.app.version,
        command: lock.app.command,
        mode: lock.deployment.mode,
      },
      piship: { version: lock.runtime.pishipVersion },
      pi: {
        package: lock.runtime.package,
        version: lock.runtime.version,
        compatibility: piCompatibility(lock),
        surfaces: piCompatibilitySurfaces(lock),
      },
      manifestSchema: lock.manifest.schema,
      lockSchema: lock.schema,
      lockSha256: hash(readFileSync(join(payload, "piship.lock"))),
      target,
      channel,
      created,
      payload: {
        path: "payload",
        inventorySha256: hash(inventory),
        files: Object.keys(JSON.parse(inventory.toString())).length + 1,
      },
      stateSchemas: lock.runtime.stateSchemas ?? STATE_SCHEMAS,
      tests,
      sbom: {
        path: "sbom.spdx.json",
        sha256: hash(readFileSync(join(root, "sbom.spdx.json"))),
        packages: packages.length,
      },
      notices: {
        path: "licenses/THIRD_PARTY_NOTICES.txt",
        index: "licenses/index.json",
      },
      vulnerabilities: {
        path: "vulnerabilities.json",
        failOn: report.failOn,
        verdict: "passed",
        counts: report.counts,
      },
      signatures,
      attribution: `${lock.app.name} ${lock.app.version}, built with PiShip ${lock.runtime.pishipVersion} on Pi ${lock.runtime.version} by Earendil Works`,
    };
    writeJson(join(root, "release.json"), metadata);
    writeFileSync(
      join(root, "checksums.txt"),
      formatChecksums(root, [...RELEASE_FILES]),
    );
    const stagedArchive = join(stage, `${name}.tar.gz`);
    const result = await createArchive(root, name, stagedArchive, {
      executable: (path) =>
        path === "install.sh" ||
        (path.startsWith("payload/bin/") && !path.endsWith(".cmd")),
    });
    rmSync(directory, { recursive: true, force: true });
    rmSync(archive, { force: true });
    renameSync(root, directory);
    renameSync(stagedArchive, archive);
    writeFileSync(`${archive}.sha256`, `${result.sha256}  ${name}.tar.gz\n`);
    return { name, directory, archive, sha256: result.sha256, metadata };
  } finally {
    rmSync(stage, { recursive: true, force: true });
  }
}

export interface VerifiedRelease {
  readonly directory: string;
  readonly payload: string;
  readonly metadata: ReleaseMetadata;
  readonly lock: DistributionLock;
  readonly sbom: SpdxDocument;
  /** Removes the extraction directory when the input was an archive. */
  readonly cleanup: () => void;
}

function fail(message: string): PiShipError {
  return new PiShipError(
    "INTEGRITY_FAILED",
    `Release verification: ${message}`,
    {
      component: "release",
      userAction:
        "Do not install this artifact; obtain it again from the trusted source",
    },
  );
}

/**
 * Consumer verification of a release directory or archive: archive checksum
 * sidecar, release checksums, every payload file against its inventory, the
 * lock and manifest, metadata consistency, SBOM completeness, notices, and
 * the vulnerability verdict. With `requireTarget`, the payload must match
 * this machine.
 */
export async function verifyRelease(
  input: string,
  options: {
    readonly requireTarget?: boolean;
    readonly expectedSha256?: string;
    readonly extractTo?: string;
  } = {},
): Promise<VerifiedRelease> {
  const path = resolve(input);
  let directory = path;
  let cleanup = () => {};
  if (statSync(path).isFile()) {
    const actual = await sha256File(path);
    if (options.expectedSha256 && actual !== options.expectedSha256)
      throw fail(
        `archive SHA-256 ${actual} does not match the expected ${options.expectedSha256}`,
      );
    const sidecar = `${path}.sha256`;
    if (existsSync(sidecar)) {
      const recorded = readFileSync(sidecar, "utf8").split(/\s+/)[0];
      if (recorded !== actual)
        throw fail(
          `archive SHA-256 ${actual} does not match ${basename(sidecar)}`,
        );
    }
    const parent =
      options.extractTo ?? mkdtempSync(join(tmpdir(), "piship-verify-"));
    const expectedRoot = basename(path).replace(/\.tar\.gz$/, "");
    const extracted = await extractArchive(path, join(parent, "x"), {
      expectedRoot,
    }).catch((error: Error) => {
      if (!options.extractTo) rmSync(parent, { recursive: true, force: true });
      throw fail(error.message);
    });
    directory = join(parent, "x", extracted.root);
    cleanup = () => rmSync(parent, { recursive: true, force: true });
  }
  try {
    const verified = verifyReleaseDirectory(directory, options.requireTarget);
    return { ...verified, cleanup };
  } catch (error) {
    cleanup();
    throw error;
  }
}

function verifyReleaseDirectory(
  directory: string,
  requireTarget = false,
): Omit<VerifiedRelease, "cleanup"> {
  try {
    return checkReleaseDirectory(directory, requireTarget);
  } catch (error) {
    // Malformed metadata is an integrity failure, not a crash.
    if (error instanceof PiShipError) throw error;
    throw fail(`malformed release metadata: ${(error as Error).message}`);
  }
}

function checkReleaseDirectory(
  directory: string,
  requireTarget: boolean,
): Omit<VerifiedRelease, "cleanup"> {
  const checksums = join(directory, "checksums.txt");
  if (!existsSync(checksums)) throw fail("checksums.txt is missing");
  try {
    verifyChecksums(directory, readFileSync(checksums, "utf8"), {
      required: RELEASE_FILES,
    });
  } catch (error) {
    throw fail((error as Error).message);
  }
  const metadata = JSON.parse(
    readFileSync(join(directory, "release.json"), "utf8"),
  ) as ReleaseMetadata;
  if (metadata.schema !== RELEASE_SCHEMA)
    throw fail(`unsupported release metadata ${String(metadata.schema)}`);
  const payload = join(directory, "payload");
  let lock: DistributionLock;
  try {
    lock = verifyPayloadContents(payload, { requireTarget });
  } catch (error) {
    throw fail((error as Error).message);
  }
  const inventory = readFileSync(join(payload, "metadata", "inventory.json"));
  const target = JSON.parse(
    readFileSync(join(payload, "metadata", "target.json"), "utf8"),
  ) as { platform: string; arch: string };
  const mismatches = [
    [metadata.distribution.id, lock.app.id, "distribution id"],
    [metadata.distribution.version, lock.app.version, "distribution version"],
    [metadata.distribution.command, lock.app.command, "command"],
    [metadata.pi.version, lock.runtime.version, "Pi version"],
    [metadata.piship.version, lock.runtime.pishipVersion, "PiShip version"],
    [metadata.lockSchema, lock.schema, "lock schema"],
    [
      metadata.lockSha256,
      hash(readFileSync(join(payload, "piship.lock"))),
      "lock digest",
    ],
    [metadata.payload.inventorySha256, hash(inventory), "payload inventory"],
    [metadata.target, `${target.platform}-${target.arch}`, "target"],
  ].filter(([a, b]) => a !== b);
  if (mismatches.length)
    throw fail(
      `release.json does not match the payload: ${mismatches.map((item) => item[2]).join(", ")}`,
    );
  const sbom = JSON.parse(
    readFileSync(join(directory, "sbom.spdx.json"), "utf8"),
  ) as SpdxDocument;
  try {
    verifySbom(payload, sbom);
    verifyNotices(
      sbom,
      JSON.parse(
        readFileSync(join(directory, "licenses", "index.json"), "utf8"),
      ),
    );
  } catch (error) {
    throw fail((error as Error).message);
  }
  const report = JSON.parse(
    readFileSync(join(directory, "vulnerabilities.json"), "utf8"),
  ) as VulnerabilityReport;
  if (
    report.schema !== VULNERABILITY_REPORT_SCHEMA ||
    report.verdict !== "passed"
  )
    throw fail("the recorded vulnerability scan did not pass");
  if (
    metadata.signatures !== undefined &&
    metadata.signatures?.verdict !== "passed" &&
    metadata.signatures?.verdict !== "unavailable"
  )
    throw fail("the recorded registry signature check did not pass");
  if (
    !metadata.tests.length ||
    metadata.tests.some((t) => t.result !== "passed")
  )
    throw fail("required release tests are not recorded as passed");
  return { directory, payload, metadata, lock, sbom };
}

/** Supported state schemas of a payload's PiShip version. */
export function payloadStateSchemas(
  lock: DistributionLock,
): StateSchemaSupport {
  return lock.runtime.stateSchemas ?? LEGACY_STATE_SCHEMAS;
}

// ------------------------------------------------------------------ channels

export interface ChannelRelease {
  readonly version: string;
  readonly target: string;
  /** Archive file name next to the channel metadata. */
  readonly archive: string;
  readonly sha256: string;
  readonly bytes: number;
  readonly pi: string;
  readonly piship: string;
  readonly lockSha256: string;
}

export interface ChannelMetadata {
  readonly schema: typeof CHANNEL_SCHEMA;
  readonly distribution: string;
  readonly channel: string;
  /** Monotonic; a client never accepts a lower sequence than it has seen. */
  readonly sequence: number;
  readonly expires: string;
  readonly releases: readonly ChannelRelease[];
}

export interface SignChannelOptions {
  readonly directory: string;
  readonly channel: string;
  readonly archives: readonly string[];
  readonly privateKeyPem: string;
  readonly keyId: string;
  readonly sequence?: number;
  readonly expiresDays?: number;
  readonly now?: () => Date;
}

/**
 * Add verified release archives to a channel directory and sign its
 * metadata. Existing entries for other versions or targets are kept.
 */
export async function signChannel(
  options: SignChannelOptions,
): Promise<{ readonly path: string; readonly metadata: ChannelMetadata }> {
  if (!(RELEASE_CHANNELS as readonly string[]).includes(options.channel))
    throw new PiShipError(
      "CONFIG_INVALID",
      `Unknown channel ${options.channel}`,
    );
  const directory = resolve(options.directory);
  mkdirSync(directory, { recursive: true });
  const path = join(directory, `${options.channel}.json`);
  const previous = existsSync(path)
    ? (JSON.parse(readFileSync(path, "utf8")) as ChannelMetadata)
    : undefined;
  const entries = new Map(
    (previous?.releases ?? []).map((item) => [
      `${item.version} ${item.target}`,
      item,
    ]),
  );
  let distribution = previous?.distribution;
  for (const archive of options.archives) {
    const verified = await verifyRelease(archive);
    try {
      const { metadata } = verified;
      if (distribution && distribution !== metadata.distribution.id)
        throw new PiShipError(
          "CONFIG_INVALID",
          `Channel ${options.channel} belongs to ${distribution}, not ${metadata.distribution.id}`,
        );
      distribution = metadata.distribution.id;
      const name = basename(archive);
      const destination = join(directory, name);
      if (resolve(archive) !== destination) copyFileSync(archive, destination);
      entries.set(`${metadata.distribution.version} ${metadata.target}`, {
        version: metadata.distribution.version,
        target: metadata.target,
        archive: name,
        sha256: await sha256File(destination),
        bytes: statSync(destination).size,
        pi: metadata.pi.version,
        piship: metadata.piship.version,
        lockSha256: metadata.lockSha256,
      });
    } finally {
      verified.cleanup();
    }
  }
  if (!distribution)
    throw new PiShipError("CONFIG_INVALID", "No release archives were given");
  const now = (options.now ?? (() => new Date()))();
  const metadata: ChannelMetadata = {
    schema: CHANNEL_SCHEMA,
    distribution,
    channel: options.channel,
    sequence: options.sequence ?? (previous?.sequence ?? 0) + 1,
    expires: new Date(
      now.getTime() + (options.expiresDays ?? 30) * 86_400_000,
    ).toISOString(),
    releases: [...entries.values()].sort((a, b) =>
      `${a.target} ${a.version}`.localeCompare(`${b.target} ${b.version}`),
    ),
  };
  if (previous && metadata.sequence <= previous.sequence)
    throw new PiShipError(
      "CONFIG_INVALID",
      `Channel sequence must increase (current ${previous.sequence})`,
    );
  const bytes = Buffer.from(`${JSON.stringify(metadata, null, 2)}\n`);
  writeFileSync(path, bytes);
  writeJson(
    `${path}.sig`,
    signBytes(bytes, options.privateKeyPem, options.keyId),
  );
  return { path, metadata };
}

/** Channel metadata and signatures are small; anything larger is refused. */
const MAX_METADATA_BYTES = 1024 * 1024;
const METADATA_TIMEOUT_MS = 30_000;
const ARCHIVE_TIMEOUT_MS = 30 * 60_000;

function tooLarge(name: string, limit: number): PiShipError {
  return new PiShipError(
    "INTEGRITY_FAILED",
    `${name} from the update source exceeds ${limit} bytes`,
    {
      userAction:
        "Do not install it; report the update source to the distribution owner",
    },
  );
}

/** Stream a response body into `destination`, stopping past `limit` bytes. */
async function saveBody(
  response: Response,
  destination: string,
  name: string,
  limit: number,
): Promise<void> {
  const { Readable, Transform } = await import("node:stream");
  const { pipeline } = await import("node:stream/promises");
  const { createWriteStream } = await import("node:fs");
  let received = 0;
  try {
    await pipeline(
      Readable.fromWeb(response.body as never),
      new Transform({
        transform(chunk: Buffer, _encoding, callback) {
          received += chunk.length;
          callback(received > limit ? tooLarge(name, limit) : null, chunk);
        },
      }),
      createWriteStream(destination, { flags: "wx" }),
    );
  } catch (error) {
    if (["TimeoutError", "AbortError"].includes((error as Error).name))
      throw new PiShipError(
        "UPDATE_FAILED",
        `Update source stopped sending ${name} before the deadline`,
        { retryable: true },
      );
    throw error;
  }
}

async function fetchSource(
  url: URL,
  name: string,
  fetcher: typeof fetch,
  timeout: number,
): Promise<Response> {
  checkSourceUrl(url);
  let response: Response;
  try {
    response = await fetcher(url, {
      redirect: "error",
      signal: AbortSignal.timeout(timeout),
    });
  } catch (error) {
    if ((error as Error).name === "TimeoutError")
      throw new PiShipError(
        "UPDATE_FAILED",
        `Update source did not answer for ${name} within ${timeout / 1000} s`,
        { retryable: true },
      );
    throw error;
  }
  if (!response.ok || !response.body)
    throw new PiShipError(
      "UPDATE_FAILED",
      `Update source returned HTTP ${response.status} for ${name}`,
      { retryable: response.status >= 500 },
    );
  return response;
}

/** Reads a small file from a directory or an https (or loopback http) source. */
export async function readSourceFile(
  source: string,
  name: string,
  fetcher: typeof fetch = fetch,
): Promise<Buffer> {
  if (isUrlSource(source)) {
    const url = new URL(name, source.endsWith("/") ? source : `${source}/`);
    const response = await fetchSource(url, name, fetcher, METADATA_TIMEOUT_MS);
    const declared = Number(response.headers.get("content-length"));
    if (declared > MAX_METADATA_BYTES) throw tooLarge(name, MAX_METADATA_BYTES);
    const chunks: Buffer[] = [];
    let received = 0;
    for await (const chunk of response.body as unknown as AsyncIterable<Uint8Array>) {
      received += chunk.length;
      if (received > MAX_METADATA_BYTES)
        throw tooLarge(name, MAX_METADATA_BYTES);
      chunks.push(Buffer.from(chunk));
    }
    return Buffer.concat(chunks);
  }
  const path = join(resolve(source), name);
  if (!existsSync(path))
    throw new PiShipError("UPDATE_FAILED", `Update source has no ${name}`);
  if (statSync(path).size > MAX_METADATA_BYTES)
    throw tooLarge(name, MAX_METADATA_BYTES);
  return readFileSync(path);
}

/**
 * A source written as `scheme:` (other than a Windows drive letter) is a URL;
 * anything else is a local directory path. A drive-relative Windows path such
 * as `C:foo` (no separator after the colon) matches the scheme pattern, so it
 * is treated as a URL and refused rather than resolved against the current
 * directory of drive C; write `C:\foo` or `C:/foo` instead.
 */
function isUrlSource(source: string): boolean {
  return (
    /^[a-z][a-z0-9+.-]*:/i.test(source) && !/^[a-z]:([\\/]|$)/i.test(source)
  );
}

/**
 * Validate an update source after `${NAME}` resolution or from `--from`, with
 * the same URL rules as the manifest: https, or http to a loopback host, with
 * no credentials, query string, or fragment. Any other value is a local
 * directory; one resolved from `updates.source` must be absolute, while a
 * `--from` directory may be relative to the working directory. Returns the
 * URL unchanged or the absolute directory path.
 */
export function checkUpdateSource(
  source: string,
  origin: "updates.source" | "--from",
): string {
  if (isUrlSource(source)) {
    let url: URL;
    try {
      url = new URL(source);
    } catch {
      throw new PiShipError(
        "CONFIG_INVALID",
        `${origin} is not a valid URL: ${redact(source)}`,
      );
    }
    checkSourceUrl(url);
    if (url.search || url.hash)
      throw new PiShipError(
        "CONFIG_INVALID",
        `${origin} may not contain a query string or fragment`,
      );
    return source;
  }
  if (origin === "updates.source" && !isAbsolute(source))
    throw new PiShipError(
      "CONFIG_INVALID",
      `updates.source resolved to ${redact(source)}, which is neither an https URL, an http URL on 127.0.0.1, localhost, or [::1], nor an absolute local directory`,
    );
  const directory = resolve(source);
  if (!existsSync(directory) || !statSync(directory).isDirectory())
    throw new PiShipError(
      "UPDATE_FAILED",
      `Update source directory ${directory} does not exist`,
    );
  return directory;
}

/** Only https, or http to a loopback host, may serve updates. */
export function checkSourceUrl(url: URL): void {
  const loopback = ["127.0.0.1", "localhost", "[::1]"].includes(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback))
    throw new PiShipError(
      "NETWORK_DENIED",
      `Update sources must use https (got ${url.protocol}//${url.host})`,
    );
  if (url.username || url.password)
    throw new PiShipError(
      "CONFIG_INVALID",
      "Update source URLs may not carry credentials",
    );
}

/**
 * Fetch and verify signed channel metadata: a trusted key, the expected
 * distribution and channel, not expired, and no older than `minSequence`.
 */
export async function readChannel(
  source: string,
  channel: string,
  options: {
    readonly distribution: string;
    readonly trusted: readonly TrustedKey[];
    readonly minSequence?: number;
    readonly now?: () => Date;
    readonly fetcher?: typeof fetch;
  },
): Promise<{ readonly metadata: ChannelMetadata; readonly keyId: string }> {
  const bytes = await readSourceFile(
    source,
    `${channel}.json`,
    options.fetcher,
  );
  const signature = await readSourceFile(
    source,
    `${channel}.json.sig`,
    options.fetcher,
  );
  let envelope: SignatureEnvelope;
  try {
    envelope = JSON.parse(signature.toString("utf8")) as SignatureEnvelope;
  } catch {
    throw new PiShipError(
      "INTEGRITY_FAILED",
      "Channel signature is not valid JSON",
    );
  }
  const keyId = verifySignature(bytes, envelope, options.trusted);
  const metadata = JSON.parse(bytes.toString("utf8")) as ChannelMetadata;
  if (metadata.schema !== CHANNEL_SCHEMA)
    throw new PiShipError(
      "INTEGRITY_FAILED",
      `Unsupported channel metadata ${String(metadata.schema)}`,
    );
  if (
    metadata.distribution !== options.distribution ||
    metadata.channel !== channel
  )
    throw new PiShipError(
      "INTEGRITY_FAILED",
      `Channel metadata is for ${metadata.distribution}/${metadata.channel}, not ${options.distribution}/${channel}`,
    );
  const now = (options.now ?? (() => new Date()))();
  if (!(Date.parse(metadata.expires) > now.getTime()))
    throw new PiShipError(
      "INTEGRITY_FAILED",
      `Channel metadata expired at ${metadata.expires}; the source must re-sign it`,
    );
  if (
    !Number.isSafeInteger(metadata.sequence) ||
    metadata.sequence < (options.minSequence ?? 0)
  )
    throw new PiShipError(
      "INTEGRITY_FAILED",
      `Channel metadata sequence ${metadata.sequence} is older than the ${options.minSequence} already seen; refusing a replayed channel`,
    );
  return { metadata, keyId };
}

/** Download a channel archive into `destination`, streaming, and check size and SHA-256. */
export async function downloadArchive(
  source: string,
  entry: ChannelRelease,
  destination: string,
  fetcher: typeof fetch = fetch,
): Promise<void> {
  if (
    basename(entry.archive) !== entry.archive ||
    !entry.archive.endsWith(".tar.gz")
  )
    throw new PiShipError(
      "INTEGRITY_FAILED",
      `Unsafe archive name ${entry.archive}`,
    );
  if (isUrlSource(source)) {
    const url = new URL(
      entry.archive,
      source.endsWith("/") ? source : `${source}/`,
    );
    const response = await fetchSource(
      url,
      entry.archive,
      fetcher,
      ARCHIVE_TIMEOUT_MS,
    );
    await saveBody(response, destination, entry.archive, entry.bytes);
  } else {
    const path = join(resolve(source), entry.archive);
    if (statSync(path).size > entry.bytes)
      throw tooLarge(entry.archive, entry.bytes);
    cpSync(path, destination);
  }
  const size = statSync(destination).size;
  const actual = await sha256File(destination);
  if (size !== entry.bytes || actual !== entry.sha256)
    throw new PiShipError(
      "INTEGRITY_FAILED",
      `Downloaded ${entry.archive} does not match the signed channel metadata`,
      {
        userAction:
          "Do not install it; report the update source to the distribution owner",
      },
    );
}

// ----------------------------------------------------------- reproducibility

export interface ReproducibilityReport {
  readonly schema: typeof REPRODUCIBILITY_SCHEMA;
  readonly distribution: string;
  readonly version: string;
  readonly target: string;
  /** Declared static payload paths and SHA-256 hashes are equal. */
  readonly payloadEqual: boolean;
  readonly payloadFiles: number;
  readonly payloadDifferences: readonly string[];
  /** Wrapper files compared separately; they may carry build metadata. */
  readonly wrapper: Readonly<Record<string, boolean>>;
  readonly archiveEqual: boolean | null;
  readonly note: string;
}

/**
 * Compare two releases of the same source, lock, and target. Payload
 * equality is the reproducibility claim; wrapper differences are reported
 * separately. Different targets are refused rather than compared.
 */
export async function compareReleases(
  first: string,
  second: string,
): Promise<ReproducibilityReport> {
  const a = await verifyRelease(first);
  try {
    const b = await verifyRelease(second);
    try {
      if (
        a.metadata.target !== b.metadata.target ||
        a.metadata.distribution.id !== b.metadata.distribution.id ||
        a.metadata.distribution.version !== b.metadata.distribution.version
      )
        throw new PiShipError(
          "CONFIG_INVALID",
          `Reproducibility compares one distribution version on one target; got ${a.metadata.distribution.id}@${a.metadata.distribution.version} ${a.metadata.target} and ${b.metadata.distribution.id}@${b.metadata.distribution.version} ${b.metadata.target}`,
        );
      const left = JSON.parse(
        readFileSync(join(a.payload, "metadata", "inventory.json"), "utf8"),
      ) as Record<string, string>;
      const right = JSON.parse(
        readFileSync(join(b.payload, "metadata", "inventory.json"), "utf8"),
      ) as Record<string, string>;
      const paths = [
        ...new Set([...Object.keys(left), ...Object.keys(right)]),
      ].sort();
      const differences = paths.filter((path) => left[path] !== right[path]);
      const wrapper: Record<string, boolean> = {};
      for (const file of RELEASE_FILES.filter(
        (item) => !item.startsWith("payload/"),
      ))
        wrapper[file] =
          hash(readFileSync(join(a.directory, file))) ===
          hash(readFileSync(join(b.directory, file)));
      const archives = [first, second].map((path) => resolve(path));
      const archiveEqual = archives.every((path) => statSync(path).isFile())
        ? (await sha256File(archives[0] as string)) ===
          (await sha256File(archives[1] as string))
        : null;
      return {
        schema: REPRODUCIBILITY_SCHEMA,
        distribution: a.metadata.distribution.id,
        version: a.metadata.distribution.version,
        target: a.metadata.target,
        payloadEqual: differences.length === 0,
        payloadFiles: paths.length,
        payloadDifferences: differences.slice(0, 200),
        wrapper,
        archiveEqual,
        note: "Equality is claimed only for this target; other targets are built and compared separately.",
      };
    } finally {
      b.cleanup();
    }
  } finally {
    a.cleanup();
  }
}

/** Lists `.tar.gz` release archives in a directory, sorted. */
export function listArchives(directory: string): string[] {
  return readdirSync(directory)
    .filter((name) => name.endsWith(".tar.gz"))
    .sort()
    .map((name) => join(directory, name));
}

export { DEFAULT_RELEASE_TARGETS };
