// What a Pi package needs around it at launch, declared in the manifest:
// the environment it reads and the JSON configuration it keeps in Pi's agent
// directory (`resources.packages[].environment` and `.agentFiles`). Both are
// non-secret values from the lock; PiShip sets them before Pi loads the
// package, so a user's shell or an old copy of a file cannot change what the
// distribution declared, except where a file is a `seed` the user has edited.
import { createHash } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { PiShipError } from "@piship/contracts";
import { writeFileAtomic } from "@piship/credentials";
import type {
  AgentFileMode,
  PackageAgentFile,
  PackageEnvironmentValue,
} from "@piship/schema";
import type { DistributionLock, LockedAgentFile } from "./lock-schema.js";

/** The bytes written for a declared file: its JSON in declared key order. */
export function agentFileContent(json: unknown): string {
  return `${JSON.stringify(json, null, 2)}\n`;
}

export function agentFileDigest(content: string): string {
  return `sha256-${createHash("sha256").update(content).digest("hex")}`;
}

/** The lock's record of the declared files. */
export function lockedAgentFiles(
  files: readonly PackageAgentFile[],
): LockedAgentFile[] {
  return files.map((file) => ({
    path: file.path,
    mode: file.mode,
    sha256: agentFileDigest(agentFileContent(file.json)),
  }));
}

// ------------------------------------------------------------ environment

export interface PackageEnvironmentEntry {
  readonly package: string;
  readonly name: string;
  /** What the process gets: the literal, or the resolved state path. */
  readonly value: string;
  /** The declared value, for reports: a state path stays relative. */
  readonly declared: PackageEnvironmentValue;
}

/** Resolve a declared value on this machine. */
function resolveEnvironmentValue(
  value: PackageEnvironmentValue,
  stateDir: string,
): string {
  return typeof value === "string"
    ? value
    : join(stateDir, ...value.statePath.split("/"));
}

/** Every environment variable the lock declares, resolved against `stateDir`. */
export function packageEnvironment(
  lock: Pick<DistributionLock, "packages">,
  stateDir: string,
): PackageEnvironmentEntry[] {
  return (lock.packages ?? []).flatMap((item) =>
    Object.entries(item.environment ?? {}).map(([name, declared]) => ({
      package: item.id,
      name,
      value: resolveEnvironmentValue(declared, stateDir),
      declared,
    })),
  );
}

/**
 * Set the declared variables on `env`. A declared value replaces the one the
 * user's shell had, in every mode: a distribution that declares
 * `PI_BG_FEATURES` declares it for the reason a user cannot undo by exporting
 * another. Called again after a managed launch removed the ambient `PI_*`
 * variables, so a managed value is never one the shell chose.
 */
export function applyPackageEnvironment(
  lock: Pick<DistributionLock, "packages">,
  stateDir: string,
  env: NodeJS.ProcessEnv = process.env,
): PackageEnvironmentEntry[] {
  const entries = packageEnvironment(lock, stateDir);
  for (const entry of entries) env[entry.name] = entry.value;
  return entries;
}

// ------------------------------------------------------------ agent files

export type AgentFileOutcome =
  /** Written for the first time. */
  | "seeded"
  /** A seed replaced by a newer default, because the user had not edited it. */
  | "updated"
  /** An enforced file rewritten to the declared content. */
  | "enforced"
  /** Already what the lock declares. */
  | "unchanged"
  /** A seed the user edited: kept as it is. */
  | "kept";

export interface AgentFileReport {
  readonly package: string;
  readonly path: string;
  readonly mode: AgentFileMode;
  readonly outcome: AgentFileOutcome;
}

interface SeedState {
  readonly schema: "piship-agent-files/v1";
  /** Digest of what PiShip last wrote, per path. */
  readonly files: Record<string, string>;
  /** A session override that has not been taken back (a crashed launch). */
  readonly override?: SessionOverride;
}

interface SessionOverride {
  readonly path: string;
  readonly key: string;
  readonly hadKey: boolean;
  readonly original?: unknown;
}

const SEED_STATE = ".piship-agent-files.json";
const SEED_SCHEMA = "piship-agent-files/v1";

function readSeedState(agentDir: string): SeedState {
  try {
    const parsed = JSON.parse(
      readFileSync(join(agentDir, SEED_STATE), "utf8"),
    ) as Partial<SeedState> | null;
    if (
      parsed?.schema === SEED_SCHEMA &&
      parsed.files &&
      typeof parsed.files === "object"
    )
      return {
        schema: SEED_SCHEMA,
        files: { ...parsed.files },
        ...(parsed.override ? { override: parsed.override } : {}),
      };
  } catch {
    // Missing or unreadable: every existing file then counts as the user's.
  }
  return { schema: SEED_SCHEMA, files: {} };
}

function writeSeedState(agentDir: string, state: SeedState): void {
  writeFileAtomic(
    join(agentDir, SEED_STATE),
    `${JSON.stringify(state, null, 2)}\n`,
    { directoryMode: 0o700 },
  );
}

/** A declared file's absolute path, refusing a link anywhere below `agentDir`. */
function filePath(agentDir: string, path: string): string {
  let current = agentDir;
  for (const segment of path.split("/")) {
    current = join(current, segment);
    if (lstatSync(current, { throwIfNoEntry: false })?.isSymbolicLink())
      throw new PiShipError(
        "CONFIG_INVALID",
        `${current} is a link; PiShip does not write package configuration through one`,
        {
          userAction: `Remove the link, or move it aside, and start the distribution again`,
        },
      );
  }
  return current;
}

interface DeclaredFile {
  readonly package: string;
  readonly file: LockedAgentFile;
  readonly content: string;
}

/**
 * The declared files with their content, from the lock: the lock's record of
 * each file is checked against the content in its manifest, so a lock whose
 * parts disagree fails before anything is written.
 */
function declaredFiles(lock: DistributionLock): DeclaredFile[] {
  const declared = lock.governance?.manifest.resources.packages ?? [];
  const output: DeclaredFile[] = [];
  for (const item of lock.packages ?? []) {
    for (const file of item.agentFiles ?? []) {
      const source = declared
        .find((entry) => entry.id === item.id)
        ?.agentFiles?.find((entry) => entry.path === file.path);
      const content = source ? agentFileContent(source.json) : undefined;
      if (content === undefined || agentFileDigest(content) !== file.sha256)
        throw new PiShipError(
          "LOCK_INVALID",
          `The lock's record of ${file.path} for package ${item.id} does not match the manifest it holds`,
          { userAction: "Run piship lock again and rebuild the distribution" },
        );
      output.push({ package: item.id, file, content });
    }
  }
  return output;
}

/**
 * The key a session-wide auto-approval is switched on with, when the
 * distribution's permission provider declares one: the settings
 * `autoApproveFile` (one of its agent files) and `autoApproveKey` (a top-level
 * boolean of that JSON file) of the `permissions` capability.
 */
export function sessionAutoApproveTarget(
  lock: Pick<DistributionLock, "governance">,
): { readonly path: string; readonly key: string } | undefined {
  const settings = lock.governance?.manifest.capabilities.find(
    (item) => item.name === "permissions" && item.enabled,
  )?.settings;
  const path = settings?.autoApproveFile;
  const key = settings?.autoApproveKey;
  return path && key ? { path, key } : undefined;
}

function readJsonObject(path: string): Record<string, unknown> | undefined {
  try {
    const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
    return typeof parsed === "object" &&
      parsed !== null &&
      !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : undefined;
  } catch {
    return undefined;
  }
}

/** Put a session override's key back to what the file had before it. */
function takeBack(agentDir: string, override: SessionOverride): void {
  const target = filePath(agentDir, override.path);
  const current = readJsonObject(target);
  if (!current) return;
  // Only the one key: what else the session changed (an extension's own
  // command saving a log setting) stays.
  if (override.hadKey) current[override.key] = override.original;
  else delete current[override.key];
  writeFileAtomic(target, agentFileContent(current), { directoryMode: 0o700 });
}

export interface AgentFilesResult {
  readonly reports: readonly AgentFileReport[];
  /** Undo the session override; idempotent, and a no-op without one. */
  readonly restore: () => void;
}

/**
 * Write the lock's agent files into `agentDir`. A `seed` is written when it is
 * absent, and replaced on a later release only while it is still what PiShip
 * last wrote; one the user edited is kept. An `enforce` file is rewritten
 * whenever it differs. `sessionAutoApprove` switches the declared
 * auto-approval key on for this launch only: it is taken back by `restore`,
 * and by the next launch if this one never got to run it.
 */
export function applyAgentFiles(
  lock: DistributionLock,
  agentDir: string,
  options: { readonly sessionAutoApprove?: boolean } = {},
): AgentFilesResult {
  const files = declaredFiles(lock);
  const target = sessionAutoApproveTarget(lock);
  if (!files.length && !target) return { reports: [], restore: () => {} };
  let state = readSeedState(agentDir);
  if (state.override) {
    // A launch that never reached its end left the override on.
    takeBack(agentDir, state.override);
    state = { schema: SEED_SCHEMA, files: state.files };
    writeSeedState(agentDir, state);
  }
  const reports: AgentFileReport[] = [];
  const recorded = { ...state.files };
  for (const { package: owner, file, content } of files) {
    const path = filePath(agentDir, file.path);
    const wanted = file.sha256;
    const exists = existsSync(path);
    const found = exists
      ? agentFileDigest(readFileSync(path, "utf8"))
      : undefined;
    let outcome: AgentFileOutcome;
    if (found === wanted) outcome = "unchanged";
    else if (file.mode === "enforce")
      outcome = found === undefined ? "seeded" : "enforced";
    else if (found === undefined) outcome = "seeded";
    else if (found === state.files[file.path]) outcome = "updated";
    else outcome = "kept";
    if (outcome !== "unchanged" && outcome !== "kept") {
      mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
      writeFileAtomic(path, content, { directoryMode: 0o700 });
    }
    // What PiShip last wrote is what a later release may replace unasked.
    if (outcome !== "kept") recorded[file.path] = wanted;
    reports.push({ package: owner, path: file.path, mode: file.mode, outcome });
  }
  let override: SessionOverride | undefined;
  if (options.sessionAutoApprove) {
    if (!target)
      throw new PiShipError(
        "CONFIG_INVALID",
        "This distribution's permission provider declares no session auto-approval (the permissions capability needs the settings autoApproveFile and autoApproveKey)",
        { userAction: "Start the distribution without the option" },
      );
    const path = filePath(agentDir, target.path);
    const current = readJsonObject(path);
    if (!current)
      throw new PiShipError(
        "CONFIG_INVALID",
        `${target.path} is not a JSON object, so the session auto-approval cannot be switched on`,
        { userAction: "Fix or remove the file and start again" },
      );
    override = {
      path: target.path,
      key: target.key,
      hadKey: target.key in current,
      ...(target.key in current ? { original: current[target.key] } : {}),
    };
    writeSeedState(agentDir, {
      schema: SEED_SCHEMA,
      files: recorded,
      override,
    });
    writeFileAtomic(
      path,
      agentFileContent({ ...current, [target.key]: true }),
      { directoryMode: 0o700 },
    );
  } else if (files.length)
    writeSeedState(agentDir, { schema: SEED_SCHEMA, files: recorded });
  let restored = false;
  return {
    reports,
    restore: () => {
      if (restored || !override) return;
      restored = true;
      takeBack(agentDir, override);
      writeSeedState(agentDir, { schema: SEED_SCHEMA, files: recorded });
    },
  };
}

export type AgentFileState =
  /** The file is what the lock declares. */
  | "current"
  /** A seed the user edited; kept at launch. */
  | "edited"
  /** Missing, or an enforced file that differs: a launch rewrites it. */
  | "pending";

export interface AgentFileStatus {
  readonly package: string;
  readonly path: string;
  readonly mode: AgentFileMode;
  readonly state: AgentFileState;
}

/** Read-only form of `applyAgentFiles`, for `doctor`. */
export function inspectAgentFiles(
  lock: DistributionLock,
  agentDir: string,
): AgentFileStatus[] {
  return declaredFiles(lock).map(({ package: owner, file }) => {
    const path = join(agentDir, ...file.path.split("/"));
    const found = existsSync(path)
      ? agentFileDigest(readFileSync(path, "utf8"))
      : undefined;
    const state: AgentFileState =
      found === file.sha256
        ? "current"
        : found !== undefined && file.mode === "seed"
          ? "edited"
          : "pending";
    return { package: owner, path: file.path, mode: file.mode, state };
  });
}
