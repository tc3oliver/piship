import {
  type ChildProcess,
  type SpawnOptions,
  spawn,
  spawnSync,
} from "node:child_process";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import {
  binHome,
  buildDistribution,
  buildPack,
  buildRelease,
  isPack,
  buildRuntimeRelease,
  releaseKind,
  checkEnforceability,
  checkDataContract,
  checkSearchTools,
  checkSkills,
  checkToolExposure,
  checkGovernance,
  unapprovedLoadWarnings,
  checkPiVersion,
  PI_VERSION,
  checkStateMigration,
  storageOf,
  compareReleases,
  diffLocks,
  downloadLockedSearchTools,
  downloadSearchToolArchives,
  explainConfiguration,
  formatDiff,
  formatExplanation,
  formatInspection,
  formatSmokeSummary,
  describeFootprint,
  formatMigrationReport,
  generateSigningKey,
  initDistribution,
  initTrustRoot,
  inspection,
  installDistribution,
  isDistributionId,
  isEncryptedPrivateKey,
  isLocalBuildOnThisHost,
  isUnqualifiedPayload,
  keyFingerprint,
  lockManifest,
  lockNeedsNetwork,
  lockStatus,
  pishipCommand,
  shellArg,
  signedInClasses,
  markLocalBuild,
  nextTrustRoot,
  payloadApp,
  payloadStateSchemas,
  pemSigner,
  probeSearchToolUpstream,
  PISHIP_VERSION,
  pathHint,
  progressReporter,
  purgeDistributionState,
  raiseThreadpool,
  relockKeepingPackages,
  removeEmptyPiShipDirectories,
  readInstallReceipt,
  readSigningPassphrase,
  repairDistribution,
  requireCurrentLock,
  resolveResources,
  runtimeStateDirectory,
  SEARCH_TOOL_SPECS,
  signChannel,
  unqualifiedBuildNotice,
  uninstallAndPurgeDistribution,
  uninstallDistribution,
  verifyPayload,
  verifyRelease,
  verifyRuntimeRelease,
  withTestState,
  writePrivateKey,
  type AbandonedStaging,
  type RuntimeCacheProvenance,
  type DistributionLock,
  type KeyedSigner,
  type PassphraseInput,
  type PurgeResult,
} from "@piship/core";
import { formatError, PiShipError, redact } from "@piship/contracts";
import {
  launchWarnings,
  runtimeVariableUse,
  referencedVariables,
  readManifest,
  ManifestError,
  type Manifest,
  checkManifestMigration,
  migrateManifestSource,
  nearestField,
  readManifestSource,
} from "@piship/schema";
import { writeFileSync } from "node:fs";

/** Every command with a one-line summary, in help order. */
const summaries = {
  init: "Create a new distribution repository",
  dev: "Build and start the branded command from a manifest",
  validate: "Check a manifest without writing a lock",
  lock: "Resolve a manifest and write piship.lock",
  build: "Assemble the distribution payload",
  test: "Build and run the branded acceptance smoke",
  inspect: "Show a distribution's locked configuration",
  doctor: "Check an artifact or installed distribution",
  install: "Install an artifact, release, or archive for this user",
  uninstall: "Remove an installed distribution",
  purge: "Delete an installed distribution's state",
  migrate: "Migrate a manifest to the current schema",
  config: "Explain the effective configuration and its sources",
  release: "Build a local release archive",
  "runtime-release":
    "Build the distribution-independent PiShip runtime release",
  "verify-release": "Verify a release or runtime release archive or directory",
  pack: "Build a cross-platform Company Pack bound to official runtime archives",
  diff: "Compare two locks, payloads, releases, or installs",
  update: "Update an installed distribution",
  rollback: "Return an installed distribution to its previous release",
  repair: "Restore a damaged installed release from a trusted source",
  "migrate-check": "Check whether a release can take over the current state",
  keygen: "Create a root or channel signing key, or show a key's public key",
  "sign-channel": "Sign channel metadata for release archives",
  "trust-root": "Create bootstrap update trust or publish the next root",
  reproducibility: "Compare two builds of the same release",
} as const;
const commands = Object.keys(summaries) as (keyof typeof summaries)[];
/** Usage of the commands that take one target and fixed options. */
export const simpleUsage: Record<string, string> = {
  init: "init <directory> [--personal | --managed] [--id <id>]",
  dev: "dev [<manifest>] [--smoke]",
  validate: "validate [<manifest>]",
  lock: "lock [<manifest>]",
  build: "build [<manifest>] [--rebuild] [--reclaim-staging]",
  test: "test [<manifest>] [--model-request] [--json]",
  inspect: "inspect <manifest|artifact|id> [--json]",
  doctor: "doctor <artifact|id> [--json]",
  purge: "purge <id> --yes [--without-logout]",
  migrate: "migrate [<manifest>] [--write | --check]",
  config: "config explain <manifest|artifact|id>",
};
/**
 * One line per option, shown by `piship <command> --help` under the usage.
 * A test checks that the options named here are exactly the ones in the usage
 * line and the parser, so help cannot list a flag the command refuses.
 */
export const optionHelp: Record<string, Record<string, string>> = {
  init: {
    "--personal": "Write a personal distribution (the default)",
    "--managed":
      "Write a company template that asks for anything unlisted (OIDC, broker, gateway)",
    "--id <id>":
      "Distribution id and command name, when the directory name is not a valid one",
  },
  dev: { "--smoke": "Run headlessly once instead of opening the command" },
  build: {
    "--rebuild": "Assemble again even when the output for this lock exists",
    "--reclaim-staging": "Remove staging directories left by a killed run",
  },
  test: {
    "--model-request": "Also send one prompt through the configured model",
    "--json": "Print the summary as JSON",
  },
  inspect: { "--json": "Print the full locked configuration as JSON" },
  doctor: { "--json": "Print the report as JSON" },
  purge: {
    "--yes": "Confirm that the state is deleted",
    "--without-logout":
      "Purge without signing out; the credential stays live until it expires",
  },
  migrate: {
    "--write": "Apply the migration to the file (the default is a dry run)",
    "--check":
      "Only classify the manifest: exit 0 migratable, 1 needs review, 3 cannot",
  },
  install: {
    "--runtime <runtime-archive>":
      "The runtime archive a Company Pack is bound to",
    "--sha256 <hex>": "Refuse the archive unless it has this SHA-256",
    "--expect-key sha256:<fingerprint>":
      "Refuse unless the update trust pins this key; repeat for several",
    "--use-existing-state": "Keep state an earlier install left behind",
    "--replace":
      "Replace an installed copy of this distribution; its state is kept",
  },
  release: {
    "--out <dir>": "Directory for the release (default: ./dist)",
    "--channel <name>": "Update channel the release belongs to",
    "--rebuild": "Assemble again even when the output for this lock exists",
    "--reclaim-staging": "Remove staging directories left by a killed run",
  },
  "runtime-release": {
    "--out <dir>": "Directory for the runtime release",
    "--rebuild": "Assemble again even when the output exists",
    "--reclaim-staging": "Remove staging directories left by a killed run",
  },
  pack: {
    "--runtime <runtime-archive>":
      "An official runtime archive to bind; repeat once per platform",
    "--out <dir>": "Directory for the Company Pack",
    "--reclaim-staging": "Remove staging directories left by a killed run",
  },
  "verify-release": {
    "--sha256 <hex>": "Refuse the archive unless it has this SHA-256",
    "--json": "Print the result as JSON",
  },
  diff: { "--json": "Print the differences as JSON" },
  update: {
    "--channel <name>":
      "Switch to this channel (it must be one the distribution allows)",
    "--from <dir|url>":
      "Update source; defaults to the one the manifest declares",
    "--check":
      "Report the available version and migration result without installing",
    "--accept-review": "Proceed when the migration check asks for review",
  },
  uninstall: {
    "--purge": "Also delete the state (needs --yes)",
    "--yes": "Confirm the purge",
    "--without-logout":
      "Purge without signing out; the credential stays live until it expires",
    "--remove-edited-shim":
      "Remove the command file even though it was edited after install",
  },
  repair: {
    "--runtime <runtime-archive>":
      "The runtime archive a Company Pack is bound to",
  },
  keygen: {
    "--id <key-id>": "Name of the key, pinned in the trust root",
    "--encrypt": "Protect the private key with a passphrase",
    "--passphrase-env <NAME>":
      "Read the passphrase from this environment variable",
    "--passphrase-stdin": "Read the passphrase from standard input",
    "--force-in-worktree": "Write the key even inside a git work tree",
    "--show-public":
      "Print the public key of an existing private key file instead",
  },
  "sign-channel": {
    "--channel <name>": "Channel the metadata is for",
    "--key <private-key-file>": "Signing key; repeat to sign with several",
    "--key-id <id>": "Id of the key given before it; repeat in the same order",
    "--passphrase-env <NAME>":
      "Read the key passphrase from this environment variable",
    "--passphrase-stdin": "Read the key passphrase from standard input",
    "--previous-key <id>=<public-key>": "Previous channel key to keep trusting",
    "--sequence <n>": "Metadata sequence number",
    "--expires-days <n>": "Days until the metadata expires",
    "--runtime <archive|dir>":
      "A runtime archive or directory to list; repeatable",
  },
  "trust-root": {
    "--key <id>=<public-key>": "A public key to include (init); repeatable",
    "--root-keys <id,...>": "Ids allowed to sign the root",
    "--channel-keys <id,...>": "Ids allowed to sign channels",
    "--root-threshold <n>": "Root signatures required",
    "--channel-threshold <n>": "Channel signatures required",
    "--expires <timestamp>": "When the root expires",
    "--expires-days <n>": "Days until the root expires",
    "--manifest <piship.yaml>": "Manifest whose trust is being updated (next)",
    "--sign <id>=<private-key-file>":
      "Signing key for the next root; repeatable",
    "--add-key <id>=<public-key>":
      "Publish this key in the next root; repeatable",
    "--remove-key <id>": "Drop this key from the next root; repeatable",
    "--passphrase-env <NAME>":
      "Read the key passphrase from this environment variable",
    "--passphrase-stdin": "Read the key passphrase from standard input",
  },
  reproducibility: {
    "--out <report.json>": "Write the comparison report here",
  },
};
/** `piship <command> --help`: usage, the summary, then each option. */
function commandHelp(command: string): string {
  const usage = lifecycleCommands[command]?.usage ?? simpleUsage[command];
  const options = Object.entries(optionHelp[command] ?? {});
  const width = Math.max(0, ...options.map(([name]) => name.length)) + 2;
  return `Usage: piship ${usage}\n\n${summaries[command as keyof typeof summaries]}.${
    options.length
      ? `\n\nOptions:\n${options.map(([name, text]) => `  ${name.padEnd(width)}${text}`).join("\n")}`
      : ""
  }`;
}
/** What was wrong with the arguments, when a token can be named. */
function argumentProblem(
  command: string,
  known: readonly string[],
  valued: readonly string[],
  maxPositional: number,
  args: readonly string[],
): string | undefined {
  let positional = 0;
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index] ?? "";
    if (valued.includes(arg)) {
      if (args[index + 1] === undefined) return `${arg} needs a value.`;
      index += 1;
    } else if (arg.startsWith("-") && !known.includes(arg))
      // Only the name: `--passphrase=<secret>` must not reach the terminal.
      return `Unknown option ${arg.split("=")[0]} for ${command}.`;
    else if (!arg.startsWith("-") && positional >= maxPositional)
      // Not echoed either: a stray word may be a secret typed in the wrong place.
      return `${command} takes ${maxPositional === 0 ? "no" : `at most ${maxPositional}`} argument${maxPositional === 1 ? "" : "s"}.`;
    else if (!arg.startsWith("-")) positional += 1;
  }
  return undefined;
}
/** The usage line, led by what was wrong when that is known. */
function usageError(
  command: string,
  usage: string | undefined,
  problem: string | undefined,
): string {
  return `${problem ? `${problem}\n` : ""}Usage: piship ${usage}`;
}
/** Commands with named options: positional count and accepted flags. */
export const lifecycleCommands: Record<
  string,
  {
    readonly usage: string;
    readonly positional: [number, number];
    readonly values: readonly string[];
    readonly flags: readonly string[];
    /** Value options that may be given more than once. */
    readonly repeated?: readonly string[];
  }
> = {
  install: {
    usage:
      "install <artifact|release-dir|archive|pack> [--runtime <runtime-archive>] [--sha256 <hex>] [--expect-key sha256:<fingerprint>]... [--use-existing-state] [--replace]",
    positional: [1, 1],
    values: ["--sha256", "--runtime"],
    flags: ["--use-existing-state", "--replace"],
    repeated: ["--expect-key"],
  },
  release: {
    usage:
      "release <manifest> [--out <dir>] [--channel <name>] [--rebuild] [--reclaim-staging]",
    positional: [1, 1],
    values: ["--out", "--channel"],
    flags: ["--rebuild", "--reclaim-staging"],
  },
  "runtime-release": {
    usage: "runtime-release [--out <dir>] [--rebuild] [--reclaim-staging]",
    positional: [0, 0],
    values: ["--out"],
    flags: ["--rebuild", "--reclaim-staging"],
  },
  pack: {
    usage:
      "pack <manifest> --runtime <runtime-archive>... [--out <dir>] [--reclaim-staging]",
    positional: [1, 1],
    values: ["--out"],
    flags: ["--reclaim-staging"],
    repeated: ["--runtime"],
  },
  "verify-release": {
    usage: "verify-release <archive|release-dir> [--sha256 <hex>] [--json]",
    positional: [1, 1],
    values: ["--sha256"],
    flags: ["--json"],
  },
  diff: {
    usage: "diff <before> <after> [--json]",
    positional: [2, 2],
    values: [],
    flags: ["--json"],
  },
  update: {
    usage:
      "update <id> [--channel <name>] [--from <dir|url>] [--check] [--accept-review]",
    positional: [1, 1],
    values: ["--channel", "--from"],
    flags: ["--check", "--accept-review"],
  },
  uninstall: {
    usage:
      "uninstall <id> [--purge --yes [--without-logout]] [--remove-edited-shim]",
    positional: [1, 1],
    values: [],
    flags: ["--purge", "--yes", "--without-logout", "--remove-edited-shim"],
  },
  rollback: {
    usage: "rollback <id>",
    positional: [1, 1],
    values: [],
    flags: [],
  },
  repair: {
    usage:
      "repair <id> <archive|release-dir|payload|pack> [--runtime <runtime-archive>]",
    positional: [2, 2],
    values: ["--runtime"],
    flags: [],
  },
  "migrate-check": {
    usage: "migrate-check <id> <archive|release-dir|payload>",
    positional: [2, 2],
    values: [],
    flags: [],
  },
  keygen: {
    usage:
      "keygen <private-key-file> --id <key-id> [--encrypt [--passphrase-env <NAME> | --passphrase-stdin]] [--force-in-worktree] [--show-public]",
    positional: [1, 1],
    values: ["--id", "--passphrase-env"],
    flags: [
      "--force-in-worktree",
      "--encrypt",
      "--passphrase-stdin",
      "--show-public",
    ],
  },
  "sign-channel": {
    usage:
      "sign-channel <channel-dir> <archive|pack>... --channel <name> --key <private-key-file> --key-id <id> [--key <private-key-file> --key-id <id>]... [--passphrase-env <NAME> | --passphrase-stdin] [--previous-key <id>=<public-key>] [--sequence <n>] [--expires-days <n>] [--runtime <archive|dir>]...",
    positional: [2, 64],
    values: [
      "--channel",
      "--passphrase-env",
      "--previous-key",
      "--sequence",
      "--expires-days",
    ],
    flags: ["--passphrase-stdin"],
    repeated: ["--key", "--key-id", "--runtime"],
  },
  "trust-root": {
    usage:
      "trust-root init --key <id>=<public-key>... --root-keys <id,...> --channel-keys <id,...> [--root-threshold <n>] [--channel-threshold <n>] (--expires <timestamp> | --expires-days <n>)\n       piship trust-root next <update-source-dir> --manifest <piship.yaml> --sign <id>=<private-key-file>... [--add-key <id>=<public-key>]... [--remove-key <id>]... [--root-keys <id,...>] [--channel-keys <id,...>] [--root-threshold <n>] [--channel-threshold <n>] (--expires <timestamp> | --expires-days <n>) [--passphrase-env <NAME> | --passphrase-stdin]",
    positional: [1, 2],
    values: [
      "--manifest",
      "--root-keys",
      "--channel-keys",
      "--root-threshold",
      "--channel-threshold",
      "--expires",
      "--expires-days",
      "--passphrase-env",
    ],
    flags: ["--passphrase-stdin"],
    repeated: ["--key", "--sign", "--add-key", "--remove-key"],
  },
  reproducibility: {
    usage: "reproducibility <release-a> <release-b> [--out <report.json>]",
    positional: [2, 2],
    values: ["--out"],
    flags: [],
  },
};
interface Parsed {
  readonly positional: string[];
  readonly options: Record<string, string>;
  readonly flags: Set<string>;
  readonly repeated: Record<string, string[]>;
}
function parseArguments(
  spec: (typeof lifecycleCommands)[string],
  args: readonly string[],
): Parsed | undefined {
  const positional: string[] = [];
  const options: Record<string, string> = {};
  const flags = new Set<string>();
  const repeated: Record<string, string[]> = {};
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index] ?? "";
    if (spec.repeated?.includes(arg)) {
      const value = args[index + 1];
      if (value === undefined) return undefined;
      repeated[arg] = [...(repeated[arg] ?? []), value];
      index += 1;
    } else if (spec.values.includes(arg)) {
      const value = args[index + 1];
      if (value === undefined || arg in options) return undefined;
      options[arg] = value;
      index += 1;
    } else if (spec.flags.includes(arg)) flags.add(arg);
    else if (arg.startsWith("--")) return undefined;
    else positional.push(arg);
  }
  if (
    positional.length < spec.positional[0] ||
    positional.length > spec.positional[1]
  )
    return undefined;
  return { positional, options, flags, repeated };
}
/** The passphrase channel a signing command names; never the passphrase. */
function passphraseInput(
  options: Parsed["options"],
  flags: Parsed["flags"],
): PassphraseInput {
  const env = options["--passphrase-env"];
  return {
    ...(env === undefined ? {} : { env }),
    stdin: flags.has("--passphrase-stdin"),
  };
}
/** `<id>=<value>` pairs of a repeated option. */
function pairs(values: readonly string[], option: string, value: string) {
  return values.map((item) => {
    const split = item.indexOf("=");
    if (split < 1 || split === item.length - 1)
      throw new Error(`${option} must be <id>=<${value}>`);
    return { id: item.slice(0, split), value: item.slice(split + 1) };
  });
}
function positiveInteger(value: string | undefined, name: string) {
  if (value === undefined) return undefined;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1)
    throw new Error(`${name} must be a positive integer`);
  return parsed;
}
function idList(value: string | undefined) {
  return value === undefined
    ? undefined
    : value.split(",").map((item) => item.trim());
}
/**
 * PEM signers for `<key id, private key file>` pairs. An encrypted key's
 * passphrase comes from --passphrase-env (one for every encrypted key),
 * --passphrase-stdin (one encrypted key only), or a prompt per key.
 */
async function pemSigners(
  keys: readonly { id: string; file: string }[],
  input: PassphraseInput,
  output: CliOutput,
): Promise<KeyedSigner[]> {
  const { readFileSync } = await import("node:fs");
  const pems = keys.map((key) => ({
    ...key,
    pem: readFileSync(key.file, "utf8"),
  }));
  const encrypted = pems.filter((key) => isEncryptedPrivateKey(key.pem));
  if (!encrypted.length && (input.env !== undefined || input.stdin))
    output.stderr(
      "Warning: no signing key is encrypted; the passphrase option is ignored.",
    );
  if (input.stdin && encrypted.length > 1)
    throw new Error(
      "--passphrase-stdin reads one passphrase; with several encrypted keys, use --passphrase-env or the prompts",
    );
  const signers: KeyedSigner[] = [];
  for (const key of pems)
    signers.push(
      pemSigner({
        keyId: key.id,
        privateKeyPem: key.pem,
        ...(isEncryptedPrivateKey(key.pem)
          ? {
              passphrase: await readSigningPassphrase(
                `Passphrase for ${key.file}`,
                input,
              ),
            }
          : {}),
      }),
    );
  return signers;
}
/** A lock from a manifest, lock file, payload, release, archive, or installed id. */
/**
 * What to upload after sign-channel, in the order the trust root page gives,
 * and when to sign again: a week before the metadata expires, or at once
 * when less is left. `present` names archives that were already in the
 * channel directory before this run; `newestRoot` is the newest
 * root/<N>.json there, which clients need before a channel its keys sign.
 */
export function publishSteps(
  channel: string,
  artifacts: readonly string[],
  expires: string,
  now = new Date(),
  context: {
    present?: readonly string[];
    newestRoot?: number | undefined;
  } = {},
): string {
  const expiry = new Date(expires);
  const week = 7 * 24 * 60 * 60 * 1000;
  const by =
    expiry.getTime() - now.getTime() > week
      ? new Date(expiry.getTime() - week).toISOString().slice(0, 10)
      : "now";
  const present = new Set(context.present ?? []);
  const names = artifacts.map((item) => basename(item));
  const added = names.filter((name) => !present.has(name));
  const kept = names.filter((name) => present.has(name));
  return [
    "Next: publish the channel directory to the update source in this order:",
    ...(context.newestRoot
      ? [
          `  0. any root/<N>.json up to root/${context.newestRoot}.json not yet published, each root/<N>.json.sig before root/<N>.json: clients refuse a channel signed by keys a root they have not fetched adds`,
        ]
      : []),
    `  1. the archives this run added: ${added.length ? added.join(", ") : "none"}${kept.length ? ` (already in the channel directory before this run; upload only if not yet published: ${kept.join(", ")})` : ""}`,
    `  2. ${channel}.json.sig and ${channel}.json together`,
    "Remove an older archive only after no published channel lists it.",
    `Sign ${channel} again by ${by}: clients refuse it after ${expires}.`,
  ].join("\n");
}

/**
 * What to upload after trust-root next: the signature before the root, and
 * the root before any channel signed by a channel key it adds.
 */
export function rootPublishSteps(
  directory: string,
  version: number,
  expires: string,
  addedChannelKeys: readonly string[],
  now = new Date(),
): string {
  const week = 7 * 24 * 60 * 60 * 1000;
  const expiry = new Date(expires).getTime();
  const by =
    expiry - now.getTime() > week
      ? new Date(expiry - week).toISOString().slice(0, 10)
      : "now";
  return [
    "Next: publish the root to the update source in this order, before any channel signed with keys it adds:",
    `  1. root/${version}.json.sig`,
    `  2. root/${version}.json`,
    "Never delete or replace a published root.",
    ...(addedChannelKeys.length
      ? [
          `Then sign each channel with the new channel key: ${pishipCommand()} sign-channel ${directory} <archive>... --channel <name> --key <private-key-file> --key-id ${addedChannelKeys[0]}`,
        ]
      : []),
    `Publish the next root by ${by}: clients stop updating after ${expires}.`,
  ].join("\n");
}

/** The newest root/<N>.json in a channel's root directory, if any. */
function newestRootVersion(directory: string): number | undefined {
  if (!existsSync(directory)) return undefined;
  const versions = readdirSync(directory).flatMap((name) => {
    const match = /^([1-9][0-9]*)\.json$/.exec(name);
    return match ? [Number(match[1])] : [];
  });
  return versions.length ? Math.max(...versions) : undefined;
}

/** A lock file's content, or LOCK_INVALID naming the file and the way out. */
function parseLockText(text: string, file: string): DistributionLock {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    value = undefined;
  }
  const record = (item: unknown): item is Record<string, unknown> =>
    typeof item === "object" && item !== null && !Array.isArray(item);
  if (
    !record(value) ||
    typeof value.schema !== "string" ||
    !value.schema.startsWith("piship-lock/") ||
    !record(value.app) ||
    !record(value.runtime)
  )
    throw new PiShipError(
      "LOCK_INVALID",
      `${file} is not a piship.lock this PiShip can read`,
      {
        component: "cli",
        userAction:
          "Pass a lock that piship lock wrote, or a manifest, payload, release, or installed id",
      },
    );
  return value as unknown as DistributionLock;
}
async function lockFor(target: string): Promise<DistributionLock> {
  const path = resolve(target);
  if (existsSync(path) && statSync(path).isFile()) {
    if (path.endsWith(".tar.gz")) {
      const verified = await verifyRelease(path);
      verified.cleanup();
      return verified.lock;
    }
    // A lock is JSON with a piship-lock schema, whatever the file is called
    // (a copy kept as previous-release.json); a manifest is YAML.
    const text = (await import("node:fs")).readFileSync(path, "utf8");
    if (path.endsWith(".lock")) return parseLockText(text, target);
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      // YAML: a manifest.
    }
    if (
      typeof (parsed as DistributionLock | undefined)?.schema === "string" &&
      (parsed as DistributionLock).schema.startsWith("piship-lock/")
    )
      return parseLockText(text, target);
    return requireCurrentLock(target);
  }
  if (existsSync(path) && existsSync(join(path, "release.json")))
    return (await verifyRelease(path)).lock;
  if (existsSync(path)) return verifyPayload(path);
  return verifyPayload(installedReceipt(target).payload);
}
const allowedOptions: Record<string, readonly string[]> = {
  build: [
    "--reclaim-staging",
    "--rebuild",
    "--rebuild --reclaim-staging",
    "--reclaim-staging --rebuild",
  ],
  purge: ["--yes", "--yes --without-logout", "--without-logout --yes"],
  init: ["--personal", "--managed"],
  migrate: ["--write", "--check"],
  test: [
    "--model-request",
    "--json",
    "--model-request --json",
    "--json --model-request",
  ],
  inspect: ["--json"],
  doctor: ["--json"],
  dev: ["--smoke"],
};
export interface CliOutput {
  readonly stdout: (message: string) => void;
  readonly stderr: (message: string) => void;
}
/**
 * What a build or release says about the staging directories of killed runs
 * in its output directory. They are removed only on request: the output
 * directory is usually inside a project that sandboxed commands can write.
 */
/** One line saying whether a release's runtime came from the runtime cache. */
export function runtimeCacheLine(cache: RuntimeCacheProvenance): string {
  if (cache.status === "disabled" || cache.entry === undefined)
    return `runtime cache: ${cache.status}`;
  const placed = [
    `entry ${cache.entry}`,
    `linked ${cache.linked ?? 0}`,
    `copied ${cache.copied ?? 0}`,
    ...(cache.framework ? [`PiShip ${cache.framework}`] : []),
    ...(cache.bundle ? [`bundle ${cache.bundle}`] : []),
    ...(cache.crossVolume ? ["cache on another volume, entry copied in"] : []),
  ];
  return `runtime cache: ${cache.status} (${placed.join(", ")})`;
}

/** `reclaim`: the command that removes them, for one without --reclaim-staging. */
export function stagingNotice(
  found: AbandonedStaging,
  reclaim = "run again with --reclaim-staging",
): string {
  const what = `${found.count} abandoned staging ${found.count === 1 ? "directory" : "directories"} of killed runs in ${found.directory}`;
  return found.attempted
    ? `${what} could not be removed; check its permissions.`
    : `${what}. They are not removed unless you ask, because this directory may be writable by sandboxed commands; ${reclaim} to remove them.`;
}
function purgeReport(purged: PurgeResult, output: CliOutput): string {
  if (purged.notRevoked)
    output.stderr(
      `Warning: purged without logout: ${purged.notRevoked.join(", ")} ${purged.notRevoked.length > 1 ? "were" : "was"} deleted locally but not revoked, and stays live at the identity provider or broker until it expires`,
    );
  if (purged.droppedSecrets)
    output.stderr(
      `Note: ${purged.droppedSecrets.length} secret reference(s) that an interrupted sign-in left (${purged.droppedSecrets.join(", ")}) were dropped without deleting anything: the secret store that recorded them is not installed here, and no secret was confirmed written under them`,
    );
  const count = purged.deletedSecrets.length;
  return `Purged ${purged.state}${count ? `\nDeleted ${count} secret-store entr${count === 1 ? "y" : "ies"}` : ""}`;
}
/**
 * Node reads the payload's package.json before any PiShip code of the payload
 * runs, and answers a damaged one with its own stack trace. Check it first,
 * so that the user gets the repair line instead.
 */
export function assertPayloadPackageJson(artifact: string): void {
  let intact = false;
  try {
    const value: unknown = JSON.parse(
      readFileSync(join(artifact, "package.json"), "utf8"),
    );
    intact =
      typeof value === "object" && value !== null && !Array.isArray(value);
  } catch (error) {
    // A missing file is Node's business (it then treats the folder as plain);
    // an unreadable one or one that is not JSON is damaged.
    intact = (error as NodeJS.ErrnoException).code === "ENOENT";
  }
  if (!intact)
    throw new PiShipError(
      "INTEGRITY_FAILED",
      `package.json in ${artifact} is damaged`,
      {
        component: "cli",
        userAction:
          "Restore the release from a trusted copy of the same version with: piship repair <id> <release archive>, or without a PiShip CLI: node <extracted release>/payload/piship.mjs repair <id> <extracted release>",
      },
    );
}
function runLauncher(
  artifact: string,
  command: string,
  args: string[],
  interactive = false,
): { status: number | null; stdout: string; stderr: string } {
  assertPayloadPackageJson(artifact);
  const target = join(artifact, "bin", command);
  const options = {
    encoding: "utf8",
    stdio: interactive ? "inherit" : "pipe",
  } as const;
  // On Windows the payload's `.cmd` shim only runs this script with Node, and
  // going through cmd.exe would split and interpret the arguments (spaces,
  // & | ^ %), so Node runs it directly and each argument arrives unchanged.
  const result =
    process.platform === "win32"
      ? spawnSync(process.execPath, [target, ...args], options)
      : spawnSync(target, args, options);
  return {
    status: result.status,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? result.error?.message ?? "",
  };
}
/**
 * Run the installed release's command while showing its stderr (progress
 * and notices) as it arrives; stdout is collected. Used only when someone
 * watches a terminal; it tells the release so with PISHIP_PROGRESS=1.
 */
function runLauncherLive(
  artifact: string,
  command: string,
  args: string[],
  stderr: (message: string) => void,
): Promise<{ status: number | null; stdout: string; stderr: string }> {
  assertPayloadPackageJson(artifact);
  const target = join(artifact, "bin", command);
  const options: SpawnOptions = {
    stdio: ["inherit", "pipe", "pipe"],
    env: { ...process.env, PISHIP_PROGRESS: "1" },
  };
  const child: ChildProcess =
    process.platform === "win32"
      ? spawn(process.execPath, [target, ...args], options)
      : spawn(target, args, options);
  let stdout = "";
  let pending = "";
  child.stdout?.setEncoding("utf8").on("data", (chunk: string) => {
    stdout += chunk;
  });
  child.stderr?.setEncoding("utf8").on("data", (chunk: string) => {
    const lines = (pending + chunk).split("\n");
    pending = lines.pop() ?? "";
    for (const line of lines) stderr(line);
  });
  return new Promise((done) => {
    child.on("error", (error: Error) =>
      done({ status: null, stdout, stderr: error.message }),
    );
    child.on("close", (status: number | null) => {
      if (pending) stderr(pending);
      done({ status, stdout, stderr: "" });
    });
  });
}
/** A directory with piship.yaml and no built payload's metadata: a distribution's source. */
function isDistributionSource(path: string): boolean {
  return (
    existsSync(join(path, "piship.yaml")) && !existsSync(join(path, "metadata"))
  );
}
/** The commands that take a manifest: given nothing, ./piship.yaml; given a source directory, its piship.yaml. */
const manifestCommands = [
  "validate",
  "lock",
  "build",
  "test",
  "dev",
  "migrate",
  "inspect",
];
/**
 * `preferInstalled` (inspect, config explain): a bare id that names both a
 * source directory here and an installed distribution means the install, as
 * it does for doctor; a path to the directory or its piship.yaml means the source.
 */
function manifestPath(
  target: string | undefined,
  preferInstalled = false,
): string | undefined {
  if (target === undefined)
    return existsSync("piship.yaml") ? "piship.yaml" : undefined;
  if (preferInstalled && installedPayload(target) !== undefined) return target;
  return isDistributionSource(target) ? join(target, "piship.yaml") : target;
}
/** The installed payload of a bare id that also names a source directory here. */
function installedPayload(target: string): string | undefined {
  if (!isDistributionId(target) || !isDistributionSource(resolve(target)))
    return undefined;
  try {
    return readInstallReceipt(target).payload;
  } catch (error) {
    if (
      !(error instanceof Error) ||
      !error.message.startsWith("No PiShip installation recorded")
    )
      throw error;
    return undefined;
  }
}
/** Why a distribution's source directory is not something to install or check, and what to run. */
function notBuilt(target: string, command: string): Error {
  let id = "<id>";
  try {
    id = readManifest(join(target, "piship.yaml")).app.id;
  } catch {
    // The advice still holds with a placeholder.
  }
  const self = pishipCommand();
  return new Error(
    `${target} is the source of a distribution (it holds piship.yaml), not a built one. Build it with ${self} build ${shellArg(target)}, then run ${self} ${command} ${shellArg(join("dist", id))}.`,
  );
}
function artifactFor(
  target: string,
  command: string,
  note: (line: string) => void,
): string {
  const path = resolve(target);
  if (existsSync(path) && statSync(path).isDirectory()) {
    if (!isDistributionSource(path)) return path;
    // `doctor my-agent` next to the source of the installed my-agent means the install.
    const installed = installedPayload(target);
    if (installed === undefined) throw notBuilt(target, command);
    // doctor checks installs only; inspect and config explain also read a manifest.
    note(
      `Note: ${command} reads the installed ${target}, not the source directory of that name${command === "doctor" ? "" : `; for the source, pass ${shellArg(join(target, "piship.yaml"))}`}.`,
    );
    return installed;
  }
  return installedReceipt(target).payload;
}
/**
 * Options may come before the positional (`build --rebuild x`): the first
 * positional argument, then the other arguments in their order, `valued`
 * options with their value.
 */
function positionalFirst(
  args: readonly string[],
  valued: readonly string[] = [],
): [string | undefined, ...string[]] {
  const positional: string[] = [];
  const options: string[] = [];
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index] ?? "";
    if (!arg.startsWith("-")) positional.push(arg);
    else {
      options.push(arg);
      if (valued.includes(arg) && index + 1 < args.length) {
        index += 1;
        options.push(args[index] ?? "");
      }
    }
  }
  const [first, ...others] = positional;
  return [first, ...others, ...options];
}
/** A target that is not an existing path is an installed id: say so when it is neither. */
function installedReceipt(target: string) {
  try {
    return readInstallReceipt(target);
  } catch (error) {
    if (
      error instanceof Error &&
      error.message.startsWith("No PiShip installation recorded")
    )
      error.message = `${error.message} ${target} is not an existing path either; pass an installed id, or a manifest, payload directory, or archive.`;
    throw error;
  }
}
/** The options of `init`: `--personal`, `--managed`, and `--id <id>`. */
function parseInitOptions(
  rest: readonly string[],
): { managed: boolean; id?: string } | undefined {
  let managed = false;
  let id: string | undefined;
  for (let index = 0; index < rest.length; index += 1) {
    const arg = rest[index];
    if (arg === "--managed") managed = true;
    else if (arg === "--personal") continue;
    else if (arg === "--id" && id === undefined) {
      id = rest[index + 1];
      if (id === undefined || id.startsWith("--")) return undefined;
      index += 1;
    } else return undefined;
  }
  return { managed, ...(id === undefined ? {} : { id }) };
}
/**
 * Whether `piship init --personal` can bundle `fd` and `rg`, which `piship
 * lock` then downloads from GitHub, or, given `url`, whether that host (the
 * npm registry) answers. `PISHIP_INIT_PROBE=reachable|unreachable`
 * answers in place of the network request: a test hook, so a test never
 * touches the network. Any other value probes.
 */
async function searchToolsDownloadable(url?: string): Promise<boolean> {
  const hook = process.env.PISHIP_INIT_PROBE;
  if (hook === "reachable") return true;
  if (hook === "unreachable") return false;
  return probeSearchToolUpstream(url === undefined ? {} : { url });
}
/** Printed when `init` cannot reach the registry the first build installs the runtime from. */
const NPM_REGISTRY_UNREACHABLE =
  "registry.npmjs.org did not answer within 3 seconds. The first build or test downloads the runtime packages from the npm registry (later ones use the cache), so it fails if npm cannot reach it, or the registry npm is configured to use, by then.";
/** Printed when `init` leaves `runtime.searchTools` out. */
const SEARCH_TOOLS_SKIPPED =
  "GitHub is not reachable from here, so fd and rg are not bundled (Pi's @ file completion and find/grep need them). Add runtime.searchTools: { mode: bundled } and https://github.com to release.sources later, or see docs/manifest.md#bundled-search-tools-v1alpha6.";
/**
 * `dev` and `test` iterate on a manifest, so they do not stop at a lock
 * that is missing or stale. With no lock yet nothing was reviewed, so it is
 * created. A stale lock is relocked; with Pi packages declared, only when
 * none of their inputs changed, keeping the recorded packages offline:
 * resolving and pinning network content stays a deliberate step. Bundled search tools are read from the download cache
 * when the old lock pins them. `build` and `release` keep requiring a
 * current lock.
 */
async function prepareLock(
  target: string,
  manifest: Manifest,
  output: CliOutput,
): Promise<void> {
  const status = lockStatus(target);
  if (status === "current") return;
  const lockCommand = `${pishipCommand()} lock ${shellArg(target)}`;
  const progress = progressReporter(output.stderr);
  await downloadSearchToolArchives(target, progress ? { progress } : {});
  if (status === "stale" && lockNeedsNetwork(manifest)) {
    if (!relockKeepingPackages(target))
      throw new Error(
        `Lockfile is stale: a Pi package declaration, packageTrust, the release settings, or a stored package lockfile changed since piship.lock was written. Locking resolves Pi packages over the network and pins them, so relock on purpose: ${lockCommand}`,
      );
  } else lockManifest(target);
  // `target` is the manifest file; the lock sits beside it.
  const lockPath = join(dirname(target), "piship.lock");
  output.stderr(
    status === "missing"
      ? `Created ${lockPath}: none existed, so nothing was reviewed yet. Review it and commit it with piship.yaml.`
      : `Relocked ${lockPath}: the manifest or a resource changed since it was written.`,
  );
}
/**
 * What to do after an install, by deployment mode: a managed distribution
 * needs its runtime variables set and a `login`; a personal one with Pi's
 * own providers signs in inside Pi.
 */
export function installNext(
  receipt: {
    app: { command: string };
    payload: string;
  },
  signedIn = false,
  env: NodeJS.ProcessEnv = process.env,
) {
  const command = receipt.app.command;
  let lock: DistributionLock | undefined;
  try {
    lock = JSON.parse(
      readFileSync(join(receipt.payload, "piship.lock"), "utf8"),
    ) as DistributionLock;
  } catch {
    // The receipt is enough to start the command; only the advice is generic.
  }
  if (lock?.deployment.mode === "managed") {
    // updates.source is read only by `update`; launch and login never need it.
    const source = JSON.stringify(lock.updates?.source ?? "");
    const elsewhere = JSON.stringify({
      ...lock.access,
      governance: lock.governance,
    });
    const variables = (lock.access?.variables ?? []).filter(
      (name) =>
        !referencedVariables(source).includes(name) ||
        referencedVariables(elsewhere).includes(name),
    );
    // Variables this install already sees need no step here, but a launcher
    // that does not read the shell profile still needs them.
    const unset = variables.filter((name) => !env[name]);
    const set = unset.length
      ? `set ${unset.join(", ")} in the environment that starts ${command}, then `
      : "";
    const launcher =
      unset.length < variables.length
        ? ` An IDE or desktop launcher does not read your shell profile, so set ${variables.join(", ")} there too.`
        : "";
    // An adopted (test or earlier) state may already hold a session.
    return signedIn
      ? `Next: ${set}run ${command}; it is already signed in. ${command} --help lists its commands.${launcher}`
      : `Next: ${set}run ${command} login, then ${command}. ${command} --help lists its commands.${launcher}`;
  }
  if (
    lock &&
    (lock.access?.credential.provider === "pi-native" || !lock.access)
  )
    return `Next: run ${command}, then sign in inside Pi with /login. ${command} --help lists its commands.`;
  return `Next: run ${command} --help to see its commands, then ${command} to start.`;
}
/** What to do about a `runtime.pi` that is not the pinned Pi. */
function piPinReview(stated: string): string {
  return `runtime.pi is ${stated} but this PiShip pins Pi ${PI_VERSION}; piship lock and build refuse the manifest until you remove the runtime.pi line (the build then uses the pinned Pi, and the field cannot go stale again) or set it to "${PI_VERSION}" after re-verifying the distribution (docs/compatibility.md, "Upgrading Pi")`;
}
/** Commands only a built distribution's own command has. */
const brandedOnlyCommands = [
  "login",
  "logout",
  "models",
  "policy",
  "capabilities",
];
export async function runCli(
  args: readonly string[],
  output: CliOutput,
): Promise<number> {
  const [command] = args;
  // `piship help [command]` is `piship [command] --help`.
  if (command === "help")
    return runCli(
      args[1] === undefined ? ["--help"] : [args[1], "--help"],
      output,
    );
  if (command === undefined || command === "--help" || command === "-h") {
    const width = Math.max(...commands.map((item) => item.length)) + 2;
    output.stdout(
      `PiShip ${PISHIP_VERSION}\n\nUsage: piship <command> [arguments]\n\nCommands:\n${commands.map((item) => `  ${item.padEnd(width)}${summaries[item]}`).join("\n")}\n\nRun piship <command> --help for a command's arguments and options.\n\nInstall defaults: ${binHome()} (add to PATH yourself)\n\nOptions:\n  -h, --help     Show this help\n  -v, --version  Show PiShip version`,
    );
    return 0;
  }
  if (command === "--version" || command === "-v") {
    output.stdout(PISHIP_VERSION);
    return 0;
  }
  if (!commands.includes(command as (typeof commands)[number])) {
    if (brandedOnlyCommands.includes(command)) {
      output.stderr(
        `${command} is a command of the built distribution, not of piship. Run dist/<id>/bin/<command> ${command} from the directory you built in, or <command> ${command} once it is installed.`,
      );
      return 2;
    }
    const near = nearestField(command, commands);
    output.stderr(
      `Unknown command: ${command}.${near ? ` Did you mean ${near}?` : ""} Run ${pishipCommand()} --help.`,
    );
    return 2;
  }
  // Before anything touches the file system asynchronously: the pool size is
  // read when it first runs.
  if (command === "install" || command === "update") raiseThreadpool();
  const lifecycle = lifecycleCommands[command];
  // --help anywhere after the command asks for help; it is never a target.
  if (args.slice(1).some((arg) => arg === "--help" || arg === "-h")) {
    output.stdout(commandHelp(command));
    return 0;
  }
  if (lifecycle) {
    const parsed = parseArguments(lifecycle, args.slice(1));
    if (!parsed) {
      output.stderr(
        usageError(
          command,
          lifecycle.usage,
          argumentProblem(
            command,
            [
              ...lifecycle.values,
              ...lifecycle.flags,
              ...(lifecycle.repeated ?? []),
            ],
            [...lifecycle.values, ...(lifecycle.repeated ?? [])],
            lifecycle.positional[1],
            args.slice(1),
          ),
        ),
      );
      return 2;
    }
    try {
      return await runLifecycle(command, parsed, output);
    } catch (error) {
      output.stderr(
        error instanceof ManifestError
          ? redact(error.message)
          : formatError(error),
      );
      return 1;
    }
  }
  const [given, ...rest] =
    command === "config"
      ? [args[1], ...args.slice(2)]
      : positionalFirst(args.slice(1), command === "init" ? ["--id"] : []);
  const target = manifestCommands.includes(command)
    ? manifestPath(given, command === "inspect")
    : given;
  if (command === "config") {
    if (target !== "explain" || rest.length !== 1) {
      output.stderr(
        usageError(
          command,
          simpleUsage.config,
          argumentProblem(command, [], [], 2, args.slice(1)),
        ),
      );
      return 2;
    }
  } else if (
    command === "init" &&
    rest.includes("--personal") &&
    rest.includes("--managed")
  ) {
    output.stderr(
      `Choose one of --personal or --managed, not both.\nUsage: piship ${simpleUsage.init}`,
    );
    return 2;
  } else if (command === "init") {
    if (!target || !parseInitOptions(rest)) {
      output.stderr(
        usageError(
          command,
          simpleUsage.init,
          argumentProblem(
            command,
            ["--personal", "--managed", "--id"],
            ["--id"],
            1,
            args.slice(1),
          ),
        ),
      );
      return 2;
    }
  } else if (
    !target ||
    (rest.length && !allowedOptions[command]?.includes(rest.join(" ")))
  ) {
    output.stderr(
      usageError(
        command,
        simpleUsage[command],
        argumentProblem(
          command,
          (allowedOptions[command] ?? []).flatMap((item) => item.split(" ")),
          [],
          1,
          args.slice(1),
        ) ??
          (!target && manifestCommands.includes(command)
            ? "No piship.yaml in this directory; pass the manifest or its directory."
            : undefined),
      ),
    );
    return 2;
  }
  if (!target) return 2;
  try {
    if (command === "init") {
      const { managed, id } = parseInitOptions(rest) ?? { managed: false };
      // Probed before anything is written; a directory that init will refuse
      // costs the probe at most its timeout.
      const [bundleSearchTools, npm] = managed
        ? [true, true]
        : await Promise.all([
            searchToolsDownloadable(),
            searchToolsDownloadable("https://registry.npmjs.org/"),
          ]);
      const created = initDistribution(target, {
        managed,
        bundleSearchTools,
        ...(id === undefined ? {} : { id }),
      });
      if (!bundleSearchTools) output.stderr(SEARCH_TOOLS_SKIPPED);
      if (!npm) output.stderr(NPM_REGISTRY_UNREACHABLE);
      const self = pishipCommand();
      const at = shellArg(created);
      output.stdout(
        managed
          ? `Created ${created}\nNext: ${self} validate ${at}; it lists the runtime variables to set on each machine. Replace example/coder with your gateway's model IDs before you build.`
          : `Created ${created}\nNext: ${self} validate ${at}, then ${self} test ${at} (the first test writes piship.lock; build and release need that lock to be current).`,
      );
    } else if (command === "validate") {
      const manifest = readManifest(target);
      checkPiVersion(manifest);
      // The same resource and governance checks as lock, without writing it.
      checkGovernance(manifest, target, resolveResources(manifest, target));
      const unenforced = checkEnforceability(manifest);
      checkDataContract(manifest);
      checkToolExposure(manifest);
      const searchTools = checkSearchTools(manifest);
      // updates.source is read only by update; launch never needs it.
      const variables = runtimeVariableUse(manifest);
      const unset = (names: readonly string[]) =>
        names.filter((name) => !process.env[name]);
      const missingLaunch = unset(variables.launch);
      const missingUpdate = unset(variables.update);
      output.stdout(
        [
          "Manifest is valid.",
          `Schema ${manifest.schema}, mode ${manifest.deployment.mode}.`,
          ...(manifest.governance?.policy.userAuto
            ? [
                manifest.governance.policy.userAuto === "allowed"
                  ? "policy.userAuto: allowed (each user may switch on auto mode, which approves asks from the distribution defaults without a prompt; deny and enforced rules still apply)."
                  : "policy.userAuto: off (users cannot switch on auto mode).",
              ]
            : []),
          ...(variables.launch.length
            ? [
                `Runtime variables needed at launch (read from the environment of the process that starts the command, never locked): ${variables.launch.join(", ")}`,
              ]
            : []),
          ...(variables.update.length
            ? [
                `Runtime variables needed only by update: ${variables.update.join(", ")}`,
              ]
            : []),
          ...(searchTools.length
            ? [
                `Bundled search tools: ${searchTools.map((item) => `${item.tool} ${item.version}`).join(", ")} for ${searchTools[0]?.targets.join(", ")}; piship lock downloads the upstream archives.`,
              ]
            : []),
          ...(manifest.lifecycle?.updates.transport
            ? [
                `Update transport ${manifest.lifecycle.updates.transport}${manifest.lifecycle.updates.transport === "http-allowed" ? ": the update channel may use plain HTTP to a private or internal host; integrity by signature only" : ""}.`,
              ]
            : []),
          `Next: ${pishipCommand()} test ${shellArg(target)} writes piship.lock if needed, builds, and runs the acceptance smoke; ${pishipCommand()} lock ${shellArg(target)} only writes the lock.`,
        ].join("\n"),
      );
      for (const warning of [
        ...launchWarnings(manifest),
        ...unapprovedLoadWarnings(manifest),
        ...checkSkills(manifest, target),
      ])
        output.stderr(`Warning: ${warning.path}: ${warning.message}`);
      for (const item of unenforced)
        output.stderr(
          `${item.level === "info" ? "Note" : "Warning"}: ${item.message}`,
        );
      const theyAre = (names: readonly string[]) =>
        names.length > 1 ? "they are" : "it is";
      const them = (names: readonly string[]) =>
        names.length > 1 ? "them" : "it";
      if (missingLaunch.length)
        output.stderr(
          `Note: ${missingLaunch.join(", ")} not set in this shell; the branded command fails with CONFIG_UNAVAILABLE until ${theyAre(missingLaunch)} set in the environment it is started from. An IDE or desktop launcher does not read your shell profile; a plain https URL in piship.yaml needs no variable.`,
        );
      if (missingUpdate.length)
        output.stderr(
          `Note: ${missingUpdate.join(", ")} not set in this shell; only update reads ${them(missingUpdate)}, and update fails until ${theyAre(missingUpdate)} set. Launch does not need ${them(missingUpdate)}.`,
        );
    } else if (command === "migrate") {
      const list = (items: readonly string[]) =>
        items.map((item) => `  - ${item}`).join("\n");
      if (rest[0] === "--check") {
        // Read-only: the manifest text is classified and nothing is written.
        // Exit 0 migratable, 1 requires review, 3 cannot migrate.
        const source = readManifestSource(target);
        const check = checkManifestMigration(source);
        if (check.verdict === "cannot migrate") {
          output.stdout(
            `Migration check -> ${check.to}\nResult: cannot migrate`,
          );
          output.stderr(`Cannot migrate ${target}: ${check.reason}`);
          return 3;
        }
        // The lock refuses a Pi pin this PiShip does not carry, so a manifest
        // that migrates cleanly can still need its pin reviewed.
        const pin = readManifest(target).runtime.pi;
        const review = [
          ...check.review,
          ...(pin === undefined || pin === PI_VERSION
            ? []
            : [piPinReview(pin)]),
        ];
        if (!check.changes.length && !review.length)
          output.stdout(`Already ${check.to}; nothing to migrate.`);
        else {
          output.stdout(
            `Migration check ${check.from} -> ${check.to}\nResult: ${review.length ? "requires review" : "migratable"}\n${list(check.changes)}`,
          );
          if (review.length) {
            output.stderr(
              `Review before migrating ${target} (${review.length} item(s)):\n${list(review)}`,
            );
            return 1;
          }
        }
      } else {
        const plan = migrateManifestSource(readManifestSource(target));
        if (!plan.changes.length)
          output.stdout(`Already ${plan.to}; nothing to migrate.`);
        else if (rest[0] === "--write") {
          writeFileSync(target, plan.source);
          output.stdout(
            `Migrated ${target} from ${plan.from} to ${plan.to}:\n${list(plan.changes)}`,
          );
          if (plan.effective.length || plan.review.length)
            output.stderr(
              `Review the result (${plan.effective.length + plan.review.length} item(s)):\n${list([...plan.effective, ...plan.review])}`,
            );
        } else
          output.stdout(
            `Migration plan ${plan.from} -> ${plan.to} (dry run; add --write to apply):\n${list(plan.changes)}\n\n${plan.source}`,
          );
        // A stale Pi pin is the usual reason to run this after a PiShip
        // upgrade, so say how to fix it even when nothing else changes.
        const pin = readManifest(target).runtime.pi;
        if (pin !== undefined && pin !== PI_VERSION)
          output.stderr(`Note: ${piPinReview(pin)}`);
      }
    } else if (command === "config") {
      const configTarget = manifestPath(rest[0], true) ?? "";
      const path = resolve(configTarget);
      if (existsSync(path) && statSync(path).isFile()) {
        // Explain straight from the manifest; no artifact is assembled.
        const manifest = readManifest(configTarget);
        checkPiVersion(manifest);
        output.stdout(
          formatExplanation(
            manifest.app.name,
            await explainConfiguration({
              app: manifest.app,
              mode: manifest.deployment.mode,
              access: manifest.access,
              stateDir: runtimeStateDirectory({ value: manifest.app.id }),
              distributionDir: dirname(path),
              schema: manifest.schema,
              ...(manifest.governance
                ? { governance: manifest.governance }
                : {}),
              ...(manifest.lifecycle
                ? { updates: manifest.lifecycle.updates }
                : {}),
              ...(manifest.runtime.searchTools
                ? {
                    searchTools: {
                      fd:
                        manifest.runtime.searchTools.fd ??
                        SEARCH_TOOL_SPECS.fd.defaultVersion,
                      rg:
                        manifest.runtime.searchTools.rg ??
                        SEARCH_TOOL_SPECS.rg.defaultVersion,
                    },
                  }
                : {}),
            }),
          ),
        );
      } else {
        const artifact = artifactFor(configTarget, command, output.stderr);
        const app = payloadApp(artifact);
        const result = runLauncher(artifact, app.command, [
          "config",
          "explain",
        ]);
        if (result.status !== 0)
          throw new Error(result.stderr || String(result.status));
        output.stdout(result.stdout.trimEnd());
      }
    } else if (command === "lock") {
      const progress = progressReporter(output.stderr);
      await downloadSearchToolArchives(target, progress ? { progress } : {});
      const first = !existsSync(join(dirname(target), "piship.lock"));
      const written = lockManifest(target);
      const locked = readManifest(target);
      // The same warnings validate prints; dev and test lock without them.
      for (const warning of [
        ...launchWarnings(locked),
        ...unapprovedLoadWarnings(locked),
      ])
        output.stderr(`Warning: ${warning.path}: ${warning.message}`);
      output.stdout(
        first
          ? `Wrote ${written}\nNext: ${pishipCommand()} test ${shellArg(target)} builds and runs the acceptance smoke; ${pishipCommand()} build ${shellArg(target)} assembles the payload to install.`
          : `Wrote ${written}\nNext: ${pishipCommand()} diff <previous piship.lock> ${shellArg(written)} reviews what changed and what to check; ${pishipCommand()} test ${shellArg(target)} builds and runs the acceptance smoke.`,
      );
    } else if (command === "build") {
      const progress = progressReporter(output.stderr);
      await downloadLockedSearchTools(
        requireCurrentLock(target),
        undefined,
        progress ? { progress } : {},
      );
      const built = buildDistribution(target, undefined, {
        reclaimStaging: rest.includes("--reclaim-staging"),
        cache: !rest.includes("--rebuild"),
        ...(rest.includes("--rebuild") ? {} : { runtimeCache: true as const }),
        abandonedStaging: (found) => output.stderr(stagingNotice(found)),
        onPackageFootprint: (report) => {
          for (const line of describeFootprint(report)) output.stderr(line);
        },
        ...(progress ? { progress } : {}),
      });
      markLocalBuild(built);
      output.stderr(unqualifiedBuildNotice(target));
      output.stdout(
        `Built ${built}\nNext: ${pishipCommand()} test ${shellArg(target)} runs the acceptance smoke, then node ${shellArg(join(built, "piship.mjs"))} install ${shellArg(built)} installs it for this user.`,
      );
    } else if (command === "purge") {
      if (!rest.includes("--yes"))
        throw new Error(
          "Purge deletes this distribution's state; repeat with --yes after checking the id",
        );
      output.stdout(
        purgeReport(
          await purgeDistributionState(target, {
            withoutLogout: rest.includes("--without-logout"),
          }),
          output,
        ),
      );
      removeEmptyPiShipDirectories();
    } else if (command === "inspect") {
      const path = resolve(target);
      const info =
        existsSync(path) && statSync(path).isFile()
          ? (() => {
              const lock = requireCurrentLock(target);
              return inspection(
                lock,
                runtimeStateDirectory({ value: lock.app.id }),
              );
            })()
          : (() => {
              const artifact = artifactFor(target, command, output.stderr);
              const lock = verifyPayload(artifact);
              return inspection(
                lock,
                runtimeStateDirectory({ value: lock.app.id }),
                artifact,
              );
            })();
      output.stdout(
        rest.includes("--json")
          ? JSON.stringify(info, null, 2)
          : `${formatInspection(info)}\nRun ${pishipCommand()} inspect ${shellArg(target)} --json for the full locked configuration.`,
      );
    } else if (command === "dev" || command === "test") {
      // Before any lock or build: the branded refusal would name a command
      // that is not installed, followed by "Pi launch failed: 1".
      if (
        command === "dev" &&
        rest[0] !== "--smoke" &&
        !(process.stdin.isTTY && process.stdout.isTTY)
      )
        throw new Error(
          `${pishipCommand()} dev starts the interactive session and needs a terminal. Without one, run ${pishipCommand()} dev ${shellArg(target)} --smoke (the headless launch, JSON) or ${pishipCommand()} test ${shellArg(target)} (the acceptance smoke).`,
        );
      const manifest = readManifest(target);
      for (const warning of checkSkills(manifest, target))
        output.stderr(`Warning: ${warning.path}: ${warning.message}`);
      await prepareLock(target, manifest, output);
      const progress = progressReporter(output.stderr);
      await downloadLockedSearchTools(
        requireCurrentLock(target),
        undefined,
        progress ? { progress } : {},
      );
      // Local iteration: the supply-chain gates run on build and release.
      const artifact = buildDistribution(target, undefined, {
        supplyChainGates: false,
        runtimeCache: true,
        // dev and test take no --reclaim-staging; build does.
        abandonedStaging: (found) =>
          output.stderr(
            stagingNotice(
              found,
              `run ${pishipCommand()} build ${shellArg(target)} --reclaim-staging`,
            ),
          ),
        ...(progress ? { progress } : {}),
      });
      markLocalBuild(artifact);
      const lock = requireCurrentLock(target);
      // `dev --smoke` runs the same isolated launch headlessly, for scripts.
      const interactive = command === "dev" && rest[0] !== "--smoke";
      // State this launch creates is marked, so the first install adopts it.
      const result = withTestState({ value: lock.app.id }, () =>
        runLauncher(
          artifact,
          lock.app.command,
          command === "test"
            ? [rest.includes("--model-request") ? "--smoke-model" : "--smoke"]
            : interactive
              ? []
              : ["--smoke"],
          interactive,
        ),
      );
      if (result.status !== 0) {
        // The branded "Run <command> login" names a command not installed
        // yet; the test state signs in through the built one.
        const signIn = /\b(IDENTITY_REQUIRED|CREDENTIAL_REQUIRED)\b/.test(
          result.stderr,
        );
        // The hint replaces the branded action line, not adds to it.
        const stderr = signIn
          ? result.stderr
              .split("\n")
              .filter(
                (line) => line !== `Action: Run ${lock.app.command} login`,
              )
              .join("\n")
          : result.stderr;
        const hint = signIn
          ? `\nThis build is not installed: sign in to the test state with ${shellArg(join(artifact, "bin", process.platform === "win32" ? `${lock.app.command}.cmd` : lock.app.command))} login, then run ${pishipCommand()} ${command} ${shellArg(target)} again. The first install adopts that state.`
          : // The branded "Ask your administrator" speaks to users; whoever
            // runs this test build is the one who chooses the values.
            /\bCONFIG_UNAVAILABLE: Runtime variables? /.test(result.stderr)
            ? `\nFor this test build, set them in this shell (staging values will do), then run ${pishipCommand()} ${command} ${shellArg(target)} again. ${pishipCommand()} validate ${shellArg(target)} lists them.`
            : "";
        throw new Error(`Pi launch failed: ${stderr || result.status}${hint}`);
      }
      if (command === "test")
        output.stdout(
          rest.includes("--json")
            ? result.stdout.trim()
            : `${lock.deployment.mode === "managed" ? "Managed" : "Personal"} acceptance passed\n${formatSmokeSummary(result.stdout.trim())}\nNext: ${pishipCommand()} build ${shellArg(target)} assembles the payload with the supply-chain checks, then node ${shellArg(join(artifact, "piship.mjs"))} install ${shellArg(artifact)} installs it for this user.`,
        );
      else if (!interactive) output.stdout(result.stdout.trim());
    } else if (command === "doctor") {
      const artifact = artifactFor(target, command, output.stderr);
      const app = payloadApp(artifact);
      const lock = verifyPayload(artifact);
      const json = rest[0] === "--json";
      const distribution = { id: app.id, version: app.version };
      let report: string[] | undefined;
      if (lock.access || lock.governance) {
        const result = runLauncher(artifact, app.command, ["doctor"]);
        report = result.stdout.trimEnd().split("\n");
        if (!json) output.stdout(result.stdout.trimEnd());
        if (result.status !== 0) {
          if (json)
            output.stdout(
              JSON.stringify({ distribution, healthy: false, report }, null, 2),
            );
          throw new Error(result.stderr.trim() || "doctor found problems");
        }
      }
      const result = runLauncher(artifact, app.command, ["--smoke"]);
      if (result.status !== 0)
        throw new Error(`Pi launch failed: ${result.stderr || result.status}`);
      const smoke = result.stdout.trim();
      if (json) {
        let parsed: unknown = smoke;
        try {
          parsed = JSON.parse(smoke);
        } catch {
          // Kept as text.
        }
        output.stdout(
          JSON.stringify(
            {
              distribution,
              healthy: true,
              ...(report ? { report } : {}),
              smoke: parsed,
            },
            null,
            2,
          ),
        );
      } else
        output.stdout(
          `Healthy ${app.id}@${app.version}\n${formatSmokeSummary(smoke)}`,
        );
    }
    return 0;
  } catch (error) {
    output.stderr(
      error instanceof ManifestError
        ? redact(error.message)
        : formatError(error),
    );
    return 1;
  }
}

async function runLifecycle(
  command: string,
  { positional, options, flags, repeated }: Parsed,
  output: CliOutput,
): Promise<number> {
  const [first = "", second = ""] = positional;
  if (command === "install") {
    if (isDistributionSource(resolve(first))) throw notBuilt(first, command);
    // The build said what it is; saying it again at the install that follows
    // on the same machine only repeats it.
    if (
      isUnqualifiedPayload(resolve(first)) &&
      !isLocalBuildOnThisHost(resolve(first))
    )
      output.stderr(
        `Warning: ${first} is an unqualified local build, not a release: it was not audited and has no SBOM, notices, or recorded tests. Install it for local testing only; use the release piship release builds, or your publisher's, for anything else.`,
      );
    // A first install has nothing to check a channel signature against; the
    // publisher's digest is what ties a copied archive to its source.
    if (
      options["--sha256"] === undefined &&
      statSync(resolve(first), { throwIfNoEntry: false })?.isFile()
    )
      output.stderr(
        `Warning: ${first} is a local archive, so no channel signature was verified for it. Pass --sha256 with the digest its publisher printed (and --expect-key) to check it; later updates through the installed command's update verify the signed channel.`,
      );
    const receipt = await installDistribution(
      first,
      flags.has("--use-existing-state"),
      {
        ...(options["--sha256"] !== undefined
          ? { expectedSha256: options["--sha256"] }
          : {}),
        ...(repeated["--expect-key"]
          ? { expectedKeys: repeated["--expect-key"] }
          : {}),
        ...(flags.has("--replace") ? { replace: true } : {}),
        ...(options["--runtime"] ? { runtime: options["--runtime"] } : {}),
      },
    );
    output.stdout(
      [
        `Installed ${receipt.app.id}@${receipt.app.version}: ${receipt.commandPath}`,
        pathHint(dirname(receipt.commandPath)),
        installNext(
          receipt,
          signedInClasses(
            runtimeStateDirectory({ value: receipt.app.id }),
          ).includes("an identity session"),
        ),
      ]
        .filter(Boolean)
        .join("\n"),
    );
  } else if (command === "release") {
    const built = await buildRelease(first, {
      ...(options["--out"] ? { outputRoot: options["--out"] } : {}),
      ...(options["--channel"] ? { channel: options["--channel"] } : {}),
      cache: !flags.has("--rebuild"),
      reclaimStaging: flags.has("--reclaim-staging"),
      abandonedStaging: (found) => output.stderr(stagingNotice(found)),
      progress: progressReporter(output.stderr),
    });
    output.stdout(
      `Built qualified release ${built.name} (built for channel ${built.metadata.channel})\n  archive  ${built.archive}\n  sha256   ${built.sha256}\n  tests    ${built.metadata.tests.map((test) => test.name).join(", ")}\n  SBOM     ${built.metadata.sbom.packages} packages\n  qualified: dependency audit, registry signatures, SBOM, notices, and the release tests passed\nThe release is not signed yet: users get it through a signed channel or verified provenance.\nNext: ${pishipCommand()} verify-release ${shellArg(built.archive)} (ideally on another machine), then ${pishipCommand()} sign-channel <channel-dir> ${shellArg(built.archive)} --channel candidate --key <private-key-file> --key-id <id>`,
    );
    // Where the runtime came from is no part of the release, so it goes to
    // stderr and to the build-info file beside the archive.
    output.stderr(runtimeCacheLine(built.runtimeCache));
  } else if (command === "runtime-release") {
    const built = await buildRuntimeRelease({
      ...(options["--out"] ? { outputRoot: options["--out"] } : {}),
      cache: !flags.has("--rebuild"),
      reclaimStaging: flags.has("--reclaim-staging"),
      abandonedStaging: (found) => output.stderr(stagingNotice(found)),
      progress: progressReporter(output.stderr),
    });
    output.stdout(
      `Built qualified runtime release ${built.name}\n  archive  ${built.archive}\n  sha256   ${built.sha256}\n  tests    ${built.metadata.tests.map((test) => test.name).join(", ")}\n  SBOM     ${built.metadata.sbom.packages} packages\n  qualified: dependency audit, registry signatures, SBOM, notices, and the runtime test passed\nThe runtime release is not signed: publish it with verified provenance.\nNext: ${pishipCommand()} verify-release ${shellArg(built.archive)}, then ${pishipCommand()} pack <piship.yaml> --runtime ${shellArg(built.archive)} (one --runtime per target)`,
    );
    output.stderr(runtimeCacheLine(built.runtimeCache));
  } else if (
    command === "verify-release" &&
    (await releaseKind(first)) === "runtime"
  ) {
    const verified = await verifyRuntimeRelease(first, {
      ...(options["--sha256"] ? { expectedSha256: options["--sha256"] } : {}),
    });
    try {
      const { metadata } = verified;
      output.stdout(
        flags.has("--json")
          ? JSON.stringify(metadata, null, 2)
          : `Verified PiShip runtime ${metadata.pishipVersion} for ${metadata.target}\n  Pi ${metadata.pi.version} (compatibility: ${metadata.pi.compatibility}), npm lock ${metadata.npmLockSha256}\n  payload ${metadata.inventory.files} files match their inventory\n  SBOM ${metadata.sbom.packages} packages, notices, checksums, and vulnerability scan (${metadata.vulnerabilities.verdict}, fail on ${metadata.vulnerabilities.failOn}) verified\n  tests ${metadata.tests.map((test) => test.name).join(", ")}\n  qualification ${metadata.qualification}\nPublisher identity is not checked here: verify the build provenance.`,
      );
    } finally {
      verified.cleanup();
    }
  } else if (command === "pack") {
    if (!repeated["--runtime"]?.length) {
      output.stderr(`Usage: piship ${lifecycleCommands.pack?.usage}`);
      return 2;
    }
    const built = await buildPack(first, {
      runtimes: repeated["--runtime"],
      ...(options["--out"] ? { outputRoot: options["--out"] } : {}),
      reclaimStaging: flags.has("--reclaim-staging"),
      abandonedStaging: (found) => output.stderr(stagingNotice(found)),
    });
    const { targets, excluded, runtimeSettings } = built.metadata;
    for (const warning of built.warnings) output.stderr(`Warning: ${warning}`);
    if (runtimeSettings.overridden.length)
      output.stderr(
        `Warning: ${runtimeSettings.overridden.join(" and ")} set to false is ignored; a pack runs on the bundled, stripped runtime.`,
      );
    output.stdout(
      `Built Company Pack ${built.name}\n  archive   ${built.archive}\n  sha256    ${built.sha256}\n  targets   ${targets.join(", ")}${Object.entries(
        excluded,
      )
        .map(([target, reason]) => `\n  excluded  ${target}: ${reason}`)
        .join(
          "",
        )}\nThis pack is unsigned and was not composed or tested with a runtime here: publish it through a signed channel.\nNext: ${pishipCommand()} sign-channel <channel-dir> ${built.archive} --channel candidate --key <private-key-file> --key-id <id>${repeated["--runtime"].map((item) => ` --runtime ${item}`).join("")}`,
    );
  } else if (command === "verify-release") {
    const verified = await verifyRelease(first, {
      ...(options["--sha256"] ? { expectedSha256: options["--sha256"] } : {}),
    });
    try {
      const { metadata } = verified;
      output.stdout(
        flags.has("--json")
          ? JSON.stringify(metadata, null, 2)
          : `Verified ${metadata.distribution.name} ${metadata.distribution.version} for ${metadata.target} (built for channel ${metadata.channel})\n  PiShip ${metadata.piship.version}, Pi ${metadata.pi.version} (compatibility: ${metadata.pi.compatibility})\n  payload ${metadata.payload.files} files match their inventory\n  SBOM ${metadata.sbom.packages} packages, notices, checksums, and vulnerability scan (${metadata.vulnerabilities.verdict}, fail on ${metadata.vulnerabilities.failOn}) verified\n  tests ${metadata.tests.map((test) => test.name).join(", ")}\n  qualification ${metadata.qualification ?? "not recorded (built before PiShip recorded it)"}\nPublisher identity is not checked here: verify the channel signature or build provenance.`,
      );
    } finally {
      verified.cleanup();
    }
  } else if (command === "diff") {
    const before = await lockFor(first);
    const after = await lockFor(second);
    let report: ReturnType<typeof diffLocks>;
    try {
      report = diffLocks(before, after);
    } catch (error) {
      // A lock with the right schema name but fields of the wrong shape.
      if (!(error instanceof TypeError)) throw error;
      throw new PiShipError(
        "LOCK_INVALID",
        `${first} or ${second} has a field of the wrong type, so the two cannot be compared`,
        {
          component: "cli",
          userAction:
            "Pass locks that piship lock wrote, or a manifest, payload, release, or installed id",
        },
      );
    }
    output.stdout(
      flags.has("--json")
        ? JSON.stringify(report, null, 2)
        : formatDiff(report).trimEnd(),
    );
  } else if (command === "uninstall") {
    if (
      (flags.has("--yes") || flags.has("--without-logout")) &&
      !flags.has("--purge")
    ) {
      output.stderr(`Usage: piship ${lifecycleCommands.uninstall?.usage}`);
      return 2;
    }
    const removeEditedShim = flags.has("--remove-edited-shim");
    if (!flags.has("--purge"))
      output.stdout(
        `Uninstalled ${first}. State preserved: ${uninstallDistribution(first, { removeEditedShim })}\nTo delete it: ${pishipCommand()} purge ${shellArg(first)} --yes`,
      );
    else {
      if (!flags.has("--yes"))
        throw new Error(
          "Uninstall with --purge also deletes this distribution's state; repeat with --yes after checking the id",
        );
      // The installed release is often the only PiShip the user has, so the
      // purge happens here rather than after it is gone.
      output.stdout(
        `Uninstalled ${first}. ${purgeReport(
          await uninstallAndPurgeDistribution(first, {
            withoutLogout: flags.has("--without-logout"),
            removeEditedShim,
          }),
          output,
        )}`,
      );
    }
    removeEmptyPiShipDirectories();
  } else if (command === "update" || command === "rollback") {
    // The active release performs the switch so its audit and credential
    // handling apply.
    const receipt = readInstallReceipt(first);
    const args = [command, ...Object.entries(options).flat(), ...[...flags]];
    // From a terminal, the release's progress and notices are shown as
    // they come; otherwise its stderr is printed once it is done.
    const live = !!progressReporter(output.stderr);
    const result = live
      ? await runLauncherLive(
          receipt.payload,
          receipt.app.command,
          args,
          output.stderr,
        )
      : runLauncher(receipt.payload, receipt.app.command, args);
    if (result.stdout.trim()) output.stdout(result.stdout.trimEnd());
    if (result.status !== 0) {
      // Shown live already, unless the release did not start.
      if (!live || result.stderr.trim())
        output.stderr(result.stderr.trim() || `${command} failed`);
      return 1;
    }
    if (result.stderr.trim()) output.stderr(result.stderr.trimEnd());
  } else if (command === "repair") {
    // Runs here, not through the installed release: the payload it restores
    // may be the active one, which refuses to run.
    const result = await repairDistribution(first, second, {
      ...(options["--runtime"] ? { runtime: options["--runtime"] } : {}),
    });
    output.stdout(
      result.status === "intact"
        ? `${result.id} ${result.version} is intact; nothing to repair`
        : `Repaired ${result.id} ${result.version} from ${second}\n  was: ${result.problem}`,
    );
  } else if (command === "migrate-check") {
    const receipt = readInstallReceipt(first);
    const current = verifyPayload(receipt.payload);
    const path = resolve(second);
    const verified =
      statSync(path).isFile() || existsSync(join(path, "release.json"))
        ? await verifyRelease(path)
        : undefined;
    try {
      const target = verified?.lock ?? verifyPayload(path);
      if (target.app.id !== first)
        throw new Error(`${second} is ${target.app.id}, not ${first}`);
      const report = checkStateMigration(
        runtimeStateDirectory({ value: first }),
        {
          version: target.app.version,
          pi: target.runtime.version,
          schemas:
            verified?.metadata.stateSchemas ?? payloadStateSchemas(target),
          ...storageOf(target),
        },
        {
          version: receipt.active,
          pi: current.runtime.version,
          ...storageOf(current),
        },
      );
      output.stdout(formatMigrationReport(report));
      if (report.verdict === "unsupported") return 1;
    } finally {
      verified?.cleanup();
    }
  } else if (command === "keygen") {
    const id = options["--id"];
    if (!id) throw new Error("keygen needs --id <key-id>");
    const input = passphraseInput(options, flags);
    if (flags.has("--show-public")) {
      if (flags.has("--encrypt") || flags.has("--force-in-worktree"))
        throw new Error(
          "--show-public reads an existing key; it takes no --encrypt or --force-in-worktree",
        );
      const [signer] = await pemSigners([{ id, file: first }], input, output);
      const publicKey = (signer as KeyedSigner).publicKey;
      output.stdout(
        `Public key: ${publicKey}\nFingerprint: ${keyFingerprint(publicKey)}\nAdd it to the next root with: ${pishipCommand()} trust-root next ... --add-key ${id}=${publicKey}\nOr pin it in a new bootstrap with: ${pishipCommand()} trust-root init --key ${id}=${publicKey} ...`,
      );
      return 0;
    }
    if (!flags.has("--encrypt") && (input.env !== undefined || input.stdin))
      throw new Error("--passphrase-env and --passphrase-stdin need --encrypt");
    const pair = generateSigningKey(
      id,
      flags.has("--encrypt")
        ? {
            passphrase: await readSigningPassphrase(
              `Passphrase for the new key ${first}`,
              { ...input, confirm: true },
            ),
          }
        : {},
    );
    const location = writePrivateKey(first, pair.privateKeyPem, {
      forceInWorktree: flags.has("--force-in-worktree"),
    });
    if (location === "tracked-worktree")
      output.stderr(
        `Warning: ${first} is inside a git work tree and not git-ignored; do not commit it.`,
      );
    output.stdout(
      `Wrote the private key to ${first}. Keep it out of the repository and out of CI logs.\nPublic key: ${pair.publicKey}\nFingerprint: ${keyFingerprint(pair.publicKey)}\nPin it in piship.yaml through ${pishipCommand()} trust-root init --key ${id}=${pair.publicKey} ... (or publish it in the next root with ${pishipCommand()} trust-root next --add-key).`,
    );
  } else if (command === "sign-channel") {
    const channel = options["--channel"];
    const keys = repeated["--key"] ?? [];
    const keyIds = repeated["--key-id"] ?? [];
    if (!channel || !keys.length || !keyIds.length)
      throw new Error("sign-channel needs --channel, --key, and --key-id");
    if (keys.length !== keyIds.length)
      throw new Error("Give one --key-id for each --key, in the same order");
    const sequence = positiveInteger(options["--sequence"], "--sequence");
    const expiresDays = positiveInteger(
      options["--expires-days"],
      "--expires-days",
    );
    const previous = options["--previous-key"];
    const split = previous?.indexOf("=") ?? -1;
    if (previous !== undefined && split < 1)
      throw new Error("--previous-key must be <id>=<public-key>");
    const [signer, ...additionalSigners] = await pemSigners(
      keys.map((file, index) => ({ id: keyIds[index] as string, file })),
      passphraseInput(options, flags),
      output,
    );
    // A Company Pack is listed under `packs`, a release archive under `releases`.
    const artifacts = positional.slice(1);
    // Archives already in the channel directory were added by an earlier run.
    const before = existsSync(first) ? readdirSync(first) : [];
    const kinds = await Promise.all(artifacts.map((item) => isPack(item)));
    const signed = await signChannel({
      directory: first,
      channel,
      archives: artifacts.filter((_, index) => !kinds[index]),
      packs: artifacts.filter((_, index) => kinds[index]),
      runtimes: repeated["--runtime"] ?? [],
      signer: signer as KeyedSigner,
      additionalSigners,
      ...(previous
        ? {
            previousKeys: [
              {
                id: previous.slice(0, split),
                publicKey: previous.slice(split + 1),
              },
            ],
          }
        : {}),
      ...(sequence ? { sequence } : {}),
      ...(expiresDays ? { expiresDays } : {}),
    });
    // A pack's runtime archives are published beside it.
    const added = artifacts.map((item) => basename(item));
    const runtimeArchives = (signed.metadata.packs ?? [])
      .filter((item) => added.includes(item.archive))
      .flatMap((item) => Object.values(item.runtimes).map((r) => r.archive));
    output.stdout(
      `Signed ${signed.path} (sequence ${signed.metadata.sequence}, expires ${signed.metadata.expires}) with ${keyIds.join(", ")}:\n${[
        ...signed.metadata.releases.map(
          (item) => `  ${item.version} ${item.target} ${item.archive}`,
        ),
        ...(signed.metadata.packs ?? []).map(
          (item) => `  ${item.version} pack ${item.archive}`,
        ),
      ].join(
        "\n",
      )}\n${publishSteps(channel, [...added, ...new Set(runtimeArchives)], signed.metadata.expires, new Date(), { present: before, newestRoot: newestRootVersion(join(first, "root")) })}`,
    );
  } else if (command === "trust-root") {
    const expiry = {
      ...(options["--expires"] !== undefined
        ? { expires: options["--expires"] }
        : {}),
      ...(options["--expires-days"] !== undefined
        ? {
            expiresDays: positiveInteger(
              options["--expires-days"],
              "--expires-days",
            ) as number,
          }
        : {}),
    };
    const roles = {
      ...(options["--root-keys"] !== undefined
        ? { rootKeyIds: idList(options["--root-keys"]) as string[] }
        : {}),
      ...(options["--channel-keys"] !== undefined
        ? { channelKeyIds: idList(options["--channel-keys"]) as string[] }
        : {}),
      ...(options["--root-threshold"] !== undefined
        ? {
            rootThreshold: positiveInteger(
              options["--root-threshold"],
              "--root-threshold",
            ) as number,
          }
        : {}),
      ...(options["--channel-threshold"] !== undefined
        ? {
            channelThreshold: positiveInteger(
              options["--channel-threshold"],
              "--channel-threshold",
            ) as number,
          }
        : {}),
    };
    const publicKeys = (values: readonly string[], option: string) =>
      pairs(values, option, "public-key").map((item) => ({
        id: item.id,
        publicKey: item.value,
      }));
    if (first === "init" && positional.length === 1) {
      if (!roles.rootKeyIds || !roles.channelKeyIds)
        throw new Error("trust-root init needs --root-keys and --channel-keys");
      const described = initTrustRoot({
        ...expiry,
        ...roles,
        rootKeyIds: roles.rootKeyIds,
        channelKeyIds: roles.channelKeyIds,
        keys: publicKeys(repeated["--key"] ?? [], "--key"),
      });
      for (const warning of described.warnings)
        output.stderr(`Warning: ${warning}`);
      output.stdout(
        `Add this bootstrap root to piship.yaml (schema piship/v1alpha5 or later). If piship.yaml already has an updates: block, put the trust: block under it instead of adding a second updates: line:\n\n${described.yaml}\nKey fingerprints:\n${described.fingerprints.map((key) => `  ${key.id} ${key.fingerprint}`).join("\n")}`,
      );
    } else if (first === "next" && positional.length === 2) {
      const manifest = options["--manifest"];
      if (!manifest) throw new Error("trust-root next needs --manifest");
      const signers = await pemSigners(
        pairs(repeated["--sign"] ?? [], "--sign", "private-key-file").map(
          (item) => ({ id: item.id, file: item.value }),
        ),
        passphraseInput(options, flags),
        output,
      );
      const result = await nextTrustRoot({
        repository: second,
        manifest,
        ...expiry,
        ...roles,
        addKeys: publicKeys(repeated["--add-key"] ?? [], "--add-key"),
        removeKeys: repeated["--remove-key"] ?? [],
        signers,
      });
      output.stdout(
        `Wrote ${result.path} and its signature: root ${result.previous.version} -> ${result.root.version}, expires ${result.root.expires}, signed by ${result.signedBy.join(", ")}\n  root role     ${result.root.roles.root.threshold} of ${result.root.roles.root.keyIds.join(", ")}\n  channel role  ${result.root.roles.channel.threshold} of ${result.root.roles.channel.keyIds.join(", ")}\n${rootPublishSteps(
          second,
          result.root.version,
          result.root.expires,
          result.root.roles.channel.keyIds.filter(
            (id) => !result.previous.roles.channel.keyIds.includes(id),
          ),
        )}`,
      );
    } else {
      output.stderr(`Usage: piship ${lifecycleCommands["trust-root"]?.usage}`);
      return 2;
    }
  } else if (command === "reproducibility") {
    const report = await compareReleases(first, second);
    const text = `${JSON.stringify(report, null, 2)}\n`;
    if (options["--out"])
      (await import("node:fs")).writeFileSync(options["--out"], text);
    output.stdout(text.trimEnd());
    if (!report.payloadEqual) {
      output.stderr(
        `Payloads differ in ${report.payloadDifferences.length} file(s) for ${report.target}`,
      );
      return 1;
    }
  }
  return 0;
}
