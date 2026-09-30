import { spawn, spawnSync } from "node:child_process";
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
import { basename, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createSecretStore } from "@piship/credentials";
import { readManifestDocument } from "@piship/schema";
import {
  type AuthorizationRequest,
  authorizationRequest,
  signInAtKeycloak,
} from "./keycloak.js";
import { PROJECT_PREFIX } from "../../../../tests/enterprise-reference/stack.js";
import { type ReferenceUser, referenceDirectory, type Stack } from "./stack.js";
import { type ChannelHost, serveChannel } from "./updates.js";

// The AcmeCode reference distribution as a user has it: built from the
// committed manifest, installed with the manager the build ships, and driven
// through its installed command against a live stack.

const root = fileURLToPath(new URL("../../../../", import.meta.url));
/** The built PiShip CLI, for a test that runs it directly. */
export const cliPath = join(root, "packages/cli/dist/bin.js");
/**
 * The installed launcher's name, as the committed manifest gives it
 * (`app.command`): the one place the reference tests learn it, so renaming it
 * is a change to the manifest and its lock and to nothing here.
 */
export const launcherCommand = (
  readManifestDocument(join(referenceDirectory, "piship.yaml")) as {
    app: { command: string };
  }
).app.command;
// Below vitest's testTimeout (120 s in vitest.reference.config.ts), so a hung
// command is killed and fails with its own output rather than a bare timeout.
const RUN_TIMEOUT_MS = 100_000;

export type StoreMode = "system" | "file";

/**
 * Which secret store the run uses. The platform store writes to the login
 * keychain or keyring of whoever runs the tests, so, like the platform-store
 * test, it runs only when `PISHIP_LIVE_SECRET_STORE=1` says one is live (the
 * CI check jobs set it). It never falls back: with the variable set and no
 * usable store, sign-in fails with SECRET_STORE_UNAVAILABLE. Otherwise the
 * distribution is built with the restricted file store, opted in the way the
 * managed E2E does.
 */
export function storeMode(): StoreMode {
  if (process.env.PISHIP_LIVE_SECRET_STORE !== "1") return "file";
  // On macOS the platform store is the login keychain of the real HOME: a
  // run on a developer's Mac would write to and delete from it.
  if (process.platform === "darwin" && !process.env.CI)
    throw new Error(
      "PISHIP_LIVE_SECRET_STORE=1 on macOS uses the login keychain; the reference tests refuse it outside CI",
    );
  return "system";
}

/** The `Secret Store` line of `doctor` for a mode on this host. */
export function storeDescription(mode: StoreMode): string {
  if (mode === "file") return "restricted plaintext file";
  if (process.platform === "darwin") return "macOS Keychain";
  if (process.platform === "win32") return "Windows Credential Manager";
  return "Linux Secret Service";
}

export interface Result {
  readonly status: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

export interface Login extends Result {
  /** The authorization request PiShip sent to the identity provider. */
  readonly authorization: AuthorizationRequest;
}

/** The secret material PiShip holds for the signed-in user. */
export interface StoredSecrets {
  readonly credentialId: string;
  readonly credential: string;
  readonly accessToken: string;
  readonly idToken: string;
  readonly refreshToken: string;
  /** Every value above except the ID, for scanning. */
  readonly values: readonly string[];
}

export interface Installed {
  readonly store: StoreMode;
  readonly temp: string;
  /**
   * The throwaway home directory the commands run with, which is their
   * `HOME` except with the platform store on macOS, where the keychain needs
   * the real one.
   */
  readonly home: string;
  /** `PISHIP_STATE_HOME`. */
  readonly state: string;
  /** The distribution's own state directory inside it. */
  readonly stateRoot: string;
  readonly install: string;
  /** The built artifact, before installation. */
  readonly artifact: string;
  /** The installed command. */
  readonly command: string;
  readonly env: NodeJS.ProcessEnv;
  /** The PiShip CLI (`piship <args>`) in this scenario's environment. */
  cli(...args: string[]): Result;
  /** Run the installed command. */
  run(
    args: readonly string[],
    env?: NodeJS.ProcessEnv,
    options?: RunOptions,
  ): Promise<Result>;
  /** Run `login` and complete the sign-in on Keycloak as `user`. */
  login(user: ReferenceUser): Promise<Login>;
  /** Run `--smoke` and parse its JSON. */
  smoke(args?: readonly string[]): Promise<Smoke>;
  /** The secrets PiShip holds now, read back through its secret store. */
  secrets(): Promise<StoredSecrets | undefined>;
  /** Everything the installed command printed so far. */
  output(): string;
  /**
   * Offer the signed 1.1.0 release on the update channel, so `update` finds
   * it. Needs `updates: true`; the release itself was built at install time.
   */
  publishUpdate(): void;
  /** Paths the update host was asked for, in order. Needs `updates: true`. */
  updateRequests(): readonly string[];
  remove(): void;
}

export interface RunOptions {
  /** The directory to run in; the sandbox's workspace is the launching one. */
  readonly cwd?: string;
  /** Kill the command after this long (default 100 s). */
  readonly timeoutMs?: number;
}

export interface Smoke {
  readonly resumed: boolean;
  readonly sessionId: string;
  readonly sessionDir: string;
  readonly access: {
    readonly identity: { readonly subject: string; readonly issuer: string };
    readonly credential: {
      readonly mode: string;
      readonly credentialId: string;
      readonly expiresAt?: string;
    };
    readonly selectedModel?: string;
    readonly allowedModels: readonly string[];
    readonly models: readonly {
      readonly id: string;
      readonly available: boolean;
      readonly reason?: string;
    }[];
    readonly removedEnvironment: readonly string[];
    readonly notices: readonly string[];
  };
  readonly modelRequest?: {
    readonly model: string;
    readonly text: string;
    readonly stopReason: string;
    readonly toolResults: number;
  };
  readonly governance?: {
    readonly workflowMode: string;
    readonly sandbox: {
      readonly level: string;
      readonly adapter: string;
      readonly network: string;
    };
  };
}

const AMBIENT_KEYS = {
  OPENAI_API_KEY: "sk-ambient-personal-key-reference",
  ANTHROPIC_API_KEY: "sk-ant-ambient-personal-key-reference",
};
const PROXY_VARIABLES = [
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "ALL_PROXY",
  "NO_PROXY",
  "http_proxy",
  "https_proxy",
  "all_proxy",
  "no_proxy",
];

function baseEnvironment(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env };
  // E2E and reference tests build from packages/core/dist/build-input.
  for (const name of [
    "PISHIP_BUILD_INPUT",
    "PISHIP_SANDBOX_ADAPTER",
    ...PROXY_VARIABLES,
  ])
    delete env[name];
  // The live provider's key and settings are for the gateway only.
  for (const name of Object.keys(env))
    if (name.startsWith("LIVE_PROVIDER_")) delete env[name];
  return env;
}

interface ManifestPatch {
  readonly store: StoreMode;
  readonly allowedModels?: readonly string[];
  /** Shell commands allowed, in Build mode: what the sandbox step needs. */
  readonly commands?: boolean;
  /** The owner's release key, for a distribution that can update. */
  readonly releaseKey?: { readonly id: string; readonly publicKey: string };
}

/** The committed manifest with the edits a scenario needs, each checked. */
function patchManifest(source: string, patch: ManifestPatch): string {
  let text = source;
  if (patch.store === "file") {
    const next = text.replace(
      "provider: system",
      "provider: file\n    acknowledgePlaintext: true",
    );
    if (next === text) throw new Error("the storage provider was not patched");
    text = next;
  }
  if (patch.allowedModels) {
    const next = text.replace(
      /( {2}allowed:\n)(?: {4}- \S+\n)+/,
      (_, head: string) =>
        `${head}${patch.allowedModels?.map((id) => `    - ${id}\n`).join("")}`,
    );
    if (next === text) throw new Error("models.allowed was not patched");
    // A catalog entry must be allowed too, so the entries that are not go.
    const pruned = next.replace(
      / {4}(\S+):\n(?: {6}\S.*\n)+/g,
      (entry, id: string) =>
        patch.allowedModels?.includes(id) || !id.startsWith("acme/")
          ? entry
          : "",
    );
    if (pruned === next) throw new Error("models.catalog was not patched");
    text = pruned;
  }
  if (patch.commands) {
    const shell =
      ' - id: acme.shell\n      action: shell.execute\n      resource: "**"\n      effect:';
    const next = text
      .replace("defaultMode: plan", "defaultMode: build")
      .replace(`${shell} ask`, `${shell} allow`);
    if (
      !next.includes("defaultMode: build") ||
      !next.includes(`${shell} allow`)
    )
      throw new Error("the command policy was not patched");
    text = next;
  }
  if (patch.releaseKey) {
    const next = text.replace(
      "    keys: []",
      `    keys:\n      - id: ${patch.releaseKey.id}\n        publicKey: ${patch.releaseKey.publicKey}`,
    );
    if (next === text) throw new Error("the release key was not pinned");
    text = next;
  }
  return text;
}

/** The ID of the release key a distribution that can update pins. */
const KEY_ID = "acme-reference-e2e";

export interface InstallOptions {
  /** A name for the temporary directory. */
  readonly name: string;
  /** Narrow `models.allowed`, for the entitlement-intersection scenario. */
  readonly allowedModels?: readonly string[];
  /**
   * Let the manifest run the agent's shell commands, in Build mode, inside
   * the required sandbox. As committed it asks before each one, which a
   * headless run resolves to a denial.
   */
  readonly commands?: boolean;
  /**
   * Make the distribution updatable: pin a release key, build a 1.1.0 release
   * signed onto a channel, and serve that channel over loopback HTTP as
   * `ACMECODE_UPDATE_SOURCE`, empty until `publishUpdate()`. The second
   * release is built with `piship release`, so this takes about as long again
   * as the install.
   */
  readonly updates?: boolean;
}

/**
 * Build the reference distribution from a copy of its committed files and
 * install it into a temporary install home with its own state. An unmodified
 * system-store build uses the committed lock as it is, which `piship build`
 * refuses when it is stale; any edited manifest is locked first.
 */
export async function installDistribution(
  stack: Stack,
  options: InstallOptions,
): Promise<Installed> {
  // Named like the stack's directory, so global setup removes it after a
  // killed run.
  const temp = mkdtempSync(
    join(tmpdir(), `${PROJECT_PREFIX}${process.pid}-${options.name}-`),
  );
  try {
    return await assemble(stack, options, temp);
  } catch (error) {
    rmSync(temp, { recursive: true, force: true });
    throw error;
  }
}

async function assemble(
  stack: Stack,
  options: InstallOptions,
  temp: string,
): Promise<Installed> {
  const store = storeMode();
  const directory = join(temp, "distribution");
  mkdirSync(directory);
  for (const entry of ["piship.yaml", "piship.lock", "resources"])
    cpSync(join(referenceDirectory, entry), join(directory, entry), {
      recursive: true,
    });
  const manifest = join(directory, "piship.yaml");
  const committed = readFileSync(manifest, "utf8");

  const state = join(temp, "state");
  const install = join(temp, "install");
  const binHome = join(temp, "bin");
  const home = join(temp, "home");
  mkdirSync(home);
  const env: NodeJS.ProcessEnv = {
    ...baseEnvironment(),
    ...stack.variables,
    ...AMBIENT_KEYS,
    PISHIP_STATE_HOME: state,
    PISHIP_INSTALL_HOME: install,
    PISHIP_BIN_HOME: binHome,
    PISHIP_NO_BROWSER: "1",
  };
  // macOS resolves its default keychain through HOME: under another HOME, the
  // platform store has nowhere to write. Every other case is isolated.
  if (!(store === "system" && process.platform === "darwin")) {
    env.HOME = home;
    env.USERPROFILE = home;
  }

  const outputs: string[] = [];
  const cli = (...args: string[]): Result => {
    const done = spawnSync(process.execPath, [cliPath, ...args], {
      cwd: temp,
      env,
      encoding: "utf8",
    });
    return { status: done.status, stdout: done.stdout, stderr: done.stderr };
  };
  const must = (result: Result, what: string): Result => {
    if (result.status !== 0)
      throw new Error(
        `${what} failed (exit ${result.status}):\n${result.stderr}`,
      );
    return result;
  };

  // An updatable distribution pins the owner's release key and offers its
  // update on a channel of its own, served over loopback HTTP.
  let releaseKey: { id: string; publicKey: string } | undefined;
  let channel: ChannelHost | undefined;
  const channelDirectory = join(temp, "channel");
  const staged = join(temp, "channel-staged");
  const keyFile = join(temp, "keys", "release.pem");
  if (options.updates) {
    mkdirSync(join(temp, "keys"));
    mkdirSync(channelDirectory);
    mkdirSync(staged);
    const keygen = must(
      cli("keygen", keyFile, "--id", KEY_ID),
      "piship keygen",
    );
    const publicKey = /publicKey: (\S+)/.exec(keygen.stdout)?.[1];
    if (!publicKey) throw new Error("keygen printed no public key");
    releaseKey = { id: KEY_ID, publicKey };
    channel = await serveChannel(channelDirectory);
    env.ACMECODE_UPDATE_SOURCE = channel.url;
  }

  try {
    const patched = patchManifest(committed, {
      store,
      ...(options.allowedModels
        ? { allowedModels: options.allowedModels }
        : {}),
      ...(options.commands ? { commands: true } : {}),
      ...(releaseKey ? { releaseKey } : {}),
    });
    writeFileSync(manifest, patched);
    if (patched !== committed) must(cli("lock", manifest), "piship lock");
    must(cli("build", manifest), "piship build");
    if (releaseKey) stageUpdate(patched);
  } catch (error) {
    channel?.close();
    throw error;
  }
  const artifact = join(temp, "dist", "acmecode-reference");
  const installed = spawnSync(
    process.execPath,
    [join(artifact, "piship.mjs"), "install", artifact],
    { cwd: temp, env, encoding: "utf8" },
  );
  if (installed.status !== 0) {
    channel?.close();
    throw new Error(
      `install failed (exit ${installed.status}):\n${installed.stderr}`,
    );
  }
  const command = join(binHome, launcherCommand);
  const stateRoot = join(state, "acmecode-reference");

  /**
   * Build the 1.1.0 release from the manifest just installed and sign a
   * channel that offers it, without putting it on the served channel yet.
   */
  function stageUpdate(installedManifest: string): void {
    const next = join(temp, "next");
    mkdirSync(next);
    cpSync(join(directory, "resources"), join(next, "resources"), {
      recursive: true,
    });
    const bumped = installedManifest.replace(
      /^ {2}version: 1\.0\.0$/m,
      "  version: 1.1.0",
    );
    if (bumped === installedManifest)
      throw new Error("the version was not bumped");
    const nextManifest = join(next, "piship.yaml");
    writeFileSync(nextManifest, bumped);
    must(cli("lock", nextManifest), "piship lock (1.1.0)");
    must(
      cli("release", nextManifest, "--out", join(next, "out")),
      "piship release (1.1.0)",
    );
    const archive = join(
      next,
      "out",
      "releases",
      `acmecode-reference-1.1.0-${process.platform}-${process.arch}.tar.gz`,
    );
    if (!existsSync(archive))
      throw new Error(`piship release built no ${basename(archive)}`);
    const copy = join(staged, basename(archive));
    cpSync(archive, copy);
    must(
      cli(
        "sign-channel",
        staged,
        copy,
        "--channel",
        "stable",
        "--key",
        keyFile,
        "--key-id",
        KEY_ID,
        "--sequence",
        "1",
      ),
      "piship sign-channel",
    );
  }

  function run(
    args: readonly string[],
    extra: NodeJS.ProcessEnv = {},
    signIn?: (url: string) => Promise<void>,
    options: RunOptions = {},
  ): Promise<Result & { authorizeUrl?: string }> {
    return new Promise((resolve, reject) => {
      const child = spawn(command, [...args], {
        cwd: options.cwd ?? temp,
        env: { ...env, ...extra },
      });
      let stdout = "";
      let stderr = "";
      let authorizeUrl: string | undefined;
      let failure: Error | undefined;
      const timer = setTimeout(() => {
        failure = new Error(`${args.join(" ")} did not finish in time`);
        child.kill("SIGKILL");
      }, options.timeoutMs ?? RUN_TIMEOUT_MS);
      child.stdout.on("data", (chunk) => {
        stdout += chunk;
      });
      child.stderr.on("data", (chunk) => {
        stderr += chunk;
        const match = /(http:\/\/127\.0\.0\.1:\d+\/realms\/\S+)/.exec(stderr);
        if (match?.[1] && signIn && !authorizeUrl) {
          authorizeUrl = match[1];
          signIn(authorizeUrl).catch((error: Error) => {
            failure = error;
            child.kill("SIGKILL");
          });
        }
      });
      child.stdin.end();
      child.on("close", (status) => {
        clearTimeout(timer);
        outputs.push(stdout, stderr);
        if (failure) reject(failure);
        else
          resolve({
            status,
            stdout,
            stderr,
            ...(authorizeUrl ? { authorizeUrl } : {}),
          });
      });
    });
  }

  const readJson = <T>(path: string): T | undefined =>
    existsSync(path)
      ? (JSON.parse(readFileSync(path, "utf8")) as T)
      : undefined;

  return {
    store,
    temp,
    home,
    state,
    stateRoot,
    install,
    artifact,
    command,
    env,
    cli,
    run: (args, extra, options) => run(args, extra, undefined, options),
    async login(user) {
      const done = await run(["login"], {}, (url) =>
        signInAtKeycloak(url, user, stack.password(user)),
      );
      if (!done.authorizeUrl)
        throw new Error(`login printed no sign-in URL:\n${done.stderr}`);
      return {
        ...done,
        authorization: authorizationRequest(done.authorizeUrl),
      };
    },
    async smoke(args = []) {
      const done = await run([...args, "--smoke"]);
      if (done.status !== 0)
        throw new Error(
          `--smoke failed (exit ${done.status}):\n${done.stderr}`,
        );
      return JSON.parse(done.stdout) as Smoke;
    },
    async secrets() {
      const session = readJson<{ secretRef: string }>(
        join(stateRoot, "identity", "session.json"),
      );
      const metadata = readJson<{
        credential_id: string;
        credential_ref: string;
      }>(join(stateRoot, "credentials-metadata", "inference.json"));
      if (!session || !metadata) return undefined;
      const secretStore = createSecretStore({
        provider: store,
        fileDirectory: join(stateRoot, "secrets"),
      });
      const bundle = await secretStore.get(session.secretRef);
      const credential = await secretStore.get(metadata.credential_ref);
      if (!bundle || !credential) return undefined;
      const tokens = JSON.parse(bundle.reveal()) as {
        accessToken: string;
        idToken: string;
        refreshToken: string;
      };
      return {
        credentialId: metadata.credential_id,
        credential: credential.reveal(),
        ...tokens,
        values: [
          credential.reveal(),
          tokens.accessToken,
          tokens.idToken,
          tokens.refreshToken,
        ],
      };
    },
    output: () => outputs.join("\n"),
    publishUpdate() {
      if (!channel) throw new Error("no update channel: install with updates");
      for (const name of readdirSync(staged))
        cpSync(join(staged, name), join(channelDirectory, name));
    },
    updateRequests() {
      if (!channel) throw new Error("no update channel: install with updates");
      return channel.requests;
    },
    remove() {
      channel?.close();
      rmSync(temp, { recursive: true, force: true });
    },
  };
}

/**
 * Paths under `directory` whose contents include one of `secrets`. With the
 * file store the `secrets` directory is where secrets belong, so it is
 * skipped; a test checks it separately.
 */
export function scan(directory: string, secrets: readonly string[]): string[] {
  const hits: string[] = [];
  const visit = (path: string) => {
    for (const name of readdirSync(path)) {
      const child = join(path, name);
      if (statSync(child).isDirectory()) {
        if (name !== "node_modules" && name !== "secrets") visit(child);
      } else {
        const text = readFileSync(child, "latin1");
        for (const secret of secrets)
          if (secret && text.includes(secret))
            hits.push(`${child} contains ${secret.slice(0, 6)}…`);
      }
    }
  };
  visit(directory);
  return hits;
}

/**
 * The values the restricted file store holds, decoded, one per secret file
 * (the store keeps each one base64url-encoded, so a plain scan of its files
 * cannot find a secret). Empty with the platform store, which keeps no file.
 */
export function fileStoreValues(stateRoot: string): string[] {
  const directory = join(stateRoot, "secrets");
  if (!existsSync(directory)) return [];
  return readdirSync(directory)
    .filter((name) => name.endsWith(".secret"))
    .map((name) => {
      const record = JSON.parse(
        readFileSync(join(directory, name), "utf8"),
      ) as { value: string };
      return Buffer.from(record.value, "base64url").toString("utf8");
    });
}

/** The secrets of `secrets` that appear in `text`, as short prefixes that are safe to print in a failure. */
export function leaks(text: string, secrets: readonly string[]): string[] {
  return secrets
    .filter((secret) => secret && text.includes(secret))
    .map((secret) => `${secret.slice(0, 6)}…`);
}
