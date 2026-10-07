import { spawn } from "node:child_process";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { createInterface } from "node:readline";
import { LocalMetrics } from "@piship/audit";
import {
  PiShipError,
  applyProcessNetworkPolicy,
  assertTlsVerificationEnabled,
  formatError,
  isLoopbackHost,
  principalId,
  redact,
  sanitizeManagedEnvironment,
} from "@piship/contracts";
import {
  CredentialManager,
  createSecretStore,
  deleteSecretsVerified,
  droppedReferencesNotice,
  isLockTimeout,
  metadataFileSecretRefs,
  metadataFileSecretStore,
  metadataSecretRefs,
  type SecretStoreProvider,
  storeForRecorded,
  withFileLock,
} from "@piship/credentials";
import {
  DEFAULT_LOGIN_TIMEOUT_MS,
  type IdentityMetadata,
  parseIdentityMetadata,
} from "@piship/identity";
import type { AccessManifest } from "@piship/schema";
import {
  type AccessEvent,
  type DistributionAccess,
  accessStatePaths,
  networkPolicyFor,
  SandboxCredential,
  writeIdentityDiscardedMarker,
} from "../access/index.js";
import { removeAccessTemporaries } from "../install/temporaries.js";
import { sweepDistributionData } from "./data.js";
import {
  type BrandedContext,
  auditAccess,
  eventDetail,
  openAccess,
  recordAudit,
  saveMetrics,
} from "./context.js";

function openBrowser(url: string): void {
  if (process.env.PISHIP_NO_BROWSER === "1") return;
  try {
    const child =
      process.platform === "darwin"
        ? spawn("open", [url], { stdio: "ignore", detached: true })
        : process.platform === "win32"
          ? spawn("rundll32", ["url.dll,FileProtocolHandler", url], {
              stdio: "ignore",
              detached: true,
            })
          : spawn("xdg-open", [url], { stdio: "ignore", detached: true });
    child.on("error", () => {});
    child.unref();
  } catch {
    // The URL is always printed; opening a browser is a convenience.
  }
}

function isRemoteShell(env: NodeJS.ProcessEnv): boolean {
  return !!(env.SSH_CONNECTION || env.SSH_CLIENT || env.SSH_TTY);
}

/**
 * Whether `login` listens for a pasted redirect: where the browser cannot
 * return to this machine. That is a remote shell, `PISHIP_NO_BROWSER=1`, a
 * Linux session with no display, or a container. There is no way to know for
 * certain that the browser is elsewhere, so these are the signals that rarely
 * misfire; with a local browser nothing reads stdin, so a stray line typed
 * while the sign-in page is open cannot end the login. WSL is not treated as
 * headless: it reaches a browser on the Windows side.
 */
export function pasteFallbackEnabled(
  env: NodeJS.ProcessEnv,
  host: {
    platform?: NodeJS.Platform;
    exists?: (path: string) => boolean;
  } = {},
): boolean {
  if (env.PISHIP_NO_BROWSER === "1" || isRemoteShell(env)) return true;
  if ((host.platform ?? process.platform) !== "linux") return false;
  if (env.WSL_DISTRO_NAME) return false;
  const exists = host.exists ?? existsSync;
  if (
    env.KUBERNETES_SERVICE_HOST ||
    exists("/.dockerenv") ||
    exists("/run/.containerenv")
  )
    return true;
  return !env.DISPLAY && !env.WAYLAND_DISPLAY;
}

/**
 * Read one pasted line from stdin for the login's paste fallback. It ends
 * (stdin closes its interface and is paused again) when `signal` aborts, and
 * stays pending when stdin ends without a line, so the loopback keeps working.
 */
export function readRedirectLine(
  signal: AbortSignal,
  notice?: string,
): Promise<string> {
  if (notice) process.stderr.write(`${notice}\n`);
  return new Promise<string>((resolve) => {
    // terminal: false keeps Ctrl-C as a plain SIGINT for untilInterrupted.
    const rl = createInterface({ input: process.stdin, terminal: false });
    const stop = () => rl.close();
    rl.once("line", (line) => {
      signal.removeEventListener("abort", stop);
      rl.close();
      resolve(line);
    });
    if (signal.aborted) stop();
    else signal.addEventListener("abort", stop, { once: true });
  });
}

/**
 * What `login` prints under the authorization URL while it waits, in English
 * and Traditional Chinese, one pair of lines per message. A loopback
 * `redirect_uri` in the URL names where the browser must return. Where it
 * cannot return (see `pasteFallbackEnabled`) the hint says to paste the
 * address instead. The timeout is named only when it is known.
 */
export function loginWaitingHint(
  url: string,
  options: { timeoutMs?: number; paste: boolean },
): string {
  const plain = [
    "Waiting for sign-in to complete in the browser. Press Ctrl-C to cancel.",
    "等待在瀏覽器完成登入，按 Ctrl-C 取消。",
  ].join("\n");
  let redirect: URL;
  try {
    redirect = new URL(new URL(url).searchParams.get("redirect_uri") ?? "");
  } catch {
    return plain;
  }
  if (redirect.protocol !== "http:" || !isLoopbackHost(redirect.hostname))
    return plain;
  const minutes =
    options.timeoutMs === undefined
      ? undefined
      : Math.round(options.timeoutMs / 60_000);
  const target = `${redirect.origin}${redirect.pathname}`;
  const lines = [
    `Waiting${minutes ? ` up to ${minutes} minute${minutes === 1 ? "" : "s"}` : ""} for the browser to return to ${target}. Press Ctrl-C to cancel.`,
    `等待瀏覽器返回 ${target}${minutes ? `（最多 ${minutes} 分鐘）` : ""}，按 Ctrl-C 取消。`,
    "If the browser shows an identity provider error, press Ctrl-C and ask your administrator to check the client ID and redirect URI.",
    "若瀏覽器顯示身分提供者的錯誤，請按 Ctrl-C，並請管理員檢查 client ID 與 redirect URI。",
  ];
  if (options.paste)
    lines.push(
      `No browser here? Open the URL on any computer, sign in, then paste the full address it ends on (\u201ccan't connect\u201d is expected) here and press Enter.`,
      "這裡沒有瀏覽器？在任何電腦開啟網址登入，把最後的完整網址（顯示「無法連線」屬正常）貼到這裡，按 Enter。",
    );
  return lines.join("\n");
}

/**
 * Run `work` with a signal that Ctrl-C aborts, so a login waiting for the
 * browser ends as a cancelled sign-in and closes its listener. The handler is
 * there once, so a second Ctrl-C gets Node's default and ends the process.
 * After the browser part only the identity wait honors the signal: a Ctrl-C
 * while the credential is replaced under its lock lets that finish.
 */
export async function untilInterrupted<T>(
  work: (signal: AbortSignal) => Promise<T>,
): Promise<T> {
  const controller = new AbortController();
  const interrupt = () => controller.abort();
  process.once("SIGINT", interrupt);
  try {
    return await work(controller.signal);
  } finally {
    process.off("SIGINT", interrupt);
  }
}

/** No secret was entered: the prompt was cancelled or stdin ended. */
function noSecretEntered(): PiShipError {
  return new PiShipError(
    "CREDENTIAL_REQUIRED",
    "No secret was entered: the prompt was cancelled or input ended",
    { component: "credential" },
  );
}

/**
 * Read a secret without it reaching argv, the environment, shell history, or
 * the terminal: a prompt on stderr with no echo, or the first line of a piped
 * stdin (for provisioning from a secret manager). Ctrl-C, Ctrl-D, or the end
 * of stdin before a line rejects, so the caller's cleanup (a lock it holds)
 * still runs.
 */
export async function readSecretInput(prompt: string): Promise<string> {
  process.stderr.write(`${prompt}: `);
  if (!process.stdin.isTTY) {
    // The first line is enough: a pipe left open after it must not hang.
    let data = "";
    for await (const chunk of process.stdin) {
      data += chunk;
      if (/[\r\n]/.test(data)) break;
    }
    process.stderr.write("\n");
    if (!data) throw noSecretEntered();
    return data.split(/\r?\n/)[0] ?? "";
  }
  const rl = createInterface({
    input: process.stdin,
    output: undefined,
    terminal: true,
  });
  try {
    // Closing the interface (Ctrl-D, end of input) never calls the question
    // callback, and a SIGINT listener keeps Ctrl-C from closing it silently.
    return await new Promise<string>((resolveAnswer, reject) => {
      rl.once("close", () => reject(noSecretEntered()));
      rl.once("SIGINT", () => reject(noSecretEntered()));
      rl.question("", resolveAnswer);
    });
  } finally {
    rl.close();
    process.stderr.write("\n");
  }
}

type LoginResult = Awaited<ReturnType<DistributionAccess["login"]>>;

/**
 * The interactive sign-in `login` and a launch's inline sign-in share: the
 * browser hint, the paste fallback, the secret prompt, and Ctrl-C as a
 * cancelled sign-in.
 */
async function interactiveLogin(
  ctx: BrandedContext,
  access: DistributionAccess,
  metrics?: LocalMetrics,
): Promise<LoginResult> {
  // The built-in OIDC login waits for the default timeout; an identity
  // adapter's own wait is not known here.
  const builtIn = ctx.metadata.access?.identity.mode === "oidc";
  const paste = pasteFallbackEnabled(process.env);
  return untilInterrupted((signal) =>
    access.login({
      openUrl: (url) => {
        ctx.err(`Open this URL in your browser to sign in:\n${url}`);
        ctx.err(
          loginWaitingHint(url, {
            ...(builtIn ? { timeoutMs: DEFAULT_LOGIN_TIMEOUT_MS } : {}),
            paste,
          }),
        );
        openBrowser(url);
      },
      readSecret: readSecretInput,
      ...(paste ? { readRedirectUrl: readRedirectLine } : {}),
      signal,
    }),
  ).finally(() => saveMetrics(metrics));
}

/** What a finished sign-in tells the user. */
function reportLogin(
  ctx: BrandedContext,
  access: DistributionAccess,
  result: LoginResult,
): void {
  const identity = result.identity
    ? `Signed in as ${result.identity.displayName ?? result.identity.subject} (${result.identity.issuer}).`
    : "No identity provider is configured.";
  const credential =
    result.credential.state === "delegated"
      ? `Credential: ${access.credentialMode} (no stored secret).`
      : `Credential: ${access.credentialMode} stored in ${access.store?.description ?? "no store"}${result.credential.metadata?.expires_at ? `; expires ${result.credential.metadata.expires_at}` : ""}.`;
  ctx.out(`${identity}\n${credential}`);
  for (const notice of result.notices) ctx.err(`Notice: ${notice}`);
  if (access.store?.kind === "file")
    ctx.err(
      "Warning: credentials use the explicitly enabled plaintext file fallback, not platform secure storage.",
    );
}

/**
 * Whether a launch that finds no sign-in may sign in on the spot: a managed
 * distribution, with a person at the terminal (stdin and stdout both), and
 * not in CI. Everything else keeps the failure that names the login command.
 */
export function inlineLoginOffered(
  mode: BrandedContext["mode"],
  terminal: { stdinTTY: boolean; stdoutTTY: boolean },
  env: NodeJS.ProcessEnv,
): boolean {
  const ci = !!env.CI && env.CI !== "0" && env.CI.toLowerCase() !== "false";
  return mode === "managed" && terminal.stdinTTY && terminal.stdoutTTY && !ci;
}

/**
 * Sign in during a launch that found no usable sign-in: the same login the
 * `login` command runs, on the access the launch already opened. The launch's
 * own listener and audit see its events, so nothing is recorded twice. A
 * failed or cancelled sign-in throws the error `login` would.
 */
export async function loginInline(
  ctx: BrandedContext,
  access: DistributionAccess,
): Promise<void> {
  ctx.err("You are not signed in; signing in now.");
  reportLogin(ctx, access, await interactiveLogin(ctx, access));
}

export async function runLogin(ctx: BrandedContext): Promise<void> {
  if (
    !ctx.metadata.access ||
    ctx.metadata.access.credential.provider === "pi-native"
  )
    throw new PiShipError(
      "POLICY_DENIED",
      "This distribution delegates authentication to Pi; start it and use Pi's /login inside the session",
    );
  assertTlsVerificationEnabled();
  const events: AccessEvent[] = [];
  const metrics = LocalMetrics.load(ctx.stateDir);
  const access = openAccess(ctx, (event) => events.push(event), metrics);
  if (ctx.mode === "managed")
    sanitizeManagedEnvironment(
      process.env,
      access.network,
      ctx.metadata.access.variables,
    );
  applyProcessNetworkPolicy(access.network);
  let result: LoginResult;
  try {
    result = await interactiveLogin(ctx, access, metrics);
  } catch (error) {
    // A login can fail after it stored the new identity or revoked the
    // previous credential (a broker refusal, say): what happened is still
    // recorded, and the login error stays the command's error.
    // Read from the stored session, which needs no credential manager: a
    // credential adapter that failed to load must not turn this into an
    // event about nobody. With no identity provider a leftover session from an
    // earlier configuration is not the user of this login.
    const stored =
      access.identityMode === "none" ? null : access.readIdentityMetadata();
    await auditAccess(
      ctx,
      access,
      stored ? principalId(stored) : null,
      events,
    ).catch((auditError) => ctx.err(`Error: ${formatError(auditError)}`));
    throw error;
  }
  await auditAccess(
    ctx,
    access,
    result.identity ? principalId(result.identity) : null,
    events,
  );
  reportLogin(ctx, access, result);
}

/** The stored identity session's metadata, or null when absent or unreadable. */
function storedIdentity(path: string): IdentityMetadata | null {
  try {
    return parseIdentityMetadata(JSON.parse(readFileSync(path, "utf8")));
  } catch {
    return null;
  }
}

/**
 * Sign out when the access configuration cannot be resolved (a runtime
 * variable that is not set, say) or a provider cannot be loaded. Nothing
 * remote can be contacted, so nothing is revoked, but the local secrets are
 * deleted and the deletion confirmed all the same. A runtime credential the
 * provider could have revoked is recorded as a pending revocation, and
 * identity tokens as not revoked, since both may still be valid remotely.
 * A secret that cannot be deleted keeps its metadata, so it stays tracked.
 * The identity's tokens are deleted from the store its session records,
 * which is not the configured one after a change of storage provider; when
 * that store is not available here they stay tracked in a discarded marker.
 */
async function logoutLocally(
  ctx: BrandedContext,
  manifest: AccessManifest,
  reason: string,
  onEvent: (event: AccessEvent) => void,
): Promise<string[]> {
  const id = ctx.metadata.app.id;
  const paths = accessStatePaths(ctx.stateDir);
  const provider = manifest.credential.storage.provider;
  const storeOf = (which: SecretStoreProvider) =>
    createSecretStore({ provider: which, fileDirectory: paths.secrets });
  const store = storeOf(provider);
  const mode = manifest.credential.provider;
  const revocable =
    mode === "adapter" ||
    (mode === "http-broker" && !!manifest.credential.broker?.revokeEndpoint);
  const manager = new CredentialManager({
    distributionId: id,
    provider: {
      mode,
      requiresIdentity: false,
      acquire: async () => null,
      ...(revocable
        ? {
            revoke: async () => {
              throw new PiShipError(
                "CONFIG_UNAVAILABLE",
                `not attempted: ${reason}`,
              );
            },
          }
        : {}),
    },
    store,
    metadataPath: paths.credential,
    revocationRetryPath: paths.revocationRetry,
    issuancePath: paths.credentialIssuance,
    beforeExpirySeconds: 0,
    onEvent,
  });
  // Both locks, credential then identity, as every other writer takes them:
  // a refresh in another process that holds the identity lock finishes
  // first, and cannot store the session again after this deleted it.
  return manager.exclusive(async () => {
    let dropped: readonly string[] = [];
    const problems = (
      await manager.logout(
        { distributionId: id },
        { onDiscard: (result) => (dropped = result.dropped) },
      )
    ).map((problem) => redact(problem));
    // Shown with the warnings: nothing was deleted for these references.
    if (dropped.length) problems.push(droppedReferencesNotice(dropped));
    if (existsSync(paths.identity))
      await withFileLock(paths.identity, async () => {
        if (!existsSync(paths.identity)) return;
        let raw: unknown = null;
        try {
          raw = JSON.parse(readFileSync(paths.identity, "utf8"));
        } catch {
          // A damaged file still names token bundles in its text (below).
        }
        const refs = [
          ...new Set([
            ...metadataSecretRefs(raw, id),
            ...metadataFileSecretRefs(paths.identity, id, "identity"),
          ]),
        ].sort();
        // The store the session records holds its tokens: looking them up in
        // the configured one would find nothing after a change of storage
        // provider, and the deletion would count as confirmed.
        const recorded = metadataFileSecretStore(paths.identity) ?? provider;
        const identityStore = storeForRecorded(
          store,
          provider,
          recorded,
          storeOf,
        );
        const failed = identityStore
          ? await deleteSecretsVerified(identityStore, refs)
          : refs.map((ref) => ({
              ref,
              problem: `the ${recorded} secret store that holds it is not available`,
            }));
        const tokens = manifest.identity.mode !== "none";
        if (tokens)
          problems.push(`identity revocation: not attempted: ${reason}`);
        for (const item of failed)
          problems.push(`identity secret ${item.ref}: ${item.problem}`);
        onEvent({
          event: "identity.logout",
          detail: { revocation: tokens ? "failed" : "unsupported" },
        });
        // What could not be deleted stays tracked in a discarded marker,
        // which is never restored as a session, instead of as usable
        // metadata.
        if (!failed.length) rmSync(paths.identity, { force: true });
        else
          writeIdentityDiscardedMarker(
            paths.identity,
            failed.map((item) => item.ref),
            new Date(),
            recorded,
          );
      });
    // The stored sandbox credential has no remote revocation to miss. It goes
    // after the identity, so a `sandbox login` that checked the signed-in
    // user before the identity lock was taken is cleared here too.
    problems.push(
      ...(
        await new SandboxCredential({
          distributionId: id,
          command: ctx.metadata.app.command,
          stateDir: ctx.stateDir,
          storage: { provider },
          secretStore: store,
          secretStoreFor: storeOf,
          principal: null,
          onEvent,
        }).clear()
      ).map((problem) => `sandbox credential: ${problem}`),
    );
    return problems;
  });
}

export async function runLogout(ctx: BrandedContext): Promise<void> {
  const manifest = ctx.metadata.access;
  if (!manifest || manifest.credential.provider === "pi-native")
    throw new PiShipError(
      "POLICY_DENIED",
      "This distribution delegates authentication to Pi; use Pi's /logout inside the session",
    );
  assertTlsVerificationEnabled();
  const events: AccessEvent[] = [];
  const onEvent = (event: AccessEvent) => events.push(event);
  const paths = accessStatePaths(ctx.stateDir);
  // Local secrets are cleared even when the runtime configuration cannot be
  // resolved: signing out never depends on a variable being set.
  let access: DistributionAccess | null = null;
  let unavailable: unknown;
  try {
    access = openAccess(ctx, onEvent);
  } catch (error) {
    unavailable = error;
  }
  const network =
    access?.network ?? networkPolicyFor(manifest, undefined, ctx.mode);
  if (ctx.mode === "managed")
    sanitizeManagedEnvironment(process.env, network, manifest.variables);
  applyProcessNetworkPolicy(network);
  const signedIn = storedIdentity(paths.identity);
  const before = {
    identity: existsSync(paths.identity),
    credential: existsSync(paths.credential),
    sandboxCredential: existsSync(paths.sandboxCredential),
  };
  // Only what happened is recorded: credential.revoke with its remote
  // revocation outcome when a credential existed, identity.logout when
  // there was an identity session.
  const auditEvents = () =>
    recordAudit(
      ctx,
      network,
      events.map((event) => ({
        event: event.event,
        user: signedIn ? principalId(signedIn) : null,
        session: null,
        detail: eventDetail(manifest.credential.provider, event.detail),
      })),
    );
  const problems: string[] = [];
  if (access) {
    // What logout found before a lock wait ran out; when the local sign-out
    // redoes the work instead, it is dropped.
    const found: string[] = [];
    try {
      problems.push(...(await access.logout(found)));
    } catch (error) {
      // Another process still holds a lock: nothing is wrong with the
      // configuration, and deleting around that process is what the locks
      // prevent. Say so instead of signing out locally.
      if (isLockTimeout(error)) {
        // What this command already did (a credential it revoked before the
        // identity lock ran out) is still shown and recorded. The lock
        // timeout stays the command's error, which a required audit sink
        // that is down must not replace: it is retryable, the audit failure
        // is reported beside it.
        for (const problem of found) ctx.err(`Warning: ${problem}`);
        await auditEvents().catch((auditError) =>
          ctx.err(`Error: ${formatError(auditError)}`),
        );
        throw error;
      }
      unavailable = error;
    }
  }
  if (unavailable !== undefined) {
    const reason = redact(formatError(unavailable));
    ctx.err(
      `Warning: ${reason}; signing out locally without contacting the identity provider or credential broker`,
    );
    problems.push(...(await logoutLocally(ctx, manifest, reason, onEvent)));
  }
  // A writer killed before its rename leaves a temporary copy of identity or
  // credential metadata; it must not outlive the sign-out.
  try {
    await removeAccessTemporaries(ctx.stateDir);
  } catch (error) {
    problems.push(
      `abandoned temporary identity or credential files could not be removed (${redact(formatError(error))}); the next start removes them`,
    );
  }
  // Revocation problems are shown before auditing, which can fail the command.
  for (const problem of problems) ctx.err(`Warning: ${problem}`);
  await auditEvents();
  // Retention, and the classes the distribution purges at logout. Sessions a
  // running launch holds are kept.
  await sweepDistributionData(ctx, "logout");
  const sessions = ctx.metadata.data?.declared?.purge.onLogout.includes(
    "sessions",
  )
    ? "sessions not in use were removed"
    : "sessions were preserved";
  // Whatever metadata is left names a secret that could not be deleted. A
  // distribution without a stored runtime credential never clears one.
  const classes = [
    ["identity", "the identity session"],
    ...(manifest.credential.provider === "none"
      ? []
      : ([["credential", "the runtime credential"]] as const)),
    ["sandboxCredential", "the sandbox credential"],
  ] as const;
  const kept = classes
    .filter(([key]) => existsSync(paths[key]))
    .map(([, name]) => name);
  if (!kept.length) {
    ctx.out(
      `Signed out of ${ctx.metadata.app.name}. Local runtime and identity credentials were cleared; ${sessions}.`,
    );
    return;
  }
  const cleared = classes
    .filter(([key]) => before[key] && !existsSync(paths[key]))
    .map(([, name]) => name);
  const many = kept.length > 1;
  throw new PiShipError(
    "SECRET_STORE_UNAVAILABLE",
    `Signed out of ${ctx.metadata.app.name} only in part: ${cleared.length ? `${cleared.join(" and ")} ${cleared.length > 1 ? "were" : "was"} cleared, but ` : ""}${kept.join(" and ")} could not be deleted from the secret store. ${many ? "They are" : "It is"} never used and ${many ? "stay" : "stays"} tracked, so the next login or logout deletes ${many ? "them" : "it"}; ${sessions}`,
    {
      component: "credential",
      userAction: `Unlock or repair the secret store, then run ${ctx.metadata.app.command} logout again`,
    },
  );
}
