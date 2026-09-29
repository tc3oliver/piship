import { spawn } from "node:child_process";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { createInterface } from "node:readline";
import { LocalMetrics } from "@piship/audit";
import {
  PiShipError,
  applyProcessNetworkPolicy,
  assertTlsVerificationEnabled,
  formatError,
  principalId,
  redact,
  sanitizeManagedEnvironment,
} from "@piship/contracts";
import {
  CredentialManager,
  createSecretStore,
  deleteSecretsVerified,
  isLockTimeout,
  metadataFileSecretRefs,
  metadataFileSecretStore,
  metadataSecretRefs,
  type SecretStoreProvider,
  storeForRecorded,
  withFileLock,
} from "@piship/credentials";
import { type IdentityMetadata, parseIdentityMetadata } from "@piship/identity";
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

/**
 * Read a secret without it reaching argv, the environment, shell history, or
 * the terminal: a prompt on stderr with no echo, or the first line of a piped
 * stdin (for provisioning from a secret manager).
 */
export async function readSecretInput(prompt: string): Promise<string> {
  if (!process.stdin.isTTY) {
    let data = "";
    for await (const chunk of process.stdin) data += chunk;
    return data.split(/\r?\n/)[0] ?? "";
  }
  process.stderr.write(`${prompt}: `);
  const rl = createInterface({
    input: process.stdin,
    output: undefined,
    terminal: true,
  });
  const answer = await new Promise<string>((resolveAnswer) =>
    rl.question("", resolveAnswer),
  );
  rl.close();
  process.stderr.write("\n");
  return answer;
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
  let result: Awaited<ReturnType<typeof access.login>>;
  try {
    result = await access
      .login({
        openUrl: (url) => {
          ctx.err(`Open this URL in your browser to sign in:\n${url}`);
          openBrowser(url);
        },
        readSecret: readSecretInput,
      })
      .finally(() => saveMetrics(metrics));
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
    beforeExpirySeconds: 0,
    onEvent,
  });
  // Both locks, credential then identity, as every other writer takes them:
  // a refresh in another process that holds the identity lock finishes
  // first, and cannot store the session again after this deleted it.
  return manager.exclusive(async () => {
    const problems = (await manager.logout({ distributionId: id })).map(
      (problem) => redact(problem),
    );
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
          secretStore: store,
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
      `Signed out of ${ctx.metadata.app.name}. Local runtime and identity credentials were cleared; sessions were preserved.`,
    );
    return;
  }
  const cleared = classes
    .filter(([key]) => before[key] && !existsSync(paths[key]))
    .map(([, name]) => name);
  const many = kept.length > 1;
  throw new PiShipError(
    "SECRET_STORE_UNAVAILABLE",
    `Signed out of ${ctx.metadata.app.name} only in part: ${cleared.length ? `${cleared.join(" and ")} ${cleared.length > 1 ? "were" : "was"} cleared, but ` : ""}${kept.join(" and ")} could not be deleted from the secret store. ${many ? "They are" : "It is"} never used and ${many ? "stay" : "stays"} tracked, so the next login or logout deletes ${many ? "them" : "it"}; sessions were preserved`,
    {
      component: "credential",
      userAction: `Unlock or repair the secret store, then run ${ctx.metadata.app.command} logout again`,
    },
  );
}
