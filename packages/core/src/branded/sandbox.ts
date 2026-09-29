// `<command> sandbox login` and `<command> sandbox logout`: store or delete
// the sandbox credential of a distribution whose remote sandbox backend
// declares `sandbox.credential: stored`. The secret is read only from a
// no-echo prompt or the first line of a piped stdin, never from argv, the
// environment, or a file, and it is never printed.
import {
  applyProcessNetworkPolicy,
  assertTlsVerificationEnabled,
  formatError,
  type NetworkPolicy,
  PiShipError,
  type PrincipalKey,
  principalId,
  principalKey,
  sanitizeManagedEnvironment,
} from "@piship/contracts";
import { RuntimeReferenceError, resolveTemplate } from "@piship/schema";
import {
  type AccessEvent,
  type DistributionAccess,
  networkPolicyFor,
  SandboxCredential,
} from "../access/index.js";
import { type BrandedContext, openAccess, recordAudit } from "./context.js";
import { readSecretInput } from "./login.js";

function notStored(ctx: BrandedContext): PiShipError {
  return new PiShipError(
    "POLICY_DENIED",
    `${ctx.metadata.app.name} does not use a stored sandbox credential (sandbox.credential: stored)`,
    { component: "sandbox" },
  );
}

/** The resolved endpoint and router the credential is bound to. */
function sandboxTargets(ctx: BrandedContext): string[] {
  const config = ctx.metadata.governance?.manifest.sandbox;
  const variables = ctx.metadata.access?.variables ?? [];
  const targets: string[] = [];
  for (const [field, template] of [
    ["sandbox.endpoint", config?.endpoint],
    ["sandbox.router", config?.router],
  ] as const) {
    if (template === undefined) continue;
    try {
      targets.push(resolveTemplate(field, template, variables, process.env));
    } catch (error) {
      if (!(error instanceof RuntimeReferenceError)) throw error;
      throw new PiShipError("SANDBOX_UNAVAILABLE", error.message, {
        component: "sandbox",
        userAction: error.variable
          ? `Set ${error.variable} to the sandbox service's URL, then run ${ctx.metadata.app.command} sandbox login again`
          : "Fix the sandbox endpoint in piship.yaml",
      });
    }
  }
  return targets;
}

/**
 * Open access, apply its network policy, and resolve the signed-in
 * principal: the stored credential is bound to it. Without an identity
 * provider the principal is null.
 */
async function signedInPrincipal(
  ctx: BrandedContext,
  onEvent: (event: AccessEvent) => void,
): Promise<{
  readonly principal: PrincipalKey | null;
  readonly network: NetworkPolicy;
  readonly access: DistributionAccess | null;
}> {
  if (!ctx.metadata.access)
    return {
      principal: null,
      network: networkPolicyFor(undefined),
      access: null,
    };
  const access = openAccess(ctx, onEvent);
  if (ctx.mode === "managed")
    sanitizeManagedEnvironment(
      process.env,
      access.network,
      ctx.metadata.access.variables,
    );
  applyProcessNetworkPolicy(access.network);
  if (access.identityMode === "none")
    return { principal: null, network: access.network, access };
  const identity = await access.currentIdentity({ required: true });
  return {
    principal: identity ? principalKey(identity) : null,
    network: access.network,
    access,
  };
}

async function audit(
  ctx: BrandedContext,
  network: NetworkPolicy,
  principal: PrincipalKey | null,
  events: readonly AccessEvent[],
): Promise<void> {
  await recordAudit(
    ctx,
    network,
    events.map((event) => ({
      event: event.event,
      user: principal ? principalId(principal) : null,
      session: null,
      detail: event.detail,
    })),
  );
}

async function sandboxLogin(ctx: BrandedContext): Promise<void> {
  const config = ctx.metadata.governance?.manifest.sandbox;
  const declared: string | undefined = config?.credential;
  if (!config?.required || !config.provider || declared !== "stored")
    throw notStored(ctx);
  assertTlsVerificationEnabled();
  const events: AccessEvent[] = [];
  const onEvent = (event: AccessEvent) => events.push(event);
  const { principal, network, access } = await signedInPrincipal(ctx, onEvent);
  const signedIn = await access?.signedInGuard(principal);
  const slot = new SandboxCredential({
    distributionId: ctx.metadata.app.id,
    command: ctx.metadata.app.command,
    stateDir: ctx.stateDir,
    provider: config.provider,
    ...(ctx.metadata.access
      ? { storage: ctx.metadata.access.credential.storage }
      : {}),
    ...(access?.store ? { secretStore: access.store } : {}),
    principal,
    ...(signedIn ? { signedIn } : {}),
    // Resolved after the managed environment was sanitized, as a launch does.
    targets: sandboxTargets(ctx),
    onEvent,
  });
  let saved: Awaited<ReturnType<SandboxCredential["save"]>>;
  try {
    saved = await slot.save(readSecretInput);
  } catch (error) {
    // The previous credential may already be gone: that is recorded.
    await audit(ctx, network, principal, events).catch((auditError) =>
      ctx.err(`Error: ${formatError(auditError)}`),
    );
    throw error;
  }
  await audit(ctx, network, principal, events);
  ctx.out(
    `Sandbox ${saved.kind === "bearer" ? "token" : "API key"} stored in ${saved.store}. It is sent only to the sandbox endpoint it was stored for${principal ? ", and only for the signed-in user" : ""}; the next launch uses it.`,
  );
  if (slot.store.kind === "file")
    ctx.err(
      "Warning: the sandbox credential uses the explicitly enabled plaintext file fallback, not platform secure storage.",
    );
}

async function sandboxLogout(ctx: BrandedContext): Promise<void> {
  assertTlsVerificationEnabled();
  const events: AccessEvent[] = [];
  const onEvent = (event: AccessEvent) => events.push(event);
  // Deleting never depends on a runtime variable or the identity provider:
  // the store is the configured one, and no principal is needed to clear.
  const access = ctx.metadata.access ? openAccessQuietly(ctx, onEvent) : null;
  const network = access?.network ?? networkPolicyFor(ctx.metadata.access);
  applyProcessNetworkPolicy(network);
  const signedIn = access?.readIdentityMetadata() ?? null;
  const slot = new SandboxCredential({
    distributionId: ctx.metadata.app.id,
    command: ctx.metadata.app.command,
    stateDir: ctx.stateDir,
    ...(ctx.metadata.access
      ? { storage: ctx.metadata.access.credential.storage }
      : {}),
    ...(access?.store ? { secretStore: access.store } : {}),
    principal: null,
    onEvent,
  });
  const stored = slot.present();
  const problems = await slot.clear();
  for (const problem of problems) ctx.err(`Warning: ${problem}`);
  await audit(ctx, network, signedIn ? principalKey(signedIn) : null, events);
  if (slot.present())
    throw new PiShipError(
      "SECRET_STORE_UNAVAILABLE",
      "The sandbox credential could not be deleted from the secret store. It is never used and stays tracked, so the next sandbox login, logout, or launch deletes it",
      {
        component: "credential",
        userAction: `Unlock or repair the secret store, then run ${ctx.metadata.app.command} sandbox logout again`,
      },
    );
  ctx.out(
    stored
      ? "The sandbox credential was deleted."
      : "No sandbox credential is stored.",
  );
}

/** Access for its store and network policy only; unresolvable is fine here. */
function openAccessQuietly(
  ctx: BrandedContext,
  onEvent: (event: AccessEvent) => void,
): DistributionAccess | null {
  try {
    return openAccess(ctx, onEvent);
  } catch {
    return null;
  }
}

/**
 * `sandbox login` or `sandbox logout`. Anything else is refused without
 * echoing it: a mistyped command line may hold the secret itself.
 */
export async function runSandbox(
  ctx: BrandedContext,
  args: readonly string[],
): Promise<void> {
  if (args.length === 1 && args[0] === "login") return sandboxLogin(ctx);
  if (args.length === 1 && args[0] === "logout") return sandboxLogout(ctx);
  throw new PiShipError(
    "CONFIG_INVALID",
    "Unknown sandbox command; use sandbox login or sandbox logout. The secret is never given on the command line: sandbox login prompts for it or reads the first line of stdin",
    { component: "sandbox" },
  );
}
