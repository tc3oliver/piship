import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { LocalMetrics } from "@piship/audit";
import {
  PiShipError,
  applyProcessNetworkPolicy,
  assertTlsVerificationEnabled,
  sanitizeManagedEnvironment,
} from "@piship/contracts";
import type { AccessEvent } from "../index.js";
import {
  type BrandedContext,
  auditAccess,
  openAccess,
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

async function readSecretInput(prompt: string): Promise<string> {
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
  const result = await access
    .login({
      openUrl: (url) => {
        ctx.err(`Open this URL in your browser to sign in:\n${url}`);
        openBrowser(url);
      },
      readSecret: readSecretInput,
    })
    .finally(() => saveMetrics(metrics));
  await auditAccess(ctx, access, result.identity?.subject ?? null, events);
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

export async function runLogout(ctx: BrandedContext): Promise<void> {
  if (
    !ctx.metadata.access ||
    ctx.metadata.access.credential.provider === "pi-native"
  )
    throw new PiShipError(
      "POLICY_DENIED",
      "This distribution delegates authentication to Pi; use Pi's /logout inside the session",
    );
  assertTlsVerificationEnabled();
  const events: AccessEvent[] = [];
  const access = openAccess(ctx, (event) => events.push(event));
  if (ctx.mode === "managed")
    sanitizeManagedEnvironment(
      process.env,
      access.network,
      ctx.metadata.access.variables,
    );
  applyProcessNetworkPolicy(access.network);
  const signedIn = (await access.status().catch(() => undefined))?.identity;
  const problems = await access.logout();
  // Only what happened is recorded: credential.revoke with its remote
  // revocation outcome when a credential existed, identity.logout when
  // there was an identity session.
  await auditAccess(ctx, access, signedIn?.subject ?? null, events);
  ctx.out(
    `Signed out of ${ctx.metadata.app.name}. Local runtime and identity credentials were cleared; sessions were preserved.`,
  );
  for (const problem of problems) ctx.err(`Warning: ${problem}`);
}
