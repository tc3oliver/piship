// Sandbox group: the backend, containment level and guarantees, how commands
// are isolated from this host, what the sandbox does not contain, and the
// state of a stored sandbox credential (never its value, reference, ID, or
// the origins it is bound to).
import {
  formatError,
  type PrincipalKey,
  principalKey,
  type SecretStore,
} from "@piship/contracts";
import {
  type ActivatedAccess,
  type DistributionAccess,
  openSandboxCredential,
  type SandboxCredentialStatus,
} from "@piship/core";
import type { ContainmentReport } from "@piship/sandbox";
import type { GovernanceManifest } from "@piship/schema";
import { resolveTemplate } from "@piship/schema";
import type { LaunchContext } from "../launch/context.js";
import type { DoctorData } from "./data.js";
import type { DoctorSection } from "./report.js";

const ISOLATION_TEXT = {
  local: "local (commands run on this host inside the sandbox)",
  remote: "remote (commands run on another machine; host files unreachable)",
  none: "none (tool subprocesses run with the user's privileges)",
} as const;
const REMOTE_WORKSPACE_TEXT =
  "remote (commands run on another machine; host files reachable only through the workspace)";

/** The stored sandbox credential as doctor reports it. */
export interface SandboxCredentialData {
  /** Non-secret status from core; absent when it could not be read. */
  readonly status?: SandboxCredentialStatus;
  /** Why the principal binding was not checked (no signed-in user). */
  readonly principalUnchecked?: string;
  /** Why the endpoint binding was not checked (an unresolved endpoint). */
  readonly originUnchecked?: string;
  /** The distribution has no identity: the credential is bound to no user. */
  readonly noIdentity?: boolean;
  /** The slot could not be opened (for example, no secret store). */
  readonly error?: string;
  /** The sandbox is required, so a launch fails without the credential. */
  readonly required: boolean;
}

/**
 * The stored sandbox credential's status, checked against the principal a
 * launch would use and the endpoint (and router) it would send it to. Only
 * for a manifest that declares `sandbox.credential: stored`. Reads metadata
 * only: no secret is read and nothing is changed or deleted.
 */
export function sandboxCredentialData(options: {
  readonly ctx: LaunchContext;
  readonly sandbox: GovernanceManifest["sandbox"] | undefined;
  readonly access?: DistributionAccess;
  readonly activated?: ActivatedAccess;
  /** The identity is a per-run workload identity, never stored. */
  readonly workload?: boolean;
  /** A store to use instead of the configured one (tests). */
  readonly secretStore?: SecretStore;
}): SandboxCredentialData | undefined {
  const { ctx, sandbox, access, activated } = options;
  if (sandbox?.credential !== "stored") return undefined;
  const required = !!sandbox.required;
  let principal: PrincipalKey | null = null;
  let principalUnchecked: string | undefined;
  try {
    if (activated?.identity) principal = principalKey(activated.identity);
    else if (ctx.metadata.access && access?.identityMode !== "none") {
      // The stored session's principal is the one the next launch signs in
      // as; a workload identity is never stored, so it cannot be told.
      const stored = options.workload ? null : access?.readIdentityMetadata();
      if (stored) principal = principalKey(stored);
      else principalUnchecked = "no signed-in user to check it against";
    }
  } catch {
    principalUnchecked = "the signed-in user could not be read";
  }
  const targets: string[] = [];
  let originUnchecked: string | undefined;
  for (const [field, template] of [
    ["sandbox.endpoint", sandbox.endpoint],
    ["sandbox.router", sandbox.router],
  ] as const) {
    if (template === undefined) continue;
    try {
      targets.push(
        resolveTemplate(
          field,
          template,
          ctx.metadata.access?.variables ?? [],
          process.env,
        ),
      );
    } catch (error) {
      originUnchecked ??= `${field} is not resolved: ${error instanceof Error ? error.message : String(error)}`;
    }
  }
  if (!targets.length) originUnchecked ??= "sandbox.endpoint is not declared";
  const unchecked = {
    ...(principalUnchecked ? { principalUnchecked } : {}),
    ...(originUnchecked ? { originUnchecked } : {}),
    ...(!principal && !principalUnchecked ? { noIdentity: true } : {}),
    required,
  };
  const secretStore = options.secretStore ?? access?.store;
  try {
    const status = openSandboxCredential({
      distributionId: ctx.metadata.app.id,
      command: ctx.metadata.app.command,
      stateDir: ctx.stateDir,
      ...(ctx.metadata.access
        ? { storage: ctx.metadata.access.credential.storage }
        : {}),
      ...(secretStore ? { secretStore } : {}),
      principal,
      // An unresolved target leaves the endpoint binding unchecked.
      ...(originUnchecked ? {} : { targets }),
    }).status();
    return { status, ...unchecked };
  } catch (error) {
    return { error: formatError(error), ...unchecked };
  }
}

function sandboxCredentialLines(
  data: DoctorData,
  credential: SandboxCredentialData,
  out: DoctorSection,
): void {
  const login = `run ${data.ctx.metadata.app.command} sandbox login`;
  const fail = credential.required ? out.bad : out.warn;
  if (credential.error) {
    fail("sandbox credential", `not checked: ${credential.error}`);
    return;
  }
  const status = credential.status;
  if (!status) return;
  const head = `(${status.source}${status.kind ? `, ${status.kind}` : ""}) in ${status.store}`;
  if (status.state === "absent") {
    fail(
      "sandbox credential",
      `absent ${head}; ${login}${status.notice ? `. ${status.notice}` : ""}`,
    );
    return;
  }
  // Without the current user, a credential bound to someone reads as
  // another user's: its state is not known until a user is signed in.
  if (credential.principalUnchecked)
    out.warn("sandbox credential", `stored ${head}; state not checked`);
  else if (status.state === "valid")
    out.ok("sandbox credential", `valid ${head}`);
  else if (status.state === "rejected")
    out.warn(
      "sandbox credential",
      `rejected ${head}: the sandbox service rejected it; ${login} to store a new one`,
    );
  else
    fail(
      "sandbox credential",
      `${status.state} ${head}${status.notice ? `. ${status.notice}` : ""}`,
    );
  if (credential.principalUnchecked)
    out.warn(
      "credential principal",
      `not checked: ${credential.principalUnchecked}`,
    );
  else if (status.boundToPrincipal)
    out.ok(
      "credential principal",
      credential.noIdentity
        ? "bound to the current principal: yes (no identity configured)"
        : "bound to the current principal: yes",
    );
  else fail("credential principal", "bound to the current principal: no");
  if (status.originMatches === true)
    out.ok(
      "credential endpoint",
      "bound origin matches the configured endpoint: yes",
    );
  else if (status.originMatches === false)
    fail(
      "credential endpoint",
      "bound origin matches the configured endpoint: no",
    );
  else
    out.warn(
      "credential endpoint",
      `not checked: ${credential.originUnchecked ?? "the sandbox endpoint is not resolved"}`,
    );
}

/** The network mode, and in deny mode how the denial is known. */
function networkText(report: ContainmentReport): string {
  const denial = report.networkDenial;
  if (!denial) return report.network;
  if (denial.evidence === "verified") return `${report.network} (verified)`;
  return `${report.network} (attested by the backend, not verified${denial.reason ? `: ${denial.reason}` : ""})`;
}

export function sandboxGroup(data: DoctorData, out: DoctorSection): void {
  const governance = data.governance;
  const inspection = governance?.inspection;
  if (!governance) return;
  if (inspection) {
    const report = inspection.sandbox;
    out.ok("provider", report.provider);
    const containment = `${report.level} (${report.adapter}${report.planes.length ? `: ${report.planes.join(", ")}` : ""})`;
    if (report.level === "enforced") out.ok("containment", containment);
    else if (report.required)
      out.bad("containment", `${containment}: ${report.reason ?? "required"}`);
    else
      out.warn(
        "containment",
        `${containment}${report.reason ? `: ${report.reason}` : ""}`,
      );
    const declared = governance.workspace.declared;
    // A mounted or synced workspace makes host files reachable, through it.
    if (
      governance.isolation === "remote" &&
      (declared === "shared" || declared === "synchronized")
    )
      out.ok("isolation", REMOTE_WORKSPACE_TEXT);
    else if (governance.isolation)
      out.ok("isolation", ISOLATION_TEXT[governance.isolation]);
    out.ok("network", networkText(report));
    out.ok(
      "scope",
      "tool subprocesses and MCP stdio servers; Pi and in-process extensions are not contained",
    );
    out.info("summary", inspection.containment);
    for (const warning of report.warnings) out.warn("sandbox", warning);
  }
  if (governance.sandboxCredential)
    sandboxCredentialLines(data, governance.sandboxCredential, out);
}
