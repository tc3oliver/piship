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
import { remoteWorkspaceLines } from "./remote-workspace.js";
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

/** Whether the manifest declares `sandbox.network.egress: it`. */
export function itEgress(data: DoctorData): boolean {
  return data.governance?.manifest.sandbox?.network.egress === "it";
}

/** What `sandbox.network.egress: it` says in doctor: a declaration, never a check. */
const IT_EGRESS_DELEGATED =
  "egress delegated to IT: declared by the distribution (sandbox.network.egress: it), not verified by PiShip";

/** The network mode, and in deny mode how the denial is known. */
export function networkText(report: ContainmentReport): string {
  const denial = report.networkDenial;
  if (!denial) return report.network;
  if (denial.evidence === "verified") return `${report.network} (verified)`;
  return `${report.network} (attested by the backend, not verified${denial.reason ? `: ${denial.reason}` : ""})`;
}

const POWERSHELL_COST =
  "each command the agent runs and each MCP stdio server starts through PowerShell, about 0.9 s slower";
const FAILED_FIX: Readonly<Record<string, string>> = {
  "the helper did not compile":
    "check that csc.exe can run here; application control (AppLocker, WDAC) may block it",
  "the compiled helper did not run a child":
    "application control (AppLocker, WDAC) probably blocks programs in that directory; ask IT to allow it",
  "the helper could not be installed":
    "check that the state home is writable by this user",
};

/** Windows: which supervisor puts governed children in a Job Object, and why. */
function jobSupervisorLine(
  status: NonNullable<DoctorData["jobSupervisor"]>,
  out: DoctorSection,
): void {
  const label = "child supervisor";
  switch (status.supervisor) {
    case "helper":
      out.ok(label, `compiled Job Object helper (${status.path})`);
      return;
    case "pending":
      out.info(
        label,
        "compiled Job Object helper, built at the first command or MCP stdio server it starts; still shown after commands ran, the state home is not writable and each start uses PowerShell, about 0.9 s slower",
      );
      return;
    case "none":
      out.bad(label, `${status.reason}; governed children cannot start`);
      return;
  }
  if (status.cause === "off") {
    out.info(
      label,
      `PowerShell (PISHIP_WINDOWS_JOB_HELPER=off): ${POWERSHELL_COST}`,
    );
    return;
  }
  if (status.cause === "no-compiler") {
    out.warn(
      label,
      `PowerShell: no .NET Framework 4 compiler (csc.exe under %SystemRoot%\\Microsoft.NET), so ${POWERSHELL_COST}; with the .NET Framework 4.x compiler present the next start compiles the faster helper`,
    );
    return;
  }
  const reason = status.reason ?? "the helper could not be made";
  const fix = FAILED_FIX[reason] ?? "see the reason";
  const retry = status.retryAt
    ? `; it is tried again after ${status.retryAt.toISOString()}`
    : "";
  out.warn(
    label,
    `PowerShell: ${reason}, so ${POWERSHELL_COST}${retry}. Fix: ${fix}, then delete ${status.dir}\\unavailable.json to try again now`,
  );
}

export function sandboxGroup(data: DoctorData, out: DoctorSection): void {
  const governance = data.governance;
  const inspection = governance?.inspection;
  // Windows records no tasks: a Job Object ends them with their owner.
  for (const task of data.orphanedTasks ?? [])
    out.warn(
      `task ${task.id}`,
      task.pid
        ? `started by PiShip process ${task.owner}, which is gone (killed without cleanup); it still runs as process ${task.pid}. Stop it and its children with: kill -- -${task.pid}; this is reported once`
        : `started by PiShip process ${task.owner}, which is gone (killed without cleanup); it may still run. Find it with ps and stop it; this is reported once`,
    );
  if (data.jobSupervisor) jobSupervisorLine(data.jobSupervisor, out);
  if (!governance) return;
  if (inspection) {
    const report = inspection.sandbox;
    out.ok("provider", report.provider);
    const containment = `${report.level} (${report.adapter}${report.planes.length ? `: ${report.planes.join(", ")}` : ""})`;
    if (report.level === "enforced") out.ok("containment", containment);
    else if (report.required)
      out.bad("containment", `${containment}: ${report.reason ?? "required"}`);
    else {
      const text = `${containment}${report.reason ? `: ${report.reason}` : ""}`;
      // Off by choice is a note; configured on but not working still warns.
      if (report.level === "not-required") out.info("containment", text);
      else out.warn("containment", text);
    }
    // A required sandbox that is not running isolates nothing and denies no
    // network, so what it declares is a note, not a pass.
    const failed = report.required && report.level !== "enforced";
    const declaredLine = (label: string, value: string) =>
      failed ? out.info(label, value) : out.ok(label, value);
    const declared = governance.workspace.declared;
    // A mounted or synced workspace makes host files reachable, through it.
    if (
      governance.isolation === "remote" &&
      (declared === "shared" || declared === "synchronized")
    )
      declaredLine("isolation", REMOTE_WORKSPACE_TEXT);
    else if (governance.isolation)
      declaredLine("isolation", ISOLATION_TEXT[governance.isolation]);
    if (itEgress(data) && report.network === "allow")
      out.info("network", `allow (${IT_EGRESS_DELEGATED})`);
    else
      declaredLine(
        "network",
        failed
          ? `${report.network} (declared; not in effect while the sandbox is unavailable)`
          : networkText(report),
      );
    out.ok(
      "scope",
      "tool subprocesses and MCP stdio servers; Pi and in-process extensions are not contained",
    );
    out.info("summary", inspection.containment);
    for (const warning of report.warnings) out.warn("sandbox", warning);
  }
  if (governance.remote) remoteWorkspaceLines(governance.remote, out);
  if (governance.sandboxCredential)
    sandboxCredentialLines(data, governance.sandboxCredential, out);
}
