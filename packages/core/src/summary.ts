// Human-readable summaries of what `piship inspect`, `test`, and `doctor`
// report. Their full JSON stays available behind `--json`.
import type { DistributionLock } from "./lock-schema.js";

/** What `piship inspect --json` prints. */
export interface Inspection {
  readonly app: DistributionLock["app"];
  readonly deployment: DistributionLock["deployment"];
  readonly runtime: DistributionLock["runtime"];
  readonly resources: DistributionLock["resources"];
  readonly access?: NonNullable<DistributionLock["access"]>;
  readonly governance?: NonNullable<DistributionLock["governance"]>;
  readonly artifact?: string;
  readonly state: string;
}

export function inspection(
  lock: DistributionLock,
  state: string,
  artifact?: string,
): Inspection {
  return {
    app: lock.app,
    deployment: lock.deployment,
    runtime: lock.runtime,
    resources: lock.resources,
    ...(lock.access ? { access: lock.access } : {}),
    ...(lock.governance ? { governance: lock.governance } : {}),
    ...(artifact ? { artifact } : {}),
    state,
  };
}

function counts(items: readonly string[]): string {
  const tally = new Map<string, number>();
  for (const item of items) tally.set(item, (tally.get(item) ?? 0) + 1);
  return [...tally].map(([name, count]) => `${name} ${count}`).join(", ");
}

const row = (label: string, value: string) => `  ${label.padEnd(11)}${value}`;

/** A short, human-readable `inspect` report. */
export function formatInspection(info: Inspection): string {
  const { app, deployment, runtime, resources, access, governance } = info;
  const lines = [
    `${app.name} ${app.version} (${app.id}, command ${app.command})`,
    row("mode", deployment.mode),
    row("runtime", `Pi ${runtime.version}, PiShip ${runtime.pishipVersion}`),
    row(
      "resources",
      resources.length
        ? `${resources.length} file(s): ${counts(resources.map((item) => item.kind))}`
        : "none",
    ),
  ];
  if (access) {
    lines.push(
      row("identity", access.identity.mode),
      row("credential", access.credential.provider),
      row("inference", access.inference.provider),
    );
    if (access.models.allowed.length || access.models.default)
      lines.push(
        row(
          "models",
          [
            access.models.default ? `default ${access.models.default}` : "",
            access.models.allowed.length
              ? `allowed ${access.models.allowed.join(", ")}`
              : "",
          ]
            .filter(Boolean)
            .join("; "),
        ),
      );
  }
  if (governance) {
    const { policy, mcp, sandbox, audit } = governance.manifest;
    lines.push(
      row(
        "policy",
        `${policy.id}@${policy.version} (default ${policy.default})`,
      ),
      row(
        "sandbox",
        `${sandbox.provider ?? "native"}${sandbox.required ? ", required" : ""}, network ${sandbox.network.mode}`,
      ),
      row("mcp", `${mcp.mode}, ${mcp.servers.length} server(s)`),
      row(
        "audit",
        audit.enabled ? `${audit.sinks.length} sink(s)` : "disabled",
      ),
    );
  }
  if (info.artifact) lines.push(row("artifact", info.artifact));
  lines.push(row("state", info.state));
  return lines.join("\n");
}

/** Fields of the branded `--smoke` summary this report reads. */
interface Smoke {
  readonly piVersion?: string;
  readonly sessionId?: string;
  readonly resumed?: boolean;
  readonly instructions?: readonly string[];
  readonly skills?: readonly string[];
  readonly extensions?: number;
  readonly prompts?: readonly string[];
  readonly themes?: readonly string[];
  readonly access?: { readonly selectedModel?: string | null };
  readonly governance?: {
    readonly policy?: string;
    readonly project?: { readonly origin?: string };
    readonly sandbox?: { readonly level?: string; readonly provider?: string };
    readonly mcp?: readonly { readonly id: string; readonly state: string }[];
    readonly audit?: string;
    readonly resources?: readonly { readonly loaded: boolean }[];
  };
  readonly modelRequest?: {
    readonly model?: string;
    readonly stopReason?: string | null;
  };
}

/**
 * A short report of the branded `--smoke` JSON summary. Output that is not
 * that JSON is returned unchanged.
 */
export function formatSmokeSummary(output: string): string {
  let smoke: Smoke;
  try {
    smoke = JSON.parse(output) as Smoke;
  } catch {
    return output;
  }
  if (typeof smoke !== "object" || smoke === null) return output;
  const length = (items: readonly unknown[] | undefined) => items?.length ?? 0;
  const lines = [
    row(
      "Pi",
      `${smoke.piVersion ?? "unknown"}, ${smoke.resumed ? "resumed" : "new"} acceptance session ${smoke.sessionId ?? ""}`.trimEnd(),
    ),
    row(
      "resources",
      `instructions ${length(smoke.instructions)}, skills ${length(smoke.skills)}, extensions ${smoke.extensions ?? 0}, prompts ${length(smoke.prompts)}, themes ${length(smoke.themes)}`,
    ),
  ];
  // Pi names no model as unknown/unknown (pi-native before /login).
  const model = smoke.access?.selectedModel;
  if (model)
    lines.push(
      row("model", model === "unknown/unknown" ? "none selected yet" : model),
    );
  const gov = smoke.governance;
  if (gov) {
    const skipped = (gov.resources ?? []).filter((item) => !item.loaded).length;
    lines.push(
      row(
        "governance",
        [
          gov.policy ? `policy ${gov.policy}` : "",
          gov.project?.origin ? `project ${gov.project.origin}` : "",
          gov.sandbox?.level ? `sandbox ${gov.sandbox.level}` : "",
          gov.audit ? `audit ${gov.audit}` : "",
          skipped ? `${skipped} resource(s) not loaded` : "",
        ]
          .filter(Boolean)
          .join(", "),
      ),
    );
    if (gov.mcp?.length)
      lines.push(
        row(
          "mcp",
          gov.mcp.map((server) => `${server.id} ${server.state}`).join(", "),
        ),
      );
  }
  if (smoke.modelRequest)
    lines.push(
      row(
        "request",
        `${smoke.modelRequest.model ?? "model"} answered (${smoke.modelRequest.stopReason ?? "no stop reason"})`,
      ),
    );
  return lines.join("\n");
}
