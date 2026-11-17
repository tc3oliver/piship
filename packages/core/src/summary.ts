// Human-readable summaries of what `piship inspect`, `test`, and `doctor`
// report. Their full JSON stays available behind `--json`.
import { isAbsolute, relative } from "node:path";
import { channelTrustFromLock } from "./lock.js";
import type { DistributionLock } from "./lock-schema.js";
import { keyFingerprint } from "./signing.js";

/** What `piship inspect --json` prints. */
export interface Inspection {
  readonly app: DistributionLock["app"];
  readonly deployment: DistributionLock["deployment"];
  readonly runtime: DistributionLock["runtime"];
  readonly resources: DistributionLock["resources"];
  /** The locked Pi packages, as `id@version` (npm) or `id@<short commit>` (git). */
  readonly packages?: readonly string[];
  readonly access?: NonNullable<DistributionLock["access"]>;
  readonly governance?: NonNullable<DistributionLock["governance"]>;
  /** The update keys the lock pins, by id and `sha256:` fingerprint. */
  readonly trust?: {
    readonly keys: readonly {
      readonly id: string;
      readonly fingerprint: string;
    }[];
  };
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
    ...(lock.packages?.length
      ? { packages: lock.packages.map(packageLabel) }
      : {}),
    ...(lock.access ? { access: lock.access } : {}),
    ...(lock.governance ? { governance: lock.governance } : {}),
    ...(lock.updates
      ? {
          trust: {
            keys: channelTrustFromLock(lock).map((key) => ({
              id: key.id,
              fingerprint: keyFingerprint(key.publicKey),
            })),
          },
        }
      : {}),
    ...(artifact ? { artifact } : {}),
    state,
  };
}

/** A locked Pi package as `id@version` (npm) or `id@<short commit>` (git). */
export function packageLabel(item: {
  readonly id: string;
  readonly version?: string;
  readonly commit?: string;
}): string {
  const at = item.version ?? item.commit?.slice(0, 7);
  return at ? `${item.id}@${at}` : item.id;
}

const LISTED = 5;
/** Up to five items, then how many more. */
function names(items: readonly string[]): string {
  const more = items.length - LISTED;
  return `${items.slice(0, LISTED).join(", ")}${more > 0 ? `, +${more} more` : ""}`;
}

/** One line of at most 160 characters. */
function oneLine(text: string): string {
  const line = text.split(/\s+/).filter(Boolean).join(" ");
  return line.length > 160 ? `${line.slice(0, 157)}...` : line;
}

/**
 * An MCP start failure on one line. Node's stderr starts with a source
 * location, so the stderr part keeps the line naming the error instead.
 */
function mcpReason(reason: string): string {
  const marker = " (stderr: ";
  const at = reason.indexOf(marker);
  if (at < 0) return oneLine(reason);
  let stderr = reason.slice(at + marker.length);
  if (stderr.endsWith(")")) stderr = stderr.slice(0, -1);
  const lines = stderr.split(" | ");
  const line = lines.find((item) => /Error\b/.test(item)) ?? lines.at(-1);
  return oneLine(`${reason.slice(0, at)}${marker}${line})`);
}

const row = (label: string, value: string) => `  ${label.padEnd(11)}${value}`;
/** A labelled list: the label on the first line only. */
const rows = (label: string, values: readonly string[]) =>
  values.map((value, index) => row(index ? "" : label, value));

/** A short, human-readable `inspect` report. */
export function formatInspection(info: Inspection): string {
  const { app, deployment, runtime, resources, access, governance } = info;
  const lines = [
    `${app.name} ${app.version} (${app.id}, command ${app.command})`,
    row("mode", deployment.mode),
    row("runtime", `Pi ${runtime.version}, PiShip ${runtime.pishipVersion}`),
  ];
  const byKind = new Map<string, string[]>();
  for (const item of resources)
    byKind.set(item.kind, [...(byKind.get(item.kind) ?? []), item.path]);
  lines.push(
    ...(byKind.size
      ? rows(
          "resources",
          [...byKind].map(
            ([kind, paths]) => `${kind} ${paths.length}: ${names(paths)}`,
          ),
        )
      : [row("resources", "none")]),
  );
  if (info.packages) lines.push(row("packages", names(info.packages)));
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
        `${policy.id}@${policy.version} (default ${policy.default}${policy.userAuto ? `, user auto ${policy.userAuto}` : ""})`,
      ),
      ...(policy.taskGrants
        ? [
            row(
              "grants",
              `${policy.taskGrants.mode}${policy.taskGrants.maxTtlMinutes ? ` (ttl <= ${policy.taskGrants.maxTtlMinutes} min)` : ""}`,
            ),
          ]
        : []),
      ...(policy.taskGrants?.declared?.length
        ? [row("grant tasks", ` ${policy.taskGrants.declared.length} declared`)]
        : []),
      row(
        "sandbox",
        `${sandbox.provider ?? "native"}${sandbox.required ? ", required" : ""}, network ${sandbox.network.mode}${sandbox.network.egress ? " (egress: it)" : ""}`,
      ),
      row("mcp", `${mcp.mode}, ${mcp.servers.length} server(s)`),
      row(
        "audit",
        audit.enabled ? `${audit.sinks.length} sink(s)` : "disabled",
      ),
    );
  }
  if (info.trust) {
    const { keys } = info.trust;
    if (!keys.length) lines.push(row("trust", "no pinned update keys"));
    lines.push(
      ...keys.map((key, index) =>
        row(index ? "" : "trust", `${key.id} ${key.fingerprint}`),
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
  readonly distributionDir?: string;
  readonly instructions?: readonly string[];
  readonly skills?: readonly string[];
  readonly extensions?: number;
  readonly extensionPaths?: readonly string[];
  readonly packages?: readonly string[];
  readonly prompts?: readonly string[];
  readonly themes?: readonly string[];
  readonly searchTools?: Readonly<Record<string, string>>;
  readonly access?: { readonly selectedModel?: string | null };
  readonly governance?: {
    readonly policy?: string;
    readonly project?: { readonly origin?: string };
    readonly sandbox?: { readonly level?: string; readonly provider?: string };
    readonly mcp?: readonly {
      readonly id: string;
      readonly state: string;
      readonly reason?: string;
    }[];
    readonly audit?: string;
    readonly resources?: readonly { readonly loaded: boolean }[];
  };
  readonly modelRequest?: {
    readonly model?: string;
    readonly stopReason?: string | null;
  };
}

/** Ids of declared MCP servers the smoke JSON reports as failed. */
export function failedMcpServers(output: string): string[] {
  try {
    const smoke = JSON.parse(output) as Smoke;
    return (smoke.governance?.mcp ?? [])
      .filter((server) => server.state === "failed")
      .map((server) => server.id);
  } catch {
    return [];
  }
}

/**
 * A short report of the branded `--smoke` JSON summary. Output that is not
 * that JSON is returned unchanged.
 */
export function formatSmokeSummary(
  output: string,
  declared: readonly string[] = [],
): string {
  let smoke: Smoke;
  try {
    smoke = JSON.parse(output) as Smoke;
  } catch {
    return output;
  }
  if (typeof smoke !== "object" || smoke === null) return output;
  const base = (path: string) => path.replaceAll("\\", "/").split("/").pop();
  // An extension is named from its extensions folder down: foo/index.ts.
  const extension = (path: string) => {
    const slashed = path.replaceAll("\\", "/");
    const at = slashed.lastIndexOf("/extensions/");
    return at < 0 ? base(slashed) : slashed.slice(at + "/extensions/".length);
  };
  // A distribution file is named by its declared path, any other from the
  // working directory, so two files of one name stay apart.
  const instruction = (path: string) => {
    const dir = smoke.distributionDir;
    if (!dir) return base(path);
    const inside = relative(dir, path);
    if (inside && !inside.startsWith("..") && !isAbsolute(inside))
      return inside.replaceAll("\\", "/").replace(/^resources\//, "");
    return relative(process.cwd(), path).replaceAll("\\", "/") || base(path);
  };
  const loaded = [
    ["instructions", (smoke.instructions ?? []).map(instruction)],
    ["skills", smoke.skills ?? []],
    ["extensions", (smoke.extensionPaths ?? []).map(extension)],
    ["prompts", smoke.prompts ?? []],
    ["themes", smoke.themes ?? []],
  ] as const;
  // A declared kind that loaded nothing still shows, as "prompts 0".
  const listed = loaded
    .filter(([kind, items]) => items.length || declared.includes(kind))
    .map(
      ([kind, items]) => `${kind} ${items.length}: ${names(items as string[])}`,
    );
  // A payload older than extensionPaths reports only the count.
  if (!smoke.extensionPaths && smoke.extensions)
    listed.push(`extensions ${smoke.extensions}`);
  const lines = [
    row(
      "Pi",
      `${smoke.piVersion ?? "unknown"}, ${smoke.resumed ? "resumed" : "new"} acceptance session ${smoke.sessionId ?? ""}`.trimEnd(),
    ),
    ...(listed.length ? rows("resources", listed) : [row("resources", "none")]),
  ];
  if (smoke.packages?.length)
    lines.push(row("packages", names(smoke.packages)));
  if (smoke.searchTools)
    lines.push(
      row(
        "search",
        `${Object.entries(smoke.searchTools)
          .map(([tool, version]) => `${tool} ${version}`)
          .join(", ")} bundled, used by Pi's find and grep`,
      ),
    );
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
        ...rows(
          "mcp",
          gov.mcp.map(
            (server) =>
              `${server.id} ${server.state}${server.reason ? `: ${mcpReason(server.reason)}` : ""}`,
          ),
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

/**
 * How to put `bin` on PATH, or `undefined` when it already is. The lines
 * fit the user's shell (from `SHELL`) or PowerShell on Windows.
 */
export function pathHint(
  bin: string,
  env: Readonly<Record<string, string | undefined>> = process.env,
  platform: NodeJS.Platform = process.platform,
): string | undefined {
  const windows = platform === "win32";
  // Trailing separators are dropped by a scan, not a regular expression, so
  // a PATH entry of many slashes costs linear time.
  const trim = (value: string) => {
    let end = value.length;
    while (
      end > 0 &&
      (value[end - 1] === "/" || (windows && value[end - 1] === "\\"))
    )
      end -= 1;
    return value.slice(0, end);
  };
  // PISHIP_BIN_HOME may be written with / where PATH has \\: the same folder.
  const fold = (value: string) =>
    trim(value).replaceAll("/", "\\").toLowerCase();
  const same = (a: string, b: string) =>
    windows ? fold(a) === fold(b) : trim(a) === trim(b);
  const path = env.PATH ?? env.Path ?? "";
  if (
    path.split(windows ? ";" : ":").some((entry) => entry && same(entry, bin))
  )
    return undefined;
  if (windows) {
    // Inside a PowerShell double-quoted string, `$`, a backtick and `"` are special.
    const escaped = bin.replace(/([`"$])/g, "`$1");
    return [
      `${bin} is not on PATH. In PowerShell (type powershell first in cmd.exe), add it for new terminals with:`,
      `  [Environment]::SetEnvironmentVariable("Path", [Environment]::GetEnvironmentVariable("Path", "User") + ";${escaped}", "User")`,
      "then open a new terminal.",
    ].join("\n");
  }
  const quoted = bin.replace(/(["\\$`])/g, "\\$1");
  const shell = (env.SHELL ?? "").split("/").pop();
  if (shell === "fish")
    return `${bin} is not on PATH. Add it with:\n  fish_add_path "${quoted}"`;
  const profile =
    shell === "zsh"
      ? "~/.zshrc"
      : shell === "bash"
        ? "~/.bashrc"
        : "~/.profile";
  return [
    `${bin} is not on PATH. Add it for this shell with:`,
    `  export PATH="${quoted}:$PATH"`,
    `and add that line to ${profile} for new shells.`,
  ].join("\n");
}
