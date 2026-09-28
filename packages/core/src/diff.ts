// Release-impact comparison of two locks for `piship diff`. Works across lock
// schemas: every field newer than piship-lock/v1alpha1 is treated as optional.
// Display values are versions, ids, effects, templates, and shortened hashes;
// secret-bearing values (env values, settings text, key material) are never shown.
import { createHash } from "node:crypto";
import type { AccessManifest, GovernanceManifest } from "@piship/schema";
import type { DistributionLock, LockedResource } from "./index.js";
import type { GovernanceLock } from "./trust.js";

export type DiffRisk = "low" | "medium" | "high";

/** Report areas in display order. */
export const DIFF_AREAS = [
  "distribution",
  "schema",
  "pi",
  "piship",
  "packages",
  "resources",
  "extensions",
  "providers",
  "capabilities",
  "policy",
  "mcp",
  "sandbox",
  "audit",
  "access",
  "models",
  "network",
  "updates",
  "release",
] as const;
export type DiffArea = (typeof DIFF_AREAS)[number];

export interface DiffChange {
  readonly area: DiffArea;
  readonly kind: "added" | "removed" | "changed";
  /** Stable identifier, such as `node_modules/foo` or `policy rule acme.shell`. */
  readonly item: string;
  readonly before?: string;
  readonly after?: string;
  readonly risk: DiffRisk;
  readonly reason: string;
}

export interface DiffSide {
  readonly id: string;
  readonly version: string;
  readonly pi: string;
  readonly piship: string;
  readonly lockSchema: string;
}

export interface DiffReport {
  readonly schema: "piship-diff/v1";
  readonly before: DiffSide;
  readonly after: DiffSide;
  readonly risk: DiffRisk | "none";
  readonly changes: readonly DiffChange[];
  readonly requiredTests: readonly string[];
}

/** Test and review names `requiredTests` draws from. */
export const DIFF_TESTS = {
  check: "npm run check",
  compatibility: "Pi compatibility suite (npm run test:compatibility)",
  installed: "installed lifecycle E2E on every advertised target",
  governance: "governance E2E and policy explain review",
  sandbox: "sandbox boundary tests on Linux and macOS",
  managed: "managed E2E (identity, credentials, inference)",
  release: "release verification and update/rollback E2E",
  migration: "manifest and lock migration review",
} as const;

// Optional v1alpha4 lock fields, typed loosely so older locks compare too.
interface LockedPackage {
  readonly path: string;
  readonly version: string;
  readonly integrity: string;
  readonly resolved?: string;
  readonly installScript?: true;
}
interface UpdatesLock {
  readonly channel?: string;
  readonly channels?: readonly string[];
  readonly source?: string;
  readonly rollback?: boolean;
  readonly trust?: {
    readonly keys?: readonly {
      readonly id: string;
      readonly publicKey: string;
    }[];
  };
}
interface ReleaseLock {
  readonly targets?: readonly string[];
  readonly sources?: readonly string[];
  readonly vulnerabilities?: {
    readonly failOn?: string;
    readonly allow?: readonly {
      readonly id: string;
      readonly reason: string;
      readonly expires: string;
    }[];
  };
}
interface AnyLock
  extends Omit<
    DistributionLock,
    "schema" | "runtime" | "digests" | "updates" | "release"
  > {
  readonly schema: string;
  readonly runtime: Omit<DistributionLock["runtime"], "packages"> & {
    readonly packages: readonly LockedPackage[];
  };
  readonly digests?: Readonly<Record<string, string>>;
  readonly updates?: UpdatesLock;
  readonly release?: ReleaseLock;
}

type Verdict = readonly [DiffRisk, string];
type Kind = DiffChange["kind"];

const RISK_RANK: Record<DiffRisk, number> = { low: 0, medium: 1, high: 2 };
const EFFECT_RANK: Record<string, number> = { deny: 0, ask: 1, allow: 2 };
const DIMENSION_RANK: Record<string, number> = {
  deny: 0,
  "company-approved": 1,
  ask: 2,
  allow: 3,
};
const TRUST_RANK: Record<string, number> = { deny: 0, policy: 1, allow: 2 };
/** Resource trust classes from most to least reviewed. */
const CLASS_RANK: Record<string, number> = {
  upstream: 0,
  builtin: 1,
  certified: 2,
  company: 3,
  user: 4,
  project: 5,
};
const MCP_MODE_RANK: Record<string, number> = {
  off: 0,
  allowlist: 1,
  explicit: 2,
};
const FAIL_ON_RANK: Record<string, number> = {
  low: 0,
  moderate: 1,
  high: 2,
  critical: 3,
};
const EXECUTABLE_KINDS: readonly string[] = [
  "extensions",
  "adapters",
  "providers",
];

class Collector {
  readonly changes: DiffChange[] = [];

  push(
    area: DiffArea,
    kind: Kind,
    item: string,
    [risk, reason]: Verdict,
    before?: string,
    after?: string,
  ): void {
    this.changes.push({
      area,
      kind,
      item,
      ...(before === undefined ? {} : { before: display(before) }),
      ...(after === undefined ? {} : { after: display(after) }),
      risk,
      reason,
    });
  }

  /** Compare one optional scalar; `verdict` sees raw values. */
  scalar(
    area: DiffArea,
    item: string,
    before: string | number | boolean | undefined,
    after: string | number | boolean | undefined,
    verdict: Verdict | ((before: string, after: string) => Verdict),
  ): void {
    if (before === after) return;
    const b = before === undefined ? undefined : String(before);
    const a = after === undefined ? undefined : String(after);
    const kind: Kind =
      b === undefined ? "added" : a === undefined ? "removed" : "changed";
    const result =
      typeof verdict === "function" ? verdict(b ?? "", a ?? "") : verdict;
    this.push(area, kind, item, result, b, a);
  }

  /** Compare two string sets element by element. */
  set(
    area: DiffArea,
    prefix: string,
    before: readonly string[] | undefined,
    after: readonly string[] | undefined,
    added: Verdict | ((value: string) => Verdict),
    removed: Verdict | ((value: string) => Verdict),
  ): void {
    const b = new Set(before ?? []);
    const a = new Set(after ?? []);
    for (const value of a)
      if (!b.has(value))
        this.push(
          area,
          "added",
          `${prefix} ${value}`,
          typeof added === "function" ? added(value) : added,
          undefined,
          value,
        );
    for (const value of b)
      if (!a.has(value))
        this.push(
          area,
          "removed",
          `${prefix} ${value}`,
          typeof removed === "function" ? removed(value) : removed,
          value,
        );
  }
}

function compare(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function byKey<T>(
  items: readonly T[] | undefined,
  key: (item: T) => string,
): Map<string, T> {
  return new Map((items ?? []).map((item) => [key(item), item]));
}

function keys<T>(before: Map<string, T>, after: Map<string, T>): string[] {
  return [...new Set([...before.keys(), ...after.keys()])].sort(compare);
}

/** Shorten digests to 12 hex characters and keep other values to one short line. */
export function display(value: string): string {
  const hex = /^(sha256-)?([0-9a-f]{64})$/.exec(value);
  if (hex) return `${hex[1] ?? ""}${hex[2]?.slice(0, 12)}`;
  const sri = /^(sha(?:1|256|384|512))-([A-Za-z0-9+/]+={0,2})$/.exec(value);
  if (sri?.[2])
    return `${sri[1]}-${Buffer.from(sri[2], "base64").toString("hex").slice(0, 12)}`;
  const line = [...value]
    .map((character) => {
      const code = character.charCodeAt(0);
      return code < 32 || code === 127 ? " " : character;
    })
    .join("");
  return line.length > 80 ? `${line.slice(0, 77)}...` : line;
}

/** A URL without credentials, query, or fragment; `${NAME}` templates as-is. */
function safeUrl(value: string | undefined): string | undefined {
  if (value === undefined || value.includes("${")) return value;
  try {
    const url = new URL(value);
    url.username = "";
    url.password = "";
    url.search = "";
    url.hash = "";
    return url.toString();
  } catch {
    return "(unparseable URL)";
  }
}

function origin(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  try {
    const url = new URL(value);
    return url.origin === "null" ? url.protocol : url.origin;
  } catch {
    return "(unparseable URL)";
  }
}

function fingerprint(publicKey: string): string {
  return `sha256:${createHash("sha256").update(publicKey).digest("hex").slice(0, 12)}`;
}

function rank(
  order: Record<string, number>,
  before: string,
  after: string,
  looser: string,
  tighter: string,
  tighterRisk: DiffRisk = "medium",
): Verdict {
  return (order[after] ?? 0) > (order[before] ?? 0)
    ? ["high", looser]
    : [tighterRisk, tighter];
}

// ------------------------------------------------------------ sections

function side(lock: AnyLock): DiffSide {
  return {
    id: lock.app?.id ?? "",
    version: lock.app?.version ?? "",
    pi: lock.runtime?.version ?? "",
    piship: lock.runtime?.pishipVersion ?? "",
    lockSchema: lock.schema ?? "",
  };
}

function distribution(out: Collector, b: AnyLock, a: AnyLock): void {
  out.scalar("distribution", "id", b.app?.id, a.app?.id, [
    "high",
    "Different distribution; compare releases of one distribution only.",
  ]);
  out.scalar("distribution", "version", b.app?.version, a.app?.version, [
    "low",
    "Release version change.",
  ]);
  out.scalar("distribution", "command", b.app?.command, a.app?.command, [
    "medium",
    "Users launch the distribution under a different command.",
  ]);
  out.scalar("distribution", "name", b.app?.name, a.app?.name, [
    "low",
    "Display name change.",
  ]);
  out.scalar("distribution", "banner", b.app?.banner, a.app?.banner, [
    "low",
    "Display banner change.",
  ]);
  out.scalar("distribution", "theme", b.app?.theme, a.app?.theme, [
    "low",
    "Default theme change.",
  ]);
  out.scalar(
    "distribution",
    "deployment mode",
    b.deployment?.mode,
    a.deployment?.mode,
    ["high", "Deployment mode changes which controls are enforced."],
  );
  out.scalar(
    "schema",
    "manifest schema",
    b.manifest?.schema,
    a.manifest?.schema,
    ["medium", "Manifest schema changed; requires migration review."],
  );
  out.scalar("schema", "lock schema", b.schema, a.schema, [
    "medium",
    "Lock schema changed; requires migration review.",
  ]);
  out.scalar("pi", "Pi runtime", b.runtime?.version, a.runtime?.version, [
    "high",
    "Pi runtime changed; extension, tool, and session behavior may differ.",
  ]);
  out.scalar(
    "piship",
    "PiShip version",
    b.runtime?.pishipVersion,
    a.runtime?.pishipVersion,
    ["medium", "PiShip runtime changed; launch and governance code differ."],
  );
}

function packages(out: Collector, b: AnyLock, a: AnyLock): void {
  const before = byKey(b.runtime?.packages, (item) => item.path);
  const after = byKey(a.runtime?.packages, (item) => item.path);
  for (const path of keys(before, after)) {
    const x = before.get(path);
    const y = after.get(path);
    if (!x && y) {
      out.push(
        "packages",
        "added",
        path,
        y.installScript
          ? ["high", "New dependency runs an install script."]
          : ["medium", "New runtime dependency."],
        undefined,
        y.version,
      );
      continue;
    }
    if (x && !y) {
      out.push(
        "packages",
        "removed",
        path,
        ["low", "Runtime dependency removed."],
        x.version,
      );
      continue;
    }
    if (!x || !y) continue;
    if (x.version !== y.version)
      out.push(
        "packages",
        "changed",
        path,
        ["medium", "Dependency version changed."],
        x.version,
        y.version,
      );
    else if (x.integrity !== y.integrity)
      out.push(
        "packages",
        "changed",
        `${path} integrity`,
        ["high", "Package content changed without a version change."],
        x.integrity,
        y.integrity,
      );
    const bo = origin(x.resolved);
    const ao = origin(y.resolved);
    if (bo !== undefined && ao !== undefined && bo !== ao)
      out.push(
        "packages",
        "changed",
        `${path} origin`,
        ["high", "Package now resolves from a different origin."],
        bo,
        ao,
      );
    if (y.installScript && !x.installScript)
      out.push(
        "packages",
        "changed",
        `${path} install script`,
        ["high", "Dependency now runs an install script."],
        "none",
        "install script",
      );
  }
}

function resourceArea(kind: string): DiffArea {
  if (kind === "providers") return "providers";
  return EXECUTABLE_KINDS.includes(kind) ? "extensions" : "resources";
}

function contentVerdict(kind: string, verb: "adds" | "changes"): Verdict {
  if (EXECUTABLE_KINDS.includes(kind))
    return [
      "high",
      `${verb === "adds" ? "Adds" : "Changes"} executable code (${kind}).`,
    ];
  if (kind === "instructions" || kind === "skills")
    return [
      "medium",
      `${verb === "adds" ? "Adds" : "Changes"} ${kind} that shape agent behavior.`,
    ];
  return ["low", `${verb === "adds" ? "Adds" : "Changes"} ${kind} content.`];
}

function resources(out: Collector, b: AnyLock, a: AnyLock): void {
  const key = (item: LockedResource) => `${item.kind} ${item.path}`;
  const before = byKey(b.resources, key);
  const after = byKey(a.resources, key);
  for (const item of keys(before, after)) {
    const x = before.get(item);
    const y = after.get(item);
    const kind = (y ?? x)?.kind ?? "";
    const area = resourceArea(kind);
    if (!x && y) {
      out.push(
        area,
        "added",
        item,
        contentVerdict(kind, "adds"),
        undefined,
        y.sha256,
      );
      continue;
    }
    if (x && !y) {
      out.push(
        area,
        "removed",
        item,
        ["low", `Removes ${kind} content.`],
        x.sha256,
      );
      continue;
    }
    if (!x || !y) continue;
    if (x.sha256 !== y.sha256)
      out.push(
        area,
        "changed",
        item,
        contentVerdict(kind, "changes"),
        x.sha256,
        y.sha256,
      );
    if (x.class !== undefined && y.class !== undefined)
      out.scalar(area, `${item} class`, x.class, y.class, (bc, ac) =>
        rank(
          CLASS_RANK,
          bc,
          ac,
          "Widens trust: content moves to a less-reviewed trust class.",
          "Narrows trust: content moves to a more-reviewed trust class.",
        ),
      );
  }
}

function contractBase(contract: string): [string, string] {
  const match = /^(.*)\/v(\d+)$/.exec(contract);
  return match ? [match[1] ?? contract, match[2] ?? ""] : [contract, ""];
}

function trustEvidence(
  out: Collector,
  b: GovernanceLock,
  a: GovernanceLock,
): void {
  const before = byKey(b.certified, (item) => item.path);
  const after = byKey(a.certified, (item) => item.path);
  for (const path of keys(before, after)) {
    const x = before.get(path);
    const y = after.get(path);
    const item = `certified ${path}`;
    const area = resourceArea((y ?? x)?.kind ?? "");
    if (!x && y) {
      out.push(
        area,
        "added",
        item,
        ["medium", "Adds a certified resource."],
        undefined,
        `${y.evidence.id}@${y.evidence.version}`,
      );
      continue;
    }
    if (x && !y) {
      out.push(
        area,
        "removed",
        item,
        ["low", "Removes a certified resource."],
        `${x.evidence.id}@${x.evidence.version}`,
      );
      continue;
    }
    if (!x || !y) continue;
    const reviewed: Verdict = [
      "high",
      "Reviewed certified content changed; confirm the new review evidence.",
    ];
    out.scalar(area, `${item} id`, x.evidence.id, y.evidence.id, reviewed);
    out.scalar(
      area,
      `${item} version`,
      x.evidence.version,
      y.evidence.version,
      reviewed,
    );
    out.scalar(area, `${item} integrity`, x.integrity, y.integrity, reviewed);
    out.scalar(area, `${item} source`, x.evidence.source, y.evidence.source, [
      "medium",
      "Certified source changed.",
    ]);
    out.scalar(
      area,
      `${item} license`,
      x.evidence.license,
      y.evidence.license,
      ["medium", "Certified license changed."],
    );
    out.set(
      area,
      `${item} pi`,
      x.evidence.pi,
      y.evidence.pi,
      ["medium", "Certified for an additional Pi version."],
      ["low", "No longer certified for this Pi version."],
    );
  }

  const bp = byKey(b.providers, (item) => item.capability);
  const ap = byKey(a.providers, (item) => item.capability);
  for (const capability of keys(bp, ap)) {
    const x = bp.get(capability);
    const y = ap.get(capability);
    const item = `provider ${capability}`;
    if (!x && y) {
      out.push(
        "providers",
        "added",
        item,
        y.class === "builtin"
          ? ["medium", "Adds a builtin capability provider."]
          : ["high", "Adds a capability provider (executable code)."],
        undefined,
        `${y.id}@${y.version}`,
      );
      continue;
    }
    if (x && !y) {
      out.push(
        "providers",
        "removed",
        item,
        ["low", "Removes a capability provider."],
        `${x.id}@${x.version}`,
      );
      continue;
    }
    if (!x || !y) continue;
    out.scalar("providers", `${item} id`, x.id, y.id, [
      "high",
      "Different provider implements the capability.",
    ]);
    out.scalar("providers", `${item} class`, x.class, y.class, (bc, ac) =>
      rank(
        CLASS_RANK,
        bc,
        ac,
        "Widens trust: provider moves to a less-reviewed trust class.",
        "Narrows trust: provider moves to a more-reviewed trust class.",
      ),
    );
    out.scalar("providers", `${item} version`, x.version, y.version, [
      "medium",
      "Provider version changed.",
    ]);
    out.scalar("providers", `${item} integrity`, x.integrity, y.integrity, [
      "high",
      "Provider code changed.",
    ]);
    const majors = new Map(x.implements.map(contractBase));
    const changedMajor = y.implements
      .map(contractBase)
      .some(([base, major]) => majors.has(base) && majors.get(base) !== major);
    out.set(
      "providers",
      `${item} implements`,
      x.implements,
      y.implements,
      changedMajor
        ? ["high", "Capability contract major version changed."]
        : ["medium", "Provider implements an additional contract."],
      changedMajor
        ? ["high", "Capability contract major version changed."]
        : ["medium", "Provider no longer implements this contract."],
    );
  }
}

function capabilities(
  out: Collector,
  b: GovernanceManifest,
  a: GovernanceManifest,
): void {
  const before = byKey(b.capabilities, (item) => item.name);
  const after = byKey(a.capabilities, (item) => item.name);
  for (const name of keys(before, after)) {
    const x = before.get(name);
    const y = after.get(name);
    const item = `capability ${name}`;
    const xe = x?.enabled ?? false;
    const ye = y?.enabled ?? false;
    if (xe !== ye)
      out.push(
        "capabilities",
        "changed",
        item,
        !ye && name === "permissions"
          ? ["high", "Disables permission enforcement."]
          : ["medium", ye ? "Enables a capability." : "Disables a capability."],
        xe ? "enabled" : "disabled",
        ye ? "enabled" : "disabled",
      );
    const bs = x?.settings ?? {};
    const as = y?.settings ?? {};
    for (const key of [
      ...new Set([...Object.keys(bs), ...Object.keys(as)]),
    ].sort(compare))
      if (bs[key] !== as[key])
        out.push(
          "capabilities",
          key in bs ? (key in as ? "changed" : "removed") : "added",
          `${item} setting ${key}`,
          ["low", "Capability setting changed."],
        );
  }
}

type RuleEntry = {
  readonly tier: string;
  readonly rule: GovernanceManifest["policy"]["enforced"][number];
};

function describeRule({ tier, rule }: RuleEntry): string {
  return `${tier}: ${rule.effect} ${rule.action} ${rule.resource}`;
}

function policy(
  out: Collector,
  b: GovernanceManifest,
  a: GovernanceManifest,
): void {
  const bp = b.policy;
  const ap = a.policy;
  out.scalar("policy", "policy id", bp?.id, ap?.id, [
    "medium",
    "Different policy set.",
  ]);
  out.scalar("policy", "policy version", bp?.version, ap?.version, [
    "low",
    "Policy version changed.",
  ]);
  out.scalar("policy", "policy default", bp?.default, ap?.default, (x, y) =>
    rank(
      EFFECT_RANK,
      x,
      y,
      "Relaxes policy default.",
      "Tightens policy default.",
    ),
  );
  out.scalar("policy", "policy adapter", bp?.adapter, ap?.adapter, (_, y) =>
    y === ""
      ? [
          "high",
          "Removes the team rules adapter, which only narrows; relaxes policy.",
        ]
      : ["high", "Team rules adapter changed (executable code)."],
  );
  const rules = (config: typeof bp | undefined) =>
    new Map<string, RuleEntry>(
      (["enforced", "defaults"] as const).flatMap((tier) =>
        (config?.[tier] ?? []).map(
          (rule) => [rule.id, { tier, rule }] as const,
        ),
      ),
    );
  const before = rules(bp);
  const after = rules(ap);
  const defaultRank = EFFECT_RANK[ap?.default ?? "deny"] ?? 0;
  for (const id of keys(before, after)) {
    const x = before.get(id);
    const y = after.get(id);
    const item = `policy rule ${id}`;
    if (!x && y) {
      const looser =
        y.rule.effect === "allow" ||
        (EFFECT_RANK[y.rule.effect] ?? 0) > defaultRank;
      out.push(
        "policy",
        "added",
        item,
        looser
          ? ["high", "Adds a rule looser than the default; relaxes policy."]
          : ["medium", "Adds a restricting rule; tightens policy."],
        undefined,
        describeRule(y),
      );
      continue;
    }
    if (x && !y) {
      out.push(
        "policy",
        "removed",
        item,
        x.rule.effect === "allow"
          ? ["medium", "Removes an allow rule; tightens policy."]
          : ["high", `Removes a ${x.rule.effect} rule; relaxes policy.`],
        describeRule(x),
      );
      continue;
    }
    if (!x || !y) continue;
    out.scalar("policy", item, x.rule.effect, y.rule.effect, (be, ae) =>
      rank(EFFECT_RANK, be, ae, "Relaxes policy.", "Tightens policy."),
    );
    out.scalar("policy", `${item} tier`, x.tier, y.tier, (_, at) =>
      at === "defaults"
        ? [
            "high",
            "Rule is no longer enforced and can be overridden; relaxes policy.",
          ]
        : ["medium", "Rule becomes enforced; tightens policy."],
    );
    const scope: Verdict = [
      "high",
      "Changes what the rule covers; review coverage with policy explain.",
    ];
    out.scalar("policy", `${item} action`, x.rule.action, y.rule.action, scope);
    out.scalar(
      "policy",
      `${item} resource`,
      x.rule.resource,
      y.rule.resource,
      scope,
    );
    out.scalar("policy", `${item} reason`, x.rule.reason, y.rule.reason, [
      "low",
      "Rule explanation changed.",
    ]);
  }
  for (const [field, order] of [
    ["resourceTrust", TRUST_RANK],
    ["providerTrust", TRUST_RANK],
  ] as const) {
    const bt: Record<string, string> = bp?.[field] ?? {};
    const at: Record<string, string> = ap?.[field] ?? {};
    for (const key of [
      ...new Set([...Object.keys(bt), ...Object.keys(at)]),
    ].sort(compare))
      out.scalar("policy", `policy ${field}.${key}`, bt[key], at[key], (x, y) =>
        rank(order, x, y, "Relaxes trust; relaxes policy.", "Tightens trust."),
      );
  }
  for (const tier of ["company", "external", "unknown"] as const) {
    const bd: Record<string, string> =
      bp?.projectTrust?.[tier]?.dimensions ?? {};
    const ad: Record<string, string> =
      ap?.projectTrust?.[tier]?.dimensions ?? {};
    for (const key of [
      ...new Set([...Object.keys(bd), ...Object.keys(ad)]),
    ].sort(compare))
      out.scalar(
        "policy",
        `policy projectTrust.${tier}.${key}`,
        bd[key],
        ad[key],
        (x, y) =>
          rank(
            DIMENSION_RANK,
            x,
            y,
            "Admits more project content; relaxes policy.",
            "Admits less project content; tightens policy.",
          ),
      );
    if (tier === "unknown") continue;
    const matchers = (config: typeof bp | undefined) =>
      (config?.projectTrust?.[tier]?.match ?? []).map((matcher) =>
        [
          matcher.remote === undefined ? "" : `remote=${matcher.remote}`,
          matcher.path === undefined ? "" : `path=${matcher.path}`,
        ]
          .filter(Boolean)
          .join(" "),
      );
    out.set(
      "policy",
      `policy projectTrust.${tier}.match`,
      matchers(bp),
      matchers(ap),
      tier === "company"
        ? [
            "high",
            "More projects are treated as company projects; relaxes policy.",
          ]
        : ["medium", "More projects are treated as external projects."],
      ["medium", "Fewer projects match this project class."],
    );
  }
}

function mcp(
  out: Collector,
  b: GovernanceManifest,
  a: GovernanceManifest,
): void {
  out.scalar("mcp", "mcp mode", b.mcp?.mode, a.mcp?.mode, (x, y) =>
    rank(
      MCP_MODE_RANK,
      x,
      y,
      "Admits more MCP servers.",
      "Admits fewer MCP servers.",
    ),
  );
  for (const field of ["project", "user"] as const)
    out.scalar("mcp", `mcp ${field}`, b.mcp?.[field], a.mcp?.[field], (x, y) =>
      rank(
        TRUST_RANK,
        x,
        y,
        `Trusts ${field} MCP definitions.`,
        `No longer trusts ${field} MCP definitions.`,
      ),
    );
  const before = byKey(b.mcp?.servers, (item) => item.id);
  const after = byKey(a.mcp?.servers, (item) => item.id);
  for (const id of keys(before, after)) {
    const x = before.get(id);
    const y = after.get(id);
    const item = `mcp server ${id}`;
    if (!x && y) {
      out.push(
        "mcp",
        "added",
        item,
        ["high", "New MCP server runs executable or remote code."],
        undefined,
        y.transport,
      );
      continue;
    }
    if (x && !y) {
      out.push(
        "mcp",
        "removed",
        item,
        ["low", "Removes an MCP server."],
        x.transport,
      );
      continue;
    }
    if (!x || !y) continue;
    const code: Verdict = [
      "high",
      "Server now runs different code or reaches a different endpoint.",
    ];
    out.scalar("mcp", `${item} transport`, x.transport, y.transport, code);
    out.scalar("mcp", `${item} command`, x.command, y.command, code);
    out.scalar("mcp", `${item} module`, x.module, y.module, code);
    out.scalar("mcp", `${item} url`, safeUrl(x.url), safeUrl(y.url), code);
    out.scalar("mcp", `${item} args`, x.args?.join(" "), y.args?.join(" "), [
      "medium",
      "Server arguments changed.",
    ]);
    out.scalar(
      "mcp",
      `${item} credential`,
      x.credential,
      y.credential,
      (_, c) =>
        c === "runtime"
          ? ["high", "Server now receives the runtime credential."]
          : ["medium", "Server no longer receives the runtime credential."],
    );
    out.scalar(
      "mcp",
      `${item} expectedServerName`,
      x.expectedServerName,
      y.expectedServerName,
      ["medium", "Server identity check changed."],
    );
    out.set(
      "mcp",
      `${item} tools.allow`,
      x.tools?.allow,
      y.tools?.allow,
      ["high", "Widens the tool allow list."],
      ["medium", "Narrows the tool allow list."],
    );
    out.set(
      "mcp",
      `${item} tools.deny`,
      x.tools?.deny,
      y.tools?.deny,
      ["medium", "Denies an additional tool."],
      ["high", "Stops denying a tool."],
    );
    out.set(
      "mcp",
      `${item} env.allow`,
      x.env?.allow,
      y.env?.allow,
      ["high", "Passes an additional environment variable to the server."],
      ["medium", "Passes fewer environment variables to the server."],
    );
    out.set(
      "mcp",
      `${item} env.set`,
      Object.keys(x.env?.set ?? {}),
      Object.keys(y.env?.set ?? {}),
      ["medium", "Sets an additional environment variable."],
      ["low", "No longer sets this environment variable."],
    );
    for (const key of Object.keys(y.env?.set ?? {}).sort(compare))
      if (key in (x.env?.set ?? {}) && x.env.set[key] !== y.env.set[key])
        out.push("mcp", "changed", `${item} env.set ${key}`, [
          "medium",
          "Environment value changed.",
        ]);
    out.scalar("mcp", `${item} required`, x.required, y.required, [
      "low",
      "Server start requirement changed.",
    ]);
    const timing = (server: typeof x) =>
      `timeout ${server.timeoutMs}ms, startup ${server.startupTimeoutMs}ms, attempts ${server.retry?.attempts}`;
    out.scalar("mcp", `${item} timing`, timing(x), timing(y), [
      "low",
      "Server timeouts or retries changed.",
    ]);
  }
}

function sandbox(
  out: Collector,
  b: GovernanceManifest,
  a: GovernanceManifest,
): void {
  const x = b.sandbox;
  const y = a.sandbox;
  out.scalar("sandbox", "sandbox required", x?.required, y?.required, (_, r) =>
    r === "false"
      ? ["high", "Sandbox no longer fails closed when unavailable."]
      : ["medium", "Sandbox becomes required."],
  );
  out.set(
    "sandbox",
    "sandbox filesystem.read.deny",
    x?.filesystem?.read?.deny,
    y?.filesystem?.read?.deny,
    ["medium", "Denies reading an additional path."],
    ["high", "Sandboxed processes may read this path."],
  );
  out.set(
    "sandbox",
    "sandbox filesystem.write.allow",
    x?.filesystem?.write?.allow,
    y?.filesystem?.write?.allow,
    ["high", "Sandboxed processes may write an additional path."],
    ["medium", "Removes a writable path."],
  );
  out.scalar(
    "sandbox",
    "sandbox network",
    x?.network?.mode,
    y?.network?.mode,
    (_, m) =>
      m === "allow"
        ? ["high", "Sandboxed processes may reach the network."]
        : ["medium", "Sandboxed processes lose network access."],
  );
  out.set(
    "sandbox",
    "sandbox environment.allow",
    x?.environment?.allow,
    y?.environment?.allow,
    ["high", "Passes an additional environment variable into the sandbox."],
    ["medium", "Passes fewer environment variables into the sandbox."],
  );
}

function audit(
  out: Collector,
  b: GovernanceManifest,
  a: GovernanceManifest,
): void {
  const x = b.audit;
  const y = a.audit;
  out.scalar("audit", "audit enabled", x?.enabled, y?.enabled, (_, e) =>
    e === "false"
      ? ["high", "Disables the audit log."]
      : ["medium", "Enables the audit log."],
  );
  const before = byKey(x?.sinks, (item) => item.id);
  const after = byKey(y?.sinks, (item) => item.id);
  for (const id of keys(before, after)) {
    const bs = before.get(id);
    const as = after.get(id);
    const item = `audit sink ${id}`;
    if (!bs && as) {
      out.push(
        "audit",
        "added",
        item,
        ["low", "Adds an audit sink."],
        undefined,
        as.type,
      );
      continue;
    }
    if (bs && !as) {
      out.push(
        "audit",
        "removed",
        item,
        bs.required
          ? ["high", "Removes a required audit sink."]
          : ["medium", "Removes an audit sink."],
        bs.type,
      );
      continue;
    }
    if (!bs || !as) continue;
    out.scalar("audit", `${item} required`, bs.required, as.required, (_, r) =>
      r === "false"
        ? ["high", "Audit delivery to this sink is no longer required."]
        : ["medium", "Audit delivery to this sink becomes required."],
    );
    out.scalar("audit", `${item} type`, bs.type, as.type, [
      "medium",
      "Audit sink type changed.",
    ]);
    out.scalar("audit", `${item} url`, safeUrl(bs.url), safeUrl(as.url), [
      "medium",
      "Audit sink endpoint changed.",
    ]);
  }
  const bc: Record<string, boolean> = { ...(x?.capture ?? {}) };
  const ac: Record<string, boolean> = { ...(y?.capture ?? {}) };
  for (const key of [...new Set([...Object.keys(bc), ...Object.keys(ac)])].sort(
    compare,
  ))
    out.scalar("audit", `audit capture.${key}`, bc[key], ac[key], (_, v) =>
      v === "true"
        ? ["high", "Audit captures content that may include sensitive data."]
        : ["medium", "Audit stops capturing this content."],
    );
  const buffer = (config: typeof x) =>
    config?.buffer
      ? `${config.buffer.maxEvents} events, ${config.buffer.flushIntervalMs}ms`
      : undefined;
  out.scalar("audit", "audit buffer", buffer(x), buffer(y), [
    "low",
    "Audit buffering changed.",
  ]);
}

function governance(out: Collector, b: AnyLock, a: AnyLock): void {
  const x = b.governance;
  const y = a.governance;
  if (!x && !y) return;
  if (!x || !y) {
    out.push(
      "policy",
      y ? "added" : "removed",
      "governance",
      y
        ? ["medium", "Adds governance: policy, MCP, sandbox, and audit."]
        : ["high", "Removes governance: policy, MCP, sandbox, and audit."],
    );
    return;
  }
  trustEvidence(out, x, y);
  capabilities(out, x.manifest, y.manifest);
  policy(out, x.manifest, y.manifest);
  mcp(out, x.manifest, y.manifest);
  sandbox(out, x.manifest, y.manifest);
  audit(out, x.manifest, y.manifest);
}

function access(out: Collector, b: AnyLock, a: AnyLock): void {
  const x: AccessManifest | undefined = b.access;
  const y: AccessManifest | undefined = a.access;
  if (!x && !y) return;
  if (!x || !y) {
    out.push(
      "access",
      y ? "added" : "removed",
      "access",
      y
        ? [
            "high",
            "Adds managed identity, credential, and inference providers.",
          ]
        : [
            "high",
            "Removes managed identity, credential, and inference settings.",
          ],
    );
    return;
  }
  const provider: Verdict = [
    "high",
    "Provider mode changed; authentication and credential flow differ.",
  ];
  const endpoint: Verdict = ["medium", "Endpoint template changed."];
  out.scalar(
    "access",
    "identity mode",
    x.identity?.mode,
    y.identity?.mode,
    provider,
  );
  const xo = x.identity?.mode === "oidc" ? x.identity.oidc : undefined;
  const yo = y.identity?.mode === "oidc" ? y.identity.oidc : undefined;
  if (xo && yo) {
    out.scalar("access", "identity issuer", xo.issuer, yo.issuer, endpoint);
    out.scalar(
      "access",
      "identity clientId",
      xo.clientId,
      yo.clientId,
      endpoint,
    );
    out.scalar(
      "access",
      "identity audience",
      xo.audience,
      yo.audience,
      endpoint,
    );
    out.scalar(
      "access",
      "identity redirectUri",
      safeUrl(xo.redirectUri),
      safeUrl(yo.redirectUri),
      endpoint,
    );
    out.set(
      "access",
      "identity scope",
      xo.scopes,
      yo.scopes,
      ["medium", "Requests an additional identity scope."],
      ["low", "Requests fewer identity scopes."],
    );
  }
  const xa = x.identity?.mode === "adapter" ? x.identity.adapter : undefined;
  const ya = y.identity?.mode === "adapter" ? y.identity.adapter : undefined;
  if (xa && ya)
    out.scalar("access", "identity adapter", xa, ya, [
      "high",
      "Identity adapter changed (executable code).",
    ]);
  out.scalar(
    "access",
    "credential provider",
    x.credential?.provider,
    y.credential?.provider,
    provider,
  );
  out.scalar(
    "access",
    "credential broker endpoint",
    safeUrl(x.credential?.broker?.endpoint),
    safeUrl(y.credential?.broker?.endpoint),
    endpoint,
  );
  out.scalar(
    "access",
    "credential revoke endpoint",
    safeUrl(x.credential?.broker?.revokeEndpoint),
    safeUrl(y.credential?.broker?.revokeEndpoint),
    endpoint,
  );
  out.scalar(
    "access",
    "credential adapter",
    x.credential?.adapter,
    y.credential?.adapter,
    ["high", "Credential adapter changed (executable code)."],
  );
  out.scalar(
    "access",
    "credential storage",
    x.credential?.storage?.provider,
    y.credential?.storage?.provider,
    (_, s) =>
      s === "file"
        ? [
            "high",
            "Credentials are stored in a file instead of the system store.",
          ]
        : ["medium", "Credential storage moves to the system store."],
  );
  out.scalar(
    "access",
    "credential acknowledgePlaintext",
    x.credential?.storage?.acknowledgePlaintext,
    y.credential?.storage?.acknowledgePlaintext,
    (_, v) =>
      v === "true"
        ? ["high", "Accepts plaintext credential storage."]
        : ["medium", "No longer accepts plaintext credential storage."],
  );
  out.scalar(
    "access",
    "credential refresh",
    x.credential?.refresh?.beforeExpirySeconds,
    y.credential?.refresh?.beforeExpirySeconds,
    ["low", "Credential refresh timing changed."],
  );
  out.scalar(
    "access",
    "inference provider",
    x.inference?.provider,
    y.inference?.provider,
    provider,
  );
  out.scalar(
    "access",
    "inference baseUrl",
    safeUrl(x.inference?.baseUrl),
    safeUrl(y.inference?.baseUrl),
    endpoint,
  );
  out.scalar("access", "inference api", x.inference?.api, y.inference?.api, [
    "medium",
    "Inference API dialect changed.",
  ]);
  out.scalar(
    "access",
    "inference liveCatalog",
    x.inference?.liveCatalog,
    y.inference?.liveCatalog,
    ["low", "Live model catalog setting changed."],
  );
  for (const layer of ["enforced", "defaults"] as const) {
    const bl: Record<string, string | undefined> = x.config?.[layer] ?? {};
    const al: Record<string, string | undefined> = y.config?.[layer] ?? {};
    for (const key of [
      ...new Set([...Object.keys(bl), ...Object.keys(al)]),
    ].sort(compare))
      out.scalar(
        "access",
        `config ${layer}.${key}`,
        bl[key],
        al[key],
        layer === "enforced" && al[key] === undefined
          ? ["medium", "Setting is no longer enforced."]
          : ["low", "Configuration value changed."],
      );
  }
  out.set(
    "access",
    "config userOverridable",
    x.config?.userOverridable,
    y.config?.userOverridable,
    ["medium", "Users may override an additional setting."],
    ["low", "Users may override fewer settings."],
  );
  out.set(
    "access",
    "variable",
    x.variables,
    y.variables,
    ["low", "Declares an additional runtime variable."],
    ["low", "Removes a runtime variable."],
  );

  out.set(
    "models",
    "model",
    x.models?.allowed,
    y.models?.allowed,
    ["medium", "Allows an additional model."],
    ["low", "Removes a model from the allow list."],
  );
  out.scalar("models", "default model", x.models?.default, y.models?.default, [
    "low",
    "Default model changed.",
  ]);
  const catalog = (models: AccessManifest["models"] | undefined) =>
    byKey(models?.catalog, (item) => item.id);
  const bc = catalog(x.models);
  const ac = catalog(y.models);
  for (const id of keys(bc, ac)) {
    const bm = bc.get(id);
    const am = ac.get(id);
    if (!bm || !am)
      out.push("models", bm ? "removed" : "added", `catalog ${id}`, [
        "low",
        "Model catalog entry changed.",
      ]);
    else if (JSON.stringify(bm) !== JSON.stringify(am))
      out.push("models", "changed", `catalog ${id}`, [
        "low",
        "Model catalog metadata changed.",
      ]);
  }

  out.scalar(
    "network",
    "network publicFallback",
    x.network?.publicFallback,
    y.network?.publicFallback,
    (_, v) =>
      v === "allow"
        ? ["high", "Falls back to public endpoints."]
        : ["medium", "No longer falls back to public endpoints."],
  );
  out.scalar(
    "network",
    "network privateOnly",
    x.network?.privateOnly,
    y.network?.privateOnly,
    (_, v) =>
      v === "false"
        ? ["high", "Endpoints are no longer restricted to private networks."]
        : ["medium", "Endpoints become restricted to private networks."],
  );
  out.set(
    "network",
    "network allowHost",
    x.network?.allowHosts,
    y.network?.allowHosts,
    ["high", "Allows an additional host."],
    ["medium", "Allows fewer hosts."],
  );
  out.set(
    "network",
    "network additionalCA",
    x.network?.tls?.additionalCA,
    y.network?.tls?.additionalCA,
    ["high", "Trusts an additional certificate authority."],
    ["medium", "Trusts fewer certificate authorities."],
  );
  out.scalar(
    "network",
    "network proxy.inheritEnvironment",
    x.network?.proxy?.inheritEnvironment,
    y.network?.proxy?.inheritEnvironment,
    ["medium", "Proxy selection changed."],
  );
}

function updates(out: Collector, b: AnyLock, a: AnyLock): void {
  const x = b.updates;
  const y = a.updates;
  if (!x && !y) return;
  out.scalar("updates", "update channel", x?.channel, y?.channel, [
    "medium",
    "Default update channel changed.",
  ]);
  out.set(
    "updates",
    "update channels",
    x?.channels,
    y?.channels,
    (value) =>
      value === "dev"
        ? ["medium", "Users may select the dev channel."]
        : ["low", "Users may select an additional channel."],
    ["low", "Removes a selectable channel."],
  );
  out.scalar(
    "updates",
    "update source",
    safeUrl(x?.source),
    safeUrl(y?.source),
    ["high", "Updates come from a different source."],
  );
  out.scalar("updates", "update rollback", x?.rollback, y?.rollback, (_, v) =>
    v === "false"
      ? ["medium", "The previous known-good release is no longer kept."]
      : ["low", "Keeps the previous known-good release."],
  );
  const before = byKey(x?.trust?.keys, (item) => item.id);
  const after = byKey(y?.trust?.keys, (item) => item.id);
  const publish: Verdict = ["high", "Changes who can publish updates."];
  for (const id of keys(before, after)) {
    const bk = before.get(id)?.publicKey;
    const ak = after.get(id)?.publicKey;
    out.scalar(
      "updates",
      `update trust key ${id}`,
      bk === undefined ? undefined : fingerprint(bk),
      ak === undefined ? undefined : fingerprint(ak),
      publish,
    );
  }
}

function release(out: Collector, b: AnyLock, a: AnyLock): void {
  const x = b.release;
  const y = a.release;
  if (!x && !y) return;
  out.set(
    "release",
    "release target",
    x?.targets,
    y?.targets,
    [
      "medium",
      "Advertises an additional target; it needs installed E2E evidence.",
    ],
    ["low", "No longer advertises this target."],
  );
  out.set(
    "release",
    "release source",
    x?.sources?.map((value) => origin(value) ?? value),
    y?.sources?.map((value) => origin(value) ?? value),
    ["high", "Approves a new package source origin."],
    ["low", "Removes an approved package source."],
  );
  out.scalar(
    "release",
    "vulnerabilities failOn",
    x?.vulnerabilities?.failOn,
    y?.vulnerabilities?.failOn,
    (bf, af) =>
      rank(
        FAIL_ON_RANK,
        bf,
        af,
        "Loosens the vulnerability gate.",
        "Tightens the vulnerability gate.",
      ),
  );
  const before = byKey(x?.vulnerabilities?.allow, (item) => item.id);
  const after = byKey(y?.vulnerabilities?.allow, (item) => item.id);
  for (const id of keys(before, after)) {
    const be = before.get(id)?.expires;
    const ae = after.get(id)?.expires;
    out.scalar("release", `vulnerability exception ${id}`, be, ae, (bv, av) =>
      av === ""
        ? ["medium", "Removes a reviewed vulnerability exception."]
        : bv === ""
          ? ["high", "Allows a known vulnerability."]
          : av > bv
            ? ["high", "Extends a vulnerability exception."]
            : ["medium", "Shortens a vulnerability exception."],
    );
  }
}

function requiredTests(changes: readonly DiffChange[]): string[] {
  const tests = new Set<string>();
  for (const change of changes) {
    tests.add(DIFF_TESTS.check);
    switch (change.area) {
      case "pi":
      case "piship":
      case "packages":
        tests.add(DIFF_TESTS.compatibility);
        tests.add(DIFF_TESTS.installed);
        break;
      case "distribution":
      case "resources":
        tests.add(DIFF_TESTS.installed);
        break;
      case "schema":
        tests.add(DIFF_TESTS.migration);
        break;
      case "extensions":
      case "providers":
      case "capabilities":
        tests.add(DIFF_TESTS.installed);
        tests.add(DIFF_TESTS.governance);
        break;
      case "policy":
      case "mcp":
      case "audit":
        tests.add(DIFF_TESTS.governance);
        break;
      case "sandbox":
        tests.add(DIFF_TESTS.governance);
        tests.add(DIFF_TESTS.sandbox);
        break;
      case "access":
      case "models":
      case "network":
        tests.add(DIFF_TESTS.managed);
        break;
      case "updates":
      case "release":
        tests.add(DIFF_TESTS.release);
        break;
    }
  }
  return [...tests].sort(compare);
}

/** Compare two locks and classify every release-impact change by risk. */
export function diffLocks(
  before: DistributionLock,
  after: DistributionLock,
): DiffReport {
  const b = before as unknown as AnyLock;
  const a = after as unknown as AnyLock;
  const out = new Collector();
  distribution(out, b, a);
  packages(out, b, a);
  resources(out, b, a);
  governance(out, b, a);
  access(out, b, a);
  updates(out, b, a);
  release(out, b, a);
  const changes = out.changes.sort(
    (x, y) =>
      DIFF_AREAS.indexOf(x.area) - DIFF_AREAS.indexOf(y.area) ||
      compare(x.item, y.item) ||
      compare(x.kind, y.kind) ||
      compare(x.reason, y.reason),
  );
  const risk = changes.reduce<DiffRisk | "none">(
    (max, change) =>
      max === "none" || RISK_RANK[change.risk] > RISK_RANK[max]
        ? change.risk
        : max,
    "none",
  );
  return {
    schema: "piship-diff/v1",
    before: side(b),
    after: side(a),
    risk,
    changes,
    requiredTests: requiredTests(changes),
  };
}

function transition(before: string, after: string): string {
  return before === after ? before : `${before} -> ${after}`;
}

/** Deterministic plain-text rendering of a diff report. */
export function formatDiff(report: DiffReport): string {
  const lines = [
    `${report.after.id} ${report.before.version} -> ${report.after.version} (risk: ${report.risk})`,
    `Pi ${transition(report.before.pi, report.after.pi)}, PiShip ${transition(report.before.piship, report.after.piship)}`,
  ];
  if (report.changes.length === 0) lines.push("No release-impact changes.");
  else {
    lines.push("Changes:");
    for (const change of report.changes) {
      const values =
        change.before !== undefined && change.after !== undefined
          ? ` (${change.before} -> ${change.after})`
          : change.before !== undefined || change.after !== undefined
            ? ` (${change.before ?? change.after})`
            : "";
      lines.push(
        `  [${change.risk}] ${change.area}: ${change.kind} ${change.item}${values}: ${change.reason}`,
      );
    }
  }
  if (report.requiredTests.length) {
    lines.push("Required tests:");
    for (const test of report.requiredTests) lines.push(`  - ${test}`);
  }
  return `${lines.join("\n")}\n`;
}
