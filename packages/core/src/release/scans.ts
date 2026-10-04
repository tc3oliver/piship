// Release dependency scans: the npm audit vulnerability policy and the
// registry signature check.
import { spawnSync } from "node:child_process";
import type { ReleaseManifest } from "@piship/schema";
import {
  VULNERABILITY_REPORT_SCHEMA,
  type CommandResult,
  type SignatureReport,
  type VulnerabilityFinding,
  type VulnerabilityReport,
} from "./metadata.js";
import { gate } from "./shared.js";

const SEVERITY_ORDER = ["info", "low", "moderate", "high", "critical"];

/**
 * `npm audit` over the npm lock in `lockDirectory` (registry access
 * required): the payload's, or a Pi package's against its `registry`.
 */
export function npmAuditScanner(
  lockDirectory: string,
  registry?: string,
): unknown {
  const args = [
    "audit",
    "--omit=dev",
    "--json",
    ...(registry ? [`--registry=${registry}`] : []),
  ];
  const result =
    process.platform === "win32"
      ? spawnSync("cmd.exe", ["/d", "/s", "/c", `npm ${args.join(" ")}`], {
          cwd: lockDirectory,
          encoding: "utf8",
          maxBuffer: 64 * 1024 * 1024,
        })
      : spawnSync("npm", args, {
          cwd: lockDirectory,
          encoding: "utf8",
          maxBuffer: 64 * 1024 * 1024,
        });
  try {
    return JSON.parse(result.stdout);
  } catch {
    throw gate(
      "UPDATE_FAILED",
      "vulnerability",
      `the dependency scan did not run: ${(result.stderr || result.error?.message || "no output").trim().slice(0, 300)}`,
      "Restore registry access for the build; releases are not produced without a scan",
    );
  }
}

const SIGNATURE_TOOL = "npm audit signatures --omit=dev";

/**
 * `npm audit signatures` over the installed payload. It reads the payload's
 * `node_modules` and needs the registry and the Sigstore trust root.
 */
export function npmSignatureAuditor(payloadDirectory: string): CommandResult {
  const args = ["audit", "signatures", "--omit=dev", "--json"];
  const options = {
    cwd: payloadDirectory,
    encoding: "utf8" as const,
    maxBuffer: 64 * 1024 * 1024,
    timeout: 300_000,
  };
  const result =
    process.platform === "win32"
      ? spawnSync(
          "cmd.exe",
          ["/d", "/s", "/c", `npm ${args.join(" ")}`],
          options,
        )
      : spawnSync("npm", args, options);
  return {
    status: result.status,
    stdout: result.stdout ?? "",
    stderr: result.stderr || result.error?.message || "",
  };
}

interface SignatureEntry {
  readonly name: string;
  readonly version: string;
  readonly code: string;
}

function signatureEntries(value: unknown): SignatureEntry[] | null {
  if (!Array.isArray(value)) return null;
  const entries: SignatureEntry[] = [];
  for (const item of value) {
    if (!item || typeof item !== "object") return null;
    const entry = item as { name?: unknown; version?: unknown; code?: unknown };
    if (typeof entry.name !== "string") return null;
    entries.push({
      name: entry.name,
      version: typeof entry.version === "string" ? entry.version : "",
      code: typeof entry.code === "string" ? entry.code : "",
    });
  }
  return entries;
}

/**
 * Apply the release signature policy to `npm audit signatures --json`
 * output. An invalid registry signature or attestation fails the build. A
 * missing signature is recorded. When npm reports that the check itself
 * could not run, the release records `unavailable` with npm's reason.
 * Output that is neither a report nor an npm error fails closed.
 */
export function evaluateSignatures(result: CommandResult): SignatureReport {
  let parsed: unknown;
  try {
    parsed = JSON.parse(result.stdout);
  } catch {
    parsed = undefined;
  }
  const value = (parsed && typeof parsed === "object" ? parsed : {}) as {
    invalid?: unknown;
    missing?: unknown;
    error?: { summary?: unknown };
  };
  const invalid = signatureEntries(value.invalid);
  const missing = signatureEntries(value.missing);
  if (invalid && missing) {
    if (invalid.length)
      throw gate(
        "INTEGRITY_FAILED",
        "signature",
        `invalid registry signatures or attestations: ${invalid
          .map(
            (item) =>
              `${item.name}@${item.version}${item.code ? ` (${item.code})` : ""}`,
          )
          .join(", ")}`,
        "Do not release this payload; reinstall the dependency from the trusted registry and investigate its source",
      );
    return {
      tool: SIGNATURE_TOOL,
      verdict: "passed",
      missing: missing.map((item) => `${item.name}@${item.version}`).sort(),
    };
  }
  const summary = value.error?.summary;
  if (typeof summary === "string" && summary.trim())
    return {
      tool: SIGNATURE_TOOL,
      verdict: "unavailable",
      missing: [],
      reason: summary.trim().replace(/\s+/g, " ").slice(0, 300),
    };
  throw gate(
    "UPDATE_FAILED",
    "signature",
    `the registry signature check returned no report: ${(result.stderr || result.stdout || "no output").trim().slice(0, 300)}`,
    "Restore npm and registry access for the build; releases are not produced from an unreadable signature check",
  );
}

/** Apply the release vulnerability policy to npm-audit-v2-shaped JSON. */
export function evaluateVulnerabilities(
  audit: unknown,
  policy: ReleaseManifest["vulnerabilities"],
  now: Date,
): VulnerabilityReport {
  const value = audit as {
    auditReportVersion?: unknown;
    vulnerabilities?: Record<
      string,
      { severity?: string; via?: readonly unknown[] }
    >;
    error?: unknown;
  };
  if (
    !value ||
    typeof value !== "object" ||
    value.auditReportVersion !== 2 ||
    !value.vulnerabilities ||
    typeof value.vulnerabilities !== "object" ||
    Array.isArray(value.vulnerabilities)
  )
    throw gate(
      "UPDATE_FAILED",
      "vulnerability",
      "the dependency scan returned no npm audit v2 report",
    );
  const threshold = SEVERITY_ORDER.indexOf(policy.failOn);
  const today = now.toISOString().slice(0, 10);
  const allowed = new Map(
    policy.allow
      .filter((entry) => entry.expires >= today)
      .map((entry) => [entry.id, entry]),
  );
  const findings = new Map<string, VulnerabilityFinding>();
  for (const [name, entry] of Object.entries(value.vulnerabilities))
    for (const via of entry.via ?? []) {
      if (!via || typeof via !== "object") continue;
      const advisory = via as {
        source?: unknown;
        url?: unknown;
        title?: unknown;
        severity?: unknown;
      };
      const url = typeof advisory.url === "string" ? advisory.url : null;
      const id =
        url?.match(/GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}/i)?.[0] ??
        `npm-${String(advisory.source ?? "unknown")}`;
      const severity =
        typeof advisory.severity === "string"
          ? advisory.severity
          : (entry.severity ?? "info");
      // An unrecognised severity cannot be ranked, so it never passes as low.
      const rank = SEVERITY_ORDER.indexOf(severity);
      const status =
        rank !== -1 && rank < threshold
          ? "below-threshold"
          : allowed.has(id)
            ? "allowed"
            : "blocking";
      findings.set(`${id} ${name}`, {
        id,
        package: name,
        severity,
        title: typeof advisory.title === "string" ? advisory.title : "",
        url,
        status,
      });
    }
  const sorted = [...findings.values()].sort((a, b) =>
    `${a.id} ${a.package}`.localeCompare(`${b.id} ${b.package}`),
  );
  const counts: Record<string, number> = {};
  for (const severity of SEVERITY_ORDER) counts[severity] = 0;
  for (const finding of sorted)
    counts[finding.severity] = (counts[finding.severity] ?? 0) + 1;
  return {
    schema: VULNERABILITY_REPORT_SCHEMA,
    scanner: "npm audit --omit=dev",
    failOn: policy.failOn,
    verdict: sorted.some((finding) => finding.status === "blocking")
      ? "failed"
      : "passed",
    counts,
    findings: sorted,
  };
}
