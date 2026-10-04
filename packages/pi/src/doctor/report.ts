// The doctor report: named groups in one fixed order, and the only place
// doctor text is written. Every label and value passes through the same
// sanitizer, so no group can print a credential, a token, URL credentials,
// or a URL query, whatever an error message or a configuration value holds.
import { redact } from "@piship/contracts";

/**
 * The groups in the order doctor prints them. The enterprise diagnostics
 * groups keep their recommended relative order (Distribution, Identity,
 * Credential, Inference, Gateway, Resources, Policy, Sandbox, Workspace,
 * Secret Store, Audit, Network, Release); the other groups sit next to the
 * one they belong with. A group with no lines is not printed.
 */
export const DOCTOR_GROUPS = [
  "Distribution",
  "Supply Chain",
  "Identity",
  "Credential",
  "Inference",
  "Gateway",
  "Resources",
  "Policy",
  "Governance",
  "Project",
  "Capabilities",
  "Sandbox",
  "Workspace",
  "MCP",
  "Secret Store",
  "Audit",
  "Network",
  "Release",
  "Update",
] as const;

export type DoctorGroup = (typeof DOCTOR_GROUPS)[number];

/** Lines of one group: passed, warning, failed (doctor exits 1), or neutral. */
export interface DoctorSection {
  ok(label: string, value: string): void;
  warn(label: string, value: string): void;
  bad(label: string, value: string): void;
  info(label: string, value: string): void;
}

// scheme://[userinfo@]authority[path][?query][#fragment]. The userinfo is
// matched up to the last `@` before the path, as URL parsers do.
const URL_PATTERN =
  /\b([a-z][a-z0-9+.-]*:\/\/)(?:[^\s/?#]*@)?([^\s/?#]*)([^\s?#]*)(\?[^\s#]*)?(#\S*)?/gi;
// Terminal control characters other than the newline a formatted error uses
// before its action.
// biome-ignore lint/suspicious/noControlCharactersInRegex: control characters are what this removes
const CONTROL = /[\u0000-\u0009\u000b-\u001f\u007f-\u009f]/g;

/**
 * Make one piece of doctor text safe to print: URL credentials, queries, and
 * fragments are removed, known secret values and token shapes are redacted,
 * and control characters are dropped.
 */
export function sanitizeDoctorText(text: string): string {
  const withoutUrlSecrets = text.replace(
    URL_PATTERN,
    (_match, scheme: string, host: string, path: string) =>
      `${scheme}${host}${path}`,
  );
  return redact(withoutUrlSecrets).replace(CONTROL, "");
}

/** One doctor line as `doctor --json` prints it, sanitized. */
export interface DoctorCheck {
  readonly status: "ok" | "warn" | "fail" | "info";
  readonly label: string;
  readonly value: string;
}

const STATUS = { ok: "ok", warn: "warn", bad: "fail", info: "info" } as const;
const MARKS = { ok: "✓", warn: "!", fail: "✗", info: "-" } as const;

export class DoctorReport {
  readonly #groups = new Map<DoctorGroup, DoctorCheck[]>();
  #failed = false;

  constructor(readonly title: string) {}

  /** Whether any group reported a failure. */
  get failed(): boolean {
    return this.#failed;
  }

  section(group: DoctorGroup): DoctorSection {
    const line =
      (mark: keyof typeof STATUS) => (label: string, value: string) => {
        if (mark === "bad") this.#failed = true;
        const checks = this.#groups.get(group) ?? [];
        checks.push({
          status: STATUS[mark],
          label: sanitizeDoctorText(label),
          value: sanitizeDoctorText(value),
        });
        this.#groups.set(group, checks);
      };
    return {
      ok: line("ok"),
      warn: line("warn"),
      bad: line("bad"),
      info: line("info"),
    };
  }

  render(): string {
    const output = [sanitizeDoctorText(this.title)];
    for (const { group, checks } of this.toJSON().groups)
      output.push(
        "",
        group,
        ...checks.map(
          (check) =>
            `  ${MARKS[check.status]} ${check.label.padEnd(20)} ${check.value}`,
        ),
      );
    return output.join("\n");
  }

  /** The report for `doctor --json`, in the same group order. */
  toJSON(): {
    title: string;
    failed: boolean;
    groups: { group: DoctorGroup; checks: DoctorCheck[] }[];
  } {
    return {
      title: sanitizeDoctorText(this.title),
      failed: this.#failed,
      groups: DOCTOR_GROUPS.flatMap((group) => {
        const checks = this.#groups.get(group);
        return checks?.length ? [{ group, checks }] : [];
      }),
    };
  }
}
