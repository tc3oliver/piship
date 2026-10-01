import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  LEGACY_STATE_SCHEMAS,
  STATE_DATA_CLASSES,
  STATE_SCHEMAS,
  checkStateMigration,
  compareVersions,
  formatMigrationReport,
  readStateMarker,
  type MigrationReport,
} from "./migration.js";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

function state(): string {
  const dir = mkdtempSync(join(tmpdir(), "piship-migration-"));
  roots.push(dir);
  return dir;
}
function write(root: string, path: string, value: unknown): void {
  const file = join(root, ...path.split("/"));
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(
    file,
    typeof value === "string" ? value : JSON.stringify(value),
  );
}
function treeHash(root: string): Record<string, string> {
  const output: Record<string, string> = {};
  const visit = (dir: string) => {
    for (const name of readdirSync(dir).sort()) {
      const path = join(dir, name);
      const stat = statSync(path);
      const key = relative(root, path);
      if (stat.isDirectory()) {
        output[`${key}/`] = String(stat.mode);
        visit(path);
      } else
        output[key] =
          `${stat.mode} ${createHash("sha256").update(readFileSync(path)).digest("hex")}`;
    }
  };
  visit(root);
  return output;
}

/** A realistic state directory written by 1.1.0 on Pi 0.87.1. */
function populated(): string {
  const dir = state();
  write(dir, "state.json", {
    schema: "piship-state/v1",
    distribution: "acmepi",
    version: "1.1.0",
    pi: "0.87.1",
    piship: "0.1.0",
  });
  write(dir, "identity/session.json", {
    schema: "piship-identity-metadata/v1",
    credential_ref: "file:identity",
  });
  write(dir, "credentials-metadata/inference.json", {
    schema: "piship-credential-metadata/v1",
    credential_ref: "file:inference",
  });
  write(dir, "secrets/inference", "sentinel-secret\n");
  write(dir, "config/preferences.json", {
    schema: "piship-preferences/v1",
    theme: "dark",
  });
  write(dir, "config/policy.json", { rules: [] });
  write(dir, "agent/auth.json", { token: "sentinel" });
  write(dir, "sessions/one.jsonl", '{"type":"message"}\n');
  write(
    dir,
    "logs/audit.jsonl",
    '{"schema":"piship-audit/v1"}\n{"schema":"piship-audit/v1"}\n',
  );
  write(dir, "cache/models.json", "{}");
  write(dir, "data/x", "x");
  return dir;
}

const target = (pi = "0.87.1", schemas = STATE_SCHEMAS) => ({
  version: "1.0.0",
  pi,
  schemas,
});
const current = { version: "1.1.0", pi: "0.87.1" };

function item(report: MigrationReport, name: string) {
  const found = report.items.find((entry) => entry.name === name);
  if (!found) throw new Error(`no item ${name}`);
  return found;
}

describe("STATE_DATA_CLASSES", () => {
  it("documents every class with unique paths and marks credential classes", () => {
    const paths = STATE_DATA_CLASSES.map((entry) => entry.path);
    expect(new Set(paths).size).toBe(paths.length);
    for (const entry of STATE_DATA_CLASSES) {
      expect(entry.scope).toBeTruthy();
      expect(entry.retention).toBeTruthy();
      expect(entry.clear).toBeTruthy();
      expect(entry.migration).toBeTruthy();
      if (entry.schema)
        expect(Object.keys(STATE_SCHEMAS)).toContain(entry.schema);
    }
    expect(
      STATE_DATA_CLASSES.filter((entry) => entry.credential).map(
        (entry) => entry.path,
      ),
    ).toEqual([
      "identity/session.json",
      "credentials-metadata/inference.json",
      "credentials-metadata/sandbox.json",
      "credentials-metadata/pending-issuance.json",
      "secrets",
      "agent",
    ]);
    for (const entry of STATE_DATA_CLASSES.filter((value) => value.credential))
      expect(entry.migration).toMatch(/never/);
  });

  it("matches the state table in docs/architecture.md, row for row", () => {
    const doc = readFileSync(
      new URL("../../../docs/architecture.md", import.meta.url),
      "utf8",
    );
    const section = doc.slice(
      doc.indexOf("| State path |"),
      doc.indexOf("Other data PiShip creates"),
    );
    const rows = [...section.matchAll(/^\| `([^`]+)` \|/gm)].map((match) =>
      (match[1] as string).replace(/\/$/, ""),
    );
    expect(rows.length).toBeGreaterThan(10);
    const covers = (path: string, row: string) =>
      row === path || row.startsWith(`${path}/`);
    // Every class has a row, and every row belongs to a class.
    for (const entry of STATE_DATA_CLASSES)
      expect(
        rows.some((row) => covers(entry.path, row)),
        entry.path,
      ).toBe(true);
    for (const row of rows)
      expect(
        STATE_DATA_CLASSES.some((entry) => covers(entry.path, row)),
        row,
      ).toBe(true);
  });
});

describe("checkStateMigration", () => {
  it("never mutates the state directory", () => {
    const dir = populated();
    write(dir, "credentials-metadata/inference.json", {
      schema: "piship-credential-metadata/v2",
    });
    write(dir, "config/preferences.json", { schema: "piship-preferences/v9" });
    const before = treeHash(dir);
    for (const pi of ["0.87.1", "0.86.0"])
      for (const schemas of [STATE_SCHEMAS, LEGACY_STATE_SCHEMAS])
        checkStateMigration(dir, target(pi, schemas), current);
    expect(treeHash(dir)).toEqual(before);
  });

  it("is safe for an empty or missing state directory", () => {
    const empty = checkStateMigration(state(), target(), current);
    expect(empty.verdict).toBe("safe");
    expect(empty.items.every((entry) => entry.reason === "Not present")).toBe(
      true,
    );
    const missing = checkStateMigration(
      join(state(), "nope"),
      target(),
      current,
    );
    expect(missing.verdict).toBe("safe");
    expect(missing.from).toEqual(current);
  });

  it("is safe when every present class is readable", () => {
    const report = checkStateMigration(populated(), target(), {
      version: null,
      pi: null,
    });
    expect(report.verdict).toBe("safe");
    expect(report.from).toEqual({ version: "1.1.0", pi: "0.87.1" });
    expect(report.to).toEqual({ version: "1.0.0", pi: "0.87.1" });
    expect(report.items.map((entry) => entry.name)).toEqual(
      STATE_DATA_CLASSES.map((entry) => entry.name),
    );
    expect(report.items.every((entry) => entry.action === "keep")).toBe(true);
    expect(item(report, "Pi agent configuration").reason).toBe(
      "Kept in place and never copied into a snapshot",
    );
    expect(item(report, "audit and metrics logs").current).toBe(
      "piship-audit/v1",
    );
    expect(formatMigrationReport(report)).toMatch(
      /^Migration check 1.1.0 -> 1.0.0 \(Pi 0.87.1 -> 0.87.1\): safe/,
    );
  });

  it("requires review when sessions exist and the target runs an older Pi", () => {
    const dir = populated();
    const report = checkStateMigration(dir, target("0.86.0"), current);
    expect(report.verdict).toBe("requires-review");
    expect(item(report, "sessions")).toMatchObject({
      verdict: "requires-review",
      action: "review",
      current: "Pi 0.87.1",
    });
    // Without session files there is nothing to review.
    rmSync(join(dir, "sessions", "one.jsonl"));
    expect(checkStateMigration(dir, target("0.86.0"), current).verdict).toBe(
      "safe",
    );
    // A newer target Pi migrates sessions forward.
    write(dir, "sessions/one.jsonl", "{}\n");
    expect(checkStateMigration(dir, target("0.88.0"), current).verdict).toBe(
      "safe",
    );
  });

  it("uses the marker over the caller's idea of the current release", () => {
    const dir = populated();
    const report = checkStateMigration(dir, target("0.87.1"), {
      version: "0.9.0",
      pi: "0.80.0",
    });
    expect(report.from).toEqual({ version: "1.1.0", pi: "0.87.1" });
    rmSync(join(dir, "state.json"));
    const fallback = checkStateMigration(dir, target("0.86.0"), {
      version: "1.1.0",
      pi: "0.87.1",
    });
    expect(fallback.verdict).toBe("requires-review");
    expect(fallback.from).toEqual({ version: "1.1.0", pi: "0.87.1" });
  });

  it("refuses preferences in a schema the target does not read", () => {
    const dir = populated();
    write(dir, "config/preferences.json", { schema: "piship-preferences/v9" });
    const report = checkStateMigration(dir, target(), current);
    expect(report.verdict).toBe("unsupported");
    expect(item(report, "preferences")).toMatchObject({
      verdict: "unsupported",
      action: "refuse",
      current: "piship-preferences/v9",
    });
    expect(item(report, "preferences").reason).toMatch(
      /reads piship-preferences\/v1 of this file, not piship-preferences\/v9/,
    );
  });

  it("refuses unreadable preferences and a newer audit log", () => {
    const dir = populated();
    // Damaged preferences cannot be rebuilt: refused, naming the file and
    // the way out, and never touched.
    const preferences = join(dir, "config", "preferences.json");
    for (const damaged of ["{not json", "", '{"schema":"piship-pref', "{}"]) {
      write(dir, "config/preferences.json", damaged);
      const refused = item(
        checkStateMigration(dir, target(), current),
        "preferences",
      );
      expect(refused).toMatchObject({
        current: "unreadable",
        verdict: "unsupported",
        action: "refuse",
      });
      expect(refused.reason).toContain(
        `${preferences} is empty, cut short, or not a preferences file`,
      );
      expect(refused.reason).toContain(
        `move it aside (for example to ${preferences}.damaged)`,
      );
      expect(readFileSync(preferences, "utf8")).toBe(damaged);
    }
    write(dir, "config/preferences.json", { schema: "piship-preferences/v1" });
    write(
      dir,
      "logs/audit.jsonl",
      '{"schema":"piship-audit/v1"}\n{"schema":"piship-audit/v2"}\n',
    );
    expect(
      item(
        checkStateMigration(dir, target(), current),
        "audit and metrics logs",
      ).verdict,
    ).toBe("unsupported");
  });

  it("reads the newest audit schema from the rotated file after a rotation", () => {
    const dir = populated();
    write(dir, "logs/audit.jsonl", "");
    write(dir, "logs/audit.jsonl.1", '{"schema":"piship-audit/v2"}\n');
    write(dir, "logs/audit.jsonl.2", '{"schema":"piship-audit/v1"}\n');
    const report = checkStateMigration(dir, target(), current);
    expect(item(report, "audit and metrics logs")).toMatchObject({
      current: "piship-audit/v2",
      verdict: "unsupported",
    });
  });

  it("keeps an audit log whose newest line was cut short, and reads the event before it", () => {
    const dir = populated();
    const event = '{"schema":"piship-audit/v1","type":"launch"}';
    // A torn final append, after an event and on its own.
    write(dir, "logs/audit.jsonl", `${event}\n{"schema":"piship-au`);
    expect(
      item(
        checkStateMigration(dir, target(), current),
        "audit and metrics logs",
      ),
    ).toMatchObject({
      current: "piship-audit/v1",
      verdict: "safe",
      action: "keep",
    });
    write(dir, "logs/audit.jsonl", '{"schema":"piship-au');
    const torn = item(
      checkStateMigration(dir, target(), current),
      "audit and metrics logs",
    );
    expect(torn).toMatchObject({ current: null, verdict: "safe" });
    expect(torn.reason).toContain(join(dir, "logs", "audit.jsonl"));
    // The newest complete event decides, also across a rotation.
    write(dir, "logs/audit.jsonl", "{\n");
    write(dir, "logs/audit.jsonl.1", '{"schema":"piship-audit/v2"}\n');
    expect(
      item(
        checkStateMigration(dir, target(), current),
        "audit and metrics logs",
      ).verdict,
    ).toBe("unsupported");
  });

  it("clears and reacquires credential classes the target cannot read", () => {
    const dir = populated();
    write(dir, "credentials-metadata/inference.json", {
      schema: "piship-credential-metadata/v2",
    });
    write(dir, "identity/session.json", "garbage");
    const report = checkStateMigration(dir, target(), current);
    expect(report.verdict).toBe("safe");
    expect(item(report, "runtime credential metadata")).toMatchObject({
      verdict: "safe",
      action: "clear-and-reacquire",
      current: "piship-credential-metadata/v2",
    });
    expect(item(report, "identity session")).toMatchObject({
      action: "clear-and-reacquire",
      current: "unreadable",
    });
    // Schemaless credential classes are kept, never cleared by schema.
    expect(item(report, "file secret fallback").action).toBe("keep");
    expect(item(report, "Pi agent configuration").action).toBe("keep");
  });

  it("moves a v0.6 install to this release without a schema bump (decision 27)", () => {
    // v0.6 locks list the six older keys; v0.7 added two, additively, under
    // the same piship-lock/v1alpha4. A v0.6 state keeps every class, and
    // this release still reads a v0.6 lock's schema list.
    const {
      sandboxCredential: _s,
      credentialIssuance: _c,
      ...v06
    } = STATE_SCHEMAS;
    const dir = populated();
    const from = { version: "0.6.0", pi: "0.87.1" };
    const forward = checkStateMigration(dir, target(), from);
    expect(forward.verdict).toBe("safe");
    expect(forward.items.every((entry) => entry.action === "keep")).toBe(true);
    const back = checkStateMigration(dir, target("0.87.1", v06), current);
    expect(back.verdict).toBe("safe");
    expect(back.items.every((entry) => entry.action === "keep")).toBe(true);
  });

  it("clears the sandbox credential for a target whose lock predates its schema key", () => {
    const dir = populated();
    write(dir, "credentials-metadata/sandbox.json", {
      schema: "piship-sandbox-credential-metadata/v1",
      credential_ref: "piship:acmepi:sandbox#1",
      generation: 1,
    });
    // A lock written before the key existed lists only the six older keys.
    const { sandboxCredential: _absent, ...older } = STATE_SCHEMAS;
    for (const schemas of [older, LEGACY_STATE_SCHEMAS]) {
      const report = checkStateMigration(
        dir,
        target("0.87.1", schemas),
        current,
      );
      expect(report.verdict).toBe("safe");
      expect(item(report, "sandbox credential metadata")).toMatchObject({
        verdict: "safe",
        action: "clear-and-reacquire",
        current: "piship-sandbox-credential-metadata/v1",
      });
    }
    // This release reads it, so a switch between two such releases keeps it.
    expect(
      item(
        checkStateMigration(dir, target(), current),
        "sandbox credential metadata",
      ).action,
    ).toBe("keep");
    // A discarded marker is never readable: always cleared.
    write(dir, "credentials-metadata/sandbox.json", {
      schema: "piship-credential-discarded/v1",
      orphans: ["piship:acmepi:sandbox#1"],
    });
    expect(
      item(
        checkStateMigration(dir, target(), current),
        "sandbox credential metadata",
      ).action,
    ).toBe("clear-and-reacquire");
  });

  it("handles the state marker for current and legacy targets", () => {
    const dir = populated();
    write(dir, "state.json", {
      schema: "piship-state/v9",
      version: "2.0.0",
      pi: "0.87.1",
    });
    expect(
      item(checkStateMigration(dir, target(), current), "state marker"),
    ).toMatchObject({
      verdict: "unsupported",
      current: "piship-state/v9",
    });
    expect(
      item(
        checkStateMigration(
          dir,
          target("0.87.1", LEGACY_STATE_SCHEMAS),
          current,
        ),
        "state marker",
      ),
    ).toMatchObject({
      verdict: "safe",
      reason: "The target does not read the state marker",
    });
    // A damaged marker counts as absent: the active release is the source.
    for (const damaged of ["{broken", "", '{"schema":"piship-st', "null"]) {
      write(dir, "state.json", damaged);
      expect(readStateMarker(dir)).toBeNull();
      const report = checkStateMigration(dir, target(), current);
      expect(item(report, "state marker")).toMatchObject({
        current: "unreadable",
        verdict: "safe",
        action: "keep",
      });
      expect(item(report, "state marker").reason).toContain(
        join(dir, "state.json"),
      );
      expect(report.from).toEqual({
        version: current.version,
        pi: current.pi,
      });
    }
  });
});

describe("compareVersions", () => {
  it("orders the SemVer 2.0 precedence example", () => {
    const ordered = [
      "1.0.0-alpha",
      "1.0.0-alpha.1",
      "1.0.0-alpha.beta",
      "1.0.0-beta",
      "1.0.0-beta.2",
      "1.0.0-beta.11",
      "1.0.0-rc.1",
      "1.0.0",
      "1.0.1",
      "1.1.0",
      "1.10.0",
      "2.0.0",
      "10.0.0",
    ];
    for (let i = 0; i < ordered.length; i += 1)
      for (let j = 0; j < ordered.length; j += 1)
        expect(
          compareVersions(ordered[i] as string, ordered[j] as string),
        ).toBe(Math.sign(i - j));
  });
  it("ignores build metadata", () => {
    expect(compareVersions("1.0.0+build.1", "1.0.0+build.2")).toBe(0);
    expect(compareVersions("1.0.0-rc.1+x", "1.0.0-rc.1")).toBe(0);
    expect(compareVersions("1.0.0-rc.1+x", "1.0.0")).toBe(-1);
  });
  it("compares alphanumeric identifiers in ASCII order", () => {
    expect(compareVersions("1.0.0-Beta", "1.0.0-alpha")).toBe(-1);
    expect(compareVersions("1.0.0-alpha-2", "1.0.0-alpha-10")).toBe(1);
    expect(compareVersions("1.0.0-1", "1.0.0-a")).toBe(-1);
  });
  it.each(["1.0", "v1.0.0", "1.0.0-", "1.0.0-alpha_1", "", "latest"])(
    "throws on the malformed version %j",
    (value) => {
      expect(() => compareVersions(value, "1.0.0")).toThrow(
        `Not a semantic version: ${value}`,
      );
      expect(() => compareVersions("1.0.0", value)).toThrow(
        `Not a semantic version: ${value}`,
      );
    },
  );
  it.each(["01.0.0", "1.0.0-01", "1.0.0-alpha..1"])(
    "throws on the malformed version %j (leading zero or empty identifier)",
    (value) => {
      expect(() => compareVersions(value, "1.0.0")).toThrow(
        /Not a semantic version/,
      );
    },
  );
});

describe("state marker", () => {
  it("reads null when absent", () => {
    const dir = state();
    expect(readStateMarker(dir)).toBeNull();
    expect(existsSync(join(dir, "state.json"))).toBe(false);
  });
});
