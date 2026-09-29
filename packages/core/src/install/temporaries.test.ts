// Recovery of atomic-write temporaries: a writer killed before its rename
// leaves one beside identity metadata, credential metadata, or preferences.
// The committed file stays authoritative, the startup sweep removes what an
// abandoned writer left, and a live writer's temporary is never touched.
import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  clearFaults,
  fired,
  injectFault,
} from "../../../../tests/helpers/fs-faults.js";
import { accessStatePaths, writeJsonAtomic } from "../access/state.js";
import { readPreferences, setPreference } from "../config.js";
import {
  STALE_TEMPORARY_MS,
  removeStaleTemporaries,
  sweepStateTemporaries,
} from "./temporaries.js";

vi.mock("node:fs", async (importOriginal) =>
  (await import("../../../../tests/helpers/fs-faults.js")).faultyFs(
    await importOriginal(),
  ),
);

let state: string;
const children: ChildProcess[] = [];
beforeEach(() => {
  state = mkdtempSync(join(tmpdir(), "piship-temporaries-"));
});
afterEach(() => {
  clearFaults();
  for (const child of children.splice(0)) child.kill();
  rmSync(state, { recursive: true, force: true });
});

const SENTINEL = "sentinel-secret-temporaries-5d1c";
const paths = () => accessStatePaths(state);
function deadPid(): number {
  return spawnSync(process.execPath, ["-e", ""]).pid as number;
}
function livePid(): number {
  const child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], {
    stdio: "ignore",
  });
  children.push(child);
  return child.pid as number;
}
function age(path: string, ms: number): void {
  const then = new Date(Date.now() - ms);
  utimesSync(path, then, then);
}
/** What a writer killed before its rename leaves: the complete new content. */
function leftover(path: string, suffix: string, value: unknown): string {
  const temporary = `${path}.${suffix}.tmp`;
  writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, {
    mode: 0o600,
  });
  return temporary;
}
function siblings(path: string): string[] {
  return readdirSync(dirname(path))
    .filter((name) => name.startsWith(`${basename(path)}.`))
    .sort();
}
function everyFile(): string {
  const texts: string[] = [];
  const visit = (dir: string) => {
    for (const entry of readdirSync(dir, { withFileTypes: true }))
      if (entry.isDirectory()) visit(join(dir, entry.name));
      else texts.push(readFileSync(join(dir, entry.name), "utf8"));
  };
  visit(state);
  return texts.join("\n");
}

const CLASSES = [
  [
    "identity metadata",
    (p: ReturnType<typeof paths>) => p.identity,
    (subject: string) => ({
      schema: "piship-identity-metadata/v1",
      subject,
      issuer: "https://idp.example.test",
      credential_ref: "piship:acmecode:identity",
    }),
  ],
  [
    "credential metadata",
    (p: ReturnType<typeof paths>) => p.credential,
    (subject: string) => ({
      schema: "piship-credential-metadata/v1",
      credential_ref: "piship:acmecode:inference:1",
      principal: { issuer: "https://idp.example.test", subject },
    }),
  ],
  [
    "preferences",
    (p: ReturnType<typeof paths>) => p.preferences,
    (subject: string) => ({
      schema: "piship-preferences/v1",
      values: { model: subject },
    }),
  ],
] as const;

describe.each(CLASSES)("a killed writer of %s", (_name, pathOf, value) => {
  it("leaves the committed file authoritative until the sweep removes its temporary", () => {
    const path = pathOf(paths());
    writeJsonAtomic(path, value("committed"));
    const committed = readFileSync(path, "utf8");
    const killed = leftover(path, `p${deadPid()}-0123456789ab`, value("new"));
    const unowned = leftover(path, "fedcba987654", value("older"));
    age(unowned, STALE_TEMPORARY_MS + 60_000);
    // Never adopted, even with the committed file gone.
    expect(readFileSync(path, "utf8")).toBe(committed);
    rmSync(path);
    expect(sweepStateTemporaries(state).sort()).toEqual(
      [killed, unowned].sort(),
    );
    expect(existsSync(path)).toBe(false);
    expect(siblings(path)).toEqual([]);
    // A later write succeeds.
    writeJsonAtomic(path, value("later"));
    expect(JSON.parse(readFileSync(path, "utf8"))).toEqual(value("later"));
    expect(siblings(path)).toEqual([]);
  });

  it("keeps a live writer's temporary", () => {
    const path = pathOf(paths());
    writeJsonAtomic(path, value("committed"));
    const ours = leftover(path, `p${process.pid}-0123456789ab`, value("a"));
    const other = leftover(path, `p${livePid()}-0123456789ab`, value("b"));
    const unowned = leftover(path, "0123456789ab", value("c"));
    expect(sweepStateTemporaries(state)).toEqual([]);
    expect(siblings(path)).toEqual(
      [ours, other, unowned].map((item) => basename(item)).sort(),
    );
    // Until it is too old to belong to a writer, whose ID may have been reused.
    for (const item of [ours, other, unowned])
      age(item, STALE_TEMPORARY_MS + 60_000);
    expect(sweepStateTemporaries(state)).toHaveLength(3);
    expect(siblings(path)).toEqual([]);
  });

  it("removes the temporary of an ordinary write failure at once", () => {
    const path = pathOf(paths());
    writeJsonAtomic(path, value("committed"));
    const committed = readFileSync(path, "utf8");
    injectFault((file) => file.startsWith(path), { op: "rename", code: "EIO" });
    expect(() => writeJsonAtomic(path, value("new"))).toThrow(/EIO/);
    expect(fired).toHaveLength(1);
    expect(readFileSync(path, "utf8")).toBe(committed);
    expect(siblings(path)).toEqual([]);
  });
});

describe("state temporaries", () => {
  it("never touches a file that only resembles a temporary", () => {
    const { identity, secrets } = paths();
    mkdirSync(dirname(identity), { recursive: true });
    mkdirSync(secrets, { recursive: true });
    const keep = [
      `${identity}.bak`,
      `${identity}.tmp`,
      `${identity}.p${deadPid()}.tmp`,
      `${identity}.0123456789ab.tmp.bak`,
      `${identity}.0123456789abcd.tmp`,
      join(dirname(identity), "notes.json.0123456789ab.tmp"),
      join(secrets, ".0123456789ab.tmp"),
    ];
    for (const path of keep) {
      writeFileSync(path, "user data");
      age(path, STALE_TEMPORARY_MS + 60_000);
    }
    const directory = `${identity}.0123456789ab.tmp`;
    mkdirSync(directory);
    age(directory, STALE_TEMPORARY_MS + 60_000);
    expect(sweepStateTemporaries(state)).toEqual([]);
    for (const path of [...keep, directory])
      expect(existsSync(path)).toBe(true);
  });

  it("covers every atomically written state file of the distribution", () => {
    const p = paths();
    const dead = deadPid();
    const files = [
      join(state, "state.json"),
      p.identity,
      p.principal,
      p.credential,
      p.revocationRetry,
      p.preferences,
      join(state, "config", "policy.json"),
      join(state, "logs", "audit.jsonl.generation"),
    ];
    const left: string[] = [];
    for (const file of files) {
      mkdirSync(dirname(file), { recursive: true });
      left.push(leftover(file, `p${dead}-0123456789ab`, {}));
    }
    // Local metrics name the temporary after the process alone.
    left.push(leftover(join(state, "logs", "metrics.json"), String(dead), {}));
    // The file secret store's temporaries hold a secret.
    mkdirSync(p.secrets, { recursive: true });
    const secret = join(p.secrets, "0f0f.secret.0123456789ab.tmp");
    writeFileSync(secret, SENTINEL);
    age(secret, STALE_TEMPORARY_MS + 60_000);
    left.push(secret);
    expect(sweepStateTemporaries(state).sort()).toEqual(left.sort());
    expect(everyFile()).toBe("");
  });

  it("removes every temporary when forced, live or not", () => {
    const { identity } = paths();
    mkdirSync(dirname(identity), { recursive: true });
    const live = leftover(identity, `p${process.pid}-0123456789ab`, {});
    const unowned = leftover(identity, "0123456789ab", {});
    expect(
      removeStaleTemporaries(dirname(identity), ["session.json"], {
        force: true,
      }).sort(),
    ).toEqual([live, unowned].sort());
  });

  it("writes preferences atomically with no temporary left", () => {
    setPreference(paths().preferences, undefined, undefined, "theme", "dark");
    expect(readPreferences(paths().preferences).values.theme).toBe("dark");
    expect(siblings(paths().preferences)).toEqual([]);
  });
});
