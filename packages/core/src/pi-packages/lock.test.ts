// `piship lock` with Pi packages, the offline stale-lock check, and the
// build's vendoring step, against a local package and a git fixture in a
// local bare repository (reached through git's own insteadOf configuration,
// so the declared repository stays an https URL). No registry is needed:
// neither package has dependencies.
import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import { readManifest } from "@piship/schema";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { lockManifest, requireCurrentLock } from "../lock.js";
import type { DistributionLock } from "../lock-schema.js";
import { PACKAGE_LOCK_DIRECTORY, vendorPiPackages } from "./lock.js";

const REPOSITORY = "https://git.example.test/platform/pi-review";
let root: string;
let commit: string;

function write(base: string, files: Record<string, string>): void {
  for (const [path, content] of Object.entries(files)) {
    mkdirSync(dirname(join(base, path)), { recursive: true });
    writeFileSync(join(base, path), content);
  }
}

function git(cwd: string, ...args: string[]): string {
  const result = spawnSync(
    "git",
    [
      "-c",
      "user.name=Fixture",
      "-c",
      "user.email=fixture@example.test",
      "-c",
      "commit.gpgsign=false",
      ...args,
    ],
    { cwd, encoding: "utf8" },
  );
  if (result.status !== 0) throw new Error(result.stderr);
  return result.stdout.trim();
}

beforeAll(() => {
  root = realpathSync(mkdtempSync(join(tmpdir(), "piship-package-lock-")));
  const work = join(root, "git-work");
  write(work, {
    "package.json": JSON.stringify({ name: "pi-review", version: "1.0.0" }),
    "prompts/review.md": "Review the change.\n",
  });
  git(work, "init", "--quiet", "--initial-branch=main");
  git(work, "add", "-A");
  git(work, "commit", "--quiet", "-m", "fixture");
  commit = git(work, "rev-parse", "HEAD");
  git(root, "clone", "--quiet", "--bare", work, join(root, "pi-review.git"));
  // This file runs in a process of its own, so the git mapping stays here.
  process.env.GIT_CONFIG_COUNT = "1";
  process.env.GIT_CONFIG_KEY_0 = `url.${pathToFileURL(join(root, "pi-review.git")).href}.insteadOf`;
  process.env.GIT_CONFIG_VALUE_0 = REPOSITORY;
});

afterAll(() => {
  if (root) rmSync(root, { recursive: true, force: true });
});

function distribution(): string {
  const dir = mkdtempSync(join(root, "distribution-"));
  write(dir, {
    "resources/AGENTS.md": "# Reviewer\n",
    "packages/team/package.json": JSON.stringify({
      name: "team",
      version: "0.1.0",
      pi: { skills: ["./skills"] },
    }),
    "packages/team/skills/triage/SKILL.md":
      "---\nname: triage\ndescription: Triage an issue.\n---\nTriage.\n",
    "piship.yaml": `schema: piship/v1alpha6
app: { id: reviewer, name: Reviewer, command: reviewer, version: 1.0.0 }
runtime: { pi: "1.0.2" }
deployment: { mode: personal }
identity: { mode: none }
credential: { provider: pi-native }
inference: { provider: pi-native }
resources:
  instructions:
    user: [./resources/AGENTS.md]
  packages:
    - id: team
      source: local
      path: ./packages/team
      class: user
    - id: pi-review
      source: git
      repository: ${REPOSITORY}
      ref: ${commit}
      class: company
packageTrust:
  git: { hosts: [git.example.test] }
  local: { paths: [./packages] }
policy:
  default: allow
updates: { channel: stable, channels: [stable] }
`,
  });
  return join(dir, "piship.yaml");
}

const readLock = (manifest: string): DistributionLock =>
  JSON.parse(
    readFileSync(join(dirname(manifest), "piship.lock"), "utf8"),
  ) as DistributionLock;

describe("Pi packages in the lock", () => {
  it("lock records each package, stores its npm root beside the lock, and stays current offline", () => {
    const manifest = distribution();
    lockManifest(manifest);
    const lock = readLock(manifest);
    expect(lock.packages?.map((item) => item.id)).toEqual([
      "team",
      "pi-review",
    ]);
    expect(lock.packages?.[1]).toMatchObject({
      source: "git",
      url: REPOSITORY,
      commit,
      files: 2,
      resources: [{ kind: "prompts", path: "prompts/review.md" }],
    });
    expect(lock.packages?.[0]?.resources).toMatchObject([
      { kind: "skills", path: "skills/triage/SKILL.md" },
    ]);
    expect(lock.digests?.packages).toMatch(/^sha256-/);
    for (const id of ["team", "pi-review"])
      expect(
        existsSync(
          join(
            dirname(manifest),
            PACKAGE_LOCK_DIRECTORY,
            id,
            "package-lock.json",
          ),
        ),
      ).toBe(true);
    // The stale-lock check reads the recorded entries and never reaches git.
    const offline = process.env.GIT_CONFIG_VALUE_0;
    process.env.GIT_CONFIG_VALUE_0 = "https://unused.example.test/";
    try {
      expect(() => requireCurrentLock(manifest)).not.toThrow();
    } finally {
      process.env.GIT_CONFIG_VALUE_0 = offline;
    }
  }, 120_000);

  it("a changed local package or a changed stored lockfile makes the lock stale", () => {
    const manifest = distribution();
    lockManifest(manifest);
    const base = dirname(manifest);
    write(base, {
      "packages/team/skills/triage/SKILL.md":
        "---\nname: triage\ndescription: Triage an issue.\n---\nChanged.\n",
    });
    expect(() => requireCurrentLock(manifest)).toThrow(/stale/);
    lockManifest(manifest);
    expect(() => requireCurrentLock(manifest)).not.toThrow();
    const stored = join(
      base,
      PACKAGE_LOCK_DIRECTORY,
      "pi-review",
      "package-lock.json",
    );
    writeFileSync(stored, `${readFileSync(stored, "utf8")}\n`);
    expect(() => requireCurrentLock(manifest)).toThrow(/stale/);
  }, 120_000);

  it("an undeclared package's npm root is removed when the lock is written", () => {
    const manifest = distribution();
    lockManifest(manifest);
    const source = readFileSync(manifest, "utf8");
    writeFileSync(
      manifest,
      source.replace(/ {4}- id: pi-review\n(?: {6}.*\n)+/, ""),
    );
    lockManifest(manifest);
    expect(readLock(manifest).packages?.map((item) => item.id)).toEqual([
      "team",
    ]);
    expect(
      existsSync(join(dirname(manifest), PACKAGE_LOCK_DIRECTORY, "pi-review")),
    ).toBe(false);
  }, 120_000);

  it("the build vendors every package under pi-packages/<id> from the lock", () => {
    const manifest = distribution();
    lockManifest(manifest);
    const lock = requireCurrentLock(manifest);
    const payload = mkdtempSync(join(root, "payload-"));
    const vendored = vendorPiPackages(
      lock,
      readManifest(manifest),
      dirname(manifest),
      payload,
    );
    expect(vendored.map((item) => item.locked)).toEqual(lock.packages);
    expect(
      readFileSync(
        join(
          payload,
          "pi-packages",
          "pi-review",
          "package",
          "prompts",
          "review.md",
        ),
        "utf8",
      ),
    ).toBe("Review the change.\n");
    expect(
      existsSync(
        join(
          payload,
          "pi-packages",
          "team",
          "package",
          "skills",
          "triage",
          "SKILL.md",
        ),
      ),
    ).toBe(true);
  }, 120_000);
});
