// The answers a person keeps about a project's own configuration: what is
// stored, when it stops applying, and how it is listed and forgotten.
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { BrandedContext } from "./branded/context.js";
import { runConfig } from "./branded/config.js";
import {
  digestProjectFiles,
  forgetProjectTrust,
  listRememberedProjects,
  markProjectNotice,
  projectNoticeSeen,
  projectTrustPath,
  recallProjectTrust,
  rememberProjectTrust,
} from "./project-trust-memory.js";

let dir: string;
let state: string;
let project: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "piship-trust-memory-"));
  state = join(dir, "state");
  project = join(dir, "project");
  mkdirSync(join(project, ".claude", "rules"), { recursive: true });
  writeFileSync(join(project, ".claude", "rules", "a.md"), "one\n");
  writeFileSync(join(project, "AGENTS.md"), "agents\n");
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

const items = () => [
  { path: ".claude/rules", resolvedPath: join(project, ".claude/rules") },
  { path: "AGENTS.md", resolvedPath: join(project, "AGENTS.md") },
];

describe("digestProjectFiles", () => {
  it("changes with a file's content, a new file, and the set of items", () => {
    const before = digestProjectFiles(items());
    expect(before).toMatch(/^[0-9a-f]{64}$/);
    expect(digestProjectFiles(items())).toBe(before);
    writeFileSync(join(project, ".claude", "rules", "a.md"), "two\n");
    const edited = digestProjectFiles(items());
    expect(edited).not.toBe(before);
    writeFileSync(join(project, ".claude", "rules", "b.md"), "x\n");
    expect(digestProjectFiles(items())).not.toBe(edited);
    expect(digestProjectFiles(items().slice(1))).not.toBe(edited);
  });

  it("reads a symlink as its target text, never through it", () => {
    writeFileSync(join(dir, "outside.md"), "secret\n");
    symlinkSync(join(dir, "outside.md"), join(project, "link.md"));
    const link = [{ path: "link.md", resolvedPath: join(project, "link.md") }];
    const before = digestProjectFiles(link);
    writeFileSync(join(dir, "outside.md"), "changed\n");
    expect(digestProjectFiles(link)).toBe(before);
  });
});

describe("the remembered answer", () => {
  it("applies only to the same files, and is stored owner-only without content", () => {
    const digest = digestProjectFiles(items()) ?? "";
    rememberProjectTrust(state, project, "allow", digest, [".claude/rules"]);
    expect(recallProjectTrust(state, project, digest)).toBe("allow");
    expect(recallProjectTrust(state, project, "other")).toBeUndefined();
    expect(recallProjectTrust(state, join(dir, "elsewhere"), digest)).toBe(
      undefined,
    );
    const text = readFileSync(projectTrustPath(state), "utf8");
    expect(text).not.toContain("agents");
    expect(listRememberedProjects(state)).toEqual([
      expect.objectContaining({ answer: "allow", items: [".claude/rules"] }),
    ]);
  });

  it("is an unanswered question when the file is damaged or foreign", () => {
    const digest = "abc";
    rememberProjectTrust(state, project, "allow", digest, []);
    writeFileSync(projectTrustPath(state), "{ not json");
    expect(recallProjectTrust(state, project, digest)).toBeUndefined();
    writeFileSync(
      projectTrustPath(state),
      JSON.stringify({ schema: "other/v1", projects: {} }),
    );
    expect(listRememberedProjects(state)).toEqual([]);
  });

  it("remembers a shown notice per digest and forgets it with the answer", () => {
    expect(projectNoticeSeen(state, project, "n1")).toBe(false);
    markProjectNotice(state, project, "n1");
    expect(projectNoticeSeen(state, project, "n1")).toBe(true);
    expect(projectNoticeSeen(state, project, "n2")).toBe(false);
    expect(forgetProjectTrust(state, project)).toBe(1);
    expect(projectNoticeSeen(state, project, "n1")).toBe(false);
  });

  it("is forgotten by the project, by a path inside it, or all at once", () => {
    rememberProjectTrust(state, project, "allow", "d", []);
    expect(forgetProjectTrust(state, join(project, ".claude", "rules"))).toBe(
      1,
    );
    rememberProjectTrust(state, project, "deny", "d", []);
    rememberProjectTrust(state, join(dir, "other"), "allow", "d", []);
    expect(forgetProjectTrust(state, "all")).toBe(2);
    expect(forgetProjectTrust(state, project)).toBe(0);
  });
});

describe("config trust", () => {
  const run = async (...args: string[]) => {
    const lines: string[] = [];
    await runConfig(
      {
        stateDir: state,
        out: (line: string) => lines.push(line),
        metadata: { app: { command: "unit" } },
      } as unknown as BrandedContext,
      args,
    );
    return lines.join("\n");
  };

  it("lists what is remembered and forgets it", async () => {
    expect(await run("trust", "list")).toBe(
      "No project answers are remembered.",
    );
    rememberProjectTrust(state, project, "allow", "d", ["AGENTS.md"]);
    expect(await run("trust", "list")).toMatch(
      /^trusted .*project \(1 item, \d{4}-/,
    );
    expect(await run("trust", "forget", project)).toMatch(
      /Forgot the remembered answer for 1 project; unit asks again/,
    );
    expect(await run("trust", "forget", project)).toBe(
      "No remembered answer for that project.",
    );
    rememberProjectTrust(state, project, "deny", "d", []);
    expect(await run("trust", "list")).toMatch(/^not trusted /);
    expect(await run("trust", "forget", "--all")).toMatch(/1 project;/);
  });
});
