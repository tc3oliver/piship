// Pi compatibility: how Pi's find and grep tools locate fd and rg, which
// bundled search tools rely on. Pi's tools manager looks in its own bin
// directory, `<agent dir>/bin`, before PATH, and fixes that directory from
// PI_CODING_AGENT_DIR when it is imported. PiShip therefore sets the variable
// before @piship/pi (and so Pi) is imported, and copies the payload's
// executables there (launch/search-tools.ts). A Pi upgrade that changes
// either behavior fails here. Each case runs Pi's public tools in a fresh
// Node process, with fake fd and rg scripts that record which copy ran.
import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

const repo = fileURLToPath(new URL("../../../", import.meta.url));
const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

/** A fake tool that records `<label>-<tool>` and prints one result. */
function fake(directory: string, tool: string, label: string, marks: string) {
  mkdirSync(directory, { recursive: true });
  writeFileSync(
    join(directory, tool),
    `#!/bin/sh\ntouch "${join(marks, `${label}-${tool}`)}"\n${tool === "fd" ? "echo found.txt" : "exit 1"}\n`,
    { mode: 0o755 },
  );
}

function setup() {
  const root = mkdtempSync(join(tmpdir(), "piship-pi-tools-"));
  roots.push(root);
  const marks = join(root, "marks");
  const work = join(root, "work");
  mkdirSync(marks);
  mkdirSync(work);
  writeFileSync(join(work, "found.txt"), "needle\n");
  const agentDir = join(root, "state", "agent");
  const home = join(root, "home");
  const onPath = join(root, "path-bin");
  for (const tool of ["fd", "rg"]) {
    fake(join(agentDir, "bin"), tool, "bundled", marks);
    fake(onPath, tool, "path", marks);
    fake(join(home, ".pi", "agent", "bin"), tool, "home", marks);
  }
  return { root, marks, work, agentDir, home, onPath };
}

/** Run Pi's find and grep tools; `before` says when the agent dir is set. */
function runPi(
  paths: ReturnType<typeof setup>,
  before: "before-import" | "after-import",
) {
  const set = `process.env.PI_CODING_AGENT_DIR = ${JSON.stringify(paths.agentDir)};`;
  const script = `${before === "before-import" ? set : ""}
const { createFindTool, createGrepTool } = await import("@earendil-works/pi-coding-agent");
${before === "after-import" ? set : ""}
const text = (result) => result.content.map((item) => item.text ?? "").join("");
console.log(text(await createFindTool(${JSON.stringify(paths.work)}).execute("compat-find", { pattern: "*.txt" })));
console.log(text(await createGrepTool(${JSON.stringify(paths.work)}).execute("compat-grep", { pattern: "needle" })));
`;
  return spawnSync(process.execPath, ["--input-type=module", "-e", script], {
    cwd: repo,
    encoding: "utf8",
    env: {
      PATH: `${paths.onPath}:/usr/bin:/bin`,
      HOME: paths.home,
      PI_OFFLINE: "1",
      PI_SKIP_VERSION_CHECK: "1",
      PI_TELEMETRY: "0",
    },
    timeout: 60_000,
  });
}

const ran = (paths: ReturnType<typeof setup>, label: string, tool: string) =>
  existsSync(join(paths.marks, `${label}-${tool}`));

describe.skipIf(process.platform === "win32")(
  "Pi's fd and rg lookup under bundled search tools",
  () => {
    it("runs the copies in <agent dir>/bin before any on PATH, without downloading", () => {
      const paths = setup();
      const result = runPi(paths, "before-import");
      expect(result.status, result.stderr).toBe(0);
      expect(result.stdout).toContain("found.txt");
      expect(result.stdout).not.toContain("not available");
      for (const tool of ["fd", "rg"]) {
        expect(ran(paths, "bundled", tool), tool).toBe(true);
        expect(ran(paths, "path", tool), tool).toBe(false);
        expect(ran(paths, "home", tool), tool).toBe(false);
      }
    });

    it("fixes the agent directory at import, so it must be set before Pi loads", () => {
      const paths = setup();
      const result = runPi(paths, "after-import");
      expect(result.status, result.stderr).toBe(0);
      // Set too late, Pi keeps ~/.pi/agent/bin: the user's own directory.
      expect(ran(paths, "home", "fd")).toBe(true);
      expect(ran(paths, "bundled", "fd")).toBe(false);
    });
  },
);
