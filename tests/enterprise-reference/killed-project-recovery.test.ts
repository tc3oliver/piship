import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { recover } from "./global-setup.js";
import { PROJECT_PREFIX } from "./stack.js";

// The crash recovery of `npm run test:reference` (global-setup.ts) against a
// real Docker Compose (#78). tests/reference-global-setup.test.ts shows the
// rules with a fake daemon; this file shows the part only Docker can: that
// `docker compose -p <name> down`, run from a directory without a Compose
// file, removes a project whose owner was killed outright and whose Compose
// file is gone.
//
// A child process creates a temporary directory and a Compose project, both
// named `piship-reftest-<its pid>-...` as the reference stacks are, starts one
// small container, and is then killed with SIGKILL: no afterAll, no exit
// handler. Its Compose file is deleted. This process then runs the recovery.
// A second project, owned by this (live) process, must survive it.
//
// Only projects this file creates are started or stopped here, never with
// `-v`; the recovery itself removes only `piship-reftest-` projects whose
// owner is dead. Needs Docker; run with `npm run test:reference`.

// The image the reference stack already uses (examples/enterprise-reference/
// compose.yaml), so the run pulls nothing new.
const IMAGE =
  "node:22.23.3-alpine3.24@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402";

const composeFile = `services:
  idle:
    image: ${IMAGE}
    command: ["node", "-e", "setInterval(() => {}, 1e9)"]
    stop_grace_period: 1s
`;

const docker = (args: readonly string[], cwd = tmpdir()) =>
  spawnSync("docker", [...args], { cwd, encoding: "utf8" });

/** The IDs of what Compose labelled as this project's, of one kind. */
const owned = (kind: "ps" | "network ls", project: string) =>
  docker([
    ...kind.split(" "),
    ...(kind === "ps" ? ["--all"] : []),
    "--filter",
    `label=com.docker.compose.project=${project}`,
    "--format",
    "{{.ID}}",
  ])
    .stdout.split("\n")
    .filter(Boolean);

const listed = (project: string) =>
  (
    JSON.parse(
      docker([
        "compose",
        "ls",
        "--all",
        "--filter",
        `name=${project}`,
        "--format",
        "json",
      ]).stdout || "[]",
    ) as { Name: string }[]
  ).some(({ Name }) => Name === project);

// The child: make the directory and project its pid names, start the project,
// say so, then wait to be killed.
const CHILD = `
const { spawnSync } = require("node:child_process");
const { mkdtempSync, writeFileSync } = require("node:fs");
const { join } = require("node:path");
const prefix = ${JSON.stringify(`${PROJECT_PREFIX}`)};
const directory = mkdtempSync(join(${JSON.stringify(tmpdir())}, prefix + process.pid + "-killed-"));
const project = prefix + process.pid + "-killed-" + ${JSON.stringify(randomBytes(3).toString("hex"))};
writeFileSync(join(directory, "compose.yaml"), ${JSON.stringify(composeFile)});
writeFileSync(join(directory, ".env"), "GENERATED=fixture\\n");
const up = spawnSync("docker", ["compose", "-p", project, "up", "-d", "--wait"], { cwd: directory, encoding: "utf8" });
if (up.status !== 0) { process.stderr.write(up.stderr); process.exit(1); }
process.stdout.write(JSON.stringify({ project, directory }) + "\\n");
setInterval(() => {}, 1e9);
`;

interface Killed {
  project: string;
  directory: string;
}

/** Start the child, wait until its project is up, then SIGKILL it. */
function startAndKill(): Promise<Killed> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["-e", CHILD], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let out = "";
    let err = "";
    child.stderr.on("data", (chunk) => {
      err += chunk;
    });
    child.stdout.on("data", (chunk) => {
      out += chunk;
      const line = out.split("\n")[0];
      if (out.includes("\n") && line) {
        const started = JSON.parse(line) as Killed;
        child.once("exit", () => resolve(started));
        child.kill("SIGKILL");
      }
    });
    child.once("exit", (code, signal) => {
      if (signal !== "SIGKILL")
        reject(
          new Error(`the child exited (${code}) before it was killed: ${err}`),
        );
    });
  });
}

let killed: Killed | undefined;
const live = `${PROJECT_PREFIX}${process.pid}-live-${randomBytes(3).toString("hex")}`;
let liveDirectory: string | undefined;

beforeAll(async () => {
  liveDirectory = mkdtempSync(
    join(tmpdir(), `${PROJECT_PREFIX}${process.pid}-live-`),
  );
  writeFileSync(join(liveDirectory, "compose.yaml"), composeFile);
  const up = docker(
    ["compose", "-p", live, "up", "-d", "--wait"],
    liveDirectory,
  );
  if (up.status !== 0) throw new Error(`starting ${live} failed: ${up.stderr}`);
  killed = await startAndKill();
  // What a killed run cannot keep: its Compose file is gone before recovery.
  rmSync(join(killed.directory, "compose.yaml"), { force: true });
}, 300_000);

afterAll(() => {
  // Only the projects this file created, never with `-v`, whatever the
  // assertions found.
  const failures: string[] = [];
  if (killed && listed(killed.project)) {
    const down = docker([
      "compose",
      "-p",
      killed.project,
      "down",
      "--remove-orphans",
    ]);
    if (down.status !== 0) failures.push(down.stderr);
  }
  if (liveDirectory) {
    const down = docker(
      ["compose", "-p", live, "down", "--remove-orphans"],
      liveDirectory,
    );
    if (down.status !== 0) failures.push(down.stderr);
    rmSync(liveDirectory, { recursive: true, force: true });
  }
  if (killed) rmSync(killed.directory, { recursive: true, force: true });
  if (failures.length > 0) throw new Error(failures.join("\n"));
}, 120_000);

const started = () => {
  if (!killed) throw new Error("the killed project did not start");
  return killed;
};

describe("recovery of a Compose project whose owner was killed", () => {
  it("starts from a project that outlived its killed owner", () => {
    const { project, directory } = started();
    expect(owned("ps", project).length).toBeGreaterThan(0);
    expect(existsSync(join(directory, "compose.yaml"))).toBe(false);
  });

  it("removes its containers, network and temporary directory, by project name alone", () => {
    const { project, directory } = started();
    recover();
    expect(listed(project)).toBe(false);
    expect(owned("ps", project)).toEqual([]);
    expect(owned("network ls", project)).toEqual([]);
    expect(existsSync(directory)).toBe(false);
  }, 120_000);

  it("keeps the project of a run that is still alive", () => {
    expect(listed(live)).toBe(true);
    expect(owned("ps", live).length).toBeGreaterThan(0);
    expect(liveDirectory && existsSync(liveDirectory)).toBe(true);
  });

  it("finds nothing left the second time", () => {
    expect(() => recover()).not.toThrow();
    expect(listed(live)).toBe(true);
  }, 120_000);
});
