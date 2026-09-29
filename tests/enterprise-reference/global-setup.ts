import { spawnSync } from "node:child_process";
import { readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PROJECT_PREFIX } from "./stack.js";

// Before `npm run test:reference` starts a stack, remove what an earlier run
// could not: a worker killed outright (SIGKILL, a crash) never reaches its
// afterAll or its exit handler, and its stack would hold the fixed ports.
//
// Only Compose projects and temporary directories named
// `piship-reftest-<pid>-...` whose process <pid> is gone are touched, so a
// run still going on in another terminal keeps its stack. Removal is
// `docker compose down --remove-orphans`: never `-v`, never a prune.

const ownerPid = (name: string) =>
  Number(/^piship-reftest-(\d+)-/.exec(name)?.[1] ?? Number.NaN);

function alive(pid: number) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

const orphaned = (name: string) => {
  const pid = ownerPid(name);
  return Number.isInteger(pid) && pid > 0 && !alive(pid);
};

function removeOrphans() {
  const listed = spawnSync(
    "docker",
    [
      "compose",
      "ls",
      "--all",
      "--filter",
      `name=${PROJECT_PREFIX}`,
      "--format",
      "json",
    ],
    { encoding: "utf8", cwd: tmpdir() },
  );
  if (listed.status !== 0)
    throw new Error(`docker compose ls failed: ${listed.stderr.trim()}`);
  const projects = (JSON.parse(listed.stdout || "[]") as { Name: string }[])
    .map((project) => project.Name)
    .filter((name) => name.startsWith(PROJECT_PREFIX) && orphaned(name));
  for (const name of projects) {
    // By project name alone, from a directory without a compose file.
    const down = spawnSync(
      "docker",
      ["compose", "-p", name, "down", "--remove-orphans"],
      { encoding: "utf8", cwd: tmpdir() },
    );
    if (down.status !== 0)
      throw new Error(
        `docker compose down failed for ${name}: ${down.stderr.trim()}`,
      );
    console.info(`removed the reference stack ${name} left by an earlier run`);
  }
  for (const entry of readdirSync(tmpdir()))
    if (entry.startsWith(PROJECT_PREFIX) && orphaned(entry))
      rmSync(join(tmpdir(), entry), { recursive: true, force: true });
}

export default function setup() {
  removeOrphans();
}
