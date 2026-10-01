import { spawnSync } from "node:child_process";
import { readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PROJECT_PREFIX } from "./stack.js";

// Before `npm run test:reference` starts a stack, remove what an earlier run
// could not: a worker killed outright (SIGKILL, a crash) never reaches its
// afterAll or its exit handler, and its stack would keep running.
//
// Only Compose projects and temporary directories named
// `piship-reftest-<pid>-...` whose process <pid> is gone are touched, so a
// run still going on in another terminal keeps its stack. Removal is
// `docker compose down --remove-orphans`: never `-v`, never a prune.
//
// The three sweeps (projects, temporary directories, sandbox containers) are
// independent, and so is each project and each directory in them: what fails
// is collected, the rest still runs, and one error at the end names every
// failure. A stack that cannot be removed this time is found again next time.

/** What recovery needs to know of a finished `docker` command. */
export interface DockerResult {
  readonly status: number | null;
  /** Null when the command could not be started at all. */
  readonly stdout?: string | null;
  readonly stderr?: string | null;
  readonly error?: Error | undefined;
}

/** What recovery touches, replaceable so a test needs no Docker and no real process. */
export interface Environment {
  /** Run `docker` from a directory that holds no Compose file. */
  readonly docker: (args: readonly string[]) => DockerResult;
  /** The directory that holds the temporary directories of the runs. */
  readonly tmp: string;
  /** Whether a process still runs. */
  readonly alive: (pid: number) => boolean;
  readonly remove: (path: string) => void;
}

const ownerPid = (name: string) =>
  Number(/^piship-reftest-(\d+)-/.exec(name)?.[1] ?? Number.NaN);

function processAlive(pid: number) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

const real: Environment = {
  docker: (args) =>
    spawnSync("docker", [...args], { encoding: "utf8", cwd: tmpdir() }),
  tmp: tmpdir(),
  alive: processAlive,
  remove: (path) => rmSync(path, { recursive: true, force: true }),
};

/** Why a finished command failed, from what it printed or from why it never started. */
const detail = (result: DockerResult) =>
  (result.stderr ?? "").trim() ||
  result.error?.message ||
  `exit status ${result.status}`;

const reason = (error: unknown) =>
  error instanceof Error ? error.message : String(error);

const orphaned = (name: string, { alive }: Environment) => {
  const pid = ownerPid(name);
  return Number.isInteger(pid) && pid > 0 && !alive(pid);
};

function removeOrphans(environment: Environment, failures: Error[]) {
  const listed = environment.docker([
    "compose",
    "ls",
    "--all",
    "--filter",
    `name=${PROJECT_PREFIX}`,
    "--format",
    "json",
  ]);
  let projects: string[] = [];
  try {
    if (listed.status !== 0) throw new Error(detail(listed));
    projects = (JSON.parse(listed.stdout || "[]") as { Name: string }[])
      .map((project) => project.Name)
      .filter(
        (name) =>
          name.startsWith(PROJECT_PREFIX) && orphaned(name, environment),
      );
  } catch (error) {
    failures.push(new Error(`docker compose ls failed: ${reason(error)}`));
  }
  for (const name of projects) {
    // By project name alone, from a directory without a compose file.
    const down = environment.docker([
      "compose",
      "-p",
      name,
      "down",
      "--remove-orphans",
    ]);
    if (down.status !== 0)
      failures.push(
        new Error(`docker compose down failed for ${name}: ${detail(down)}`),
      );
    else
      console.info(
        `removed the reference stack ${name} left by an earlier run`,
      );
  }
}

function removeOrphanDirectories(environment: Environment, failures: Error[]) {
  try {
    for (const entry of readdirSync(environment.tmp))
      if (entry.startsWith(PROJECT_PREFIX) && orphaned(entry, environment))
        try {
          environment.remove(join(environment.tmp, entry));
        } catch (error) {
          failures.push(
            new Error(`removing ${entry} failed: ${reason(error)}`),
          );
        }
  } catch (error) {
    failures.push(
      new Error(`listing ${environment.tmp} failed: ${reason(error)}`),
    );
  }
}

// The reference sandbox tests start containers outside any Compose project.
// Each carries the label `piship.sandbox.instance=piship-reftest-<pid>-...`,
// and only one whose instance name has that shape and whose process <pid> is
// gone is removed, by ID: a sandbox service of a developer's own, or of a run
// still going on, has another instance name or a live owner.
function removeOrphanSandboxes(environment: Environment, failures: Error[]) {
  const listed = environment.docker([
    "ps",
    "--all",
    "--filter",
    "label=piship.sandbox.instance",
    "--format",
    '{{.ID}} {{.Label "piship.sandbox.instance"}}',
  ]);
  if (listed.status !== 0) {
    failures.push(new Error(`docker ps failed: ${detail(listed)}`));
    return;
  }
  const ids = (listed.stdout ?? "").split("\n").flatMap((line) => {
    const [id, instance] = line.trim().split(" ");
    return id &&
      instance?.startsWith(PROJECT_PREFIX) &&
      orphaned(instance, environment)
      ? [id]
      : [];
  });
  if (ids.length === 0) return;
  environment.docker(["rm", "--force", ...ids]);
  console.info(
    `removed ${ids.length} sandbox container(s) left by an earlier run`,
  );
}

/**
 * Remove what a killed run left behind. Every sweep runs, whatever an earlier
 * one did; the failures are thrown at the end, one as it is, several as an
 * AggregateError.
 */
export function recover(environment: Environment = real) {
  const failures: Error[] = [];
  removeOrphans(environment, failures);
  removeOrphanDirectories(environment, failures);
  removeOrphanSandboxes(environment, failures);
  if (failures.length === 1) throw failures[0];
  if (failures.length > 1)
    throw new AggregateError(
      failures,
      `${failures.length} steps of the recovery of earlier reference runs failed:\n${failures.map((failure) => `- ${failure.message}`).join("\n")}`,
    );
}

export default function setup() {
  recover();
}
