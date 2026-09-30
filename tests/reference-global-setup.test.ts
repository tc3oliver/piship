import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  type DockerResult,
  recover,
} from "./enterprise-reference/global-setup.js";

// The crash recovery of `npm run test:reference` (global-setup.ts), without
// Docker: `docker` is a fake daemon that holds the Compose projects and
// containers a test gives it, and a process is alive when the test says so.
// It shows what recovery may and may not touch and that one failure does not
// stop the rest. That Compose finds a project by its name alone, after the
// killed run's files are gone, is Docker's part and is not shown here.

const DEAD = 4101;
const DEAD_TOO = 4102;
const DEAD_THIRD = 4103;
const LIVE = 4200;

const ok = (stdout = ""): DockerResult => ({ status: 0, stdout, stderr: "" });
const refused = (stderr: string): DockerResult => ({
  status: 1,
  stdout: "",
  stderr,
});

interface Daemon {
  projects: string[];
  /** Containers with a `piship.sandbox.instance` label, by ID. */
  sandboxes: { id: string; instance: string }[];
  /** Projects whose `down` fails, with the answer. */
  failing: Map<string, DockerResult>;
  /** Commands that fail outright, by their first word. */
  broken: Map<string, DockerResult>;
  calls: string[][];
}

function daemon(state: Partial<Daemon> = {}) {
  const held: Daemon = {
    projects: [],
    sandboxes: [],
    failing: new Map(),
    broken: new Map(),
    calls: [],
    ...state,
  };
  const docker = (args: readonly string[]): DockerResult => {
    held.calls.push([...args]);
    const broken = held.broken.get(args.slice(0, 2).join(" "));
    if (broken) return broken;
    if (args[0] === "compose" && args[1] === "ls")
      return ok(JSON.stringify(held.projects.map((Name) => ({ Name }))));
    if (args[0] === "compose" && args[1] === "-p" && args[3] === "down") {
      const name = args[2] as string;
      const failure = held.failing.get(name);
      if (failure) return failure;
      held.projects = held.projects.filter((project) => project !== name);
      return ok();
    }
    if (args[0] === "ps")
      return ok(
        held.sandboxes
          .map(({ id, instance }) => `${id} ${instance}`)
          .join("\n"),
      );
    if (args[0] === "rm" && args[1] === "--force") {
      const ids = args.slice(2);
      held.sandboxes = held.sandboxes.filter(({ id }) => !ids.includes(id));
      return ok();
    }
    return refused(`unexpected docker command: ${args.join(" ")}`);
  };
  return { held, docker };
}

let tmp: string;
let live: Set<number>;

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), "piship-global-setup-"));
  live = new Set([LIVE]);
  vi.spyOn(console, "info").mockImplementation(() => undefined);
});

afterEach(() => {
  vi.restoreAllMocks();
  rmSync(tmp, { recursive: true, force: true });
});

const environment = (
  docker: (args: readonly string[]) => DockerResult,
  remove?: (path: string) => void,
) => ({
  docker,
  tmp,
  alive: (pid: number) => live.has(pid),
  remove:
    remove ??
    ((path: string) => rmSync(path, { recursive: true, force: true })),
});

const entries = () => readdirSync(tmp).sort();
const temporary = (pid: number, suffix: string) => {
  const path = join(tmp, `piship-reftest-${pid}-${suffix}`);
  mkdirSync(path);
  writeFileSync(join(path, ".env"), "GENERATED=fixture\n");
  return path;
};

/** What `recover` throws: each failure as one message, however many there were. */
function failures(run: () => void): string[] {
  try {
    run();
  } catch (error) {
    return error instanceof AggregateError
      ? error.errors.map((each: Error) => each.message)
      : [(error as Error).message];
  }
  return [];
}

describe("recovery of the stacks a killed run left", () => {
  it("removes a stale project by its name alone, and never a live run's or an unrelated project", () => {
    const { held, docker } = daemon({
      projects: [
        `piship-reftest-${DEAD}-usage-a1b2c3`,
        `piship-reftest-${LIVE}-usage-d4e5f6`,
        "my-own-project",
      ],
    });
    recover(environment(docker));
    expect(held.projects).toEqual([
      `piship-reftest-${LIVE}-usage-d4e5f6`,
      "my-own-project",
    ]);
    // Nothing of the killed run's temporary directory is named: no compose
    // file, no env file, no project directory.
    expect(held.calls).toContainEqual([
      "compose",
      "-p",
      `piship-reftest-${DEAD}-usage-a1b2c3`,
      "down",
      "--remove-orphans",
    ]);
    const words = held.calls.flat();
    for (const word of ["-f", "--env-file", "--project-directory"])
      expect(words).not.toContain(word);
  });

  it("never removes a volume and never prunes", () => {
    const { held, docker } = daemon({
      projects: [`piship-reftest-${DEAD}-a-000000`],
      sandboxes: [{ id: "c0ffee", instance: `piship-reftest-${DEAD}-sbx` }],
    });
    recover(environment(docker));
    const words = held.calls.flat();
    for (const word of ["-v", "--volumes", "prune", "system", "volume"])
      expect(words).not.toContain(word);
  });

  it("does nothing the second time", () => {
    const { held, docker } = daemon({
      projects: [`piship-reftest-${DEAD}-a-000000`],
      sandboxes: [{ id: "c0ffee", instance: `piship-reftest-${DEAD}-sbx` }],
    });
    temporary(DEAD, "AAAAAA");
    recover(environment(docker));
    held.calls.length = 0;
    expect(failures(() => recover(environment(docker)))).toEqual([]);
    expect(held.calls.map((args) => args.slice(0, 2).join(" "))).toEqual([
      "compose ls",
      "ps --all",
    ]);
    expect(entries()).toEqual([]);
  });

  it("removes stale temporary directories, and keeps a live run's and any other", () => {
    const { docker } = daemon();
    temporary(DEAD, "AAAAAA");
    temporary(DEAD_TOO, "BBBBBB");
    const running = temporary(LIVE, "CCCCCC");
    mkdirSync(join(tmp, "not-ours"));
    mkdirSync(join(tmp, "piship-reftest-")); // no owner: not one of ours
    recover(environment(docker));
    expect(entries()).toEqual([
      "not-ours",
      "piship-reftest-",
      `piship-reftest-${LIVE}-CCCCCC`,
    ]);
    expect(existsSync(join(running, ".env"))).toBe(true);
  });

  it("removes only a sandbox container of a dead run, by ID", () => {
    const { held, docker } = daemon({
      sandboxes: [
        { id: "aaa111", instance: `piship-reftest-${DEAD}-sbx` },
        { id: "bbb222", instance: `piship-reftest-${LIVE}-sbx` },
        { id: "ccc333", instance: "a-developers-own" },
      ],
    });
    recover(environment(docker));
    expect(held.sandboxes.map(({ id }) => id)).toEqual(["bbb222", "ccc333"]);
    expect(held.calls).toContainEqual(["rm", "--force", "aaa111"]);
  });

  describe("when removing one project fails", () => {
    const first = `piship-reftest-${DEAD}-one-000001`;
    const second = `piship-reftest-${DEAD_TOO}-two-000002`;
    const third = `piship-reftest-${DEAD_THIRD}-three-000003`;

    it("still removes the others, sweeps the temporary directories and the sandboxes, then fails once, naming it", () => {
      const { held, docker } = daemon({
        projects: [first, second, third],
        sandboxes: [{ id: "c0ffee", instance: `piship-reftest-${DEAD}-sbx` }],
        failing: new Map([[second, refused("no configuration file provided")]]),
      });
      temporary(DEAD, "AAAAAA");
      temporary(LIVE, "BBBBBB");

      expect(failures(() => recover(environment(docker)))).toEqual([
        `docker compose down failed for ${second}: no configuration file provided`,
      ]);
      expect(held.projects).toEqual([second]);
      expect(held.sandboxes).toEqual([]);
      expect(entries()).toEqual([`piship-reftest-${LIVE}-BBBBBB`]);
    });

    it("recovers it on the next run", () => {
      const { held, docker } = daemon({
        projects: [first, second],
        failing: new Map([[first, refused("daemon busy")]]),
      });
      expect(failures(() => recover(environment(docker)))).toHaveLength(1);
      expect(held.projects).toEqual([first]);
      held.failing.clear();
      expect(failures(() => recover(environment(docker)))).toEqual([]);
      expect(held.projects).toEqual([]);
    });

    it("reports every failed project together", () => {
      const { docker } = daemon({
        projects: [first, second, third],
        failing: new Map([
          [first, refused("a")],
          [third, refused("c")],
        ]),
      });
      expect(failures(() => recover(environment(docker)))).toEqual([
        `docker compose down failed for ${first}: a`,
        `docker compose down failed for ${third}: c`,
      ]);
    });
  });

  describe("when Docker cannot answer", () => {
    it("still sweeps the temporary directories, and reports both commands", () => {
      const { docker } = daemon({
        broken: new Map([
          ["compose ls", refused("Cannot connect to the Docker daemon")],
          ["ps --all", refused("Cannot connect to the Docker daemon")],
        ]),
      });
      temporary(DEAD, "AAAAAA");
      const running = temporary(LIVE, "BBBBBB");
      expect(failures(() => recover(environment(docker)))).toEqual([
        "docker compose ls failed: Cannot connect to the Docker daemon",
        "docker ps failed: Cannot connect to the Docker daemon",
      ]);
      expect(entries()).toEqual([`piship-reftest-${LIVE}-BBBBBB`]);
      expect(existsSync(running)).toBe(true);
    });

    it("names why a docker that could not be started failed, not a TypeError", () => {
      const missing: DockerResult = {
        status: null,
        stdout: null,
        stderr: null,
        error: new Error("spawn docker ENOENT"),
      };
      const { docker } = daemon({
        broken: new Map([
          ["compose ls", missing],
          ["ps --all", missing],
        ]),
      });
      expect(failures(() => recover(environment(docker)))).toEqual([
        "docker compose ls failed: spawn docker ENOENT",
        "docker ps failed: spawn docker ENOENT",
      ]);
    });

    it("reports an answer it cannot read, and still goes on", () => {
      const { docker } = daemon({
        broken: new Map([["compose ls", ok("not json")]]),
      });
      temporary(DEAD, "AAAAAA");
      const [message, ...more] = failures(() => recover(environment(docker)));
      expect(message).toContain("docker compose ls");
      expect(more).toEqual([]);
      expect(entries()).toEqual([]);
    });
  });

  it("goes on removing directories when one cannot be removed", () => {
    const { docker } = daemon();
    temporary(DEAD, "AAAAAA");
    temporary(DEAD_TOO, "BBBBBB");
    const removed: string[] = [];
    const [message, ...more] = failures(() =>
      recover(
        environment(docker, (path) => {
          if (path.includes("AAAAAA")) throw new Error("EBUSY: locked");
          removed.push(path);
          rmSync(path, { recursive: true, force: true });
        }),
      ),
    );
    expect(message).toContain("EBUSY");
    expect(more).toEqual([]);
    expect(removed).toHaveLength(1);
    expect(entries()).toEqual([`piship-reftest-${DEAD}-AAAAAA`]);
  });
});
