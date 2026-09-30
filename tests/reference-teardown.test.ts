import {
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  type ComposeResult,
  registerTeardown,
} from "../examples/enterprise-reference/tests/support/teardown.js";

// The teardown of a reference stack, without Docker: `docker compose` is a
// function that records its arguments and answers as the test says, and the
// log keeper and the directory removal are replaced where a test needs them
// to fail. Both stack helpers (tests/enterprise-reference/stack.ts and
// examples/enterprise-reference/tests/support/stack.ts) stop through this.

const PROJECT = "piship-reftest-4242-teardown-a1b2c3";
const ok: ComposeResult = { status: 0, stdout: "", stderr: "" };
const refused = (stderr: string): ComposeResult => ({
  status: 1,
  stdout: "",
  stderr,
});

const handlers = () => ({
  exit: process.listenerCount("exit"),
  sigint: process.listenerCount("SIGINT"),
  sigterm: process.listenerCount("SIGTERM"),
});

let temp: string;
let logDirectory: string;
let baseline: ReturnType<typeof handlers>;

beforeEach(() => {
  temp = mkdtempSync(join(tmpdir(), "piship-teardown-"));
  logDirectory = join(temp, "logs");
  baseline = handlers();
});

afterEach(() => {
  // A teardown left incomplete would keep the process's exit and signal
  // handlers for good; every scenario below ends by completing its own.
  expect(handlers()).toEqual(baseline);
  vi.unstubAllEnvs();
  rmSync(temp, { recursive: true, force: true });
});

interface Behaviour {
  /** Answer `docker compose logs`. */
  logs?: () => ComposeResult;
  /** Answer `docker compose down`, each time it runs. */
  down?: () => ComposeResult;
  /** Replace the log keeper. Omitted, it records; `"real"` uses logs.ts as it is. */
  keepLogs?:
    | ((project: string, envFile: string, logs: string) => void)
    | "real";
  removeDirectory?: (directory: string) => void;
  /** Whether PISHIP_REFERENCE_LOG_DIR names a directory. Default: it does. */
  keepingLogs?: boolean;
  /** The directory it names. Default: one in the test's temporary directory. */
  logTo?: string;
}

function scenario(behaviour: Behaviour = {}) {
  const directory = mkdtempSync(join(temp, "stack-"));
  const envFile = join(directory, ".env");
  writeFileSync(envFile, "GENERATED_FIXTURE_VALUE=not-a-real-secret-value\n");
  writeFileSync(join(directory, "override.yaml"), "services: {}\n");
  vi.stubEnv(
    "PISHIP_REFERENCE_LOG_DIR",
    behaviour.keepingLogs === false ? "" : (behaviour.logTo ?? logDirectory),
  );

  const calls: string[][] = [];
  const kept: string[] = [];
  const stop = registerTeardown({
    project: PROJECT,
    envFile,
    directory,
    downArguments: ["down", "--remove-orphans"],
    compose(args) {
      calls.push([...args]);
      if (args[0] === "logs")
        return (
          behaviour.logs?.() ?? {
            status: 0,
            stdout: "planted container output\n",
            stderr: "",
          }
        );
      return (behaviour.down ?? (() => ok))();
    },
    ...(behaviour.keepLogs === "real"
      ? {}
      : {
          keepLogs:
            behaviour.keepLogs ??
            ((_project, _envFile, logs) => {
              kept.push(logs);
            }),
        }),
    ...(behaviour.removeDirectory
      ? { removeDirectory: behaviour.removeDirectory }
      : {}),
  });
  const verbs = () => calls.map((args) => args[0]);
  return { stop, calls, kept, verbs, directory, envFile };
}

/** What `stop` throws: each failure as one message, however many there were. */
function failures(stop: () => void): string[] {
  try {
    stop();
  } catch (error) {
    return error instanceof AggregateError
      ? error.errors.map((each: Error) => each.message)
      : [(error as Error).message];
  }
  return [];
}

describe("the teardown of a reference stack", () => {
  it("keeps the logs, stops the project, and removes its directory, once", () => {
    const { stop, calls, kept, verbs, directory } = scenario();
    // Registered at once, so an exit or a signal before the stop still stops it.
    expect(handlers()).toEqual({
      exit: baseline.exit + 1,
      sigint: baseline.sigint + 1,
      sigterm: baseline.sigterm + 1,
    });
    stop();
    expect(verbs()).toEqual(["logs", "down"]);
    expect(calls[1]).toEqual(["down", "--remove-orphans"]);
    expect(kept).toEqual(["planted container output\n"]);
    expect(existsSync(directory)).toBe(false);
    // Its own handlers are gone, and a second call does nothing.
    expect(handlers()).toEqual(baseline);
    stop();
    expect(verbs()).toEqual(["logs", "down"]);
  });

  it("does not collect logs when none are kept, and still stops the project", () => {
    const { stop, verbs, directory } = scenario({ keepingLogs: false });
    stop();
    expect(verbs()).toEqual(["down"]);
    expect(existsSync(directory)).toBe(false);
  });

  it("only runs the two commands of its own project: no volume removal, no prune", () => {
    const { stop, calls } = scenario();
    stop();
    expect(calls).toEqual([
      ["logs", "--no-color", "--timestamps"],
      ["down", "--remove-orphans"],
    ]);
    for (const word of ["-v", "--volumes", "prune", "rm", "system"])
      expect(calls.flat()).not.toContain(word);
  });

  describe("when keeping the logs fails", () => {
    it("still stops the project and removes the directory: log collection", () => {
      const { stop, verbs, directory } = scenario({
        logs: () => {
          throw new Error("docker compose logs could not start");
        },
      });
      expect(failures(stop)).toEqual([
        expect.stringContaining("could not start"),
      ]);
      expect(verbs()).toEqual(["logs", "down"]);
      expect(existsSync(directory)).toBe(false);
    });

    it("still stops the project and removes the directory: the log writer", () => {
      const { stop, verbs, directory } = scenario({
        keepLogs() {
          throw new Error("ENOSPC: no space left on device");
        },
      });
      expect(failures(stop)).toEqual([expect.stringContaining("ENOSPC")]);
      expect(verbs()).toEqual(["logs", "down"]);
      expect(existsSync(directory)).toBe(false);
    });

    it("still stops the project and removes the directory: an artifact directory that cannot be created", () => {
      // The real log keeper, pointed below a regular file.
      writeFileSync(join(temp, "not-a-directory"), "");
      const { stop, verbs, directory } = scenario({
        keepLogs: "real",
        logTo: join(temp, "not-a-directory", "logs"),
      });
      const [message, ...more] = failures(stop);
      expect(message).toContain("container logs");
      expect(more).toEqual([]);
      expect(verbs()).toEqual(["logs", "down"]);
      expect(existsSync(directory)).toBe(false);
    });

    it("still stops the project when the scrubber fails, and writes no raw log", () => {
      // The real log keeper, with an env file the scrubber cannot read.
      const { stop, verbs, directory, envFile } = scenario({
        keepLogs: "real",
      });
      rmSync(envFile);
      expect(failures(stop)).toEqual([]);
      expect(verbs()).toEqual(["logs", "down"]);
      expect(existsSync(directory)).toBe(false);
      const written = readdirSync(logDirectory).map((name) =>
        readFileSync(join(logDirectory, name), "utf8"),
      );
      expect(written).toHaveLength(1);
      expect(written[0]).toContain("the logs were not kept");
      expect(written[0]).not.toContain("planted container output");
    });
  });

  describe("when docker compose down fails", () => {
    it("can be stopped again: the directory and the handlers stay, and the logs are not kept twice", () => {
      const answers = [refused("network is in use")];
      const { stop, verbs, kept, directory, envFile } = scenario({
        down: () => answers.shift() ?? ok,
      });
      expect(failures(stop)).toEqual([
        `docker compose down failed for ${PROJECT}: network is in use`,
      ]);
      // A retry of `down` reads the env file and the override: they stay.
      expect(existsSync(envFile)).toBe(true);
      expect(existsSync(join(directory, "override.yaml"))).toBe(true);
      expect(handlers().exit).toBe(baseline.exit + 1);

      expect(failures(stop)).toEqual([]);
      expect(verbs()).toEqual(["logs", "down", "down"]);
      expect(kept).toHaveLength(1);
      expect(existsSync(directory)).toBe(false);
      expect(handlers()).toEqual(baseline);

      stop();
      expect(verbs()).toEqual(["logs", "down", "down"]);
    });

    it("keeps trying on every call until it succeeds", () => {
      let failing = 3;
      const { stop, verbs, directory } = scenario({
        keepingLogs: false,
        down: () => (failing-- > 0 ? refused("daemon busy") : ok),
      });
      for (let attempt = 0; attempt < 3; attempt += 1)
        expect(failures(stop)).toHaveLength(1);
      expect(failures(stop)).toEqual([]);
      expect(verbs()).toEqual(["down", "down", "down", "down"]);
      expect(existsSync(directory)).toBe(false);
    });

    it("counts a command that could not start as a failure, and names why", () => {
      const answers: ComposeResult[] = [
        {
          status: null,
          stdout: null,
          stderr: null,
          error: new Error("spawn docker ENOENT"),
        },
      ];
      const { stop, directory } = scenario({
        keepingLogs: false,
        down: () => answers.shift() ?? ok,
      });
      expect(failures(stop)).toEqual([
        `docker compose down failed for ${PROJECT}: spawn docker ENOENT`,
      ]);
      expect(existsSync(directory)).toBe(true);
      expect(failures(stop)).toEqual([]);
    });

    it("counts a command that throws as a failure too", () => {
      let throws = true;
      const { stop, directory } = scenario({
        keepingLogs: false,
        down() {
          if (throws) {
            throws = false;
            throw new Error("the docker client crashed");
          }
          return ok;
        },
      });
      expect(failures(stop)).toEqual([
        expect.stringContaining("the docker client crashed"),
      ]);
      expect(failures(stop)).toEqual([]);
      expect(existsSync(directory)).toBe(false);
    });

    it("reports the failed logs and the failed stop together, and the retry finishes the stop", () => {
      const answers = [refused("still running")];
      const { stop, verbs, directory } = scenario({
        logs: () => {
          throw new Error("logs unavailable");
        },
        down: () => answers.shift() ?? ok,
      });
      const first = failures(stop);
      expect(first).toHaveLength(2);
      expect(first[0]).toContain("logs unavailable");
      expect(first[1]).toContain("still running");
      expect(existsSync(directory)).toBe(true);

      // The evidence is tried again while the containers may still be there.
      expect(failures(stop)).toEqual([
        expect.stringContaining("logs unavailable"),
      ]);
      expect(verbs()).toEqual(["logs", "down", "logs", "down"]);
      expect(existsSync(directory)).toBe(false);
    });
  });

  describe("when removing the directory fails", () => {
    it("does not stop the project again, and removes the directory on the next call", () => {
      let refusing = true;
      const removed: string[] = [];
      const { stop, verbs, directory } = scenario({
        keepingLogs: false,
        removeDirectory(path) {
          if (refusing) {
            refusing = false;
            throw new Error("EBUSY: resource busy or locked");
          }
          removed.push(path);
          rmSync(path, { recursive: true, force: true });
        },
      });
      expect(failures(stop)).toEqual([expect.stringContaining("EBUSY")]);
      // The project is down; only the directory is left to retry.
      expect(handlers().exit).toBe(baseline.exit + 1);
      expect(failures(stop)).toEqual([]);
      expect(verbs()).toEqual(["down"]);
      expect(removed).toEqual([directory]);
      expect(handlers()).toEqual(baseline);
    });
  });
});
