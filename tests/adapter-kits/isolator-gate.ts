// Where the sandbox kit's tests need an OS isolator. They run commands for
// real, in Seatbelt on macOS or bubblewrap on Linux, so a host without either
// (Windows, or a Linux host where bubblewrap cannot create user namespaces,
// as on Ubuntu 24.04 with AppArmor's restriction on) cannot run them. Such a
// run skips them and says why, on the console and in the test names, so the
// missing evidence is visible. With PISHIP_REQUIRE_ISOLATOR=1 it fails
// instead: a job that must show the sandbox kit's evidence turns red on a
// runner that cannot produce it, rather than green with no sandbox tests.
import { existsSync } from "node:fs";
import { delimiter, join } from "node:path";
import { describe, it } from "vitest";

const SANDBOX_EXEC = "/usr/bin/sandbox-exec";

/** The bubblewrap binary on PATH, if there is one. */
export function findBwrap(): string | undefined {
  for (const dir of (process.env.PATH ?? "").split(delimiter)) {
    const candidate = join(dir, "bwrap");
    if (dir && existsSync(candidate)) return candidate;
  }
  return undefined;
}

/** Why no isolator works on this host, judged from what is installed. */
export function noIsolatorReason(): string {
  if (process.platform === "darwin")
    return existsSync(SANDBOX_EXEC)
      ? "sandbox-exec is present but refused the probe policy"
      : `${SANDBOX_EXEC} is missing`;
  if (process.platform === "linux")
    return findBwrap()
      ? "bubblewrap is installed but could not start a sandbox, probably because unprivileged user namespaces are restricted (on Ubuntu 24.04, kernel.apparmor_restrict_unprivileged_userns=0 lifts it)"
      : "bubblewrap (bwrap) is not on PATH";
  return `${process.platform} has no OS isolator here: Seatbelt is macOS-only and bubblewrap Linux-only`;
}

type Define = () => void;
type Run = () => void | Promise<void>;

/** The vitest calls the gate makes; replaceable so the gate can be tested. */
export interface Host {
  readonly describe: (name: string, define: Define) => void;
  readonly describeSkip: (name: string, define: Define) => void;
  readonly it: (name: string, run: Run, timeoutMs?: number) => void;
  readonly itSkip: (name: string, run: Run, timeoutMs?: number) => void;
  readonly warn: (message: string) => void;
}

const vitest: Host = {
  describe: (name, define) => describe(name, define),
  describeSkip: (name, define) => describe.skip(name, define),
  it: (name, run, timeoutMs) => it(name, run, timeoutMs),
  itSkip: (name, run, timeoutMs) => it.skip(name, run, timeoutMs),
  warn: (message) => console.warn(message),
};

export interface IsolatorGate {
  /** `describe` for a suite that needs an isolator; `found` is the one this host has. */
  readonly describe: (
    found: string | undefined,
  ) => (name: string, define: Define) => void;
  /** `it` for one test that needs an isolator. */
  readonly it: (
    found: string | undefined,
  ) => (name: string, run: Run, timeoutMs?: number) => void;
}

export function isolatorGate(
  options: {
    readonly host?: Host;
    readonly required?: boolean;
    readonly reason?: () => string;
  } = {},
): IsolatorGate {
  const host = options.host ?? vitest;
  const required =
    options.required ?? process.env.PISHIP_REQUIRE_ISOLATOR === "1";
  const reason = options.reason ?? noIsolatorReason;
  const failure = (name: string) =>
    new Error(
      `${name} needs an OS isolator and this host has none: ${reason()}. PISHIP_REQUIRE_ISOLATOR=1 asks for the sandbox tests to run, so their absence fails the run.`,
    );
  const announce = (name: string) =>
    host.warn(
      `${name}: skipped, no OS isolator on this host (${reason()}). Set PISHIP_REQUIRE_ISOLATOR=1 to fail instead of skipping.`,
    );
  return {
    describe: (found) => (name, define) => {
      if (found) return host.describe(name, define);
      if (required)
        return host.describe(name, () =>
          host.it("has an OS isolator (PISHIP_REQUIRE_ISOLATOR=1)", () => {
            throw failure(name);
          }),
        );
      announce(name);
      host.describeSkip(`${name} (skipped: no OS isolator)`, define);
    },
    it: (found) => (name, run, timeoutMs) => {
      if (found) return host.it(name, run, timeoutMs);
      if (required)
        return host.it(name, () => {
          throw failure(name);
        });
      announce(name);
      host.itSkip(`${name} (skipped: no OS isolator)`, run, timeoutMs);
    },
  };
}

export const { describe: describeIsolated, it: itIsolated } = isolatorGate();
