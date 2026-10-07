// `login` goes on into the session it was run for, only where a person is at
// the terminal of a managed distribution; every other form prints and exits.
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PiShipError } from "@piship/contracts";
import type { DistributionLock } from "@piship/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  runLogin: vi.fn(),
  runInteractive: vi.fn(),
}));
vi.mock("@piship/core", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@piship/core")>()),
  runLogin: mocks.runLogin,
}));
vi.mock("./commands/session.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./commands/session.js")>()),
  runInteractive: mocks.runInteractive,
}));

import { preparePiEnvironment } from "./environment.js";
import { launchPiDistribution, PINNED_PI_VERSION } from "./index.js";

let temp: string;
const saved = {
  home: process.env.PISHIP_STATE_HOME,
  agentDir: process.env.PI_CODING_AGENT_DIR,
  ci: process.env.CI,
  stdin: Object.getOwnPropertyDescriptor(process.stdin, "isTTY"),
  stdout: Object.getOwnPropertyDescriptor(process.stdout, "isTTY"),
};
const setTTY = (stream: NodeJS.ReadStream | NodeJS.WriteStream, on: boolean) =>
  Object.defineProperty(stream, "isTTY", { value: on, configurable: true });
const restore = (
  stream: NodeJS.ReadStream | NodeJS.WriteStream,
  descriptor: PropertyDescriptor | undefined,
) => {
  if (descriptor) Object.defineProperty(stream, "isTTY", descriptor);
  else delete (stream as { isTTY?: boolean }).isTTY;
};
const put = (name: string, value: string | undefined) => {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
};

beforeEach(() => {
  temp = mkdtempSync(join(tmpdir(), "piship-login-continues-"));
  process.env.PISHIP_STATE_HOME = temp;
  delete process.env.CI;
  mocks.runLogin.mockReset().mockResolvedValue(undefined);
  mocks.runInteractive.mockReset().mockResolvedValue(undefined);
  setTTY(process.stdin, true);
  setTTY(process.stdout, true);
});
afterEach(() => {
  vi.restoreAllMocks();
  put("PISHIP_STATE_HOME", saved.home);
  put("PI_CODING_AGENT_DIR", saved.agentDir);
  put("CI", saved.ci);
  restore(process.stdin, saved.stdin);
  restore(process.stdout, saved.stdout);
  rmSync(temp, { recursive: true, force: true });
});

const metadata = (mode: "managed" | "personal") =>
  ({
    app: { id: "acmecode", command: "acmecode", name: "AcmeCode" },
    runtime: {
      package: "@earendil-works/pi-coding-agent",
      version: PINNED_PI_VERSION,
    },
    deployment: { mode },
  }) as unknown as DistributionLock;

const launch = (args: string[], mode: "managed" | "personal" = "managed") => {
  preparePiEnvironment("acmecode");
  return launchPiDistribution({
    distributionDir: temp,
    metadata: metadata(mode),
    args,
  });
};

describe("login at a terminal", () => {
  it("starts the session after a successful sign-in, and says so", async () => {
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    await launch(["login"]);
    expect(mocks.runLogin).toHaveBeenCalledTimes(1);
    expect(mocks.runInteractive).toHaveBeenCalledTimes(1);
    expect(mocks.runLogin.mock.invocationCallOrder[0]).toBeLessThan(
      mocks.runInteractive.mock.invocationCallOrder[0] ?? 0,
    );
    expect(err).toHaveBeenCalledWith("Signed in. Starting acmecode...");
  });

  it.each([
    ["stdin is not a terminal", false, true, undefined],
    ["stdout is not a terminal", true, false, undefined],
    ["CI is set", true, true, "true"],
  ])("only signs in when %s", async (_, stdin, stdout, ci) => {
    setTTY(process.stdin, stdin);
    setTTY(process.stdout, stdout);
    if (ci) process.env.CI = ci;
    await launch(["login"]);
    expect(mocks.runLogin).toHaveBeenCalledTimes(1);
    expect(mocks.runInteractive).not.toHaveBeenCalled();
  });

  it("only signs in for a personal distribution", async () => {
    await launch(["login"], "personal");
    expect(mocks.runLogin).toHaveBeenCalledTimes(1);
    expect(mocks.runInteractive).not.toHaveBeenCalled();
  });

  it("does not start the session when the sign-in fails or is cancelled", async () => {
    const cancelled = new PiShipError(
      "IDENTITY_REQUIRED",
      "Sign-in was cancelled",
    );
    mocks.runLogin.mockRejectedValue(cancelled);
    await expect(launch(["login"])).rejects.toBe(cancelled);
    expect(mocks.runInteractive).not.toHaveBeenCalled();
  });

  it("leaves every other login form alone", async () => {
    for (const args of [
      ["login", "--status"],
      ["--new-session", "login"],
    ])
      await launch(args).catch(() => undefined);
    expect(mocks.runLogin).not.toHaveBeenCalled();
    expect(mocks.runInteractive).not.toHaveBeenCalled();
  });
});
