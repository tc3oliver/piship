import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PiShipError } from "@piship/contracts";
import type { DistributionLock } from "@piship/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { launchPiDistribution, PINNED_PI_VERSION } from "./index.js";

let temp: string;
const saved = {
  home: process.env.PISHIP_STATE_HOME,
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

beforeEach(() => {
  temp = mkdtempSync(join(tmpdir(), "piship-no-terminal-"));
  process.env.PISHIP_STATE_HOME = temp;
});
afterEach(() => {
  if (saved.home === undefined) delete process.env.PISHIP_STATE_HOME;
  else process.env.PISHIP_STATE_HOME = saved.home;
  restore(process.stdin, saved.stdin);
  restore(process.stdout, saved.stdout);
  rmSync(temp, { recursive: true, force: true });
});

const metadata = {
  app: { id: "acmecode", command: "acmecode", name: "AcmeCode" },
  runtime: {
    package: "@earendil-works/pi-coding-agent",
    version: PINNED_PI_VERSION,
  },
  deployment: { mode: "managed" },
} as unknown as DistributionLock;

const launch = (args: string[]) =>
  launchPiDistribution({ distributionDir: temp, metadata, args });

describe("interactive launch without a terminal", () => {
  it.each([
    ["stdin", true, false],
    ["stdout", false, true],
  ])(
    "fails at once when %s is not a terminal, before any state exists",
    async (_, stdin, stdout) => {
      setTTY(process.stdin, stdin);
      setTTY(process.stdout, stdout);
      for (const args of [[], ["--new-session"], ["--model", "acme/coder"]]) {
        const error = await launch(args).then(
          () => undefined,
          (failure: unknown) => failure,
        );
        expect(error).toBeInstanceOf(PiShipError);
        expect((error as PiShipError).code).toBe("CONFIG_INVALID");
        expect((error as PiShipError).message).toContain(
          "acmecode needs a terminal",
        );
        expect((error as PiShipError).userAction).toContain("acmecode --smoke");
      }
      expect(existsSync(join(temp, "acmecode"))).toBe(false);
    },
  );
});
