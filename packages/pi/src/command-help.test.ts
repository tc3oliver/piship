import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { DistributionLock } from "@piship/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { preparePiEnvironment } from "./environment.js";
import { launchPiDistribution, PINNED_PI_VERSION } from "./index.js";

let temp: string;
const savedHome = process.env.PISHIP_STATE_HOME;

beforeEach(() => {
  temp = mkdtempSync(join(tmpdir(), "piship-command-help-"));
  process.env.PISHIP_STATE_HOME = temp;
});
afterEach(() => {
  vi.restoreAllMocks();
  if (savedHome === undefined) delete process.env.PISHIP_STATE_HOME;
  else process.env.PISHIP_STATE_HOME = savedHome;
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

describe("<command> --help for the one-word commands", () => {
  it.each([
    ["login", "--help"],
    ["logout", "-h"],
    ["models", "help"],
    ["rollback", "--help"],
    ["version", "help"],
  ])(
    "prints usage for %s %s instead of an unknown command",
    async (command, flag) => {
      const lines: string[] = [];
      vi.spyOn(console, "log").mockImplementation((line: string) => {
        lines.push(String(line));
      });
      preparePiEnvironment("acmecode");
      await launchPiDistribution({
        distributionDir: temp,
        metadata,
        args: [command, flag],
      });
      expect(lines.join("\n")).toMatch(
        new RegExp(`^Usage: acmecode ${command}\\n`),
      );
    },
  );
});

describe("--help for config and policy subcommands", () => {
  it.each([
    [["config", "--help"], "config"],
    [["config", "help"], "config"],
    [["config", "set", "--help"], "config"],
    [["config", "explain", "-h"], "config"],
    [["policy", "--help"], "policy"],
    [["policy", "explain", "--help"], "policy"],
  ])("prints usage for %j", async (args, command) => {
    const lines: string[] = [];
    vi.spyOn(console, "log").mockImplementation((line: string) => {
      lines.push(String(line));
    });
    preparePiEnvironment("acmecode");
    await launchPiDistribution({ distributionDir: temp, metadata, args });
    expect(lines.join("\n")).toMatch(
      new RegExp(`^Usage: acmecode ${command} `),
    );
  });
});

describe("a refused command line", () => {
  it.each([
    [["--frobnicate"]],
    [["models", "--yaml"]],
    [["doctor", "--yaml"]],
    [["--model"]],
  ])("is a usage error, which the launcher exits 2 for: %j", async (args) => {
    preparePiEnvironment("acmecode");
    const error = await launchPiDistribution({
      distributionDir: temp,
      metadata,
      args,
    }).catch((caught: unknown) => caught);
    expect((error as { usage?: unknown }).usage).toBe(true);
  });
});
