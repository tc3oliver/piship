import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { formatError } from "@piship/contracts";
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

describe("--help for uninstall, capabilities, auto, and the command itself", () => {
  it.each([
    [["uninstall", "--help"], "^Usage: acmecode uninstall "],
    [["uninstall", "help"], "^Usage: acmecode uninstall "],
    [["capabilities", "-h"], "^Usage: acmecode capabilities "],
    [["auto", "--help"], "^Usage: acmecode auto "],
    [["-h"], "^AcmeCode\\n"],
    [["help"], "^AcmeCode\\n"],
  ])("prints usage for %j", async (args, pattern) => {
    const lines: string[] = [];
    vi.spyOn(console, "log").mockImplementation((line: string) => {
      lines.push(String(line));
    });
    preparePiEnvironment("acmecode");
    await launchPiDistribution({ distributionDir: temp, metadata, args });
    expect(lines.join("\n")).toMatch(new RegExp(pattern));
  });
});

describe("a refused command line", () => {
  it.each([
    [
      ["doctor", "--josn"],
      "Unknown option --josn for doctor. Did you mean --json?\nUsage: acmecode doctor [--json]",
    ],
    [
      ["update", "--form", "x"],
      "Unknown option --form for update. Did you mean --from?\nUsage: acmecode update ",
    ],
    [
      ["doctr"],
      "Unknown command: doctr. Did you mean doctor? Run acmecode --help",
    ],
    [
      ["version", "--json"],
      "Unknown option --json for version. Run acmecode version --help for its usage.",
    ],
    [
      ["rollback", "x"],
      "rollback takes no further arguments. Run acmecode rollback --help",
    ],
    [
      ["policy", "explain", "shel.execute", "ls"],
      "Unknown policy action shel.execute. Did you mean shell.execute?",
    ],
  ])("names what %j got wrong, exiting 2", async (args, expected) => {
    preparePiEnvironment("acmecode");
    const error = (await launchPiDistribution({
      distributionDir: temp,
      metadata,
      args,
    }).catch((caught: unknown) => caught)) as Error & { usage?: boolean };
    expect(error.usage).toBe(true);
    expect(formatError(error).startsWith(expected)).toBe(true);
  });

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
