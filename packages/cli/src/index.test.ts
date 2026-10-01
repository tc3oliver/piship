import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { runCli } from "./index.js";

const ID = "mypi";
let temp: string;

/**
 * An installed release whose branded command records the arguments it
 * receives. Its `.cmd` shim is the one `piship build` writes, so a manager
 * that forwarded through cmd.exe would reach it on Windows.
 */
function installRecorder(): { received: string; payload: string } {
  const install = join(temp, "install home");
  const payload = join(install, "apps", ID, "1.0.0");
  const received = join(temp, "received.json");
  mkdirSync(join(payload, "bin"), { recursive: true });
  const command = join(payload, "bin", ID);
  writeFileSync(
    command,
    `#!/usr/bin/env node\nrequire("node:fs").writeFileSync(${JSON.stringify(received)}, JSON.stringify(process.argv.slice(2)));\n`,
  );
  chmodSync(command, 0o755);
  writeFileSync(`${command}.cmd`, `@echo off\r\nnode "%~dp0\\${ID}" %*\r\n`);
  mkdirSync(join(install, "receipts"), { recursive: true });
  const bin = join(temp, "bin");
  mkdirSync(bin);
  writeFileSync(
    join(install, "receipts", `${ID}.json`),
    JSON.stringify({
      schema: "piship-install/v1",
      app: { id: ID, name: "MyPi", command: ID, version: "1.0.0" },
      payload,
      commandPath: join(bin, process.platform === "win32" ? `${ID}.cmd` : ID),
      launcher: join(install, "apps", ID, "launch.mjs"),
      active: "1.0.0",
      releases: [{ version: "1.0.0", payload, installedAt: "" }],
    }),
  );
  process.env.PISHIP_INSTALL_HOME = install;
  process.env.PISHIP_BIN_HOME = bin;
  return { received, payload };
}

async function cli(args: string[]): Promise<number> {
  const errors: string[] = [];
  const status = await runCli(args, {
    stdout: () => {},
    stderr: (message) => errors.push(message),
  });
  expect(errors.join("\n")).not.toContain("failed");
  return status;
}

describe("forwarding update and rollback to the installed release", () => {
  beforeEach(() => {
    temp = mkdtempSync(join(tmpdir(), "piship-cli-forward-"));
  });
  afterEach(() => {
    delete process.env.PISHIP_INSTALL_HOME;
    delete process.env.PISHIP_BIN_HOME;
    rmSync(temp, { recursive: true, force: true });
  });

  it("passes a --from value with spaces and cmd metacharacters through unchanged", async () => {
    const { received } = installRecorder();
    const marker = join(temp, "planted");
    const from = `${join(temp, "My Channel (v2) 100% ^x")} & echo planted> "${marker}" | %PATH% !`;
    expect(await cli(["update", ID, "--from", from, "--check"])).toBe(0);
    expect(JSON.parse(readFileSync(received, "utf8"))).toEqual([
      "update",
      "--from",
      from,
      "--check",
    ]);
    // Nothing in the value ran as a command.
    expect(existsSync(marker)).toBe(false);
  });

  it("forwards rollback unchanged", async () => {
    const { received } = installRecorder();
    expect(await cli(["rollback", ID])).toBe(0);
    expect(JSON.parse(readFileSync(received, "utf8"))).toEqual(["rollback"]);
  });
});

describe("uninstall --purge", () => {
  beforeEach(() => {
    temp = mkdtempSync(join(tmpdir(), "piship-cli-uninstall-"));
    process.env.PISHIP_STATE_HOME = join(temp, "state");
  });
  afterEach(() => {
    delete process.env.PISHIP_INSTALL_HOME;
    delete process.env.PISHIP_BIN_HOME;
    delete process.env.PISHIP_STATE_HOME;
    rmSync(temp, { recursive: true, force: true });
  });

  function seedState(): string {
    const state = join(temp, "state", ID);
    mkdirSync(join(state, "sessions"), { recursive: true });
    writeFileSync(join(state, "sessions", "s1.jsonl"), "{}\n");
    return state;
  }

  it("needs --yes, and --yes alone is not an option of uninstall", async () => {
    const { payload } = installRecorder();
    const state = seedState();
    const errors: string[] = [];
    const output = {
      stdout: () => {},
      stderr: (message: string) => errors.push(message),
    };
    expect(await runCli(["uninstall", ID, "--purge"], output)).toBe(1);
    expect(errors.join("\n")).toContain("repeat with --yes");
    expect(await runCli(["uninstall", ID, "--yes"], output)).toBe(2);
    expect(existsSync(payload)).toBe(true);
    expect(existsSync(state)).toBe(true);
  });

  it("removes an edited command shim only with --remove-edited-shim (#158)", async () => {
    const { payload } = installRecorder();
    const launcher = join(temp, "install home", "apps", ID, "launch.mjs");
    const shim = join(
      temp,
      "bin",
      process.platform === "win32" ? `${ID}.cmd` : ID,
    );
    writeFileSync(
      shim,
      process.platform === "win32"
        ? `@echo off\r\nset FOO=1\r\nnode "${launcher}" %*\r\n`
        : `#!/bin/sh\nexport FOO=1\nexec node '${launcher}' "$@"\n`,
    );
    const errors: string[] = [];
    const output = {
      stdout: () => {},
      stderr: (message: string) => errors.push(message),
    };
    expect(await runCli(["uninstall", ID], output)).toBe(1);
    expect(errors.join("\n")).toContain("--remove-edited-shim");
    expect(existsSync(shim)).toBe(true);
    expect(existsSync(payload)).toBe(true);
    expect(
      await runCli(["uninstall", ID, "--remove-edited-shim"], output),
    ).toBe(0);
    expect(existsSync(shim)).toBe(false);
    expect(existsSync(payload)).toBe(false);
  });

  it("removes the install and the state in one command", async () => {
    const { payload } = installRecorder();
    const state = seedState();
    const lines: string[] = [];
    expect(
      await runCli(["uninstall", ID, "--purge", "--yes"], {
        stdout: (message) => lines.push(message),
        stderr: (message) => lines.push(message),
      }),
      lines.join("\n"),
    ).toBe(0);
    expect(lines.join("\n")).toBe(`Uninstalled ${ID}. Purged ${state}`);
    expect(existsSync(payload)).toBe(false);
    expect(
      existsSync(join(temp, "install home", "receipts", `${ID}.json`)),
    ).toBe(false);
    expect(existsSync(state)).toBe(false);
  });

  it("refuses while signed in, naming logout, and purges --without-logout with a warning", async () => {
    const { payload } = installRecorder();
    const state = seedState();
    // The file fallback holds the secret, so no platform store is touched.
    mkdirSync(join(state, "secrets"));
    writeFileSync(join(state, "secrets", "inference"), "fake-SENTINEL\n");
    mkdirSync(join(state, "credentials-metadata"));
    writeFileSync(
      join(state, "credentials-metadata", "inference.json"),
      JSON.stringify({
        schema: "piship-credential-metadata/v1",
        credential_ref: "file:inference",
      }),
    );
    const lines: string[] = [];
    const output = {
      stdout: (message: string) => lines.push(message),
      stderr: (message: string) => lines.push(message),
    };
    expect(await runCli(["uninstall", ID, "--purge", "--yes"], output)).toBe(1);
    expect(lines.join("\n")).toContain(
      `Run ${ID} logout first, then purge again`,
    );
    expect(existsSync(payload)).toBe(true);
    expect(existsSync(state)).toBe(true);
    expect(await runCli(["uninstall", ID, "--without-logout"], output)).toBe(2);
    lines.length = 0;
    expect(
      await runCli(
        ["uninstall", ID, "--purge", "--yes", "--without-logout"],
        output,
      ),
      lines.join("\n"),
    ).toBe(0);
    expect(lines.join("\n")).toContain(
      "Warning: purged without logout: a runtime credential was deleted locally but not revoked",
    );
    expect(existsSync(payload)).toBe(false);
    expect(existsSync(state)).toBe(false);
  });
});
