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

describe("repair", () => {
  beforeEach(() => {
    temp = mkdtempSync(join(tmpdir(), "piship-cli-repair-"));
  });
  afterEach(() => {
    delete process.env.PISHIP_INSTALL_HOME;
    delete process.env.PISHIP_BIN_HOME;
    rmSync(temp, { recursive: true, force: true });
  });

  async function repair(args: string[]) {
    const errors: string[] = [];
    const status = await runCli(["repair", ...args], {
      stdout: () => {},
      stderr: (message) => errors.push(message),
    });
    return { status, stderr: errors.join("\n") };
  }

  it("runs in PiShip and never runs the installed release it repairs", async () => {
    const { received } = installRecorder();
    const source = join(temp, "not-a-release");
    mkdirSync(source);
    const result = await repair([ID, source]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("inventory.json");
    expect(existsSync(received)).toBe(false);
  });

  it("needs the distribution and the trusted source", async () => {
    expect(await repair([ID])).toEqual({
      status: 2,
      stderr: "Usage: piship repair <id> <archive|release-dir|payload>",
    });
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

describe("validate", () => {
  const base = {
    schema: "piship/v1alpha4",
    app: {
      id: "acmecode",
      name: "AcmeCode",
      command: "acmecode",
      version: "1.0.0",
    },
    runtime: { pi: "0.87.1" },
    deployment: { mode: "managed" },
    identity: {
      mode: "oidc",
      oidc: {
        issuer: "https://login.acme.example",
        clientId: "acmecode",
        redirectUri: "http://127.0.0.1:8765/callback",
      },
    },
    credential: {
      provider: "http-broker",
      broker: { endpoint: "https://broker.acme.example/token" },
    },
    inference: {
      provider: "openai-compatible",
      baseUrl: "https://gateway.acme.example/v1",
    },
    models: {
      default: "acme/coder",
      allowed: ["acme/coder"],
      catalog: {
        "acme/coder": {
          name: "Acme Coder",
          contextWindow: 128000,
          maxOutputTokens: 8192,
        },
      },
    },
    updates: { channel: "stable", channels: ["stable"] },
  };
  beforeEach(() => {
    temp = mkdtempSync(join(tmpdir(), "piship-cli-validate-"));
  });
  afterEach(() => {
    rmSync(temp, { recursive: true, force: true });
  });
  async function validate(extra: Record<string, unknown>) {
    const manifest = join(temp, "piship.yaml");
    writeFileSync(manifest, JSON.stringify({ ...base, ...extra }));
    const stdout: string[] = [];
    const stderr: string[] = [];
    const status = await runCli(["validate", manifest], {
      stdout: (message) => stdout.push(message),
      stderr: (message) => stderr.push(message),
    });
    return { status, stdout: stdout.join("\n"), stderr: stderr.join("\n") };
  }

  it("prints a warning for a setting that fails on some machines", async () => {
    const result = await validate({
      network: { tls: { additionalCA: ["certs/acme.pem"] } },
    });
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("Manifest is valid.");
    expect(result.stderr).toContain(
      "Warning: network.tls.additionalCA[0]: A relative CA bundle path",
    );
  });

  it("separates the variables launch needs from the ones only update reads", async () => {
    delete process.env.ACME_GATEWAY_URL;
    delete process.env.ACME_UPDATE_URL;
    const result = await validate({
      variables: ["ACME_GATEWAY_URL", "ACME_UPDATE_URL"],
      inference: {
        provider: "openai-compatible",
        baseUrl: `\${ACME_GATEWAY_URL}`,
      },
      updates: {
        channel: "stable",
        channels: ["stable"],
        source: `\${ACME_UPDATE_URL}`,
      },
    });
    expect(result.status).toBe(0);
    expect(result.stdout).toContain(
      "Runtime variables needed at launch (read from the environment of the process that starts the command, never locked): ACME_GATEWAY_URL",
    );
    expect(result.stdout).toContain(
      "Runtime variables needed only by update: ACME_UPDATE_URL",
    );
    const [launch, update] = result.stderr.split("\n");
    expect(launch).toContain(
      "Note: ACME_GATEWAY_URL not set in this shell; the branded command fails with CONFIG_UNAVAILABLE until it is set",
    );
    expect(launch).not.toContain("ACME_UPDATE_URL");
    expect(launch).toContain("a plain https URL");
    expect(update).toBe(
      "Note: ACME_UPDATE_URL not set in this shell; only update reads it, and update fails until it is set. Launch does not need it.",
    );
  });

  it("prints no variable lines for plain URLs", async () => {
    const result = await validate({});
    expect(result.stdout).not.toContain("Runtime variables");
    expect(result.stderr).toBe("");
  });
});
