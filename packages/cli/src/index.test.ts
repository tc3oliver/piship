import { generateKeyPairSync } from "node:crypto";
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
import { delimiter, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { markLocalBuild, PI_VERSION, shellArg } from "@piship/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  assertPayloadPackageJson,
  installNext,
  lifecycleCommands,
  optionHelp,
  publishSteps,
  rootPublishSteps,
  runCli,
  runtimeCacheLine,
  simpleUsage,
  stagingNotice,
} from "./index.js";

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

  it("shows the release's progress as it comes when someone watches", async () => {
    const { payload } = installRecorder();
    const command = join(payload, "bin", ID);
    writeFileSync(
      command,
      `#!/usr/bin/env node\nprocess.stderr.write("Downloading 1.1.0...\\n" + "progress=" + process.env.PISHIP_PROGRESS + "\\n");\nprocess.stdout.write("Updated\\n");\n`,
    );
    const lines: string[] = [];
    const output = {
      stdout: (message: string) => lines.push(`out:${message}`),
      stderr: (message: string) => lines.push(`err:${message}`),
    };
    process.env.PISHIP_PROGRESS = "1";
    try {
      expect(await runCli(["rollback", ID], output)).toBe(0);
    } finally {
      delete process.env.PISHIP_PROGRESS;
    }
    // stderr lines arrive before the result, each once.
    expect(lines).toEqual([
      "err:Downloading 1.1.0...",
      "err:progress=1",
      "out:Updated",
    ]);
    // Without a terminal the release is not asked for progress.
    lines.length = 0;
    expect(await runCli(["rollback", ID], output)).toBe(0);
    expect(lines).toContain("err:Downloading 1.1.0...\nprogress=undefined");
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
      stderr:
        "Usage: piship repair <id> <archive|release-dir|payload|pack> [--runtime <runtime-archive>]",
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

  it("names a purge command that outlives the uninstall when run from the installed piship.mjs", async () => {
    const { payload } = installRecorder();
    seedState();
    const lines: string[] = [];
    const argv = process.argv;
    process.argv = [argv[0] as string, join(payload, "piship.mjs")];
    try {
      expect(
        await runCli(["uninstall", ID], {
          stdout: (message) => lines.push(message),
          stderr: (message) => lines.push(message),
        }),
      ).toBe(0);
    } finally {
      process.argv = argv;
    }
    expect(existsSync(payload)).toBe(false);
    const text = lines.join("\n");
    expect(text).not.toContain(payload);
    expect(text).toContain(
      `To delete it: node dist/${ID}/piship.mjs purge ${ID} --yes`,
    );
  });

  it("purge accepts --yes and --without-logout in either order, and a second uninstall names it", async () => {
    installRecorder();
    const state = seedState();
    const lines: string[] = [];
    const output = {
      stdout: (message: string) => lines.push(message),
      stderr: (message: string) => lines.push(message),
    };
    expect(await runCli(["uninstall", ID], output)).toBe(0);
    // A second uninstall finds only the state, and names purge.
    lines.length = 0;
    expect(await runCli(["uninstall", ID, "--purge", "--yes"], output)).toBe(1);
    expect(lines.join("\n")).toContain(
      `Its state remains in ${state}; to delete it: `,
    );
    expect(lines.join("\n")).toContain(`purge ${ID} --yes`);
    expect(
      await runCli(["purge", ID, "--without-logout", "--yes"], output),
      lines.join("\n"),
    ).toBe(0);
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
      `Run ${ID} logout first, then uninstall again; or add --without-logout to purge without signing out`,
    );
    expect(existsSync(payload)).toBe(true);
    expect(existsSync(state)).toBe(true);
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
  it("uninstalls while signed in, warning that the sign-in stays live, and without the warning under --without-logout", async () => {
    const identity = (state: string) => {
      mkdirSync(join(state, "identity"), { recursive: true });
      writeFileSync(
        join(state, "identity", "session.json"),
        JSON.stringify({ schema: "piship-identity-metadata/v1" }),
      );
    };
    const run = async (args: string[]) => {
      const out: string[] = [];
      const err: string[] = [];
      const status = await runCli(["uninstall", ID, ...args], {
        stdout: (message) => out.push(message),
        stderr: (message) => err.push(message),
      });
      return { status, out: out.join("\n"), err: err.join("\n") };
    };
    let { payload } = installRecorder();
    const state = seedState();
    identity(state);
    const warned = await run([]);
    expect(warned.status, warned.err).toBe(0);
    expect(warned.out).toContain(`Uninstalled ${ID}.`);
    expect(warned.err).toBe(
      `Warning: ${ID} is still signed in (an identity session); it stays live until it expires. Sign out with the release's own logout (node bin/<command> logout, in the directory that holds the release's piship.mjs) before purge.`,
    );
    expect(existsSync(payload)).toBe(false);
    expect(existsSync(state)).toBe(true);
    rmSync(join(temp, "bin"), { recursive: true, force: true });
    ({ payload } = installRecorder());
    const quiet = await run(["--without-logout"]);
    expect(quiet).toMatchObject({ status: 0, err: "" });
    expect(existsSync(payload)).toBe(false);
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
    runtime: { pi: "1.5.0" },
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

  it("prints the http-allowed and runtime credential refusals unredacted", async () => {
    const v6 = { schema: "piship/v1alpha6" };
    const sandbox = await validate({
      ...v6,
      sandbox: {
        required: true,
        provider: "e2b-compatible",
        endpoint: "http://sandbox.corp.internal:3000",
        credential: "runtime",
        httpTransport: "http-allowed",
      },
    });
    expect(sandbox.status).not.toBe(0);
    expect(sandbox.stderr).toContain(
      "http-allowed cannot be combined with sandbox.credential set to runtime; the runtime credential is never sent to the sandbox over plain HTTP",
    );
    const mcp = await validate({
      ...v6,
      mcp: {
        servers: {
          tickets: {
            transport: "streamable-http",
            url: "http://10.20.30.40/mcp",
            credential: "runtime",
            httpTransport: "http-allowed",
          },
        },
      },
    });
    expect(mcp.status).not.toBe(0);
    expect(mcp.stderr).toContain(
      "http-allowed cannot be combined with the credential field set to runtime",
    );
    for (const output of [sandbox.stderr, mcp.stderr])
      expect(output).not.toContain("[REDACTED]");
  });

  it("admits a plain-HTTP private endpoint by default and warns on one line", async () => {
    const result = await validate({
      schema: "piship/v1alpha6",
      inference: {
        provider: "openai-compatible",
        baseUrl: "http://10.20.30.40:4000/v1",
      },
      audit: {
        sinks: [
          { id: "collector", type: "http", url: "http://10.0.0.6/events" },
        ],
      },
    });
    expect(result.status).toBe(0);
    const lines = result.stderr
      .split("\n")
      .filter((line) => line.startsWith("Warning: network: "));
    expect(lines).toHaveLength(1);
    expect(lines[0]).toContain(
      "Plain HTTP to a private or internal host is admitted by default",
    );
    expect(lines[0]).toContain("inference.baseUrl (the gateway credential");
    expect(lines[0]).toContain("audit.sinks[0].url (audit events");
  });

  it("names httpTransport: https when it refuses a private plain-HTTP endpoint", async () => {
    const result = await validate({
      schema: "piship/v1alpha6",
      inference: {
        provider: "openai-compatible",
        baseUrl: "http://10.20.30.40:4000/v1",
        httpTransport: "https",
      },
    });
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(
      "this endpoint is https-only (inference.httpTransport: https",
    );
  });

  it("refuses a public plain-HTTP endpoint without any setting", async () => {
    const result = await validate({
      schema: "piship/v1alpha6",
      inference: {
        provider: "openai-compatible",
        baseUrl: "http://gateway.acme.example/v1",
      },
    });
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("is public, so serve it over https");
  });

  it("rejects a required MCP server that fails every launch and warns about an optional one", async () => {
    const mcp = (required: boolean) => ({
      mcp: {
        servers: {
          docs: {
            transport: "streamable-http",
            url: "https://mcp.acme.example/mcp",
            required,
          },
        },
      },
    });
    const rejected = await validate(mcp(true));
    expect(rejected.status).not.toBe(0);
    expect(rejected.stdout).not.toContain("Manifest is valid.");
    expect(rejected.stderr).toContain("mcp.servers.docs.url");
    expect(rejected.stderr).toContain("MCP_UNHEALTHY");
    const warned = await validate(mcp(false));
    expect(warned.status).toBe(0);
    expect(warned.stderr).toContain(
      "Warning: mcp.servers.docs.url: mcp.acme.example is not in network.allowHosts",
    );
  });

  it("rejects a managed deny on an unsupported action unless acknowledged, and warns in personal mode", async () => {
    const policy = {
      enforced: [
        { id: "acme.web.deny", action: "web.request", effect: "deny" },
      ],
    };
    const rejected = await validate({ policy });
    expect(rejected.status).not.toBe(0);
    expect(rejected.stdout).not.toContain("Manifest is valid.");
    expect(rejected.stderr).toContain("POLICY_UNENFORCEABLE");
    expect(rejected.stderr).toContain(
      "policy.enforced rule acme.web.deny (deny web.request:**)",
    );
    const acknowledged = await validate({
      schema: "piship/v1alpha6",
      policy: { ...policy, acknowledgeUnenforced: ["web.request:**"] },
    });
    expect(acknowledged.status).toBe(0);
    expect(acknowledged.stdout).toContain("Manifest is valid.");
    expect(acknowledged.stderr).toContain(
      "Note: policy.enforced rule acme.web.deny (deny web.request:**): web.request has no runtime seam in this Pi version, so the rule is neither prevented nor recorded (acknowledged in policy.acknowledgeUnenforced)",
    );
    const manifest = join(temp, "piship.yaml");
    writeFileSync(
      manifest,
      JSON.stringify({
        schema: "piship/v1alpha3",
        app: base.app,
        runtime: base.runtime,
        deployment: { mode: "personal" },
        policy,
      }),
    );
    const stderr: string[] = [];
    const personal = {
      status: await runCli(["validate", manifest], {
        stdout: () => {},
        stderr: (message) => stderr.push(message),
      }),
      stderr: stderr.join("\n"),
    };
    expect(personal.status).toBe(0);
    expect(personal.stderr).toContain(
      "Warning: policy.enforced rule acme.web.deny (deny web.request:**): web.request has no runtime seam",
    );
  });

  it("validate and lock warn, without failing, about a filesystem deny that never matches", async () => {
    const policy = {
      policy: {
        default: "ask",
        enforced: [
          {
            id: "acme.env",
            action: "filesystem.read",
            resource: ".env",
            effect: "deny",
          },
        ],
      },
    };
    const warning =
      "Warning: policy.enforced[0].resource: acme.env (deny filesystem.read) never matches .env: it is relative";
    const result = await validate(policy);
    expect(result.status, result.stderr).toBe(0);
    expect(result.stderr).toContain(warning);
    const manifest = join(temp, "piship.yaml");
    const stderr: string[] = [];
    const locked = await runCli(["lock", manifest], {
      stdout: () => {},
      stderr: (message) => stderr.push(message),
    });
    expect(locked, stderr.join("\n")).toBe(0);
    expect(stderr.join("\n")).toContain(warning);
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

  it("shows policy.userAuto when a v1alpha5 manifest declares it", async () => {
    const allowed = await validate({
      schema: "piship/v1alpha5",
      policy: { userAuto: "allowed" },
    });
    expect(allowed.status).toBe(0);
    expect(allowed.stdout).toContain(
      "policy.userAuto: allowed (each user may switch on auto mode",
    );
    const off = await validate({
      schema: "piship/v1alpha5",
      policy: { userAuto: "off" },
    });
    expect(off.stdout).toContain("policy.userAuto: off (users cannot");
    expect((await validate({})).stdout).not.toContain("userAuto");
    const older = await validate({ policy: { userAuto: "allowed" } });
    expect(older.status).not.toBe(0);
    expect(older.stderr).toContain("policy.userAuto");
  });

  it("warns about an unused variable and still validates", async () => {
    const result = await validate({ variables: ["ACME_UNUSED"] });
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("Manifest is valid.");
    expect(result.stdout).not.toContain("Runtime variables");
    expect(result.stderr).toContain(
      "Warning: variables[0]: ACME_UNUSED is declared but not referenced",
    );
    // lock prints the same warnings validate does.
    const stderr: string[] = [];
    const locked = await runCli(["lock", join(temp, "piship.yaml")], {
      stdout: () => {},
      stderr: (message) => stderr.push(message),
    });
    expect(locked, stderr.join("\n")).toBe(0);
    expect(stderr.join("\n")).toContain(
      "Warning: variables[0]: ACME_UNUSED is declared but not referenced",
    );
  });

  it("prints no variable lines for plain URLs", async () => {
    const result = await validate({});
    expect(result.stdout).not.toContain("Runtime variables");
    expect(result.stderr).toBe("");
  });
});

describe("help", () => {
  async function run(args: string[]) {
    const stdout: string[] = [];
    const stderr: string[] = [];
    const status = await runCli(args, {
      stdout: (message) => stdout.push(message),
      stderr: (message) => stderr.push(message),
    });
    return { status, stdout: stdout.join("\n"), stderr: stderr.join("\n") };
  }

  it("summarizes every command in the top-level help", async () => {
    const result = await run(["--help"]);
    expect(result.status).toBe(0);
    expect(result.stdout).toMatch(/^ {2}validate\s+Check a manifest/m);
    expect(result.stdout).toContain("piship <command> --help");
  });

  it("asks to add the bin directory to PATH only when it is not there", async () => {
    const bin = join(tmpdir(), "piship-help-bin");
    vi.stubEnv("PISHIP_BIN_HOME", bin);
    try {
      vi.stubEnv("PATH", "/usr/bin");
      expect((await run(["--help"])).stdout).toContain(
        `Install defaults: ${bin} (add to PATH yourself)`,
      );
      vi.stubEnv("PATH", `/usr/bin${delimiter}${bin}`);
      expect((await run(["--help"])).stdout).not.toContain("add to PATH");
    } finally {
      vi.unstubAllEnvs();
    }
  });

  it.each([
    ["validate", "validate [<manifest>]"],
    ["install", "install <artifact|release-dir|archive|pack>"],
    ["doctor", "doctor <artifact|id>"],
    ["config", "config explain <manifest|artifact|id> [--json]"],
    ["update", "update <id>"],
    ["keygen", "keygen <private-key-file> --id <key-id>"],
  ])(
    "prints usage for %s --help instead of reading a file named --help",
    async (command, usage) => {
      for (const args of [
        [command, "--help"],
        [command, "-h"],
        [command, "explain", "--help"],
      ]) {
        const result = await run(args);
        expect(result.status).toBe(0);
        expect(result.stdout).toContain(`Usage: piship ${usage}`);
        expect(result.stderr).toBe("");
      }
    },
  );

  it("lists the install-time digest and key checks", async () => {
    const result = await run(["install", "--help"]);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("[--sha256 <hex>]");
    expect(result.stdout).toContain("[--expect-key sha256:<fingerprint>]...");
    expect(result.stdout).toContain("[--use-existing-state]");
  });

  it("lists every option of every command with a description", async () => {
    const optionsIn = (text: string) =>
      new Set(text.match(/--[a-z][a-z0-9-]*/g) ?? []);
    for (const command of [
      ...Object.keys(simpleUsage),
      ...Object.keys(lifecycleCommands),
    ]) {
      const usage = lifecycleCommands[command]?.usage ?? simpleUsage[command];
      // The usage line, the help table and the parser name the same options.
      const documented = optionsIn(
        Object.keys(optionHelp[command] ?? {}).join(" "),
      );
      expect(documented, command).toEqual(optionsIn(usage ?? ""));
      const spec = lifecycleCommands[command];
      if (spec)
        for (const flag of [
          ...spec.values,
          ...spec.flags,
          ...(spec.repeated ?? []),
        ])
          expect(documented, `${command} ${flag}`).toContain(flag);
      const help = (await run([command, "--help"])).stdout;
      for (const [name, text] of Object.entries(optionHelp[command] ?? {}))
        expect(help, `${command} ${name}`).toMatch(
          new RegExp(
            `^ {2}${name.replace(/[|\\^$.*+?()[\]{}]/g, "\\$&")} +${text.slice(0, 12)}`,
            "m",
          ),
        );
    }
  });

  it("answers piship help and piship help <command> like --help", async () => {
    expect(await run(["help"])).toEqual(await run(["--help"]));
    expect(await run(["help", "build"])).toEqual(
      await run(["build", "--help"]),
    );
    expect((await run(["help", "build"])).stdout).toContain("--rebuild");
  });
});

describe("argument errors", () => {
  async function run(args: string[]) {
    const stderr: string[] = [];
    const status = await runCli(args, {
      stdout: () => {},
      stderr: (m) => stderr.push(m),
    });
    return { status, stderr: stderr.join("\n") };
  }

  it.each([
    [
      ["build", "m.yaml", "--bogus"],
      "Unknown option --bogus for build.\nUsage: piship build ",
    ],
    [
      ["init", "d", "--bogus"],
      "Unknown option --bogus for init.\nUsage: piship init ",
    ],
    [
      ["validate", "a", "b"],
      "validate takes at most 1 argument.\nUsage: piship validate ",
    ],
    [
      ["release", "m.yaml", "--out"],
      "--out needs a value.\nUsage: piship release ",
    ],
    [
      ["install", "a", "--nope"],
      "Unknown option --nope for install.\nUsage: piship install ",
    ],
  ])("names what %j got wrong before the usage", async (args, expected) => {
    const result = await run(args);
    expect(result.status).toBe(2);
    expect(result.stderr.startsWith(expected)).toBe(true);
  });

  it("prints only the usage when nothing specific is wrong", async () => {
    expect((await run(["doctor"])).stderr).toMatch(/^Usage: piship doctor /);
  });

  it("reads options before the positional argument", async () => {
    for (const args of [
      ["build", "--bogus", "m.yaml"],
      ["build", "--json", "m.yaml"],
    ]) {
      const result = await run(args);
      expect(result.status).toBe(2);
      expect(result.stderr).toMatch(
        /^Unknown option --(bogus|json) for build\./,
      );
    }
  });

  it("says when there is no ./piship.yaml to default to", async () => {
    const result = await run(["dev", "--smoke"]);
    expect(result.status).toBe(2);
    expect(result.stderr).toMatch(/^No piship.yaml in this directory; /);
  });

  it("suggests the command a typo meant", async () => {
    const typo = await run(["int"]);
    expect(typo.status).toBe(2);
    expect(typo.stderr).toMatch(/^Unknown command: int\. Did you mean init\? /);
    expect((await run(["zzzzzz"])).stderr).not.toContain("Did you mean");
  });

  it("points a command only the built distribution has at it", async () => {
    const policy = await run(["policy", "explain", "shell.execute", "ls"]);
    expect(policy.status).toBe(2);
    expect(policy.stderr).toBe(
      "policy is a command of the built distribution, not of piship. Run dist/<id>/bin/<command> policy from the directory you built in, or <command> policy once it is installed.",
    );
    expect((await run(["login"])).stderr).toMatch(/^login is a command of/);
  });
});

describe("the first-run journey from the directory above the source", () => {
  const saved = { ...process.env };
  const cwd = process.cwd();
  async function run(args: string[]) {
    const stdout: string[] = [];
    const stderr: string[] = [];
    const status = await runCli(args, {
      stdout: (m) => stdout.push(m),
      stderr: (m) => stderr.push(m),
    });
    return { status, stdout: stdout.join("\n"), stderr: stderr.join("\n") };
  }
  beforeEach(async () => {
    temp = mkdtempSync(join(tmpdir(), "piship-cli-journey-"));
    process.env.PISHIP_INSTALL_HOME = join(temp, "install");
    process.env.PISHIP_STATE_HOME = join(temp, "state");
    process.env.PISHIP_BIN_HOME = join(temp, "bin");
    process.chdir(temp);
    expect((await run(["init", "my-agent"])).status).toBe(0);
  });
  afterEach(() => {
    process.chdir(cwd);
    process.env = { ...saved };
    rmSync(temp, { recursive: true, force: true });
  });

  it("takes the source directory, or ./piship.yaml, as the manifest", async () => {
    const validated = await run(["validate", "my-agent"]);
    expect(validated.status).toBe(0);
    expect(validated.stdout).toMatch(/^Next: .* test .*piship\.yaml"? /m);
    process.chdir("my-agent");
    expect((await run(["validate"])).status).toBe(0);
  });

  it("refuses an interactive dev without a terminal before locking or building", async () => {
    // Vitest workers run without a terminal.
    const result = await run(["dev", "my-agent"]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("dev starts the interactive session");
    expect(result.stderr).toMatch(/ dev .*piship\.yaml"? --smoke /);
    expect(result.stderr).not.toContain("Pi launch failed");
    expect(existsSync(join("my-agent", "piship.lock"))).toBe(false);
  });

  it("points a first lock at test and a relock at diff", async () => {
    const first = await run(["lock", "my-agent"]);
    expect(first.status).toBe(0);
    expect(first.stdout).not.toContain("diff");
    expect(first.stdout).toMatch(/^Next: .* test .* build /m);
    const again = await run(["lock", "my-agent"]);
    // Nothing installed: lock overwrote the only earlier lock there was.
    expect(again.stdout).not.toContain("diff");
    expect(again.stdout).toMatch(/^Next: .* test /m);
  });

  it("points a relock of an installed distribution at diff against the install", async () => {
    expect((await run(["init", ID])).status).toBe(0);
    expect((await run(["lock", ID])).status).toBe(0);
    installRecorder();
    const again = await run(["lock", ID]);
    expect(again.stdout).toMatch(
      new RegExp(`^Next: piship diff ${ID} \\S*piship\\.lock"? reviews`, "m"),
    );
  });

  it("diff of a bare id naming a source directory too reads the install, and says so", async () => {
    mkdirSync(join(temp, ID));
    writeFileSync(
      join(temp, ID, "piship.yaml"),
      readFileSync(join(temp, "my-agent", "piship.yaml")),
    );
    installRecorder();
    const result = await run(["diff", ID, "my-agent"]);
    expect(result.stderr).toContain(
      `Note: diff reads the installed ${ID}, not the source directory of that name`,
    );
  });

  it.each(["doctor", "install"])(
    "%s of the source directory says to build it, not that it is damaged",
    async (command) => {
      const result = await run([command, "my-agent"]);
      expect(result.status).toBe(1);
      expect(result.stderr).not.toContain("INTEGRITY_FAILED");
      expect(result.stderr).toContain(
        `my-agent is the source of a distribution (it holds piship.yaml), not a built one. Build it with piship build my-agent, then run piship ${command} ${shellArg(join("dist", "my-agent"))}.`,
      );
    },
  );

  it.each([["doctor"], ["inspect"], ["config", "explain"]])(
    "%s of a bare id naming a source directory too reads the install, and says so",
    async (...command) => {
      mkdirSync(join(temp, ID));
      writeFileSync(
        join(temp, ID, "piship.yaml"),
        readFileSync(join(temp, "my-agent", "piship.yaml")),
      );
      installRecorder();
      const result = await run([...command, ID]);
      expect(result.stderr).not.toContain("is the source of a distribution");
      expect(result.stderr).toContain(
        `Note: ${command[0]} reads the installed ${ID}, not the source directory of that name`,
      );
      // The source's manifest by path is still the source.
      if (command[0] !== "doctor")
        expect(
          (await run([...command, join(ID, "piship.yaml")])).stderr,
        ).not.toContain("reads the installed");
    },
  );

  it("names the manifest's id when a path is given for an id", async () => {
    const result = await run([
      "purge",
      join("my-agent", "piship.yaml"),
      "--yes",
    ]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(
      "is a path, not a distribution id; pass the distribution id (app.id in piship.yaml), here my-agent",
    );
    expect(result.stderr).not.toContain("use my-agent");
  });
});

describe("file system errors", () => {
  beforeEach(() => {
    temp = mkdtempSync(join(tmpdir(), "piship-cli-fs-"));
  });
  afterEach(() => {
    rmSync(temp, { recursive: true, force: true });
  });
  async function run(args: string[]) {
    const stderr: string[] = [];
    const status = await runCli(args, {
      stdout: () => {},
      stderr: (message) => stderr.push(message),
    });
    return { status, stderr: stderr.join("\n") };
  }

  it.each([
    "",
    "null",
    "[]",
    "{",
    '{"schema":"piship-lock/v1"}',
    '{"schema":"piship-lock/v1","app":5,"runtime":{}}',
    '{"schema":"piship-lock/v1","app":{"command":"a-"},"runtime":{},"resources":[]}',
    '{"schema":"piship-lock/v1","app":{"command":"a"},"runtime":{},"resources":[{"path":"../x"}]}',
    '{"schema":"piship-lock/v1","app":{"command":"a"},"runtime":{}}',
    "\u0000\u0001\u0002 binary",
  ])(
    "names a damaged lock file instead of failing inside it: %j",
    async (content) => {
      const path = join(temp, "broken.lock");
      writeFileSync(path, content);
      const result = await run(["diff", path, path]);
      expect(result.status).toBe(1);
      expect(result.stderr).toContain("LOCK_INVALID");
      expect(result.stderr).toContain(path);
      expect(result.stderr).toContain("Action:");
      expect(result.stderr).not.toMatch(
        /Cannot read properties|Unexpected (token|end)|is not valid JSON/,
      );
    },
  );

  it.each([
    [
      '{"schema":"piship-lock/v1","app":{"command":"a-"},"runtime":{},"resources":[]}',
      "app.command",
    ],
    [
      '{"schema":"piship-lock/v1","app":{"command":"a"},"runtime":{},"resources":[{"path":"../x"}]}',
      "resource path",
    ],
  ])("names the unsafe field of a lock file: %j", async (content, field) => {
    const path = join(temp, "unsafe.lock");
    writeFileSync(path, content);
    const result = await run(["diff", path, path]);
    expect(result.stderr).toContain(
      `${path} is not a piship.lock this PiShip can read: it has an unsafe ${field}\n`,
    );
  });

  it.skipIf(process.platform === "win32" || process.getuid?.() === 0)(
    "says a resource directory cannot be read, not that it does not exist",
    async () => {
      const directory = join(temp, "agent");
      await runCli(["init", directory], { stdout: () => {}, stderr: () => {} });
      const resources = join(directory, "resources");
      chmodSync(resources, 0o000);
      try {
        const result = await run(["validate", join(directory, "piship.yaml")]);
        expect(result.status).toBe(1);
        expect(result.stderr).toContain("cannot be read (EACCES)");
        expect(result.stderr).not.toContain("does not exist");
      } finally {
        chmodSync(resources, 0o755);
      }
    },
  );

  it.each(["", "null", "[]", "{", "\u0001binary"])(
    "answers a damaged payload package.json (%j) with the repair line before Node can fail on it",
    (content) => {
      writeFileSync(join(temp, "package.json"), content);
      expect(() => assertPayloadPackageJson(temp)).toThrow(
        expect.objectContaining({
          code: "INTEGRITY_FAILED",
          userAction: expect.stringContaining("piship repair"),
        }),
      );
    },
  );

  it("accepts an intact payload package.json and leaves a missing one to Node", () => {
    writeFileSync(join(temp, "package.json"), '{"type":"module"}');
    expect(() => assertPayloadPackageJson(temp)).not.toThrow();
    rmSync(join(temp, "package.json"));
    expect(() => assertPayloadPackageJson(temp)).not.toThrow();
  });

  it("names a directory passed as a manifest and the file to pass", async () => {
    for (const command of ["validate", "migrate"]) {
      const result = await run([command, temp]);
      expect(result.status).toBe(1);
      expect(result.stderr).toContain(
        `CONFIG_INVALID: ${temp} is a directory where a file was expected (EISDIR`,
      );
      expect(result.stderr).toContain(
        `Action: Pass the manifest file, such as ${join(temp, "piship.yaml")}`,
      );
    }
  });

  it("refuses an expected archive digest for a directory, with an action", async () => {
    const result = await run(["install", temp, "--sha256", "a".repeat(64)]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(
      `CONFIG_INVALID: --sha256 checks a release archive, but ${temp} is a directory`,
    );
    expect(result.stderr).toContain("Action: Install the release .tar.gz");
  });

  it("warns before installing a local build, and verify-release names it unqualified", async () => {
    const build = join(temp, "dist", "mypi");
    mkdirSync(join(build, "metadata"), { recursive: true });
    writeFileSync(join(build, "metadata", "inventory.json"), "{}\n");
    const installed = await run(["install", build]);
    expect(installed.stderr).toContain(
      `Warning: ${build} is an unqualified local build, not a release`,
    );
    const verified = await run(["verify-release", build]);
    expect(verified.status).toBe(1);
    expect(verified.stderr).toContain("unqualified local build, not a release");
    expect(verified.stderr).toContain("Action: Run piship release");
    // A build made on this machine said what it is when it was built; the
    // install that follows does not say it again.
    markLocalBuild(build);
    expect((await run(["install", build])).stderr).not.toContain(
      "unqualified local build",
    );
    // A marker that names another machine is a payload someone copied here.
    writeFileSync(
      `${build}.piship-qualification.json`,
      JSON.stringify({
        schema: "piship-qualification/v1",
        qualification: "unqualified-local",
        host: "another-machine.invalid",
      }),
    );
    expect((await run(["install", build])).stderr).toContain(
      "unqualified local build, not a release",
    );
    // A directory that is no build at all gets no such warning.
    const other = join(temp, "other");
    mkdirSync(other);
    expect((await run(["install", other])).stderr).not.toContain("Warning:");
  });

  it("warns that a local archive's channel signature was not verified, unless its digest is pinned", async () => {
    const archive = join(temp, "copied.tar.gz");
    writeFileSync(archive, "not an archive");
    const previous = process.env.PISHIP_INSTALL_HOME;
    process.env.PISHIP_INSTALL_HOME = join(temp, "install-home");
    try {
      const unchecked = await run(["install", archive]);
      expect(unchecked.status).toBe(1);
      expect(
        unchecked.stderr
          .split("\n")
          .filter((line) => line.includes("no channel signature was verified")),
      ).toEqual([
        `Warning: ${archive} is a local archive, so no channel signature was verified for it. Pass --sha256 with the digest its publisher printed (and --expect-key) to check it; later updates through the installed command's update verify the signed channel.`,
      ]);
      const pinned = await run([
        "install",
        archive,
        "--sha256",
        "a".repeat(64),
      ]);
      expect(pinned.stderr).not.toContain("channel signature");
      // A directory is no copied archive, and a missing path is not either.
      expect((await run(["install", temp])).stderr).not.toContain(
        "channel signature",
      );
      expect(
        (await run(["install", join(temp, "missing")])).stderr,
      ).not.toContain("channel signature");
    } finally {
      if (previous === undefined) delete process.env.PISHIP_INSTALL_HOME;
      else process.env.PISHIP_INSTALL_HOME = previous;
    }
  });

  it("refuses malformed install checks before touching the source", async () => {
    const missing = join(temp, "missing");
    const digest = await run(["install", missing, "--sha256", "xyz"]);
    expect(digest.status).toBe(1);
    expect(digest.stderr).toContain("64 hexadecimal characters");
    const key = await run([
      "install",
      missing,
      "--expect-key",
      `sha256:${"a".repeat(64)}`,
      "--expect-key",
      "not-a-fingerprint",
    ]);
    expect(key.status).toBe(1);
    expect(key.stderr).toContain("not-a-fingerprint");
    expect(key.stderr).toContain("sha256:<64 hexadecimal characters>");
    expect((await run(["install", missing, "--sha256"])).status).toBe(2);
  });

  it("names a missing install source and what install accepts", async () => {
    const missing = join(temp, "missing");
    const result = await run(["install", missing]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(
      `CONFIG_INVALID: ${missing} does not exist (ENOENT`,
    );
    expect(result.stderr).toContain("Action: Pass the artifact directory");
  });

  it("refuses to overwrite a key with an action instead of EEXIST", async () => {
    const key = join(temp, "signing.pem");
    expect((await run(["keygen", key, "--id", "k1"])).status).toBe(0);
    const before = readFileSync(key, "utf8");
    const result = await run(["keygen", key, "--id", "k1"]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(
      `CONFIG_INVALID: ${key} already exists (EEXIST`,
    );
    expect(result.stderr).toContain("Action: keygen never overwrites a key");
    expect(readFileSync(key, "utf8")).toBe(before);
  });

  it("shows an existing key's public key in --add-key form without touching it", async () => {
    const key = join(temp, "signing.pem");
    const run = async (args: string[]) => {
      const stdout: string[] = [];
      const status = await runCli(args, {
        stdout: (message) => stdout.push(message),
        stderr: () => {},
      });
      return { status, stdout: stdout.join("\n") };
    };
    const made = await run(["keygen", key, "--id", "k1"]);
    const publicKey = /^Public key: (\S+)$/m.exec(made.stdout)?.[1];
    expect(publicKey).toBeTruthy();
    const before = readFileSync(key, "utf8");
    const shown = await run(["keygen", key, "--id", "k2", "--show-public"]);
    expect(shown.status).toBe(0);
    expect(shown.stdout).toContain(`Public key: ${publicKey}`);
    expect(shown.stdout).toContain(`--add-key k2=${publicKey}`);
    expect(shown.stdout).not.toContain("PRIVATE KEY");
    expect(readFileSync(key, "utf8")).toBe(before);
    const mixed = await run([
      "keygen",
      key,
      "--id",
      "k2",
      "--show-public",
      "--encrypt",
    ]);
    expect(mixed.status).toBe(1);
    expect(readFileSync(key, "utf8")).toBe(before);
  });
});

describe("signing key passphrases", () => {
  const SECRET = "hunter2-cli-passphrase-sentinel";
  beforeEach(() => {
    temp = mkdtempSync(join(tmpdir(), "piship-cli-passphrase-"));
    // No terminal: a passphrase must come from a named channel.
    vi.spyOn(process, "stdin", "get").mockReturnValue({
      isTTY: false,
    } as unknown as typeof process.stdin);
  });
  afterEach(() => {
    vi.restoreAllMocks();
    delete process.env.PISHIP_TEST_SIGNING_PASSPHRASE;
    rmSync(temp, { recursive: true, force: true });
  });
  async function run(args: string[]) {
    const stdout: string[] = [];
    const stderr: string[] = [];
    const status = await runCli(args, {
      stdout: (message) => stdout.push(message),
      stderr: (message) => stderr.push(message),
    });
    return { status, stdout: stdout.join("\n"), stderr: stderr.join("\n") };
  }
  const signChannel = (key: string, ...extra: string[]) =>
    run([
      "sign-channel",
      join(temp, "channel"),
      join(temp, "missing.tar.gz"),
      "--channel",
      "stable",
      "--key",
      key,
      "--key-id",
      "k1",
      ...extra,
    ]);

  it("never accepts the passphrase as a command-line value", async () => {
    const key = join(temp, "signing.pem");
    for (const args of [
      ["--passphrase", SECRET],
      [`--passphrase=${SECRET}`],
      [
        "--passphrase-env",
        "PISHIP_TEST_SIGNING_PASSPHRASE",
        "--passphrase",
        SECRET,
      ],
    ]) {
      const result = await signChannel(key, ...args);
      expect(result.status).toBe(2);
      expect(`${result.stdout}${result.stderr}`).not.toContain(SECRET);
    }
    const keygen = await run([
      "keygen",
      key,
      "--id",
      "k1",
      "--encrypt",
      "--passphrase",
      SECRET,
    ]);
    expect(keygen.status).toBe(2);
    expect(existsSync(key)).toBe(false);
    // A value given where the variable name belongs is refused unechoed.
    const named = await signChannel(key, "--passphrase-env", `${SECRET}!`);
    expect(named.status).toBe(1);
    expect(`${named.stdout}${named.stderr}`).not.toContain(SECRET);
  });

  it("writes an encrypted key and fails closed without its passphrase", async () => {
    const key = join(temp, "signing.pem");
    process.env.PISHIP_TEST_SIGNING_PASSPHRASE = SECRET;
    const keygen = await run([
      "keygen",
      key,
      "--id",
      "k1",
      "--encrypt",
      "--passphrase-env",
      "PISHIP_TEST_SIGNING_PASSPHRASE",
    ]);
    expect(keygen.status).toBe(0);
    expect(readFileSync(key, "utf8")).toMatch(
      /^-----BEGIN ENCRYPTED PRIVATE KEY-----\n/,
    );
    const shown = await run([
      "keygen",
      key,
      "--id",
      "k1",
      "--show-public",
      "--passphrase-env",
      "PISHIP_TEST_SIGNING_PASSPHRASE",
    ]);
    expect(shown.status).toBe(0);
    expect(shown.stdout).toContain(
      /^Public key: .+$/m.exec(keygen.stdout)?.[0] as string,
    );
    expect(`${shown.stdout}${shown.stderr}`).not.toContain(SECRET);
    const pem = readFileSync(key, "utf8");
    const body = pem
      .split("\n")
      .filter((line) => line && !line.startsWith("-"));
    // No terminal and no channel: refused before any archive is read.
    const none = await signChannel(key);
    expect(none.status).toBe(1);
    expect(none.stderr).toContain("CREDENTIAL_REQUIRED");
    expect(none.stderr).toContain("no terminal is attached");
    process.env.PISHIP_TEST_SIGNING_PASSPHRASE = `${SECRET}-wrong`;
    const wrong = await signChannel(
      key,
      "--passphrase-env",
      "PISHIP_TEST_SIGNING_PASSPHRASE",
    );
    expect(wrong.status).toBe(1);
    expect(wrong.stderr).toContain(
      "INTEGRITY_FAILED: Signing key could not be decrypted",
    );
    process.env.PISHIP_TEST_SIGNING_PASSPHRASE = SECRET;
    // The right passphrase gets past the key to the missing archive.
    const right = await signChannel(
      key,
      "--passphrase-env",
      "PISHIP_TEST_SIGNING_PASSPHRASE",
    );
    expect(right.status).toBe(1);
    expect(right.stderr).not.toContain("Signing key");
    for (const result of [keygen, none, wrong, right]) {
      const text = `${result.stdout}${result.stderr}`;
      expect(text).not.toContain(SECRET);
      for (const line of body) expect(text).not.toContain(line);
    }
    expect(existsSync(join(temp, "channel"))).toBe(false);
    // --passphrase-* without --encrypt is a mistake, not a plaintext key.
    const plain = await run([
      "keygen",
      join(temp, "plain.pem"),
      "--id",
      "k1",
      "--passphrase-env",
      "PISHIP_TEST_SIGNING_PASSPHRASE",
    ]);
    expect(plain.status).toBe(1);
    expect(existsSync(join(temp, "plain.pem"))).toBe(false);
  });

  it("pairs each sign-channel --key with a --key-id", async () => {
    const result = await signChannel(join(temp, "a.pem"), "--key", "b.pem");
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("Give one --key-id for each --key");
  });

  it("creates a bootstrap root and publishes the next root with an encrypted root key", async () => {
    process.env.PISHIP_TEST_SIGNING_PASSPHRASE = SECRET;
    const rootKey = join(temp, "root.pem");
    const keygen = await run([
      "keygen",
      rootKey,
      "--id",
      "root-a",
      "--encrypt",
      "--passphrase-env",
      "PISHIP_TEST_SIGNING_PASSPHRASE",
    ]);
    expect(keygen.status).toBe(0);
    const publicKey = /Public key: (\S+)/.exec(keygen.stdout)?.[1] as string;
    const channel = await run([
      "keygen",
      join(temp, "channel.pem"),
      "--id",
      "channel-a",
    ]);
    const channelKey = /Public key: (\S+)/.exec(channel.stdout)?.[1] as string;
    const next = await run([
      "keygen",
      join(temp, "next.pem"),
      "--id",
      "channel-b",
    ]);
    const nextKey = /Public key: (\S+)/.exec(next.stdout)?.[1] as string;
    const init = await run([
      "trust-root",
      "init",
      "--key",
      `root-a=${publicKey}`,
      "--key",
      `channel-a=${channelKey}`,
      "--root-keys",
      "root-a",
      "--channel-keys",
      "channel-a",
      "--expires-days",
      "365",
    ]);
    expect(init.status).toBe(0);
    expect(init.stdout).toContain("    bootstrap:\n      version: 1\n");
    expect(init.stdout).toContain(
      "If piship.yaml already has an updates: block, put the trust: block under it",
    );
    mkdirSync(join(temp, "project", "resources"), { recursive: true });
    writeFileSync(join(temp, "project", "resources", "AGENTS.md"), "# Acme\n");
    const yaml = (/^(updates:\n[\s\S]*?)\n\n/m.exec(init.stdout)?.[1] ??
      "") as string;
    writeFileSync(
      join(temp, "project", "piship.yaml"),
      `schema: piship/v1alpha5\napp:\n  id: acmepi\n  name: AcmePi\n  command: acmepi\n  version: 1.0.0\nruntime:\n  pi: "1.5.0"\ndeployment:\n  mode: personal\nresources:\n  instructions:\n    user: [./resources/AGENTS.md]\n${yaml}\n`,
    );
    const args = [
      "trust-root",
      "next",
      join(temp, "updates"),
      "--manifest",
      join(temp, "project", "piship.yaml"),
      "--add-key",
      `channel-b=${nextKey}`,
      "--remove-key",
      "channel-a",
      "--channel-keys",
      "channel-b",
      "--expires-days",
      "90",
      "--sign",
      `root-a=${rootKey}`,
    ];
    // Without the passphrase nothing is written.
    const refused = await run(args);
    expect(refused.status).toBe(1);
    expect(refused.stderr).toContain("CREDENTIAL_REQUIRED");
    expect(existsSync(join(temp, "updates"))).toBe(false);
    const published = await run([
      ...args,
      "--passphrase-env",
      "PISHIP_TEST_SIGNING_PASSPHRASE",
    ]);
    expect(published.stderr).toBe("");
    expect(published.status).toBe(0);
    expect(published.stdout).toContain("root 1 -> 2");
    const root = JSON.parse(
      readFileSync(join(temp, "updates", "root", "2.json"), "utf8"),
    );
    expect(root).toMatchObject({
      schema: "piship-update-root/v1",
      distribution: "acmepi",
      version: 2,
      roles: { channel: { keyIds: ["channel-b"], threshold: 1 } },
    });
    expect(existsSync(join(temp, "updates", "root", "2.json.sig"))).toBe(true);
    for (const result of [keygen, init, refused, published])
      expect(`${result.stdout}${result.stderr}`).not.toContain(SECRET);
  });
});

describe("inspect", () => {
  const manifest = fileURLToPath(
    new URL("../../../examples/demo-company/piship.yaml", import.meta.url),
  );
  async function inspect(args: string[]) {
    const stdout: string[] = [];
    const status = await runCli(["inspect", manifest, ...args], {
      stdout: (message) => stdout.push(message),
      stderr: () => {},
    });
    return { status, stdout: stdout.join("\n") };
  }

  it("prints a human summary by default", async () => {
    const result = await inspect([]);
    expect(result.status).toBe(0);
    expect(result.stdout).toMatch(/^\S.* \(\S+, command \S+\)$/m);
    expect(result.stdout).toMatch(/^ {2}mode\s+managed$/m);
    expect(result.stdout).toMatch(/^ {2}policy\s+\S+@\d+/m);
    expect(result.stdout).toContain("--json for the full locked configuration");
    expect(() => JSON.parse(result.stdout)).toThrow();
  });

  it("keeps the full JSON behind --json", async () => {
    const result = await inspect(["--json"]);
    expect(result.status).toBe(0);
    const info = JSON.parse(result.stdout);
    expect(info.deployment.mode).toBe("managed");
    expect(info.access).toBeDefined();
    expect(info.governance).toBeDefined();
    expect(info.trust).toEqual({ keys: [] });
    expect(typeof info.state).toBe("string");
  });

  it("names the pinned update keys in the human summary", async () => {
    const result = await inspect([]);
    expect(result.stdout).toMatch(/^ {2}trust\s+no pinned update keys$/m);
  });

  it("verifies a release archive instead of reading it as a manifest", async () => {
    const directory = mkdtempSync(join(tmpdir(), "piship-cli-inspect-"));
    try {
      const archive = join(directory, "a-1.0.0-darwin-arm64.tar.gz");
      writeFileSync(archive, `\u0000\u001b[31m${"binary: : [".repeat(5000)}`);
      const stderr: string[] = [];
      const status = await runCli(["inspect", archive], {
        stdout: () => {},
        stderr: (message) => stderr.push(message),
      });
      expect(status).toBe(1);
      const text = stderr.join("\n");
      expect(text).not.toContain("YAML");
      expect(text).not.toContain("binary: :");
      expect(text.length).toBeLessThan(2000);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("diff reads a source directory's piship.yaml, not a payload", async () => {
    const stdout: string[] = [];
    const stderr: string[] = [];
    const status = await runCli(["diff", manifest, dirname(manifest)], {
      stdout: (message) => stdout.push(message),
      stderr: (message) => stderr.push(message),
    });
    expect(stderr.join("\n")).not.toContain("inventory.json");
    expect(status).toBe(0);
    expect(stdout.join("\n")).toContain("No release-impact changes.");
  });
});

describe("init", () => {
  beforeEach(() => {
    temp = mkdtempSync(join(tmpdir(), "piship-cli-init-"));
  });
  afterEach(() => {
    rmSync(temp, { recursive: true, force: true });
  });

  it("ends with the next command to run", async () => {
    const stdout: string[] = [];
    const directory = join(temp, "agent");
    expect(
      await runCli(["init", directory], {
        stdout: (message) => stdout.push(message),
        stderr: () => {},
      }),
    ).toBe(0);
    const manifest = join(directory, "piship.yaml");
    expect(stdout.join("\n")).toBe(
      `Created ${manifest}\nNext: piship validate ${shellArg(manifest)}, then piship test ${shellArg(manifest)} (the first test writes piship.lock; build and release need that lock to be current).`,
    );
  });

  it.each(["con", "nul", "com3", "a".repeat(65)])(
    "init refuses the id %s, which validate would refuse too",
    async (id) => {
      const stderr: string[] = [];
      const status = await runCli(["init", join(temp, "idtest"), "--id", id], {
        stdout: () => {},
        stderr: (message) => stderr.push(message),
      });
      expect(status).toBe(1);
      expect(stderr.join("\n")).toMatch(/cannot be a distribution id/);
      expect(existsSync(join(temp, "idtest"))).toBe(false);
    },
  );

  it("keeps the build output out of git", async () => {
    const directory = join(temp, "ignored");
    await runCli(["init", directory], { stdout: () => {}, stderr: () => {} });
    expect(readFileSync(join(directory, ".gitignore"), "utf8")).toBe("dist/\n");
    // The lock holds byte digests, so a Windows checkout must not turn LF into CRLF.
    expect(readFileSync(join(directory, ".gitattributes"), "utf8")).toBe(
      "* text=auto eol=lf\n",
    );
  });

  it("puts a missing resource at its line in the manifest", async () => {
    const directory = join(temp, "located");
    await runCli(["init", directory], { stdout: () => {}, stderr: () => {} });
    rmSync(join(directory, "resources", "AGENTS.md"));
    const stderr: string[] = [];
    const status = await runCli(["validate", join(directory, "piship.yaml")], {
      stdout: () => {},
      stderr: (message) => stderr.push(message),
    });
    expect(status).toBe(1);
    expect(stderr.join("\n")).toMatch(
      /missing resource at resources\.instructions\.user\[0\] \(line \d+, column \d+\)/,
    );
  });

  it("names the real command when it runs from bin.js", async () => {
    const original = process.argv[1];
    process.argv[1] = join(temp, "my dir", "bin.js");
    try {
      const result = await run(["init", join(temp, "agent")]);
      expect(result.stdout).toContain(
        `Next: node ${shellArg(join(temp, "my dir", "bin.js"))} validate `,
      );
      expect(result.stdout).not.toContain("Next: piship");
    } finally {
      process.argv[1] = original as string;
    }
  });

  it("refuses a directory name that is no distribution id and suggests one", async () => {
    for (const [name, id] of [
      ["my_agent", "my-agent"],
      ["agent.v2", "agent-v2"],
      ["2fast", "app-2fast"],
    ] as const) {
      const directory = join(temp, name);
      const result = await run(["init", directory]);
      expect(result.status).toBe(1);
      expect(result.stderr).toContain(`not a valid distribution id`);
      expect(result.stderr).toContain(`init ${shellArg(directory)} --id ${id}`);
      expect(existsSync(directory)).toBe(false);
    }
  });

  it("takes the distribution id from --id instead of the directory name", async () => {
    const directory = join(temp, "my_agent");
    const result = await run(["init", directory, "--id", "my-agent"]);
    expect(result.status).toBe(0);
    const text = readFileSync(join(directory, "piship.yaml"), "utf8");
    expect(text).toContain("  id: my-agent\n");
    expect(text).toContain("  command: my-agent\n");
    expect(
      (await run(["validate", join(directory, "piship.yaml")])).status,
    ).toBe(0);
    // --id is checked as well, with its own suggestion, and combines with --managed.
    const bad = await run(["init", join(temp, "other"), "--id", "My_Agent"]);
    expect(bad.status).toBe(1);
    expect(bad.stderr).toContain("Try --id my-agent");
    expect(
      (await run(["init", join(temp, "managed"), "--managed", "--id", "co-ai"]))
        .status,
    ).toBe(0);
    expect((await run(["init", join(temp, "x"), "--id"])).status).toBe(2);
  });

  async function run(args: string[]) {
    const stdout: string[] = [];
    const stderr: string[] = [];
    const status = await runCli(args, {
      stdout: (message) => stdout.push(message),
      stderr: (message) => stderr.push(message),
    });
    return { status, stdout: stdout.join("\n"), stderr: stderr.join("\n") };
  }

  it.each([
    ["--personal", "personal"],
    ["--managed", "managed"],
  ])(
    "%s writes a %s manifest that validates as generated",
    async (flag, mode) => {
      const directory = join(temp, `${mode}-agent`);
      expect((await run(["init", directory, flag])).status).toBe(0);
      const validated = await run(["validate", join(directory, "piship.yaml")]);
      expect(validated.status).toBe(0);
      expect(validated.stdout).toContain(`mode ${mode}.`);
      if (mode === "managed")
        expect(validated.stdout).toContain(
          "MANAGED_AGENT_OIDC_ISSUER, MANAGED_AGENT_OIDC_CLIENT_ID, MANAGED_AGENT_CREDENTIAL_BROKER_URL, MANAGED_AGENT_CREDENTIAL_REVOKE_URL, MANAGED_AGENT_LLM_GATEWAY_URL",
        );
    },
  );

  describe("bundling fd and rg", () => {
    afterEach(() => {
      vi.unstubAllEnvs();
    });

    it("bundles them when GitHub is reachable", async () => {
      vi.stubEnv("PISHIP_INIT_PROBE", "reachable");
      const directory = join(temp, "reachable-agent");
      const result = await run(["init", directory, "--personal"]);
      expect(result.status).toBe(0);
      expect(result.stderr).toBe("");
      const text = readFileSync(join(directory, "piship.yaml"), "utf8");
      expect(text).toContain("  searchTools:\n    mode: bundled\n");
      expect(text).toContain("https://github.com");
    });

    it("leaves them out and says so when GitHub is not reachable", async () => {
      vi.stubEnv("PISHIP_INIT_PROBE", "unreachable");
      const directory = join(temp, "offline-agent");
      const result = await run(["init", directory, "--personal"]);
      expect(result.status).toBe(0);
      expect(result.stderr).toBe(
        "GitHub is not reachable from here, so fd and rg are not bundled (Pi's @ file completion and find/grep need them). Add runtime.searchTools: { mode: bundled } and https://github.com to release.sources later, or see docs/manifest.md#bundled-search-tools-v1alpha6.\nregistry.npmjs.org did not answer within 3 seconds. The first build or test downloads the runtime packages from the npm registry (later ones use the cache), so it fails if npm cannot reach it, or the registry npm is configured to use, by then.",
      );
      expect(result.stdout).toContain(
        `Created ${join(directory, "piship.yaml")}`,
      );
      const text = readFileSync(join(directory, "piship.yaml"), "utf8");
      expect(text).not.toContain("searchTools");
      expect(text).toContain("sources: [https://registry.npmjs.org]\n");
      const validated = await run(["validate", join(directory, "piship.yaml")]);
      expect(validated.status).toBe(0);
      expect(validated.stdout).not.toContain("Bundled search tools");
    });

    it("does not probe for a managed distribution", async () => {
      vi.stubEnv("PISHIP_INIT_PROBE", "unreachable");
      const result = await run([
        "init",
        join(temp, "managed-agent"),
        "--managed",
      ]);
      expect(result.status).toBe(0);
      expect(result.stderr).toBe("");
    });
  });

  it("refuses --personal with --managed in either order", async () => {
    for (const flags of [
      ["--personal", "--managed"],
      ["--managed", "--personal"],
    ]) {
      const directory = join(temp, "both");
      const result = await run(["init", directory, ...flags]);
      expect(result.status).toBe(2);
      expect(result.stderr).toContain(
        "Choose one of --personal or --managed, not both.",
      );
      expect(existsSync(directory)).toBe(false);
    }
  });
});

describe("migrate --check", () => {
  beforeEach(() => {
    temp = mkdtempSync(join(tmpdir(), "piship-cli-migrate-"));
  });
  afterEach(() => {
    rmSync(temp, { recursive: true, force: true });
  });

  async function run(args: string[]) {
    const stdout: string[] = [];
    const stderr: string[] = [];
    const status = await runCli(args, {
      stdout: (message) => stdout.push(message),
      stderr: (message) => stderr.push(message),
    });
    return { status, stdout: stdout.join("\n"), stderr: stderr.join("\n") };
  }

  const manifest = (
    schema: string,
    runtime = `runtime: { pi: "${PI_VERSION}" }`,
  ) => {
    const path = join(temp, "piship.yaml");
    writeFileSync(
      path,
      [
        `schema: ${schema}`,
        "app: { id: mypi, name: MyPi, command: mypi, version: 1.0.0 }",
        runtime,
        "deployment: { mode: personal }",
        "updates: { channel: stable, channels: [stable] }",
        "",
      ].join("\n"),
    );
    return path;
  };

  it("exits 1, writing nothing, when migrating changes an effective decision", async () => {
    const path = manifest("piship/v1alpha5");
    const before = readFileSync(path, "utf8");
    const result = await run(["migrate", path, "--check"]);
    expect(result.status).toBe(1);
    expect(result.stdout).toContain(
      "Migration check piship/v1alpha5 -> piship/v1\nResult: requires review",
    );
    expect(result.stderr).toContain("2 item(s)");
    expect(result.stderr).toContain("runtime.cacheWarming");
    expect(result.stderr).toContain("release.bundle and release.strip");
    expect(readFileSync(path, "utf8")).toBe(before);
  });

  it("exits 0 and writes nothing for a migratable piship/v1alpha6 manifest", async () => {
    const path = manifest("piship/v1alpha6");
    const before = readFileSync(path, "utf8");
    const result = await run(["migrate", path, "--check"]);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain(
      "Migration check piship/v1alpha6 -> piship/v1\nResult: migratable",
    );
    expect(result.stderr).toBe("");
    expect(readFileSync(path, "utf8")).toBe(before);
  });

  it("exits 1 for a Pi pin this PiShip does not carry", async () => {
    const path = manifest("piship/v1alpha6", 'runtime: { pi: "0.0.1" }');
    const result = await run(["migrate", path, "--check"]);
    expect(result.status).toBe(1);
    expect(result.stdout).toContain("Result: requires review");
    expect(result.stderr).toContain(
      `runtime.pi is 0.0.1 but this PiShip pins Pi ${PI_VERSION}`,
    );
  });

  it("exits 3, writing nothing, when the manifest cannot migrate", async () => {
    const path = manifest("piship/v1alpha6", 'runtime: { pi: "latest" }');
    const before = readFileSync(path, "utf8");
    const result = await run(["migrate", path, "--check"]);
    expect(result.status).toBe(3);
    expect(result.stdout).toContain("Result: cannot migrate");
    expect(result.stderr).toContain("Cannot migrate");
    expect(result.stderr).toContain("runtime.pi");
    expect(readFileSync(path, "utf8")).toBe(before);
  });

  it("exits 0 when the manifest is already current", async () => {
    const path = manifest("piship/v1");
    const result = await run(["migrate", path, "--check"]);
    expect(result.status).toBe(0);
    expect(result.stdout).toBe("Already piship/v1; nothing to migrate.");
  });

  it("exits 0 for a manifest written by --write", async () => {
    const path = manifest("piship/v1alpha6");
    expect((await run(["migrate", path, "--write"])).status).toBe(0);
    expect(readFileSync(path, "utf8")).toContain("schema: piship/v1\n");
    expect((await run(["migrate", path, "--check"])).status).toBe(0);
  });

  it("refuses --check together with --write", async () => {
    const path = manifest("piship/v1alpha5");
    const result = await run(["migrate", path, "--write", "--check"]);
    expect(result.status).toBe(2);
    expect(readFileSync(path, "utf8")).toContain("piship/v1alpha5");
  });
});

describe("docs/agent-setup.md", () => {
  it("names only piship commands and options the CLI has", async () => {
    const text = readFileSync(
      fileURLToPath(new URL("../../../docs/agent-setup.md", import.meta.url)),
      "utf8",
    );
    const uses = [...text.matchAll(/\bpiship ([a-z][a-z-]*)([^`\n]*)/g)];
    expect(uses.length).toBeGreaterThan(10);
    for (const [, command, rest] of uses) {
      const help: string[] = [];
      const status = await runCli([command ?? "", "--help"], {
        stdout: (message) => help.push(message),
        stderr: () => {},
      });
      expect(status, `piship ${command}`).toBe(0);
      for (const option of rest?.match(/--[a-z][a-z0-9-]*/g) ?? [])
        expect(help.join("\n"), `piship ${command} ${option}`).toContain(
          option,
        );
    }
  });

  it("places the built command relative to where piship test ran", () => {
    const text = readFileSync(
      fileURLToPath(new URL("../../../docs/agent-setup.md", import.meta.url)),
      "utf8",
    );
    // `dist/` is written under the directory build or test runs in, which
    // is not necessarily the directory that holds piship.yaml.
    expect(text).toContain(
      "`dist/<id>/bin/<command> login`, run in the directory where you ran `piship test`",
    );
  });
});

describe("config explain from a manifest", () => {
  beforeEach(() => {
    temp = mkdtempSync(join(tmpdir(), "piship-cli-explain-"));
    process.env.PISHIP_STATE_HOME = join(temp, "state");
  });
  afterEach(() => {
    delete process.env.PISHIP_STATE_HOME;
    rmSync(temp, { recursive: true, force: true });
  });

  it("shows the manifest schema and the governance rows", async () => {
    const out: string[] = [];
    const manifest = fileURLToPath(
      new URL("../../../examples/demo-company/piship.yaml", import.meta.url),
    );
    const status = await runCli(["config", "explain", manifest], {
      stdout: (message) => out.push(message),
      stderr: () => {},
    });
    expect(status).toBe(0);
    const text = out.join("\n");
    expect(text).toMatch(/^schema\s+"piship\/v1"/m);
    for (const key of ["policy", "mcp\\.mode", "sandbox\\.required"])
      expect(text).toMatch(new RegExp(`^${key}\\s`, "m"));
    expect(text).toMatch(
      /^updates\.transport\s+"http-allowed"\s+\[builtin-default\] — the update channel may use plain HTTP to a private or internal host by default/m,
    );
  });

  it("prints the rows as JSON with --json, before or after the manifest", async () => {
    const manifest = fileURLToPath(
      new URL("../../../examples/demo-company/piship.yaml", import.meta.url),
    );
    for (const args of [
      ["config", "explain", manifest, "--json"],
      ["config", "explain", "--json", manifest],
    ]) {
      const out: string[] = [];
      expect(
        await runCli(args, {
          stdout: (message) => out.push(message),
          stderr: () => {},
        }),
      ).toBe(0);
      const rows = JSON.parse(out.join("\n")) as { key: string }[];
      expect(rows.map((row) => row.key)).toContain("schema");
    }
    for (const args of [
      ["config", "explain", manifest, "--json", "--json"],
      ["config", "explain", manifest, "--yaml"],
      ["config", "explain", "--json"],
    ]) {
      const err: string[] = [];
      expect(
        await runCli(args, {
          stdout: () => {},
          stderr: (message) => err.push(message),
        }),
      ).toBe(2);
      expect(err.join("\n")).toContain("Usage: piship config explain");
    }
  });

  it("shows updates.transport http-allowed, which validate also reports", async () => {
    const key = generateKeyPairSync("ed25519")
      .publicKey.export({ type: "spki", format: "der" })
      .toString("base64");
    const manifest = join(temp, "piship.yaml");
    writeFileSync(
      manifest,
      JSON.stringify({
        schema: "piship/v1alpha5",
        app: { id: ID, name: "MyPi", command: ID, version: "1.0.0" },
        runtime: { pi: "1.5.0" },
        deployment: { mode: "personal" },
        updates: {
          source: "http://updates.corp.internal/mypi",
          transport: "http-allowed",
          trust: {
            bootstrap: {
              version: 1,
              expires: "2099-01-01T00:00:00Z",
              keys: [{ id: "release", publicKey: key }],
              roles: {
                root: { keyIds: ["release"], threshold: 1 },
                channel: { keyIds: ["release"], threshold: 1 },
              },
            },
          },
        },
      }),
    );
    const run = async (args: string[]) => {
      const out: string[] = [];
      const status = await runCli(args, {
        stdout: (message) => out.push(message),
        stderr: () => {},
      });
      return { status, text: out.join("\n") };
    };
    const explained = await run(["config", "explain", manifest]);
    expect(explained.status).toBe(0);
    expect(explained.text).toMatch(
      /^updates\.transport\s+"http-allowed"\s+\[distribution-enforced\] — the update channel may use plain HTTP/m,
    );
    const validated = await run(["validate", manifest]);
    expect(validated.status).toBe(0);
    expect(validated.text).toContain(
      "Update transport http-allowed: the update channel may use plain HTTP to a private or internal host; integrity by signature only.",
    );
  });
});

describe("the runtime cache line of piship release", () => {
  const entry = "ab".repeat(32);
  it("says where the runtime came from, with the entry and how files were placed", () => {
    expect(
      runtimeCacheLine({ status: "hit", entry, linked: 7440, copied: 3 }),
    ).toBe(`runtime cache: hit (entry ${entry}, linked 7440, copied 3)`);
    expect(
      runtimeCacheLine({
        status: "miss",
        entry,
        linked: 0,
        copied: 7443,
        bundle: "miss",
        crossVolume: true,
      }),
    ).toBe(
      `runtime cache: miss (entry ${entry}, linked 0, copied 7443, bundle miss, cache on another volume, entry copied in)`,
    );
  });
  it("is one short line when the runtime was built cold", () => {
    expect(runtimeCacheLine({ status: "disabled" })).toBe(
      "runtime cache: disabled",
    );
  });
});

describe("what to do after an install", () => {
  beforeEach(() => {
    temp = mkdtempSync(join(tmpdir(), "piship-cli-next-"));
  });
  afterEach(() => {
    rmSync(temp, { recursive: true, force: true });
  });
  const receipt = (lock: unknown) => {
    if (lock !== undefined)
      writeFileSync(join(temp, "piship.lock"), JSON.stringify(lock));
    return { app: { command: "acme" }, payload: temp };
  };

  it("tells a managed distribution to set its variables, then log in", () => {
    const next = installNext(
      receipt({
        deployment: { mode: "managed" },
        access: { variables: ["ACME_ISSUER", "ACME_GATEWAY"] },
      }),
    );
    expect(next).toContain(
      "set ACME_ISSUER, ACME_GATEWAY in the environment that starts acme, then run acme login",
    );
  });

  it("does not ask an adopted state that is signed in to log in again", () => {
    const next = installNext(
      receipt({
        deployment: { mode: "managed" },
        access: { variables: ["ACME_ISSUER"] },
      }),
      ["an identity session"],
    );
    expect(next).toBe(
      "Next: set ACME_ISSUER in the environment that starts acme, then run acme; it is already signed in. acme --help lists its commands.",
    );
  });

  it("skips the variables this install already sees but keeps the launcher caveat", () => {
    const managed = receipt({
      deployment: { mode: "managed" },
      access: { variables: ["ACME_ISSUER", "ACME_GATEWAY"] },
    });
    expect(
      installNext(managed, ["an identity session"], {
        ACME_ISSUER: "https://idp",
        ACME_GATEWAY: "https://gw",
      }),
    ).toBe(
      "Next: run acme; it is already signed in. acme --help lists its commands. An IDE or desktop launcher does not read your shell profile, so set ACME_ISSUER, ACME_GATEWAY there too.",
    );
    const partly = installNext(managed, [], { ACME_ISSUER: "https://idp" });
    expect(partly).toContain(
      "Next: set ACME_GATEWAY in the environment that starts acme, then run acme login",
    );
    expect(partly).toContain("set ACME_ISSUER, ACME_GATEWAY there too.");
  });

  it("leaves out a variable that only update reads", () => {
    const next = installNext(
      receipt({
        deployment: { mode: "managed" },
        access: {
          variables: ["ACME_ISSUER", "ACME_SOURCE", "ACME_SHARED"],
          identity: { oidc: { issuer: "${ACME_ISSUER}/${ACME_SHARED}" } },
        },
        updates: { source: "${ACME_SOURCE}/${ACME_SHARED}" },
      }),
    );
    expect(next).toContain("set ACME_ISSUER, ACME_SHARED in the environment");
    expect(next).not.toContain("ACME_SOURCE");
  });

  it("skips the variables when a managed distribution has none", () => {
    expect(
      installNext(
        receipt({ deployment: { mode: "managed" }, access: { variables: [] } }),
      ),
    ).toMatch(/^Next: run acme login, then acme\./);
  });

  it("tells a Pi-native personal distribution to sign in inside Pi", () => {
    for (const lock of [
      {
        deployment: { mode: "personal" },
        access: { credential: { provider: "pi-native" }, variables: [] },
      },
      { deployment: { mode: "personal" } },
    ])
      expect(installNext(receipt(lock))).toContain(
        "sign in inside Pi with /login",
      );
  });

  it("tells a personal local-secret distribution to log in first", () => {
    expect(
      installNext(
        receipt({
          deployment: { mode: "personal" },
          access: { credential: { provider: "local-secret" }, variables: [] },
        }),
      ),
    ).toMatch(/^Next: run acme login to store the API key, then acme\./);
  });

  it("does not ask a local-secret state that a test run stored a key in to log in again", () => {
    const lock = receipt({
      deployment: { mode: "personal" },
      access: { credential: { provider: "local-secret" }, variables: [] },
    });
    expect(installNext(lock, ["a runtime credential"])).toBe(
      "Next: run acme; its API key is already stored. acme --help lists its commands.",
    );
    // A managed sign-in check is not a stored key.
    expect(installNext(lock, ["an identity session"])).toContain("acme login");
  });

  it("falls back to the generic next step when the lock cannot be read", () => {
    expect(installNext({ app: { command: "acme" }, payload: temp })).toBe(
      "Next: run acme --help to see its commands, then acme to start.",
    );
  });
});

describe("publishSteps", () => {
  const now = new Date("2026-11-15T00:00:00Z");
  it("orders the uploads and asks for a new signature a week before expiry", () => {
    const steps = publishSteps(
      "stable",
      [join("dist", "releases", "acmecode-1.1.0-darwin-arm64.tar.gz")],
      "2026-12-15T14:38:15.643Z",
      now,
    );
    expect(steps).toContain(
      "1. the archives this run added: acmecode-1.1.0-darwin-arm64.tar.gz",
    );
    expect(steps).not.toContain("root/");
    expect(steps).toContain("2. stable.json.sig and stable.json together");
    expect(steps).toContain(
      "Sign stable again by 2026-12-08: clients refuse it after 2026-12-15T14:38:15.643Z. sign-channel with no archive re-signs it with the same key.",
    );
  });
  it("says now when less than a week is left", () => {
    expect(
      publishSteps("candidate", [], "2026-11-18T00:00:00.000Z", now),
    ).toContain("Sign candidate again by now:");
  });
  it("separates archives already in the channel and puts hosted roots first", () => {
    const steps = publishSteps(
      "stable",
      ["a-1.1.0-darwin-arm64.tar.gz", "a-1.2.0-pack.tar.gz"],
      "2026-12-15T00:00:00.000Z",
      now,
      { present: ["a-1.1.0-darwin-arm64.tar.gz"], newestRoot: 2 },
    );
    expect(steps).toContain(
      "1. the archives this run added: a-1.2.0-pack.tar.gz (already in the channel directory before this run; upload only if not yet published: a-1.1.0-darwin-arm64.tar.gz)",
    );
    const root = steps.indexOf("0. any root/<N>.json up to root/2.json");
    expect(root).toBeGreaterThan(-1);
    expect(root).toBeLessThan(steps.indexOf("1. the archives"));
    expect(
      publishSteps("stable", ["x.tar.gz"], "2026-12-15T00:00:00Z", now, {
        present: ["x.tar.gz"],
      }),
    ).toContain("1. the archives this run added: none (already");
  });
});

describe("rootPublishSteps", () => {
  const now = new Date("2026-11-15T00:00:00Z");
  it("uploads the signature first and names the new channel key", () => {
    const steps = rootPublishSteps(
      "./channel",
      2,
      "2027-11-15T00:00:00Z",
      ["acme-channel-2027"],
      now,
    );
    expect(steps.indexOf("1. root/2.json.sig")).toBeLessThan(
      steps.indexOf("2. root/2.json\n"),
    );
    expect(steps).toContain(
      "piship sign-channel ./channel --channel <name> --key <private-key-file> --key-id acme-channel-2027 (with no archive it re-signs what the channel lists; add --previous-key <old-key-id>=<old-public-key> so the metadata the old key signed verifies)",
    );
    expect(steps).toContain("Publish the next root by 2027-11-08");
    expect(
      rootPublishSteps("./channel", 3, "2027-11-15T00:00:00Z", [], now),
    ).not.toContain("sign-channel");
  });
});

describe("stagingNotice", () => {
  const found = { count: 2, directory: "/work/dist", attempted: false };
  it("tells build and release to run again with --reclaim-staging", () => {
    expect(stagingNotice(found)).toContain(
      "2 abandoned staging directories of killed runs in /work/dist. They are not removed unless you ask",
    );
    expect(stagingNotice(found)).toContain(
      "run again with --reclaim-staging to remove them.",
    );
  });
  it("names the build command for dev and test, which take no --reclaim-staging", () => {
    expect(
      stagingNotice(found, "run piship build a/piship.yaml --reclaim-staging"),
    ).toContain(
      "; run piship build a/piship.yaml --reclaim-staging to remove them.",
    );
  });
});
