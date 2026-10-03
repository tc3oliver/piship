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
import { fileURLToPath } from "node:url";
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
    runtime: { pi: "1.0.0" },
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

  it.each([
    ["validate", "validate <manifest>"],
    ["install", "install <artifact|release-dir|archive>"],
    ["doctor", "doctor <artifact|id>"],
    ["config", "config explain <manifest|artifact|id>"],
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
      `Created ${manifest}\nNext: piship validate ${manifest}, then piship test ${manifest}.`,
    );
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
      for (const option of rest?.match(/--[a-z][a-z-]*/g) ?? [])
        expect(help.join("\n"), `piship ${command} ${option}`).toContain(
          option,
        );
    }
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
    expect(text).toMatch(/^schema\s+"piship\/v1alpha4"/m);
    for (const key of ["policy", "mcp\\.mode", "sandbox\\.required"])
      expect(text).toMatch(new RegExp(`^${key}\\s`, "m"));
  });
});
