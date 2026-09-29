import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  applyProcessNetworkPolicy,
  DEFAULT_NETWORK_POLICY,
  type NetworkPolicy,
} from "@piship/contracts";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { selfSignedLoopbackCertificate } from "../../../tests/helpers/x509.js";
import { activateSandbox, SANDBOX_READY_MARKER } from "./activate.js";
import type {
  SandboxCapabilities,
  SandboxExecRequest,
  SandboxInstance,
} from "./backend.js";
import { customBackend } from "./custom.js";
import type { SandboxPolicy } from "./profile.js";

// What the commands of an enforced sandbox receive from the network policy:
// the approved proxy and CA settings when the sandbox allows the network on
// this host, never when it denies it and never on a remote backend.

const LOCAL: SandboxCapabilities = {
  isolation: "local",
  planes: [
    "filesystem-read-deny",
    "filesystem-write-allowlist",
    "network-deny",
    "environment-filter",
  ],
  network: ["deny", "allow"],
  localProcesses: false,
};
const REMOTE: SandboxCapabilities = {
  isolation: "remote",
  planes: ["host-filesystem-isolation", "network-deny", "environment-filter"],
  network: ["deny", "allow"],
  localProcesses: false,
};
const PROXY_NAMES = ["HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy"];

const policy = (mode: "deny" | "allow"): SandboxPolicy => ({
  required: true,
  filesystem: { read: { deny: [] }, write: { allow: ["workspace"] } },
  network: { mode },
  environment: { allow: ["PATH", "HTTPS_PROXY"] },
});

function backend(capabilities: SandboxCapabilities) {
  const commands: SandboxExecRequest[] = [];
  return {
    commands,
    backend: customBackend({
      id: "acme-sandbox",
      available: async () => ({ available: true }),
      capabilities: () => capabilities,
      prepare: async (): Promise<SandboxInstance> => ({
        exec: async (request, io) => {
          if (request.command.includes(SANDBOX_READY_MARKER)) {
            io.onStdout(Buffer.from(`${SANDBOX_READY_MARKER} unset\n`));
            io.onStdout(Buffer.from("piship-network-blocked\n"));
          } else commands.push(request);
          return { exitCode: 0 };
        },
        dispose: async () => undefined,
      }),
    }),
  };
}

let root: string;
let workspace: string;
let bundle: string;
beforeEach(() => {
  root = realpathSync(mkdtempSync(join(tmpdir(), "piship-network-env-")));
  workspace = join(root, "ws");
  mkdirSync(workspace, { recursive: true });
  bundle = join(root, "corp-ca.pem");
  writeFileSync(bundle, selfSignedLoopbackCertificate().certificate);
  const saved = new Map(PROXY_NAMES.map((name) => [name, process.env[name]]));
  for (const name of PROXY_NAMES) delete process.env[name];
  process.env.HTTPS_PROXY = "http://proxy.corp.example:3128";
  process.env.NO_PROXY = "localhost";
  return async () => {
    for (const [name, value] of saved)
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    const { Agent, setGlobalDispatcher } = await import("undici");
    setGlobalDispatcher(new Agent());
  };
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

/** The environment one command of the sandbox receives. */
async function environmentOf(
  mode: "deny" | "allow",
  capabilities: SandboxCapabilities,
  network?: NetworkPolicy,
): Promise<Record<string, string>> {
  if (network) applyProcessNetworkPolicy(network);
  const fake = backend(capabilities);
  const sandbox = await activateSandbox(policy(mode), {
    workspace,
    homeDir: join(root, "home"),
    backend: fake.backend,
    env: {
      PATH: "/usr/bin",
      HTTPS_PROXY: "http://ambient-user:ambient-pw@ambient.example:3128",
      SSL_CERT_FILE: "/etc/ambient.pem",
    },
  });
  await sandbox.exec("true", workspace, { onData: () => undefined });
  await sandbox.dispose();
  return { ...fake.commands.at(-1)?.env };
}

describe("the network environment of sandboxed commands", () => {
  const declared = (): NetworkPolicy => ({
    ...DEFAULT_NETWORK_POLICY,
    additionalCA: [bundle],
  });

  // Must stay first: applying a policy is recorded for the rest of the process.
  it("changes nothing for a process with no network policy", async () => {
    expect(await environmentOf("allow", LOCAL)).toEqual({
      PATH: "/usr/bin",
      HTTPS_PROXY: "http://ambient-user:ambient-pw@ambient.example:3128",
    });
  });

  it("gives a local command in an allow-mode sandbox the approved settings and no ambient ones", async () => {
    expect(await environmentOf("allow", LOCAL, declared())).toEqual({
      PATH: "/usr/bin",
      HTTPS_PROXY: "http://proxy.corp.example:3128",
      https_proxy: "http://proxy.corp.example:3128",
      NO_PROXY: "localhost",
      no_proxy: "localhost",
      NODE_EXTRA_CA_CERTS: bundle,
    });
  });

  it("gives a local command in a deny-mode sandbox nothing it did not allowlist", async () => {
    const env = await environmentOf("deny", LOCAL, declared());
    expect(Object.keys(env).sort()).toEqual(["HTTPS_PROXY", "PATH"]);
    expect(env.NODE_EXTRA_CA_CERTS).toBeUndefined();
  });

  it("never sends this host's proxy or CA to a remote backend", async () => {
    const env = await environmentOf("allow", REMOTE, declared());
    for (const name of [
      "https_proxy",
      "NO_PROXY",
      "no_proxy",
      "NODE_EXTRA_CA_CERTS",
    ])
      expect(env[name]).toBeUndefined();
  });

  it("withholds a proxy URL that embeds credentials", async () => {
    process.env.HTTPS_PROXY = "http://svc:hunter2@proxy.corp.example:3128";
    const env = await environmentOf("allow", LOCAL, declared());
    expect(JSON.stringify(env)).not.toContain("hunter2");
    expect(env.HTTPS_PROXY).toBeUndefined();
    expect(env.https_proxy).toBeUndefined();
    expect(env.NO_PROXY).toBe("localhost");
  });
});
