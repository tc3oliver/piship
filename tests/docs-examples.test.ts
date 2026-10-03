// Manifest and adapter examples in the docs, run as a reader would paste
// them: the Kubernetes sandbox snippet in a managed manifest must ask for a
// network mode its backend can enforce, and the workload identity adapter
// must read a variable a managed launch keeps.
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  createManagedFetch,
  DEFAULT_NETWORK_POLICY,
  sanitizeManagedEnvironment,
} from "@piship/contracts";
import {
  capabilityMismatch,
  KubernetesAgentSandboxBackend,
} from "@piship/sandbox";
import {
  DEFAULT_SANDBOX_ENVIRONMENT,
  DEFAULT_SANDBOX_READ_DENY,
  readManifest,
} from "@piship/schema";
import { afterEach, describe, expect, it } from "vitest";

const root = fileURLToPath(new URL("..", import.meta.url));
const directories: string[] = [];

afterEach(() => {
  for (const directory of directories.splice(0))
    rmSync(directory, { recursive: true, force: true });
});

function temporary(): string {
  const directory = mkdtempSync(join(tmpdir(), "piship-docs-examples-"));
  directories.push(directory);
  return directory;
}

function block(file: string, language: string, marker: string): string {
  const text = readFileSync(join(root, file), "utf8");
  const blocks = [
    ...text.matchAll(new RegExp(`\`\`\`${language}\\n([\\s\\S]*?)\`\`\``, "g")),
  ]
    .map((match) => match[1] ?? "")
    .filter((body) => body.includes(marker));
  expect(blocks).toHaveLength(1);
  return blocks[0] ?? "";
}

describe("documented examples", () => {
  it("the Kubernetes sandbox example asks for a network mode its backend enforces", () => {
    const snippet = block(
      "docs/sandbox.md",
      "yaml",
      "provider: kubernetes-agent-sandbox",
    );
    const variables = /^variables: \[(.*)\]$/m.exec(snippet)?.[1] ?? "";
    const sandbox = snippet.slice(snippet.indexOf("sandbox:\n"));
    const directory = temporary();
    let manifest = readFileSync(
      join(root, "examples/demo-company/piship.yaml"),
      "utf8",
    );
    manifest = manifest.replace(
      "variables:\n",
      `variables:\n${variables
        .split(",")
        .map((name) => `  - ${name.trim()}\n`)
        .join("")}`,
    );
    const start = manifest.indexOf("\nsandbox:\n");
    const end = manifest.indexOf("\naudit:\n");
    expect(start).toBeGreaterThan(0);
    manifest = `${manifest.slice(0, start + 1)}${sandbox}${manifest.slice(end)}`;
    writeFileSync(join(directory, "piship.yaml"), manifest);
    const parsed = readManifest(join(directory, "piship.yaml"));
    const config = parsed.governance?.sandbox;
    expect(config?.provider).toBe("kubernetes-agent-sandbox");
    const backend = new KubernetesAgentSandboxBackend({
      endpoint: "http://127.0.0.1:9",
      router: "http://127.0.0.1:9",
      namespace: config?.namespace ?? "default",
      template: config?.template ?? "",
      fetch: createManagedFetch(DEFAULT_NETWORK_POLICY, "sandbox"),
    });
    expect(
      capabilityMismatch(
        backend.capabilities(),
        config?.network.mode ?? "deny",
      ),
    ).toBeUndefined();
  });

  it("the workload identity adapter reads a variable a managed launch keeps", async () => {
    const source = block("docs/identity.md", "js", "interactive: false");
    const names = [...source.matchAll(/process\.env\.([A-Z0-9_]+)/g)].map(
      (match) => match[1] ?? "",
    );
    expect(names.length).toBeGreaterThan(0);
    const directory = temporary();
    const claims = { iss: "https://idp.example", sub: "job:demo", exp: 4e9 };
    const token = [
      "e30",
      Buffer.from(JSON.stringify(claims)).toString("base64url"),
      "sig",
    ].join(".");
    writeFileSync(join(directory, "token"), token, { mode: 0o600 });
    const env: NodeJS.ProcessEnv = Object.fromEntries(
      names.map((name) => [name, join(directory, "token")]),
    );
    expect(sanitizeManagedEnvironment(env, DEFAULT_NETWORK_POLICY)).toEqual([]);
    const adapter = join(directory, "workload-identity.mjs");
    writeFileSync(adapter, source);
    const factory = (await import(pathToFileURL(adapter).href)).default;
    const saved = names.map((name) => [name, process.env[name]] as const);
    Object.assign(process.env, env);
    try {
      const session = await factory({}).login({});
      expect(session.issuer).toBe(claims.iss);
      expect(session.subject).toBe(claims.sub);
    } finally {
      for (const [name, value] of saved)
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
    }
  });

  // A declared `sandbox.filesystem.read.deny` or `sandbox.environment.allow`
  // replaces the default list, so an example that declares one must still
  // carry every default it does not mean to drop.
  it.each([
    "examples/demo-company/piship.yaml",
    "examples/enterprise-reference/piship.yaml",
    "examples/enterprise-reference/sandbox/piship.yaml",
  ])("%s keeps every default sandbox read denial", (file) => {
    const sandbox = readManifest(join(root, file)).governance?.sandbox;
    expect(sandbox?.required).toBe(true);
    expect(sandbox?.filesystem.read.deny).toEqual(
      expect.arrayContaining([...DEFAULT_SANDBOX_READ_DENY]),
    );
    expect(sandbox?.environment.allow).toEqual(
      expect.arrayContaining([...DEFAULT_SANDBOX_ENVIRONMENT]),
    );
  });

  it("the README manifest is a complete manifest PiShip accepts on its own", () => {
    const snippet = block("README.md", "yaml", "schema: piship/v1alpha5");
    const directory = temporary();
    writeFileSync(join(directory, "piship.yaml"), snippet);
    const manifest = readManifest(join(directory, "piship.yaml"));
    expect(manifest.deployment.mode).toBe("managed");
    expect(manifest.governance?.sandbox?.required).toBe(true);
  });
});
