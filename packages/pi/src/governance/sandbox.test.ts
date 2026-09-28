import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  E2bCompatibleBackend,
  KubernetesAgentSandboxBackend,
} from "@piship/sandbox";
import type { SandboxConfig } from "@piship/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { GovernanceOptions } from "./options.js";
import { sandboxBackend } from "./sandbox.js";

let distributionDir: string;
beforeEach(() => {
  distributionDir = mkdtempSync(join(tmpdir(), "piship-sandbox-backend-"));
});
afterEach(() => rmSync(distributionDir, { recursive: true, force: true }));

const base: SandboxConfig = {
  required: true,
  filesystem: { read: { deny: [] }, write: { allow: ["workspace"] } },
  network: { mode: "deny" },
  environment: { allow: ["PATH"] },
};

const variables: Record<string, string> = {
  ACME_SANDBOX_URL: "https://gateway.acme.example/sandbox",
  ACME_ROUTER_URL: "https://router.acme.example",
};

function options(
  sandbox: Partial<SandboxConfig>,
  extra: Partial<GovernanceOptions> = {},
): GovernanceOptions {
  return {
    lock: {
      app: { id: "acmecode" },
      governance: { manifest: { sandbox: { ...base, ...sandbox } } },
    },
    distributionDir,
    fetch: async () => new Response(null, { status: 204 }),
    resolveTemplate: (_key: string, template: string) =>
      template.replace(/\$\{([A-Z_]+)\}/g, (_match, name: string) => {
        const value = variables[name];
        if (value === undefined)
          throw new Error(`Runtime variable ${name} is not set`);
        return value;
      }),
    ...extra,
  } as unknown as GovernanceOptions;
}

const gateway = {
  credential: async () => "runtime-credential",
  credentialOrigins: ["https://gateway.acme.example/v1"],
};

describe("the declared sandbox backend", () => {
  it("is the native OS sandbox unless a provider is declared", async () => {
    expect(await sandboxBackend(options({}))).toBeUndefined();
    expect(
      await sandboxBackend(
        options({ required: false, provider: "e2b-compatible" }),
      ),
    ).toBeUndefined();
  });

  it("builds the e2b-compatible and kubernetes backends from resolved endpoints", async () => {
    expect(
      await sandboxBackend(
        options({
          provider: "e2b-compatible",
          endpoint: `\${ACME_SANDBOX_URL}`,
        }),
      ),
    ).toBeInstanceOf(E2bCompatibleBackend);
    expect(
      await sandboxBackend(
        options({
          provider: "kubernetes-agent-sandbox",
          endpoint: "https://k8s.acme.example",
          router: `\${ACME_ROUTER_URL}`,
          template: "python-pool",
        }),
      ),
    ).toBeInstanceOf(KubernetesAgentSandboxBackend);
  });

  it("fails closed when an endpoint variable is not set", async () => {
    await expect(
      sandboxBackend(
        options({ provider: "e2b-compatible", endpoint: `\${MISSING_URL}` }),
      ),
    ).rejects.toMatchObject({
      code: "SANDBOX_UNAVAILABLE",
      message: expect.stringContaining("MISSING_URL"),
    });
  });

  it("sends the runtime credential only to origins it is issued for", async () => {
    const declared = {
      provider: "e2b-compatible" as const,
      endpoint: `\${ACME_SANDBOX_URL}`,
      credential: "runtime" as const,
    };
    expect(await sandboxBackend(options(declared, gateway))).toBeInstanceOf(
      E2bCompatibleBackend,
    );
    await expect(
      sandboxBackend(
        options(
          { ...declared, endpoint: "https://sandbox.elsewhere.example" },
          gateway,
        ),
      ),
    ).rejects.toMatchObject({
      code: "SANDBOX_UNAVAILABLE",
      message: expect.stringContaining("https://sandbox.elsewhere.example"),
    });
    await expect(sandboxBackend(options(declared))).rejects.toMatchObject({
      code: "SANDBOX_UNAVAILABLE",
      message: expect.stringContaining("no runtime credential"),
    });
    // Every URL the credential goes to must qualify, the router included.
    await expect(
      sandboxBackend(
        options(
          {
            provider: "kubernetes-agent-sandbox",
            endpoint: `\${ACME_SANDBOX_URL}`,
            router: `\${ACME_ROUTER_URL}`,
            template: "python-pool",
            credential: "runtime",
          },
          gateway,
        ),
      ),
    ).rejects.toMatchObject({
      code: "SANDBOX_UNAVAILABLE",
      message: expect.stringContaining("https://router.acme.example"),
    });
  });

  describe("custom adapters", () => {
    const write = (source: string) => {
      mkdirSync(join(distributionDir, "resources", "sandbox"), {
        recursive: true,
      });
      writeFileSync(
        join(distributionDir, "resources", "sandbox", "acme.mjs"),
        source,
      );
    };
    const adapter = {
      provider: "custom" as const,
      adapter: "./sandbox/acme.mjs",
    };

    it("loads the verified payload module with a narrow context", async () => {
      write(`
        export default (context) => ({
          id: "acme-sandbox",
          context,
          available: async () => ({ available: true }),
          capabilities: () => ({ isolation: "remote", planes: [], network: [], localProcesses: false }),
          prepare: async () => ({ exec: async () => ({ exitCode: 0 }), dispose: async () => {} }),
        });
      `);
      const backend = await sandboxBackend(
        options(
          {
            ...adapter,
            endpoint: `\${ACME_SANDBOX_URL}`,
            credential: "runtime",
          },
          gateway,
        ),
      );
      expect(backend).toMatchObject({ id: "acme-sandbox", provider: "custom" });
      // The module's own fields never reach PiShip: only the contract does.
      expect(backend).not.toHaveProperty("context");
    });

    it("passes the credential only when declared and on an allowed origin", async () => {
      write(`
        export let seen;
        export default (context) => {
          seen = context;
          return {
            id: "acme-sandbox",
            available: async () => ({ available: true }),
            capabilities: () => ({}),
            prepare: async () => ({ exec: async () => ({ exitCode: 0 }), dispose: async () => {} }),
          };
        };
      `);
      const url = join(distributionDir, "resources", "sandbox", "acme.mjs");
      await sandboxBackend(
        options({ ...adapter, endpoint: `\${ACME_SANDBOX_URL}` }, gateway),
      );
      const { seen } = (await import(url)) as {
        seen: Record<string, unknown>;
      };
      expect(Object.keys(seen).sort()).toEqual([
        "distributionId",
        "endpoint",
        "fetch",
      ]);
      expect(seen.distributionId).toBe("acmecode");
      expect(seen.endpoint).toBe("https://gateway.acme.example/sandbox");
      await sandboxBackend(
        options(
          {
            ...adapter,
            endpoint: `\${ACME_SANDBOX_URL}`,
            credential: "runtime",
          },
          gateway,
        ),
      );
      const again = (await import(url)) as {
        seen: { credential?: () => Promise<string> };
      };
      expect(await again.seen.credential?.()).toBe("runtime-credential");
    });

    it.each([
      ["a missing module", undefined],
      ["a module without a factory", "export const x = 1;"],
      ["a malformed backend", "export default () => ({ id: 'acme' });"],
      [
        "a factory that throws",
        "export default () => { throw new Error('no license'); };",
      ],
    ])("fails closed on %s", async (_label, source) => {
      if (source !== undefined) write(source);
      await expect(sandboxBackend(options(adapter))).rejects.toMatchObject({
        code: "SANDBOX_UNAVAILABLE",
      });
    });
  });
});
