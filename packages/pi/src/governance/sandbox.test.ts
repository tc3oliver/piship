import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  type ContainmentReport,
  E2bCompatibleBackend,
  KubernetesAgentSandboxBackend,
} from "@piship/sandbox";
import type { SandboxConfig } from "@piship/schema";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { GovernanceSession } from "../governance-session.js";
import { gatePath } from "../governed-tools.js";
import { gitProtection, policyContainment } from "./engine.js";
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

  it("reaches an http-allowed endpoint over plain HTTP through a fetch scoped to it", async () => {
    let admit: ((target: URL) => boolean) | undefined;
    const used: string[] = [];
    const plainHttpFetch = (plainHttp: (target: URL) => boolean) => {
      admit = plainHttp;
      return async (url: string | URL) => {
        used.push(String(url));
        return new Response(null, { status: 204 });
      };
    };
    const backend = await sandboxBackend(
      options(
        {
          provider: "e2b-compatible",
          endpoint: "http://api.sandbox.corp.internal:3000",
          httpTransport: "http-allowed",
        },
        { plainHttpFetch } as Partial<GovernanceOptions>,
      ),
    );
    await backend?.available();
    expect(used).toEqual(["http://api.sandbox.corp.internal:3000/health"]);
    expect(admit?.(new URL("http://api.sandbox.corp.internal:3000/x"))).toBe(
      true,
    );
    // envd, a host under the endpoint's domain, is admitted; nothing else.
    expect(admit?.(new URL("http://49983-sbx1.sandbox.corp.internal/"))).toBe(
      true,
    );
    expect(admit?.(new URL("http://10.0.0.9:3000/"))).toBe(false);
    expect(admit?.(new URL("http://api.sandbox.corp.internal:3001/"))).toBe(
      false,
    );
    // A runtime value that resolves to a public plain-HTTP host fails closed.
    variables.ACME_PUBLIC = "http://sandbox.acme.example";
    await expect(
      sandboxBackend(
        options(
          {
            provider: "e2b-compatible",
            endpoint: `\${ACME_PUBLIC}`,
            httpTransport: "http-allowed",
          },
          { plainHttpFetch } as Partial<GovernanceOptions>,
        ),
      ),
    ).rejects.toMatchObject({
      code: "SANDBOX_UNAVAILABLE",
      message: expect.stringContaining("which is public"),
    });
    delete variables.ACME_PUBLIC;
  });

  it("passes sandbox.user to the e2b-compatible data plane", async () => {
    const seen: string[] = [];
    const fetch = async (url: string | URL, init: RequestInit = {}) => {
      const path = new URL(url).pathname;
      if (path.endsWith("/process.Process/Start"))
        seen.push(new Headers(init.headers).get("authorization") ?? "");
      if (path.endsWith("/sandboxes"))
        return Response.json({
          sandboxID: "sbx1",
          domain: "cube.acme.example",
        });
      return new Response(null, { status: 204 });
    };
    for (const [user, expected] of [
      [undefined, "user:"],
      ["root", "root:"],
    ] as const) {
      const backend = await sandboxBackend(
        options(
          {
            provider: "e2b-compatible",
            endpoint: "https://cube.acme.example",
            ...(user ? { user } : {}),
          },
          { fetch } as Partial<GovernanceOptions>,
        ),
      );
      const instance = await backend?.prepare({
        profile: { network: "deny" } as never,
      });
      await instance
        ?.exec(
          { command: "true", cwd: "/w", workspacePath: ".", env: {} },
          {
            signal: new AbortController().signal,
            onStdout: () => {},
            onStderr: () => {},
          },
        )
        .catch(() => undefined);
      expect(seen.at(-1)).toBe(
        `Basic ${Buffer.from(expected).toString("base64")}`,
      );
    }
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
      // The adapter records its context on globalThis: the test must not
      // depend on importing the same module instance PiShip loaded.
      write(`
        export default (context) => {
          globalThis.__pishipSandboxContext = context;
          return {
            id: "acme-sandbox",
            available: async () => ({ available: true }),
            capabilities: () => ({}),
            prepare: async () => ({ exec: async () => ({ exitCode: 0 }), dispose: async () => {} }),
          };
        };
      `);
      const seen = () =>
        (globalThis as { __pishipSandboxContext?: Record<string, unknown> })
          .__pishipSandboxContext ?? {};
      await sandboxBackend(
        options({ ...adapter, endpoint: `\${ACME_SANDBOX_URL}` }, gateway),
      );
      expect(Object.keys(seen()).sort()).toEqual([
        "distributionId",
        "endpoint",
        "fetch",
      ]);
      expect(seen().distributionId).toBe("acmecode");
      expect(seen().endpoint).toBe("https://gateway.acme.example/sandbox");
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
      const credential = seen().credential as
        | (() => Promise<string>)
        | undefined;
      expect(await credential?.()).toBe("runtime-credential");
      delete (globalThis as { __pishipSandboxContext?: unknown })
        .__pishipSandboxContext;
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

describe("policy containment from a sandbox report", () => {
  const report = (planes: readonly string[]): ContainmentReport =>
    ({
      level: "enforced",
      adapter: "x",
      provider: "e2b-compatible",
      required: true,
      planes,
      network: "deny",
      localProcesses: false,
      warnings: [],
    }) as ContainmentReport;

  it("does not count a remote backend's host isolation as filesystem containment", () => {
    expect(
      policyContainment(
        report([
          "network-deny",
          "environment-filter",
          "host-filesystem-isolation",
        ]),
      ),
    ).toEqual({ filesystem: false, network: true, shell: true });
  });

  it("counts the path policy only with both path planes", () => {
    for (const plane of ["filesystem-read-deny", "filesystem-write-allowlist"])
      expect(
        policyContainment(
          report([
            plane,
            "network-deny",
            "environment-filter",
            "host-filesystem-isolation",
          ]),
        ).filesystem,
      ).toBe(false);
  });

  it("keeps the native planes as before", () => {
    expect(
      policyContainment(
        report([
          "filesystem-read-deny",
          "filesystem-write-allowlist",
          "network-deny",
          "environment-filter",
        ]),
      ),
    ).toEqual({ filesystem: true, network: true, shell: true });
    expect(policyContainment({ ...report([]), level: "unavailable" })).toEqual({
      filesystem: false,
      network: false,
      shell: false,
    });
  });
});

describe("file-tool denial labels", () => {
  const fakeSession = (planes: readonly string[]) => {
    const root = mkdtempSync(join(tmpdir(), "piship-gate-"));
    const workspace = join(root, "ws");
    const secret = join(workspace, ".secrets");
    mkdirSync(secret, { recursive: true });
    const events: { rule?: string; enforcement?: string }[] = [];
    const gov = {
      workflowMode: "build",
      policyId: "acme@1",
      metrics: { recordPolicyDenial: () => {} },
      emit: (_event: string, fields: { rule?: string; enforcement?: string }) =>
        events.push(fields),
      engine: {
        context: { workspaceRoot: workspace, homeDir: root, tmpDir: root },
      },
      options: { stateDir: join(root, "state") },
      project: { root: workspace },
      sandbox: {
        report: { level: "enforced", planes },
        profile: { readDeny: [secret], writeAllow: [workspace] },
      },
    } as unknown as GovernanceSession;
    return { gov, events, secret, root };
  };

  it.each([
    [["filesystem-read-deny", "filesystem-write-allowlist"], "sandbox"],
    [["filesystem-read-deny"], "control-plane"],
    [["filesystem-write-allowlist"], "control-plane"],
    [["host-filesystem-isolation"], "control-plane"],
  ])(
    "labels a path-rule denial with planes %j as %s",
    async (planes, label) => {
      const { gov, events, secret, root } = fakeSession(planes);
      try {
        await expect(
          gatePath(gov, "filesystem.read", join(secret, "key"), "read"),
        ).rejects.toThrow(/outside what this distribution lets tools read/);
        expect(events).toEqual([
          expect.objectContaining({
            rule: "sandbox.filesystem.read.deny",
            enforcement: label,
          }),
        ]);
      } finally {
        rmSync(root, { recursive: true, force: true });
      }
    },
  );
});

/**
 * Whether this platform lets a test create a symbolic link: Windows without
 * developer mode or elevation does not.
 */
const canSymlink = (() => {
  try {
    const probe = mkdtempSync(join(tmpdir(), "piship-symlink-probe-"));
    try {
      symlinkSync(probe, join(probe, "link"), "dir");
      return true;
    } finally {
      rmSync(probe, { recursive: true, force: true });
    }
  } catch {
    return false;
  }
})();

describe("a linked git config file or hooks directory", () => {
  afterEach(() => vi.unstubAllEnvs());

  // Skipped, and reported as skipped, where links cannot be made; this check
  // fails on Linux and macOS.
  it("can create symbolic links on this platform, which the test below needs", () => {
    if (process.platform !== "win32") expect(canSymlink).toBe(true);
  });

  it.skipIf(!canSymlink)(
    "is passed to the sandbox as a link its protection cannot cover",
    () => {
      const root = realpathSync(
        mkdtempSync(join(tmpdir(), "piship-git-link-")),
      );
      try {
        const home = join(root, "home");
        const workspace = join(root, "ws");
        mkdirSync(join(workspace, ".git"), { recursive: true });
        mkdirSync(home);
        vi.stubEnv("HOME", home);
        vi.stubEnv("USERPROFILE", home);
        vi.stubEnv("GIT_CONFIG_NOSYSTEM", "1");
        for (const name of [
          "XDG_CONFIG_HOME",
          "GIT_CONFIG_GLOBAL",
          "GIT_CONFIG_COUNT",
        ])
          vi.stubEnv(name, undefined);
        writeFileSync(
          join(workspace, ".git", "config"),
          "[include]\n\tpath = ../team.cfg\n",
        );
        writeFileSync(join(workspace, "real.cfg"), "[user]\n\tname = x\n");
        expect(gitProtection(workspace).links).toBeUndefined();

        symlinkSync(join(workspace, "real.cfg"), join(workspace, "team.cfg"));
        const protection = gitProtection(workspace);
        expect(protection.links).toEqual([
          join(workspace, "team.cfg").split("\\").join("/"),
        ]);
        // The target is protected all the same.
        expect(protection.files).toContain(
          join(workspace, "real.cfg").split("\\").join("/"),
        );
      } finally {
        rmSync(root, { recursive: true, force: true });
      }
    },
  );
});

describe("the user's git config outside the project", () => {
  afterEach(() => vi.unstubAllEnvs());

  it("is protected from sandboxed commands but stays editable by the file tools", async () => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), "piship-git-home-")));
    try {
      const workspace = join(root, "ws");
      const home = join(root, "home");
      mkdirSync(join(workspace, ".git"), { recursive: true });
      writeFileSync(join(workspace, ".git", "config"), "[core]\n");
      mkdirSync(home);
      const global = join(home, ".gitconfig");
      writeFileSync(global, "[user]\n\tname = someone\n");
      vi.stubEnv("HOME", home);
      vi.stubEnv("USERPROFILE", home);
      vi.stubEnv("GIT_CONFIG_NOSYSTEM", "1");
      for (const name of [
        "XDG_CONFIG_HOME",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_COUNT",
      ])
        vi.stubEnv(name, undefined);
      const posix = (path: string) => path.split("\\").join("/");

      // A sandbox that may write the home directory must not plant a hooks
      // path in the file git reads there.
      expect(gitProtection(workspace).files).toEqual(
        expect.arrayContaining([
          posix(global),
          posix(join(workspace, ".git", "config")),
        ]),
      );

      const events: { rule?: string }[] = [];
      const gov = {
        workflowMode: "build",
        policyId: "acme@1",
        metrics: { recordPolicyDenial: () => {} },
        emit: (_event: string, fields: { rule?: string }) =>
          events.push(fields),
        engine: {
          context: { workspaceRoot: workspace, homeDir: home, tmpDir: root },
        },
        options: { stateDir: join(root, "state") },
        project: { root: workspace },
        sandbox: { report: { level: "unavailable" } },
        currentChannel: () => "interactive",
        decide: async () => ({ outcome: "allow" }),
      } as unknown as GovernanceSession;
      // The edit tool still changes the user's own git configuration...
      await expect(
        gatePath(gov, "filesystem.write", global, "edit"),
      ).resolves.toBe(global);
      // ...and still refuses the project's.
      await expect(
        gatePath(
          gov,
          "filesystem.write",
          join(workspace, ".git", "config"),
          "edit",
        ),
      ).rejects.toThrow(/what git runs/);
      expect(events.map((event) => event.rule)).toEqual([
        "piship.project.git-config",
      ]);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
