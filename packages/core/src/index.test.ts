import {
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  LATEST_SCHEMA,
  type Manifest,
  narrowRuleWarnings,
  readManifest,
} from "@piship/schema";
import {
  checkGovernance,
  checkPiVersion,
  distributionStateDirectory,
  initDistribution,
  isDistributionId,
  lockManifest,
  lockNeedsNetwork,
  lockStatus,
  pishipCommand,
  shellArg,
  suggestDistributionId,
  requireCurrentLock,
  unapprovedLoadWarnings,
  certifiedPiWarnings,
  PI_VERSION,
  resolveLock,
  runtimeStateDirectory,
} from "./index.js";
const roots: string[] = [];
function fixture() {
  const dir = mkdtempSync(join(tmpdir(), "piship-core-"));
  roots.push(dir);
  mkdirSync(join(dir, "resources"));
  writeFileSync(join(dir, "resources", "AGENTS.md"), "first\n");
  const path = join(dir, "piship.yaml");
  writeFileSync(
    path,
    'schema: piship/v1alpha1\napp:\n  id: mypi\n  name: My Pi\n  command: mypi\n  version: 0.1.0\nruntime:\n  pi: "1.5.0"\ndeployment:\n  mode: personal\nresources:\n  instructions:\n    - ./resources/AGENTS.md\n',
  );
  return { dir, path };
}
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
}, 180000);
describe("distribution core", () => {
  it("keeps state separate by id", () => {
    const home = join(tmpdir(), "state");
    expect(runtimeStateDirectory({ value: "a" }, home)).not.toBe(
      runtimeStateDirectory({ value: "b" }, home),
    );
    expect(distributionStateDirectory({ value: "my-agent" })).toBe(
      ".piship/my-agent",
    );
    expect(() => distributionStateDirectory({ value: "../outside" })).toThrow();
  });
  it("writes a byte-stable lock and detects resource drift", () => {
    const { dir, path } = fixture();
    const lockPath = lockManifest(path);
    const first = readFileSync(lockPath, "utf8");
    lockManifest(path);
    expect(readFileSync(lockPath, "utf8")).toBe(first);
    const lock = requireCurrentLock(path);
    expect(lock.runtime.version).toBe("1.5.0");
    expect(lock.resources[0]?.path).toBe("resources/AGENTS.md");
    expect(first).not.toMatch(/apiKey|password|secret/i);
    writeFileSync(join(dir, "resources", "AGENTS.md"), "changed\n");
    expect(() => requireCurrentLock(path)).toThrow("stale");
    expect(resolveLock(path).resources[0]?.sha256).not.toBe(
      lock.resources[0]?.sha256,
    );
  });
  it("names the Pi upgrade when the lock was made by an older Pi", () => {
    const { dir, path } = fixture();
    const lockPath = lockManifest(path);
    const lock = JSON.parse(readFileSync(lockPath, "utf8"));
    lock.runtime.version = "1.1.0";
    writeFileSync(lockPath, JSON.stringify(lock));
    expect(() => requireCurrentLock(path)).toThrow(
      `${lockPath} was made for Pi 1.1.0 and this PiShip uses Pi ${PI_VERSION}. Copy it to previous.lock`,
    );
    // Any other drift keeps the plain message.
    lockManifest(path);
    writeFileSync(join(dir, "resources", "AGENTS.md"), "changed\n");
    expect(() => requireCurrentLock(path)).not.toThrow("was made for Pi");
  });
  it("uses the pinned Pi when an emptied runtime: is left behind", () => {
    const { path } = fixture();
    writeFileSync(
      path,
      readFileSync(path, "utf8").replace(
        'runtime:\n  pi: "1.5.0"\n',
        "runtime:\n",
      ),
    );
    expect(readManifest(path).runtime.pi).toBeUndefined();
  });
  it("requires a current lock before building", () => {
    const { path } = fixture();
    expect(() => requireCurrentLock(path)).toThrow("Lockfile missing");
    lockManifest(path);
    expect(requireCurrentLock(path).app.id).toBe("mypi");
  });
  it("tells a missing lock from a stale one and a current one", () => {
    const { dir, path } = fixture();
    expect(lockStatus(path)).toBe("missing");
    lockManifest(path);
    expect(lockStatus(path)).toBe("current");
    writeFileSync(join(dir, "resources", "AGENTS.md"), "changed\n");
    expect(lockStatus(path)).toBe("stale");
    expect(lockNeedsNetwork(readManifest(path))).toBe(false);
  });
  it("resolves new content to relock only for Pi packages, not for bundled search tools", () => {
    const { path } = fixture();
    const manifest = readManifest(path);
    expect(
      lockNeedsNetwork({
        ...manifest,
        runtime: { ...manifest.runtime, searchTools: { mode: "bundled" } },
      } as typeof manifest),
    ).toBe(false);
  });
  it("uses the pinned Pi when runtime.pi is left out", () => {
    const { path } = fixture();
    writeFileSync(
      path,
      readFileSync(path, "utf8").replace('runtime:\n  pi: "1.5.0"\n', ""),
    );
    expect(readManifest(path).runtime.pi).toBeUndefined();
    lockManifest(path);
    expect(requireCurrentLock(path).runtime.version).toBe("1.5.0");
  });
  it("refuses another Pi and says how to fix the manifest", () => {
    const { path } = fixture();
    writeFileSync(
      path,
      readFileSync(path, "utf8").replace('"1.5.0"', '"0.9.9"'),
    );
    expect(() => checkPiVersion(readManifest(path))).toThrow(
      /Pi 0\.9\.9 is not available.*Remove the runtime\.pi line.*set it to "1\.5\.0"/,
    );
  });
  it("rejects resource roots and nested symlinks during locking", () => {
    const { dir, path } = fixture();
    writeFileSync(
      path,
      `${readFileSync(path, "utf8")}  skills:\n    - ./resources\n`,
    );
    const external = join(dir, "outside.md");
    writeFileSync(external, "outside\n");
    const nested = join(dir, "resources", "linked.md");
    try {
      symlinkSync(external, nested);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EPERM") return;
      throw error;
    }
    expect(() => resolveLock(path)).toThrow(
      "Resource symlinks are not allowed",
    );
    rmSync(nested);
    rmSync(join(dir, "resources", "AGENTS.md"));
    symlinkSync(external, join(dir, "resources", "AGENTS.md"));
    expect(() => resolveLock(path)).toThrow(
      "Resource symlinks are not allowed",
    );
    const other = fixture();
    const externalRoot = join(other.dir, "elsewhere");
    mkdirSync(externalRoot);
    writeFileSync(join(externalRoot, "AGENTS.md"), "outside\n");
    rmSync(join(other.dir, "resources"), { recursive: true });
    try {
      symlinkSync(externalRoot, join(other.dir, "resources"), "dir");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EPERM") return;
      throw error;
    }
    expect(() => resolveLock(other.path)).toThrow(
      "Resource symlinks are not allowed",
    );
  });
});

describe("sandbox adapter locking", () => {
  it("locks a custom sandbox adapter module like other adapters", () => {
    const dir = mkdtempSync(join(tmpdir(), "piship-core-"));
    roots.push(dir);
    mkdirSync(join(dir, "sandbox"));
    writeFileSync(
      join(dir, "sandbox", "acme.mjs"),
      "export default () => ({});\n",
    );
    const path = join(dir, "piship.yaml");
    writeFileSync(
      path,
      'schema: piship/v1alpha3\napp:\n  id: mypi\n  name: My Pi\n  command: mypi\n  version: 0.1.0\nruntime:\n  pi: "1.5.0"\ndeployment:\n  mode: personal\nsandbox:\n  required: true\n  provider: custom\n  adapter: ./sandbox/acme.mjs\n',
    );
    const locked = resolveLock(path).resources.find(
      (item) => item.kind === "adapters",
    );
    expect(locked?.path).toBe("sandbox/acme.mjs");
    writeFileSync(join(dir, "sandbox", "acme.mjs"), "export default 1;\n");
    expect(
      resolveLock(path).resources.find((item) => item.kind === "adapters")
        ?.sha256,
    ).not.toBe(locked?.sha256);
  });
});

describe("MCP module locking", () => {
  it("locks a module two servers share once", () => {
    const dir = mkdtempSync(join(tmpdir(), "piship-core-"));
    roots.push(dir);
    writeFileSync(join(dir, "srv.mjs"), "export {};\n");
    const path = join(dir, "piship.yaml");
    writeFileSync(
      path,
      'schema: piship/v1alpha3\napp:\n  id: mypi\n  name: My Pi\n  command: mypi\n  version: 0.1.0\nruntime:\n  pi: "1.5.0"\ndeployment:\n  mode: personal\nmcp:\n  servers:\n    one: { transport: stdio, module: ./srv.mjs, args: [one] }\n    two: { transport: stdio, module: ./srv.mjs, args: [two] }\n',
    );
    expect(
      resolveLock(path)
        .resources.filter((item) => item.kind === "adapters")
        .map((item) => item.path),
    ).toEqual(["srv.mjs"]);
  });
});

describe("init", () => {
  it.each([
    ["personal", false],
    ["managed", true],
  ] as const)(
    "writes a %s manifest on the latest schema that validates and locks",
    (mode, managed) => {
      const root = mkdtempSync(join(tmpdir(), "piship-init-"));
      roots.push(root);
      const path = initDistribution(join(root, `${mode}-agent`), { managed });
      const manifest = readManifest(path);
      expect(manifest.schema).toBe(LATEST_SCHEMA);
      expect(manifest.deployment.mode).toBe(mode);
      checkPiVersion(manifest);
      expect(() => checkGovernance(manifest, path)).not.toThrow();
      expect(manifest.governance).toBeDefined();
      expect(manifest.governance?.sandbox.required).toBe(false);
      const projectTrust = manifest.governance?.policy.projectTrust;
      // Managed: a repository's text loads anywhere (the managed defaults);
      // nothing in an untrusted one that starts code does.
      const closed = {
        passiveContext: "allow",
        instructions: "allow",
        skills: "allow",
        agents: "deny",
        hooks: "deny",
        extensions: "deny",
        mcp: "deny",
        providers: "deny",
      };
      // A person's own projects must work: instructions and skills load
      // (an unknown origin is treated like an external one), code asks, and hooks, agents, and
      // providers stay denied.
      const own = {
        passiveContext: "allow",
        instructions: "allow",
        skills: "allow",
        agents: "deny",
        hooks: "deny",
        extensions: "ask",
        mcp: "ask",
        providers: "deny",
      };
      expect(projectTrust?.external.dimensions).toEqual(managed ? closed : own);
      expect(projectTrust?.unknown.dimensions).toEqual(managed ? closed : own);
      expect(manifest.runtime.searchTools).toEqual(
        managed ? undefined : { mode: "bundled" },
      );
      expect(manifest.lifecycle?.updates).toMatchObject({
        channel: "stable",
        channels: ["stable"],
        rollback: true,
        trust: {},
      });
      expect(manifest.lifecycle?.updates.source).toBeUndefined();
      if (managed) {
        expect(manifest.access?.identity.mode).toBe("oidc");
        expect(manifest.governance?.policy.default).toBe("ask");
        expect(manifest.governance?.mcp.mode).toBe("allowlist");
        expect(manifest.governance?.mcp.servers).toEqual([]);
        expect(manifest.governance?.audit.enabled).toBe(true);
        expect(manifest.governance?.resources.declared).toMatchObject([
          { kind: "instructions", class: "company" },
        ]);
      } else {
        expect(manifest.access?.identity.mode).toBe("none");
        expect(manifest.access?.credential.provider).toBe("pi-native");
        expect(manifest.access?.inference.provider).toBe("pi-native");
        expect(manifest.governance?.policy.default).toBe("allow");
        expect(manifest.governance?.mcp.mode).toBe("off");
        expect(manifest.governance?.audit.enabled).toBe(false);
        expect(manifest.governance?.resources.declared).toMatchObject([
          { kind: "instructions", class: "user" },
        ]);
      }
      // Locking the bundled search tools reads PiShip's download cache, which
      // a fresh machine does not have, so the lock is checked on the same
      // template without them.
      const lockable = managed
        ? path
        : initDistribution(join(root, "personal-offline-agent"), {
            bundleSearchTools: false,
          });
      lockManifest(lockable);
      const lock = requireCurrentLock(lockable);
      expect(lock.schema).toBe("piship-lock/v1");
      expect(lock.manifest.schema).toBe(LATEST_SCHEMA);
      expect(lock.updates?.trust).toEqual({});
    },
    180000,
  );

  it("bundles fd and rg and lists github.com by default, and leaves both out on request", () => {
    const root = mkdtempSync(join(tmpdir(), "piship-init-"));
    roots.push(root);
    const bundled = readFileSync(
      initDistribution(join(root, "bundled-agent")),
      "utf8",
    );
    expect(bundled).toContain("runtime:\n");
    expect(bundled).toContain("  searchTools:\n    mode: bundled\n");
    expect(bundled).toContain(
      "sources: [https://registry.npmjs.org, https://github.com]",
    );
    const path = initDistribution(join(root, "plain-agent"), {
      bundleSearchTools: false,
    });
    const plain = readFileSync(path, "utf8");
    expect(plain).not.toMatch(/^runtime:/m);
    expect(plain).not.toContain("searchTools");
    // github.com stays only in the docs links.
    expect(plain).not.toContain("https://github.com,");
    expect(plain).not.toContain("https://github.com]");
    expect(plain).toContain("sources: [https://registry.npmjs.org]");
    const manifest = readManifest(path);
    expect(manifest.runtime.searchTools).toBeUndefined();
    checkPiVersion(manifest);
    // It locks offline: nothing in it needs a download.
    lockManifest(path);
    expect(requireCurrentLock(path).searchTools).toBeUndefined();
    // The managed template has no search tools either way.
    const managed = readFileSync(
      initDistribution(join(root, "managed-agent"), {
        managed: true,
        bundleSearchTools: true,
      }),
      "utf8",
    );
    expect(managed).not.toContain("searchTools");
  });

  it("writes a managed MCP example that validates once uncommented", () => {
    const root = mkdtempSync(join(tmpdir(), "piship-init-"));
    roots.push(root);
    const path = initDistribution(join(root, "mcp-agent"), { managed: true });
    const lines = readFileSync(path, "utf8").split("\n");
    const first = lines.indexOf("  #   servers:");
    const last = lines.indexOf('  #         "*": hidden');
    expect(first).toBeGreaterThan(-1);
    expect(last).toBeGreaterThan(first);
    // `#` and three spaces become the two-space indent under `mcp:`.
    for (let index = first; index <= last; index += 1)
      lines[index] = (lines[index] as string).replace(/^ {2}# {3}/, "  ");
    writeFileSync(path, lines.join("\n"));
    const server = readManifest(path).governance?.mcp.servers[0];
    expect(server?.id).toBe("docs");
    expect(server?.toolExposure).toEqual([
      { pattern: "search", exposure: "direct" },
      { pattern: "*", exposure: "hidden" },
    ]);
  });

  it.each([
    ["personal", false],
    ["managed", true],
  ] as const)(
    "writes %s example blocks that all validate once uncommented",
    (mode, managed) => {
      const root = mkdtempSync(join(tmpdir(), "piship-init-"));
      roots.push(root);
      const path = initDistribution(join(root, `${mode}-agent`), { managed });
      // An example line is an indented `#` and three spaces; uncommenting it
      // leaves the indent before the `#`. (The top-level variable list in
      // the managed header is prose, not an example.)
      let uncommented = 0;
      const text = readFileSync(path, "utf8")
        .split("\n")
        .map((line) => {
          const match = /^( +)# {3}(.+)$/.exec(line);
          if (!match) return line;
          uncommented += 1;
          return `${match[1]}${match[2]}`;
        })
        .join("\n")
        // The collector sink's URL variable must be declared.
        .replace("variables:\n", "variables:\n  - AUDIT_COLLECTOR_URL\n");
      expect(uncommented).toBe(managed ? 14 : 0);
      writeFileSync(path, text);
      const manifest = readManifest(path);
      expect(() => checkGovernance(manifest, path)).not.toThrow();
      if (!managed) return;
      expect(manifest.governance?.mcp.servers[0]?.id).toBe("docs");
      expect(manifest.governance?.audit.sinks).toMatchObject([
        { id: "local", required: false },
        { id: "collector", type: "http", required: true },
      ]);
      expect(manifest.access?.inference.liveCatalog).toBe(true);
    },
  );
});

describe("init mode", () => {
  it("writes the personal template with --personal and with no flag", () => {
    const root = mkdtempSync(join(tmpdir(), "piship-init-mode-"));
    roots.push(root);
    const explicit = initDistribution(join(root, "explicit"), {
      personal: true,
    });
    const implicit = initDistribution(join(root, "implicit"));
    for (const path of [explicit, implicit])
      expect(readManifest(path).deployment.mode).toBe("personal");
    expect(readFileSync(explicit, "utf8").replaceAll("explicit", "id")).toBe(
      readFileSync(implicit, "utf8").replaceAll("implicit", "id"),
    );
  });

  it("refuses --personal together with --managed and writes nothing", () => {
    const root = mkdtempSync(join(tmpdir(), "piship-init-mode-"));
    roots.push(root);
    const directory = join(root, "both");
    expect(() =>
      initDistribution(directory, { personal: true, managed: true }),
    ).toThrow(/--personal or --managed/);
    expect(existsSync(directory)).toBe(false);
  });

  it("templates every company-specific managed value as a runtime variable", () => {
    const root = mkdtempSync(join(tmpdir(), "piship-init-mode-"));
    roots.push(root);
    const manifest = readManifest(
      initDistribution(join(root, "acme-agent"), { managed: true }),
    );
    expect(manifest.access?.variables).toEqual([
      "ACME_AGENT_OIDC_ISSUER",
      "ACME_AGENT_OIDC_CLIENT_ID",
      "ACME_AGENT_CREDENTIAL_BROKER_URL",
      "ACME_AGENT_CREDENTIAL_REVOKE_URL",
      "ACME_AGENT_LLM_GATEWAY_URL",
    ]);
    expect(manifest.access?.identity).toMatchObject({
      mode: "oidc",
      oidc: {
        issuer: `\${ACME_AGENT_OIDC_ISSUER}`,
        clientId: `\${ACME_AGENT_OIDC_CLIENT_ID}`,
      },
    });
    expect(manifest.access?.credential.broker).toEqual({
      endpoint: `\${ACME_AGENT_CREDENTIAL_BROKER_URL}`,
      revokeEndpoint: `\${ACME_AGENT_CREDENTIAL_REVOKE_URL}`,
    });
    expect(manifest.access?.inference).toMatchObject({
      provider: "openai-compatible",
      baseUrl: `\${ACME_AGENT_LLM_GATEWAY_URL}`,
      api: "openai-completions",
    });
    expect(manifest.access?.network.proxy.inheritEnvironment).toBe(true);
  });
});

describe("managed init", () => {
  it("creates a valid managed profile even when the id resembles secret words", () => {
    for (const id of ["acme-agent", "token-agent"]) {
      const root = mkdtempSync(join(tmpdir(), "piship-init-managed-"));
      roots.push(root);
      const manifest = readManifest(
        initDistribution(join(root, id), { managed: true }),
      );
      expect(manifest.deployment.mode).toBe("managed");
      expect(manifest.access?.identity.mode).toBe("oidc");
      expect(
        manifest.access?.variables.every((name) => !/TOKEN/.test(name)),
      ).toBe(true);
    }
  });

  it("lets policy load the repository text that project trust admits", () => {
    const root = mkdtempSync(join(tmpdir(), "piship-init-managed-"));
    roots.push(root);
    const policy = readManifest(
      initDistribution(join(root, "acme-agent"), { managed: true }),
    ).governance?.policy;
    // Project trust admits the text; policy then loads it without a prompt.
    for (const action of ["instruction.load", "skill.load"])
      expect(policy?.defaults).toContainEqual(
        expect.objectContaining({ action, resource: "**", effect: "allow" }),
      );
  });
});

describe("unapproved load warnings", () => {
  it("names declared resources and MCP servers only policy.default decides", () => {
    const root = mkdtempSync(join(tmpdir(), "piship-init-managed-"));
    roots.push(root);
    const path = initDistribution(join(root, "acme-agent"), { managed: true });
    // The template as written loads everything it declares.
    expect(unapprovedLoadWarnings(readManifest(path))).toEqual([]);
    const dir = join(root, "acme-agent", "resources", "ext");
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "index.ts"), "export default () => {};\n");
    const lines = readFileSync(path, "utf8")
      .replace(
        "      - ./resources/AGENTS.md\n",
        "      - ./resources/AGENTS.md\n  extensions:\n    company: [./resources/ext]\n",
      )
      .split("\n");
    // Uncomment the MCP example, as the test above does.
    const first = lines.indexOf("  #   servers:");
    const last = lines.indexOf('  #         "*": hidden');
    for (let index = first; index <= last; index += 1)
      lines[index] = (lines[index] as string).replace(/^ {2}# {3}/, "  ");
    const source = lines.join("\n");
    writeFileSync(path, source);
    expect(
      unapprovedLoadWarnings(readManifest(path)).map((item) => item.path),
    ).toEqual([
      "resources.extensions.company",
      "mcp.servers.docs",
      "mcp.servers.docs.tools.search",
    ]);
    expect(unapprovedLoadWarnings(readManifest(path))[0]?.message).toBe(
      './resources/ext: no policy rule allows extension.load company:./resources/ext, so policy.default (ask) asks at every launch and headless runs leave it out; add a policy.defaults allow rule for extension.load on "company:**"',
    );
  });
});

describe("certified Pi warnings", () => {
  it("names certified evidence that leaves out the pinned Pi", () => {
    const evidence = (pi: string[]) => ({
      id: "x",
      version: "1.0.0",
      source: "s",
      integrity: "sha256-0",
      license: "MIT",
      pi,
      platforms: [],
    });
    const manifest = {
      governance: {
        resources: {
          declared: [
            {
              kind: "skills",
              class: "certified",
              path: "./old",
              certified: evidence(["1.1.0"]),
            },
            {
              kind: "skills",
              class: "certified",
              path: "./new",
              certified: evidence([PI_VERSION]),
            },
            { kind: "skills", class: "user", path: "./mine" },
          ],
          builtin: [],
          packages: [
            { id: "pkg", class: "certified", certified: evidence(["1.1.0"]) },
          ],
        },
        capabilities: [
          {
            name: "workflow",
            provider: {
              id: "certified/flow",
              certified: evidence(["1.1.0", "1.2.0"]),
            },
          },
        ],
      },
    } as unknown as Manifest;
    const warnings = certifiedPiWarnings(manifest);
    expect(warnings.map((item) => item.path)).toEqual([
      "resources.skills.certified",
      "resources.packages",
      "capabilities.workflow.provider",
    ]);
    expect(warnings[0]?.message).toBe(
      `./old is certified for Pi 1.1.0, not Pi ${PI_VERSION} that this PiShip uses, so it is not loaded; review it on Pi ${PI_VERSION} and add "${PI_VERSION}" to its certified pi list`,
    );
  });
});

describe("shell glob warnings", () => {
  it("warns on a shell.execute deny or ask using * without **", () => {
    const root = mkdtempSync(join(tmpdir(), "piship-init-glob-"));
    roots.push(root);
    const path = initDistribution(join(root, "acme-agent"), { managed: true });
    const rule = (id: string, resource: string, effect: string) =>
      `    - { id: ${id}, action: shell.execute, resource: "${resource}", effect: ${effect} }\n`;
    const yaml = readFileSync(path, "utf8");
    expect(narrowRuleWarnings(readManifest(path))).toEqual([]);
    writeFileSync(
      path,
      yaml.replace(
        /^policy:\n/m,
        `policy:\n  enforced:\n${rule("no-rm", "rm -rf *", "deny")}${rule("rm-ok", "rm -rf **", "deny")}${rule("ls-ok", "ls *", "allow")}${rule("push-force", "git push ** --force*", "ask")}`,
      ),
    );
    const warnings = narrowRuleWarnings(readManifest(path));
    expect(warnings.map((item) => item.path)).toEqual([
      "policy.enforced[0].resource",
      "policy.enforced[3].resource",
    ]);
    expect(warnings[0]?.message).toMatch(/^no-rm: /);
    expect(warnings[0]?.message).toContain(
      "does not match arguments containing / or :",
    );
    // A ** elsewhere does not excuse the single *: --force* misses --force-with-lease=main:abc.
    expect(warnings[1]?.message).toContain('"git push ** --force**"');
  });
});

describe("distribution ids", () => {
  it.each([
    ["my_agent", "my-agent"],
    ["agent.v2", "agent-v2"],
    ["My Agent!", "my-agent"],
    ["2fast", "app-2fast"],
    ["--x--", "x"],
  ])("suggests %s as %s", (name, id) => {
    expect(isDistributionId(name)).toBe(false);
    expect(suggestDistributionId(name)).toBe(id);
    expect(isDistributionId(id)).toBe(true);
  });
  it("has no suggestion when nothing usable is left", () => {
    expect(suggestDistributionId("___")).toBeUndefined();
  });
  it("suggests only an id init accepts", () => {
    const long = suggestDistributionId(`${"a".repeat(63)}_b${"c".repeat(40)}`);
    expect(long).toBe("a".repeat(63));
    expect(suggestDistributionId(`2${"a".repeat(100)}`)).toBe(
      `app-2${"a".repeat(59)}`,
    );
    // A Windows device name is refused too, so it is not suggested.
    expect(suggestDistributionId("Con!")).toBeUndefined();
  });
  it("answers a very long run of hyphens at once", () => {
    const started = Date.now();
    expect(suggestDistributionId("-".repeat(200_000))).toBeUndefined();
    expect(
      suggestDistributionId(`${"-".repeat(200_000)}x${"-".repeat(200_000)}`),
    ).toBe("x");
    expect(Date.now() - started).toBeLessThan(1000);
  });
  it("names the suggestion where a bad id is refused", () => {
    expect(() => distributionStateDirectory({ value: "my_agent" })).toThrow(
      "use my-agent",
    );
  });
});

describe("the command PiShip prints for its next step", () => {
  it("names the CLI script by path, quoted when it needs it", () => {
    // The path is made absolute for the platform (a drive letter and
    // backslashes on Windows).
    const script = resolve("/opt/piship/packages/cli/dist/bin.js");
    expect(pishipCommand("/opt/piship/packages/cli/dist/bin.js")).toBe(
      `node ${shellArg(script)}`,
    );
    const spaced = resolve("/opt/my tools/piship.mjs");
    expect(pishipCommand("/opt/my tools/piship.mjs")).toBe(
      `node ${shellArg(spaced)}`,
    );
  });
  it("quotes an argument only when needed, in a form the platform's shell pastes", () => {
    expect(shellArg("examples/minimal/piship.yaml", "linux")).toBe(
      "examples/minimal/piship.yaml",
    );
    expect(shellArg("/opt/my tools", "darwin")).toBe("'/opt/my tools'");
    expect(shellArg("it's", "linux")).toBe("'it'\\''s'");
    // Git Bash eats bare backslashes, so a Windows path is always quoted.
    expect(shellArg("C:\\Users\\RUNNER~1\\a.yaml", "win32")).toBe(
      '"C:\\Users\\RUNNER~1\\a.yaml"',
    );
    expect(shellArg("C:/Users/a.yaml", "win32")).toBe("C:/Users/a.yaml");
    // cmd.exe has no single quotes; double quotes work there and in PowerShell.
    expect(shellArg("C:\\my tools\\x", "win32")).toBe('"C:\\my tools\\x"');
    expect(shellArg("it's", "win32")).toBe('"it\'s"');
    expect(shellArg("a,b", "win32")).toBe('"a,b"');
    expect(shellArg("", "win32")).toBe('""');
    // A backslash run before the closing quote or a `"` is doubled, so it
    // does not escape the quote (`.\My Dist\` as PowerShell completes it).
    expect(shellArg(".\\My Dist\\", "win32")).toBe('".\\My Dist\\\\"');
    expect(shellArg("a b\\\\", "win32")).toBe('"a b\\\\\\\\"');
    expect(shellArg('a\\"b', "win32")).toBe('"a\\\\""b"');
    // Backslashes elsewhere are literal and stay single.
    expect(shellArg("C:\\my tools\\x", "win32")).toBe('"C:\\my tools\\x"');
  });
  it("falls back to piship when the running script is not PiShip", () => {
    expect(pishipCommand("/usr/bin/vitest")).toBe("piship");
    expect(pishipCommand(undefined)).toBe("piship");
  });
});

describe("inert rule warnings", () => {
  it("warns on git.push and load resources that can never match", () => {
    const root = mkdtempSync(join(tmpdir(), "piship-init-inert-"));
    roots.push(root);
    const path = initDistribution(join(root, "acme-agent"), { managed: true });
    const rule = (id: string, action: string, resource: string) =>
      `    - { id: ${id}, action: ${action}, resource: "${resource}", effect: deny }\n`;
    const yaml = readFileSync(path, "utf8");
    expect(narrowRuleWarnings(readManifest(path))).toEqual([]);
    writeFileSync(
      path,
      yaml.replace(
        /^policy:\n/m,
        `policy:\n  enforced:\n${[
          rule("p-bare", "git.push", "main"),
          rule("p-cmd", "git.push", "git push origin main"),
          rule("p-ok", "git.push", "origin/main"),
          rule("p-any", "git.push", "**/main"),
          rule("l-bad", "skill.load", "company:resources/skills/**"),
          rule("l-ok", "skill.load", "company:./resources/skills/**"),
          rule("l-all", "extension.load", "company:**"),
          rule("l-builtin", "extension.load", "builtin:piship-workflow"),
          rule("l-star", "resource.load", "**"),
        ].join("")}`,
      ),
    );
    expect(
      narrowRuleWarnings(readManifest(path)).map((item) => item.path),
    ).toEqual([
      "policy.enforced[0].resource",
      "policy.enforced[1].resource",
      "policy.enforced[4].resource",
    ]);
  });
});
