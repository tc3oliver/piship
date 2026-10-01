// The governed session's side of the sandbox workspace check: the project
// origin reaches the sandbox (a working-tree sentinel directory only for a
// company-origin project), each result is recorded in local metrics and, when
// lower than declared, shown once as a session notice, and Plan mode never
// writes a sentinel because no command reaches the sandbox there. The backend
// is a custom adapter module with a shared workspace: commands run with
// /bin/sh in the project itself, so both sides are the same files.
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type {
  ExtensionContext,
  ExtensionFactory,
  InlineExtension,
} from "@earendil-works/pi-coding-agent";
import type { ManagedFetch } from "@piship/contracts";
import { resolveLock } from "@piship/core";
import { afterEach, describe, expect, it } from "vitest";
import { governanceHooks, workflowExtension } from "./builtins.js";
import { GovernanceSession } from "./governance-session.js";

const posix = process.platform !== "win32";
const asRoot = typeof process.getuid === "function" && process.getuid() === 0;
const CHECK = "echo piship-ws done";

const roots: string[] = [];
const sessions: GovernanceSession[] = [];
afterEach(async () => {
  for (const session of sessions.splice(0))
    await session.close().catch(() => undefined);
  for (const root of roots.splice(0)) {
    // Undo the read-only modes that keep the git control files protected.
    for (const path of ["", "hooks", "info"])
      if (existsSync(join(root, "workspace", ".git", path)))
        chmodSync(join(root, "workspace", ".git", path), 0o755);
    rmSync(root, { recursive: true, force: true });
  }
  delete (globalThis as { __pishipWorkspaceRequests?: unknown })
    .__pishipWorkspaceRequests;
});

/**
 * A shared-workspace custom adapter; records every command on globalThis.
 * With `network`, it declares that probe; with the network allowed its
 * sandbox reaches the `reachable` targets (`host:port`), with it denied none.
 */
function adapter(
  declaration: Record<string, unknown>,
  network?: {
    readonly probe: { host: string; port: number };
    readonly reachable: readonly string[];
  },
): string {
  return `
import { spawn } from "node:child_process";
import { join } from "node:path";
export default () => ({
  id: "acme-shared",
  available: async () => ({ available: true }),
  capabilities: () => ({
    isolation: "remote",
    planes: ["workspace-confinement", "git-control-protection", "network-deny", "environment-filter"],
    network: ["deny", "allow"],
    localProcesses: false,
    workspace: ${JSON.stringify(declaration)},
    ${network ? `networkProbe: ${JSON.stringify(network.probe)},` : ""}
  }),
  prepare: async ({ profile }) => ({
    exec: (request, io) => {
      (globalThis.__pishipWorkspaceRequests ??= []).push(request.command);
      if (request.command.includes("piship-sandbox-ready")) {
        io.onStdout(Buffer.from("piship-sandbox-ready " + (request.env.PISHIP_PROBE_UNLISTED ?? "unset") + "\\n"));
        const target = /\\/dev\\/tcp\\/([^/']+)\\/(\\d+)'/.exec(request.command);
        if (target) {
          const reached = profile.network === "allow" &&
            ${JSON.stringify(network?.reachable ?? [])}.includes(target[1] + ":" + target[2]);
          io.onStdout(Buffer.from(reached ? "piship-network-reachable\\n" : "piship-network-blocked\\n"));
        }
        return Promise.resolve({ exitCode: 0 });
      }
      const cwd = request.workspacePath && request.workspacePath !== "."
        ? join(profile.workspace, ...request.workspacePath.split("/"))
        : profile.workspace;
      return new Promise((resolve, reject) => {
        const child = spawn("/bin/sh", ["-c", request.command], {
          cwd,
          env: { ...request.env, PATH: "/usr/bin:/bin" },
          stdio: ["ignore", "pipe", "pipe"],
        });
        const abort = () => child.kill("SIGKILL");
        io.signal.addEventListener("abort", abort, { once: true });
        child.stdout.on("data", io.onStdout);
        child.stderr.on("data", io.onStderr);
        child.once("error", reject);
        child.once("close", (code, signal) => {
          io.signal.removeEventListener("abort", abort);
          resolve({ exitCode: code, signal });
        });
      });
    },
    dispose: async () => {},
  }),
});
`;
}

const requests = (): string[] =>
  (globalThis as { __pishipWorkspaceRequests?: string[] })
    .__pishipWorkspaceRequests ?? [];
const checks = () => requests().filter((command) => command.includes(CHECK));

async function open(options: {
  readonly declaration: Record<string, unknown>;
  readonly company: boolean;
  /** Text added to the repository's git config. */
  readonly config?: string;
  readonly network?: Parameters<typeof adapter>[1];
}) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "piship-gov-ws-")));
  roots.push(root);
  const distribution = join(root, "distribution");
  const workspace = join(root, "workspace");
  const git = join(workspace, ".git");
  mkdirSync(distribution, { recursive: true });
  mkdirSync(join(git, "hooks"), { recursive: true });
  mkdirSync(join(git, "info"));
  writeFileSync(join(git, "HEAD"), "ref: refs/heads/main\n");
  writeFileSync(
    join(git, "config"),
    `[core]\n\tbare = false\n[remote "origin"]\n\turl = https://git.acme.example/acme/app.git\n${options.config ?? ""}`,
  );
  writeFileSync(join(git, "hooks", "pre-commit"), "#!/bin/sh\necho hook\n");
  writeFileSync(join(workspace, "notes.txt"), "workspace notes\n");
  // The backend must keep the git control files read-only from inside the
  // sandbox, and keep files git follows (`commondir`, `config.worktree`) from
  // appearing; this shared fake does it with file modes. The sentinel
  // location is made up front, since nothing can be created in `.git` now.
  mkdirSync(join(git, "piship-workspace"), { mode: 0o700 });
  chmodSync(join(git, "config"), 0o444);
  chmodSync(join(git, "hooks"), 0o555);
  chmodSync(join(git, "info"), 0o555);
  chmodSync(git, 0o555);
  const source = adapter(options.declaration, options.network);
  for (const path of ["sandbox/acme.mjs", "resources/sandbox/acme.mjs"]) {
    mkdirSync(dirname(join(distribution, path)), { recursive: true });
    writeFileSync(join(distribution, path), source);
  }
  const manifest = join(distribution, "piship.yaml");
  writeFileSync(
    manifest,
    [
      "schema: piship/v1alpha3",
      "app: { id: unit, name: Unit, command: unit, version: 0.1.0 }",
      'runtime: { pi: "0.87.1" }',
      "deployment: { mode: personal }",
      "policy:",
      "  id: unit",
      "  version: 1",
      "  default: deny",
      "  defaults:",
      '    - { id: read, action: filesystem.read, resource: "workspace/**", effect: allow }',
      '    - { id: shell, action: shell.execute, resource: "**", effect: allow }',
      '    - { id: tools, action: tool.execute, resource: "*", effect: allow }',
      ...(options.company
        ? [
            "  projectTrust:",
            "    company:",
            '      match: [{ remote: "git.acme.example/acme/*" }]',
          ]
        : []),
      "sandbox:",
      "  required: true",
      "  provider: custom",
      "  adapter: ./sandbox/acme.mjs",
      "  network: { mode: deny }",
      "  environment: { allow: [PATH] }",
      "audit:",
      "  enabled: true",
      "  sinks:",
      "    - { id: local, type: file, required: false }",
      "",
    ].join("\n"),
  );
  const lock = resolveLock(manifest);
  const session = await GovernanceSession.open({
    lock: lock as Parameters<typeof GovernanceSession.open>[0]["lock"],
    distributionDir: distribution,
    stateDir: join(root, "state"),
    cwd: workspace,
    piVersion: "0.87.1",
    interactive: false,
    fetch: (() => {
      throw new Error("no network in unit tests");
    }) as unknown as ManagedFetch,
    resolveTemplate: (_key, template) => template,
    homeDir: join(root, "home"),
  });
  sessions.push(session);
  return { session, root, workspace, git };
}

/** A Pi context whose UI, when it has one, collects the notices. */
function context(notices: string[] = [], hasUI = true): ExtensionContext {
  return {
    hasUI,
    ui: {
      confirm: async () => true,
      select: async () => undefined,
      setStatus: () => {},
      notify: (message: string) => notices.push(message),
    },
  } as unknown as ExtensionContext;
}

/** The factory of an inline extension, in either of its public shapes. */
const factoryOf = (extension: InlineExtension): ExtensionFactory =>
  typeof extension === "function" ? extension : extension.factory;

/** The governance hooks and workflow commands, as Pi would register them. */
function load(session: GovernanceSession, workflow: boolean) {
  const handlers = new Map<string, (event: unknown, ctx: unknown) => unknown>();
  const commands = new Map<
    string,
    { handler: (args: string, ctx: unknown) => Promise<void> }
  >();
  const api = {
    on: (event: string, handler: (event: unknown, ctx: unknown) => unknown) =>
      handlers.set(event, handler),
    registerCommand: (
      name: string,
      options: { handler: (args: string, ctx: unknown) => Promise<void> },
    ) => commands.set(name, options),
  } as never;
  factoryOf(governanceHooks(session))(api);
  if (workflow) factoryOf(workflowExtension(session, {}))(api);
  return { handlers, commands };
}

/** Run one `!` command through the governed shell operations. */
async function userBash(
  hooks: ReturnType<typeof load>,
  workspace: string,
  command: string,
  ctx = context(),
) {
  const handler = hooks.handlers.get("user_bash");
  if (!handler) throw new Error("user_bash is not registered");
  const { operations } = (await handler({ command }, ctx)) as {
    operations: {
      exec: (
        command: string,
        cwd: string,
        options: { onData: (chunk: Buffer) => void },
      ) => Promise<{ exitCode: number | null }>;
    };
  };
  let output = "";
  const result = await operations.exec(command, workspace, {
    onData: (chunk) => {
      output += chunk.toString("utf8");
    },
  });
  return { ...result, output };
}

/** Every 32-hex value (nonces and sentinel tokens) the workspace checks carried. */
const checkSecrets = () => [
  ...new Set(
    checks().flatMap((command) => command.match(/[0-9a-f]{32}/g) ?? []),
  ),
];

describe.skipIf(!posix || asRoot)(
  "the governed session's workspace check",
  () => {
    it("uses a working-tree sentinel directory only for a company-origin project", async () => {
      const declaration = { mode: "shared", sentinelDir: "sync-probe" };
      const company = await open({ declaration, company: true });
      expect(company.session.project.origin).toBe("company");
      const hooks = load(company.session, false);
      expect(
        (await userBash(hooks, company.workspace, "echo company")).output,
      ).toBe("company\n");
      expect(company.session.sandbox.workspace()).toMatchObject({
        declared: "shared",
        effective: "shared",
        verification: "verified",
        complete: true,
      });
      // Created in the working tree, and the run's own directory removed.
      expect(
        readdirSync(join(company.workspace, "sync-probe", "piship-workspace")),
      ).toEqual([]);
      await company.session.close();
      delete (globalThis as { __pishipWorkspaceRequests?: unknown })
        .__pishipWorkspaceRequests;

      const other = await open({ declaration, company: false });
      expect(other.session.project.origin).toBe("unknown");
      expect(
        (await userBash(load(other.session, false), other.workspace, "echo x"))
          .output,
      ).toBe("x\n");
      expect(other.session.sandbox.workspace()).toMatchObject({
        declared: "shared",
        effective: "snapshot",
        verification: "unverifiable",
        complete: false,
      });
      expect(existsSync(join(other.workspace, "sync-probe"))).toBe(false);
    });

    it("records each result in metrics, shows one notice when lower than declared, and leaks no path, nonce or token", async () => {
      const { session, root, workspace, git } = await open({
        declaration: { mode: "shared", sentinelDir: "sync-probe" },
        company: false,
      });
      const hooks = load(session, false);
      // A notice raised before the UI attaches is held, then shown once.
      await userBash(hooks, workspace, "echo one", context([], false));
      const notices: string[] = [];
      session.attachNotices((message) => notices.push(message));
      await userBash(hooks, workspace, "echo two");
      expect(notices).toEqual([
        expect.stringMatching(
          /^The sandbox workspace is weaker than the distribution declares\. Workspace: snapshot \(declared shared; no PiShip-owned location to verify it: /,
        ),
      ]);
      expect(checks()).toHaveLength(1);
      expect(session.metrics.snapshot().workspace).toEqual({
        declared: "shared",
        effective: "snapshot",
        verification: "unverifiable",
        checkedAt: expect.stringMatching(
          /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/,
        ),
      });
      await session.close();

      const metrics = readFileSync(
        join(root, "state", "logs", "metrics.json"),
        "utf8",
      );
      expect(JSON.parse(metrics).workspace).toMatchObject({
        declared: "shared",
        verification: "unverifiable",
      });
      const audit = readFileSync(
        join(root, "state", "logs", "audit.jsonl"),
        "utf8",
      );
      const start = audit
        .split("\n")
        .filter(Boolean)
        .map((line) => JSON.parse(line))
        .find((event) => event.event === "session.start");
      expect(start.detail).toEqual({
        project: "unknown",
        sandbox: "enforced",
        workspace: "shared",
      });
      // No secret, nonce, token or path in anything the session wrote or showed.
      const secrets = checkSecrets();
      expect(secrets.length).toBeGreaterThan(0);
      for (const text of [metrics, audit, ...notices]) {
        for (const value of secrets) expect(text).not.toContain(value);
        for (const path of [
          root,
          workspace,
          git,
          "piship-workspace",
          "sync-probe",
        ])
          expect(text).not.toContain(path);
      }
    });

    it("records network denial evidence, and shows one notice when a declared probe proved nothing", async () => {
      const probe = { host: "probe.sandbox.test", port: 8443 };
      const verified = await open({
        declaration: { mode: "shared" },
        company: false,
        network: { probe, reachable: ["probe.sandbox.test:8443"] },
      });
      const quiet: string[] = [];
      verified.session.attachNotices((message) => quiet.push(message));
      expect(verified.session.metrics.snapshot().sandbox).toMatchObject({
        level: "enforced",
        networkDenial: "verified",
      });
      expect(quiet).toEqual([]);

      // The allow-mode sandbox reaches something else: nothing is proven.
      const attested = await open({
        declaration: { mode: "shared" },
        company: false,
        network: { probe, reachable: ["other.sandbox.test:8443"] },
      });
      const notices: string[] = [];
      attested.session.attachNotices((message) => notices.push(message));
      expect(attested.session.metrics.snapshot().sandbox).toMatchObject({
        level: "enforced",
        networkDenial: "attested",
      });
      expect(notices).toEqual([
        "Network denial in the sandbox is attested by the acme-shared backend, not verified: the backend's network probe was not reachable from an allow-mode sandbox either, so a blocked connection proves nothing.",
      ]);
      for (const text of notices)
        expect(text).not.toContain("probe.sandbox.test");
    });

    it("shows the notice through the session's UI as soon as it is raised, once", async () => {
      const { session, workspace } = await open({
        declaration: { mode: "shared", sentinelDir: "sync-probe" },
        company: false,
      });
      const hooks = load(session, false);
      const notices: string[] = [];
      const ctx = context(notices);
      await userBash(hooks, workspace, "echo one", ctx);
      await userBash(hooks, workspace, "echo two", ctx);
      expect(notices).toEqual([
        expect.stringContaining("The sandbox workspace is weaker"),
      ]);
    });

    it("follows only the first 64 includes of a large git config, so the check still runs, and reports git control not verified", async () => {
      // One config file can list tens of thousands of includes; each would be
      // a protected path in the check command.
      const includes = Array.from(
        { length: 5000 },
        (_, index) => `[include]\n\tpath = extra-${index}`,
      ).join("\n");
      const { session, workspace } = await open({
        declaration: { mode: "shared" },
        company: false,
        config: `${includes}\n`,
      });
      const hooks = load(session, false);
      expect((await userBash(hooks, workspace, "echo hi")).output).toBe("hi\n");
      expect(session.sandbox.workspace()).toMatchObject({
        effective: "shared",
        verification: "verified",
        gitControlProtection: "not-verified",
      });
      expect(session.sandbox.report.warnings.join("\n")).toContain(
        "more than 64 included files, hooks paths, or environment settings",
      );
      expect(checks()).toHaveLength(1);
      expect(checks()[0]?.length).toBeLessThan(40_000);
    });

    it("writes no sentinel in Plan mode, then checks once before the first command in Build mode (T10)", async () => {
      const { session, workspace, git } = await open({
        declaration: { mode: "shared" },
        company: false,
      });
      const hooks = load(session, true);
      const ctx = context();
      expect(session.workflowMode).toBe("plan");
      const location = join(git, "piship-workspace");
      // The agent's bash tool and a user's `!` command are both refused.
      expect(
        await hooks.handlers.get("tool_call")?.({ toolName: "bash" }, ctx),
      ).toMatchObject({ block: true });
      expect(await userBash(hooks, workspace, "echo plan", ctx)).toMatchObject({
        exitCode: 126,
        output: expect.stringContaining("Plan mode does not run commands"),
      });
      // No sentinel; the location itself was made up front.
      expect(readdirSync(location)).toEqual([]);
      expect(checks()).toEqual([]);
      expect(session.sandbox.workspace()?.verification).toBe("pending");

      await hooks.commands.get("build")?.handler("", ctx);
      expect(session.workflowMode).toBe("build");
      expect(readdirSync(location)).toEqual([]);
      expect((await userBash(hooks, workspace, "echo built", ctx)).output).toBe(
        "built\n",
      );
      expect((await userBash(hooks, workspace, "echo again", ctx)).output).toBe(
        "again\n",
      );
      // Created for the first command and removed again; checked only once.
      expect(readdirSync(location)).toEqual([]);
      expect(checks()).toHaveLength(1);
      expect(session.sandbox.workspace()).toMatchObject({
        effective: "shared",
        verification: "verified",
      });
      expect(session.metrics.snapshot().workspace).toMatchObject({
        declared: "shared",
        effective: "shared",
        verification: "verified",
      });
      // The hooks the sandbox could reach are unchanged.
      expect(readdirSync(join(git, "hooks"))).toEqual(["pre-commit"]);
    });
  },
);
