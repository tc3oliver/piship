import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { createServer, request as httpRequest } from "node:http";
import { connect } from "node:net";
import { networkInterfaces, tmpdir } from "node:os";
import { join } from "node:path";
import {
  type ConformanceReport,
  SANDBOX_BEHAVIORS,
  testSandboxAdapter,
} from "@piship/adapter-conformance";
import type { SandboxAdapterFactory } from "@piship/adapter-sdk";
import { createManagedFetch, type ManagedFetch } from "@piship/contracts";
import { openSandboxCredential, verifyPayload } from "@piship/core";
import { MemorySecretStore } from "@piship/credentials";
import { type GovernanceOptions, GovernanceSession } from "@piship/pi";
import { describeContainment } from "@piship/sandbox";
import { resolveTemplate } from "@piship/schema";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
// @ts-expect-error The adapter is plain JavaScript, as a distribution ships it.
import acmeContainerSandbox from "../sandbox/acme-container-sandbox.mjs";
import { leaks, scan } from "./support/distribution.js";
import {
  type BuiltDistribution,
  buildSandboxDistribution,
  distribution,
  type NetworkTarget,
  nodeImage,
  type SandboxService,
  type SandboxUser,
  startNetworkTarget,
  startSandboxService,
} from "./support/sandbox.js";

// The AcmeCode reference distribution's own sandbox: an organization-style
// service that runs each user's commands in a container with the project
// bind-mounted (examples/enterprise-reference/sandbox), and the custom adapter
// that lets PiShip use it. Real Docker, no mocks: the service is started as a
// user would start it, on its own loopback port, with its own instance name
// and keys, and everything it makes is removed when the file ends.
//
// What is shown: the service's boundary (credential, host name, loopback
// only, no privilege), the sandbox conformance kit against it (every behavior
// passes, none is skipped), and a governed session built from the committed
// manifest and lock, with the stored sandbox credential, whose first sandboxed
// command is preceded by PiShip's two-direction workspace check. Needs Docker;
// run with `npm run test:reference` after `npm run build`.

const adapter = acmeContainerSandbox as SandboxAdapterFactory;
// A principal the stored sandbox credential is bound to. The reference
// distribution's Keycloak users are not needed to show the binding.
const PRINCIPAL = {
  issuer: "https://issuer.example.invalid/realms/piship-reference",
  subject: "alice-subject",
};
const sha256 = (path: string) =>
  createHash("sha256").update(readFileSync(path)).digest("hex");
const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** Collect what `console` is given until the returned function is called; it is still shown. */
function captureConsole(into: string[]): () => void {
  const methods = ["log", "info", "warn", "error", "debug"] as const;
  const originals = methods.map((method) => console[method]);
  methods.forEach((method, index) => {
    console[method] = (...args: unknown[]) => {
      into.push(args.map(String).join(" "));
      (originals[index] as (...values: unknown[]) => void).apply(console, args);
    };
  });
  return () =>
    methods.forEach((method, index) => {
      console[method] = originals[index] as (typeof console)[typeof method];
    });
}

/** The network policy the reference manifest resolves to for a loopback stack. */
const policy = {
  inheritProxyEnvironment: false,
  additionalCA: [],
  privateOnly: true,
  allowHosts: ["127.0.0.1"],
} as const;

/** A git repository with its control files, as PiShip finds a project. */
function makeProject(root: string, name: string, config = ""): string {
  const project = join(root, name);
  for (const directory of [".git/hooks", ".git/info"])
    mkdirSync(join(project, directory), { recursive: true });
  writeFileSync(
    join(project, ".git", "config"),
    `[core]\n\tbare = false\n${config}`,
  );
  writeFileSync(join(project, ".git", "HEAD"), "ref: refs/heads/main\n");
  writeFileSync(
    join(project, ".git", "hooks", "pre-commit"),
    "#!/bin/sh\necho hook\n",
  );
  writeFileSync(join(project, "notes.txt"), "workspace notes\n");
  return project;
}

function docker(...args: string[]) {
  const done = spawnSync("docker", args, { encoding: "utf8" });
  if (done.status !== 0)
    throw new Error(`docker ${args[0]} failed: ${done.stderr.trim()}`);
  return done.stdout;
}

interface Inspected {
  Config: { User: string; Labels: Record<string, string> };
  HostConfig: {
    Privileged: boolean;
    CapAdd: string[] | null;
    CapDrop: string[] | null;
    SecurityOpt: string[] | null;
    ReadonlyRootfs: boolean;
    NetworkMode: string;
    PortBindings: Record<string, unknown> | null;
    PidMode: string;
    IpcMode: string;
    UsernsMode: string;
    AutoRemove: boolean;
    Memory: number;
    PidsLimit: number;
    Devices: unknown[] | null;
  };
  Mounts: { Type: string; Source: string; Destination: string; RW: boolean }[];
}

const inspect = (id: string) =>
  (JSON.parse(docker("inspect", id)) as Inspected[])[0] as Inspected;

/** A request with a Host header of the caller's choosing. */
function statusWithHost(service: SandboxService, host: string) {
  return new Promise<number | undefined>((resolve, reject) => {
    const sent = httpRequest(
      {
        host: "127.0.0.1",
        port: service.port,
        path: "/v1/status",
        headers: { host, authorization: `Bearer ${service.key("alice")}` },
      },
      (response) => {
        response.resume();
        resolve(response.statusCode);
      },
    );
    sent.on("error", reject).end();
  });
}

/** Run a command through the service's API, as the adapter does. */
async function run(
  service: SandboxService,
  user: SandboxUser,
  id: string,
  command: string,
  extra: Record<string, unknown> = {},
) {
  const answer = await service.request(`/v1/sandboxes/${id}/exec`, {
    user,
    body: { command, ...extra },
  });
  let out = "";
  let exit: { exit: number | null; signal: string | null } | undefined;
  if (answer.status === 200)
    for (const line of answer.text.split("\n").filter(Boolean)) {
      const record = JSON.parse(line) as {
        stream?: string;
        data?: string;
        exit?: number | null;
        signal?: string | null;
      };
      if (record.stream === "stdout")
        out += Buffer.from(record.data ?? "", "base64").toString();
      else if (record.stream === undefined)
        exit = { exit: record.exit ?? null, signal: record.signal ?? null };
    }
  return { status: answer.status, out, exit };
}

async function create(
  service: SandboxService,
  user: SandboxUser,
  workspace: string,
) {
  const answer = await service.request("/v1/sandboxes", {
    user,
    body: { workspace, network: "deny" },
  });
  return {
    status: answer.status,
    text: answer.text,
    id: answer.status === 201 ? (answer.json() as { id: string }).id : "",
  };
}

/** Write the kit's report to PISHIP_KIT_REPORT, when set, like the other kit runs. */
function writeKitReport(report: ConformanceReport) {
  const path = process.env.PISHIP_KIT_REPORT;
  if (!path) return;
  let previous: Record<string, ConformanceReport> = {};
  try {
    previous = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    // a new file
  }
  writeFileSync(
    path,
    `${JSON.stringify({ ...previous, "reference container sandbox": report }, null, 2)}\n`,
  );
}

describe.skipIf(process.platform === "win32")(
  "the reference container sandbox",
  () => {
    let service: SandboxService;
    let target: NetworkTarget | undefined;

    beforeAll(async () => {
      service = await startSandboxService();
      console.info(
        `sandbox service: ${service.url}, instance ${service.instance}, image ${service.image}`,
      );
    }, 300_000);

    afterAll(async () => {
      target?.remove();
      await service?.stop();
    }, 120_000);

    describe("the service", () => {
      it("answers only a request that carries a credential it issued", async () => {
        // It says which service answered, so this run can tell its own from
        // one another run left on the port.
        expect((await service.request("/health")).json()).toEqual({
          status: "ok",
          instance: service.instance,
        });
        for (const init of [
          {},
          { key: "not-a-credential-at-all" },
          { key: `${service.key("alice")}x` },
        ]) {
          const refused = await service.request("/v1/status", init);
          expect(refused.status).toBe(401);
          expect(refused.headers["www-authenticate"]).toBe("Bearer");
          expect(refused.text).not.toContain(service.key("alice"));
        }
        const refusedCreate = await service.request("/v1/sandboxes", {
          body: { workspace: service.root, network: "deny" },
        });
        expect(refusedCreate.status).toBe(401);
        const ok = await service.request("/v1/status", { user: "alice" });
        expect(ok.json()).toMatchObject({ runtime: "ok", sandboxes: 0 });
        // Nothing was created for the unauthenticated attempts.
        expect(service.containers()).toEqual([]);
      });

      it("answers only for its own loopback name", async () => {
        expect(await statusWithHost(service, "attacker.example")).toBe(421);
        expect(await statusWithHost(service, `127.0.0.1:${service.port}`)).toBe(
          200,
        );
      });

      it("listens on loopback and on no other address of this machine", async () => {
        const external = Object.values(networkInterfaces())
          .flat()
          .flatMap((address) =>
            address && address.family === "IPv4" && !address.internal
              ? [address.address]
              : [],
          );
        // A CI runner always has a non-loopback IPv4 address, so there the
        // check must run rather than skip.
        if (process.env.CI === "true")
          expect(
            external,
            "no external IPv4 address on a CI runner",
          ).not.toEqual([]);
        if (external.length === 0) {
          console.info(
            "no external IPv4 address: the loopback-only check is skipped",
          );
          return;
        }
        for (const host of external) {
          const outcome = await new Promise<string>((resolve) => {
            const socket = connect({ host, port: service.port });
            const timer = setTimeout(() => {
              socket.destroy();
              resolve("timeout");
            }, 3000);
            socket.once("connect", () => {
              clearTimeout(timer);
              socket.destroy();
              resolve("connected");
            });
            socket.once("error", (error: NodeJS.ErrnoException) => {
              clearTimeout(timer);
              resolve(error.code ?? "error");
            });
          });
          expect(outcome, `${host}:${service.port}`).not.toBe("connected");
        }
      });

      it("starts each sandbox unprivileged with only the workspace mounted, and refuses what it may not mount", async () => {
        const project = makeProject(service.root, "inspected");
        const before = new Set(service.containers());
        const made = await create(service, "alice", project);
        expect(made.status, made.text).toBe(201);
        const [id] = service.containers().filter((entry) => !before.has(entry));
        expect(id).toBeTruthy();
        const container = inspect(id as string);
        // Commands run as the workspace's owner and group, never as root.
        const { uid, gid } = statSync(project);
        expect(uid).not.toBe(0);
        expect(container.Config.User).toBe(`${uid}:${gid}`);
        expect(container.HostConfig).toMatchObject({
          Privileged: false,
          CapAdd: null,
          CapDrop: ["ALL"],
          ReadonlyRootfs: true,
          NetworkMode: "none",
          AutoRemove: true,
          UsernsMode: "",
          PidMode: "",
        });
        expect(container.HostConfig.SecurityOpt).toEqual(["no-new-privileges"]);
        expect(container.HostConfig.IpcMode).not.toBe("host");
        expect(container.HostConfig.PortBindings ?? {}).toEqual({});
        expect(container.HostConfig.Devices ?? []).toEqual([]);
        expect(container.HostConfig.Memory).toBeGreaterThan(0);
        expect(container.HostConfig.PidsLimit).toBeGreaterThan(0);
        expect(container.Config.Labels["piship.sandbox.instance"]).toBe(
          service.instance,
        );
        // The mounts: the workspace, its .git read-only, and the one writable
        // place under it. No docker socket, no host directory beyond those.
        const bound = container.Mounts.filter((mount) => mount.Type === "bind")
          .map((mount) => [mount.Destination, mount.RW] as const)
          .sort(([a], [b]) => a.localeCompare(b));
        expect(bound).toEqual([
          ["/workspace", true],
          ["/workspace/.git", false],
          ["/workspace/.git/piship-workspace", true],
        ]);
        expect(
          container.Mounts.some((mount) => /docker\.sock/.test(mount.Source)),
        ).toBe(false);

        // Inside: the workspace owner's uid, no network interface but
        // loopback, the .git unchanged, and nothing of the host outside.
        const outside = join(service.root, "..", "outside-secret.txt");
        writeFileSync(outside, "host-only");
        const config = sha256(join(project, ".git", "config"));
        const inside = await run(
          service,
          "alice",
          made.id,
          [
            "id -u",
            "ls /sys/class/net",
            "( : >> .git/config ) 2>/dev/null && echo git-config-writable",
            "( mkdir .git/modules ) 2>/dev/null && echo git-modules-created",
            `cat ${JSON.stringify(outside)} 2>/dev/null && echo host-file-read`,
            "ls /workspace | tr '\\n' ' '",
          ].join("; "),
        );
        expect(inside.exit).toEqual({ exit: 0, signal: null });
        expect(inside.out).toBe(`${uid}\nlo\nnotes.txt `);
        expect(sha256(join(project, ".git", "config"))).toBe(config);
        expect(existsSync(join(project, ".git", "modules"))).toBe(false);
        rmSync(outside, { force: true });

        // Refusals: a directory outside the root, and one that is not a repository.
        const notGit = join(service.root, "not-a-repository");
        mkdirSync(notGit);
        expect((await create(service, "alice", tmpdir())).status).toBe(422);
        expect((await create(service, "alice", notGit)).status).toBe(409);
        expect(service.containers().length).toBe(before.size + 1);

        // Another user's key cannot reach it; its owner's key removes it.
        expect((await run(service, "bob", made.id, "true")).status).toBe(404);
        expect(
          (
            await service.request(`/v1/sandboxes/${made.id}`, {
              method: "DELETE",
              user: "bob",
            })
          ).status,
        ).toBe(404);
        expect(service.containers()).toContain(id);
        expect(
          (
            await service.request(`/v1/sandboxes/${made.id}`, {
              method: "DELETE",
              user: "alice",
            })
          ).status,
        ).toBe(204);
        expect(service.containers()).toEqual([...before]);
      });

      it("protects absent and existing Claude configuration without blocking ordinary workspace writes", async () => {
        for (const existing of [false, true]) {
          const project = makeProject(
            service.root,
            `protected-claude-${existing}`,
          );
          const claude = join(project, ".claude");
          const tools = join(project, "tools");
          mkdirSync(tools);
          if (existing) {
            mkdirSync(claude);
            writeFileSync(join(claude, "rules.md"), "trusted rules");
          }
          const answer = await service.request("/v1/sandboxes", {
            user: "alice",
            body: {
              workspace: project,
              network: "deny",
              writeProtect: {
                directories: [
                  claude,
                  join(project, ".pi"),
                  join(tools, ".claude", "hooks"),
                ],
                files: [
                  join(claude, "settings.json"),
                  join(claude, "settings.local.json"),
                ],
              },
            },
          });
          expect(answer.status, answer.text).toBe(201);
          const { id } = answer.json() as { id: string };
          try {
            const attempts = [
              ": > .claude/settings.json",
              ": > .claude/settings.local.json",
              "mkdir -p .claude/hooks",
              ": > .pi/settings.json",
              "mkdir -p tools/.claude/hooks",
              "mv .claude claude-old",
              "rmdir .claude",
              "mv tools tools-old",
              "rmdir tools/.claude",
            ];
            const result = await run(
              service,
              "alice",
              id,
              [
                ...attempts.map(
                  (command, index) =>
                    `if ( ${command} ) 2>/dev/null; then echo escaped-${index}; fi`,
                ),
                "printf 'ordinary-write\n' > notes.txt; cat notes.txt",
              ].join("; "),
            );
            expect(result.exit).toEqual({ exit: 0, signal: null });
            expect(result.out).toBe("ordinary-write\n");
            expect(readFileSync(join(project, "notes.txt"), "utf8")).toBe(
              "ordinary-write\n",
            );
            expect(existsSync(join(claude, "settings.json"))).toBe(false);
            expect(existsSync(join(claude, "settings.local.json"))).toBe(false);
            expect(existsSync(join(project, ".pi", "settings.json"))).toBe(
              false,
            );
            expect(existsSync(join(project, "tools-old"))).toBe(false);
            if (existing)
              expect(readFileSync(join(claude, "rules.md"), "utf8")).toBe(
                "trusted rules",
              );
          } finally {
            expect(
              (
                await service.request(`/v1/sandboxes/${id}`, {
                  method: "DELETE",
                  user: "alice",
                })
              ).status,
            ).toBe(204);
          }
        }
      });

      it("keeps a command's environment off this machine's process list and out of every file", async () => {
        const project = makeProject(service.root, "environment");
        const made = await create(service, "alice", project);
        const marker = `ENV-MARKER-${Math.random().toString(16).slice(2)}`;
        const running = run(service, "alice", made.id, "sleep 5; echo $LIVE", {
          env: { LIVE: marker },
        });
        // Look while the command's `docker exec` runs: poll until it is
        // there (a loaded machine is slow to start it), for up to three seconds.
        const exec = /docker exec --interactive .*sleep 5/;
        let processes = "";
        for (const deadline = Date.now() + 3000; Date.now() < deadline; ) {
          processes = spawnSync("ps", ["-axo", "args"], {
            encoding: "utf8",
          }).stdout;
          if (exec.test(processes)) break;
          await pause(100);
        }
        expect(processes).toMatch(exec);
        expect(processes).not.toContain(marker);
        // The environment goes to the CLI on its standard input: no file of
        // the service's holds it (its TMPDIR is private to it, and empty),
        // while the command runs or after.
        expect(readdirSync(service.scratch)).toEqual([]);
        // And the command has it.
        expect((await running).out).toBe(`${marker}\n`);
        expect(readdirSync(service.scratch)).toEqual([]);
        await service.request(`/v1/sandboxes/${made.id}`, {
          method: "DELETE",
          user: "alice",
        });
      });

      it("mounts a project only for the key bound to the user who owns it", async () => {
        // Commands run as the project's owner: a key that could name any
        // project under the service's roots could mount another user's.
        // bob's key is bound to another user than the one running the tests.
        const project = makeProject(service.root, "bound");
        const outside = await create(service, "bob", tmpdir());
        const before = service.containers();
        const refused = await create(service, "bob", project);
        expect(refused.status).toBe(422);
        expect(refused.text).toBe(outside.text);
        expect(service.containers()).toEqual(before);
        // Nothing was made in a project the key may not use.
        expect(existsSync(join(project, ".git", "piship-workspace"))).toBe(
          false,
        );
        const own = await create(service, "alice", project);
        expect(own.status, own.text).toBe(201);
        await service.request(`/v1/sandboxes/${own.id}`, {
          method: "DELETE",
          user: "alice",
        });
      });

      it("does not let a command outlive its cancellation by dropping its ID", async () => {
        const project = makeProject(service.root, "strays");
        const made = await create(service, "alice", project);
        const controller = new AbortController();
        const response = await fetch(
          `${service.url}/v1/sandboxes/${made.id}/exec`,
          {
            method: "POST",
            signal: controller.signal,
            headers: {
              authorization: `Bearer ${service.key("alice")}`,
              "content-type": "application/json",
              connection: "close",
            },
            // The command's own ID is the variable the cancel looks for;
            // these two start a process without it, and without any variable.
            body: JSON.stringify({
              command:
                "echo started; (env -u PISHIP_EXEC_ID bash -c 'sleep 3; echo late > stray-one' &); (env -i /bin/bash -c 'sleep 3; echo late > stray-two' &); sleep 30",
            }),
          },
        );
        await response.body?.getReader().read();
        controller.abort();
        await pause(5500);
        expect(existsSync(join(project, "stray-one"))).toBe(false);
        expect(existsSync(join(project, "stray-two"))).toBe(false);
        // The sandbox is still there, and runs the next command.
        expect((await run(service, "alice", made.id, "echo alive")).out).toBe(
          "alive\n",
        );
        await service.request(`/v1/sandboxes/${made.id}`, {
          method: "DELETE",
          user: "alice",
        });
      });

      it("runs from images pinned by digest", () => {
        // The sandbox image, and the one the network target listens in.
        for (const image of [service.image, nodeImage()])
          expect(image).toMatch(/@sha256:[0-9a-f]{64}$/);
      });

      it("does not mistake another service on its port for its own", async () => {
        // Asked for the running service's port, a second service cannot
        // listen and exits; the running one answers /health meanwhile, as
        // another instance, and is never taken for it.
        await expect(
          startSandboxService({ port: service.port }),
        ).rejects.toThrow(/exited \(1\) at start[\s\S]*EADDRINUSE/);
        // The running service is untouched, and still the one that answers.
        const health = await service.request("/health");
        expect((health.json() as { instance: string }).instance).toBe(
          service.instance,
        );
      });

      it("exits by itself, removing its sandboxes, when the process that started it is gone", async () => {
        // A run that is killed leaves nothing but the closed pipe on the
        // service's input. A second service, on a port of its own, shows
        // what that alone does: it removes its sandboxes and exits, and its
        // port is free again.
        const second = await startSandboxService();
        try {
          const project = makeProject(second.root, "orphaned");
          const made = await create(second, "alice", project);
          expect(made.status, made.text).toBe(201);
          expect(second.containers()).toHaveLength(1);
          const outcome = await second.orphan();
          expect(outcome.exited).toBe(true);
          expect(outcome.leftover).toEqual([]);
          await expect(
            fetch(`${second.url}/health`, { headers: { connection: "close" } }),
          ).rejects.toThrow();
        } finally {
          await second.stop();
        }
        // The first service was not touched.
        expect(await service.sandboxes("alice")).toBe(0);
      }, 120_000);
    });

    describe("the sandbox conformance kit", () => {
      it("passes every behavior against the service, and skips none", async () => {
        const project = join(service.root, "kit-workspace");
        mkdirSync(project);
        const listener = startNetworkTarget(service);
        target = listener;
        const managed = createManagedFetch(policy, "sandbox");
        // The kit gives the backend a fake credential of its own to watch
        // where it goes. The service knows only the keys it issued, so the
        // one header that carries the kit's credential is swapped for the
        // user's key on its way out, after the kit has watched it go.
        const asUser: ManagedFetch = (url, init) => {
          const headers = new Headers(init?.headers);
          const presented = headers.get("authorization");
          if (
            presented &&
            /^Bearer conformance-sandbox-credential-[0-9a-f]{16}$/.test(
              presented,
            )
          )
            headers.set("authorization", `Bearer ${service.key("alice")}`);
          return managed(url, { ...init, headers });
        };
        const started = Date.now();
        const shown: string[] = [];
        const release = captureConsole(shown);
        let report: ConformanceReport;
        try {
          report = await testSandboxAdapter(adapter, {
            context: {
              endpoint: service.url,
              fetch: asUser,
              distributionId: distribution.id,
            },
            workspace: project,
            sandboxes: () => service.sandboxes("alice"),
            networkTarget: { host: listener.host, port: listener.port },
            callTimeoutMs: 60_000,
          });
        } finally {
          release();
        }
        listener.remove();
        target = undefined;
        const summary = `sandbox conformance kit against the reference container sandbox (${Math.round((Date.now() - started) / 1000)} s):\n${report.results
          .map(
            (result) =>
              `${result.status.padEnd(7)} ${result.behavior}${result.reason ? `: ${result.reason}` : ""}`,
          )
          .join("\n")}`;
        console.info(summary);
        shown.push(summary);
        writeKitReport(report);
        // The kit's own leak evidence (a behavior of the report) covers only
        // its fake credential, the one it hands the backend to watch. The
        // user's real key never passes through the kit: it is swapped in on
        // the wire, in `asUser` above. So the report, and everything the run
        // printed, are searched for that key here.
        expect(
          leaks(`${JSON.stringify(report)}\n${shown.join("\n")}`, [
            service.key("alice"),
          ]),
        ).toEqual([]);
        expect(
          Object.fromEntries(
            report.results.map((result) => [result.behavior, result.status]),
          ),
        ).toEqual(
          Object.fromEntries(
            SANDBOX_BEHAVIORS.map((behavior) => [behavior, "passed"]),
          ),
        );
        // Every sandbox the kit made is gone.
        expect(await service.sandboxes("alice")).toBe(0);
      }, 600_000);
    });

    describe("in a governed AcmeCode session", () => {
      let built: BuiltDistribution;
      const temporary: string[] = [];
      const sessions: GovernanceSession[] = [];

      beforeAll(() => {
        built = buildSandboxDistribution("sandbox-distribution");
      }, 300_000);

      afterEach(async () => {
        for (const session of sessions.splice(0)) await session.close();
      });

      afterAll(async () => {
        for (const session of sessions.splice(0))
          await session.close().catch(() => undefined);
        built?.remove();
        for (const path of temporary.splice(0))
          rmSync(path, { recursive: true, force: true });
      }, 120_000);

      /** A user's sandbox credential slot for `targets`, as the launch opens it. */
      function slot(
        state: string,
        store: MemorySecretStore,
        targets: readonly string[],
      ) {
        return openSandboxCredential({
          distributionId: distribution.id,
          command: distribution.command,
          stateDir: state,
          provider: "custom",
          principal: PRINCIPAL,
          secretStore: store,
          targets,
        });
      }

      function newState() {
        const state = mkdtempSync(
          join(tmpdir(), `piship-reftest-${process.pid}-state-`),
        );
        temporary.push(state);
        return state;
      }

      /**
       * Open a governed session for `project` as the launch does: the built
       * payload and the lock it carries, the managed fetch under the
       * reference manifest's network policy, the endpoint from its runtime
       * variable, and the stored sandbox credential checked against that
       * endpoint's origin. With `key`, it is stored first, as
       * `<command> sandbox login` does.
       */
      async function open(options: {
        readonly project: string;
        readonly key?: string;
        readonly url?: string;
        readonly state?: string;
        readonly store?: MemorySecretStore;
      }) {
        const state = options.state ?? newState();
        const store = options.store ?? new MemorySecretStore();
        const home = join(state, "home");
        mkdirSync(home, { recursive: true });
        if (options.key !== undefined) {
          const key = options.key;
          await slot(state, store, [service.url]).save(async () => key);
        }
        const lock = verifyPayload(built.artifact) as GovernanceOptions["lock"];
        const session = await GovernanceSession.open({
          lock,
          distributionDir: built.artifact,
          stateDir: state,
          cwd: options.project,
          piVersion: lock.runtime.version,
          interactive: false,
          fetch: createManagedFetch(policy, "governance"),
          resolveTemplate: (field, template) =>
            resolveTemplate(field, template, ["ACMECODE_SANDBOX_URL"], {
              ACMECODE_SANDBOX_URL: options.url ?? service.url,
            }),
          homeDir: home,
          sandboxCredential: (targets) => slot(state, store, targets).access(),
        });
        sessions.push(session);
        return { session, state, store };
      }

      async function bash(
        session: GovernanceSession,
        cwd: string,
        command: string,
      ) {
        let output = "";
        const result = await session.sandbox.exec(command, cwd, {
          onData: (chunk) => {
            output += chunk.toString("utf8");
          },
        });
        return { ...result, output };
      }

      it("checks the workspace in both directions before the first sandboxed command, and finds it shared", async () => {
        const project = makeProject(service.root, "governed");
        const hook = sha256(join(project, ".git", "hooks", "pre-commit"));
        const config = sha256(join(project, ".git", "config"));
        const { session, state } = await open({
          project,
          key: service.key("alice"),
        });
        const reports: string[] = [];
        session.sandbox.onWorkspaceReport((report) =>
          reports.push(`${report.effective}/${report.verification}`),
        );

        // Activation made the sandbox and ran PiShip's outside check in it;
        // the workspace is declared shared and not yet verified, and nothing
        // has been written into the project.
        expect(session.sandbox.report).toMatchObject({
          level: "enforced",
          adapter: "acme-container",
          provider: "custom",
          isolation: "remote",
          network: "deny",
          verification: "backend-attested",
          // No network probe: denial is the service's word, and no
          // allow-mode container was created to contrast it.
          networkDenial: { evidence: "attested", probe: false },
        });
        expect(session.sandbox.report.planes).toEqual(
          expect.arrayContaining([
            "workspace-confinement",
            "git-control-protection",
            "network-deny",
            "environment-filter",
          ]),
        );
        expect(session.sandbox.report.planes).not.toContain(
          "host-filesystem-isolation",
        );
        expect(session.sandbox.report.workspace).toMatchObject({
          declared: "shared",
          verification: "pending",
          complete: false,
        });
        expect(await service.sandboxes("alice")).toBe(1);
        expect(readdirSync(join(project, ".git", "piship-workspace"))).toEqual(
          [],
        );

        // The first command is preceded by the check: the sandbox reads a
        // file the host wrote and the host reads one the sandbox wrote, both
        // at once, and the git control files could not be changed.
        const first = await bash(
          session,
          project,
          "cat notes.txt; printf from-the-sandbox > written.txt",
        );
        expect(first).toEqual({ exitCode: 0, output: "workspace notes\n" });
        expect(readFileSync(join(project, "written.txt"), "utf8")).toBe(
          "from-the-sandbox",
        );
        expect(session.sandbox.workspace()).toMatchObject({
          declared: "shared",
          effective: "shared",
          verification: "verified",
          hostToSandbox: "immediate",
          sandboxToHost: "immediate",
          gitControlProtection: "attested-renames",
          complete: true,
        });
        expect(
          describeContainment(
            session.sandbox.report,
            session.sandbox.workspace(),
          ),
        ).toMatch(
          /Workspace: shared \(verified \S+, both directions immediate\)/,
        );
        const planted = await bash(
          session,
          project,
          "if ( : > .claude/settings.json ) 2>/dev/null; then echo planted; fi; if mv .claude claude-old 2>/dev/null; then echo moved; fi; echo protected",
        );
        expect(planted.output).toBe("protected\n");
        expect(existsSync(join(project, ".claude", "settings.json"))).toBe(
          false,
        );
        expect(existsSync(join(project, "claude-old"))).toBe(false);
        expect(session.metrics.snapshot().workspace).toMatchObject({
          declared: "shared",
          effective: "shared",
          verification: "verified",
        });

        // The result counts for the next commands: one check, no more.
        const verifiedAt = session.sandbox.workspace()?.verifiedAt;
        expect((await bash(session, project, "ls written.txt")).output).toBe(
          "written.txt\n",
        );
        expect(session.sandbox.workspace()?.verifiedAt).toBe(verifiedAt);
        expect(reports).toEqual(["shared/verified"]);

        // A subdirectory is the working directory the command asked for.
        mkdirSync(join(project, "src"));
        expect((await bash(session, join(project, "src"), "pwd")).output).toBe(
          "/workspace/src\n",
        );

        // Nothing of the check is left, and the protected files are as they were.
        expect(readdirSync(join(project, ".git", "piship-workspace"))).toEqual(
          [],
        );
        expect(sha256(join(project, ".git", "hooks", "pre-commit"))).toBe(hook);
        expect(sha256(join(project, ".git", "config"))).toBe(config);
        expect(existsSync(join(project, ".git", "modules"))).toBe(false);

        // Ending the session removes the sandbox.
        await session.close();
        expect(await service.sandboxes("alice")).toBe(0);

        // The credential is in the secret store only: not in the state, the
        // audit log, the lock, or the built distribution.
        const secrets = [service.key("alice")];
        expect(scan(state, secrets)).toEqual([]);
        expect(scan(built.artifact, secrets)).toEqual([]);
        expect(
          leaks(
            readFileSync(join(state, "logs", "audit.jsonl"), "utf8"),
            secrets,
          ),
        ).toEqual([]);
      }, 300_000);

      it("protects existing and missing hooks directories in the working tree", async () => {
        const project = makeProject(
          service.root,
          "hooks-in-tree",
          "[core]\n\thooksPath = .githooks\n",
        );
        mkdirSync(join(project, ".githooks"));
        writeFileSync(join(project, ".githooks", "pre-push"), "#!/bin/sh\n");
        const { session } = await open({ project, key: service.key("alice") });
        const attempt = await bash(
          session,
          project,
          "( : > .githooks/planted ) 2>/dev/null && echo planted; ( : >> .githooks/pre-push ) 2>/dev/null && echo appended; echo done",
        );
        expect(attempt.output).toBe("done\n");
        expect(existsSync(join(project, ".githooks", "planted"))).toBe(false);
        // The scripts git runs from the working tree are read-only, and PiShip
        // does not vouch for them: the commands run, git control is not verified.
        expect(session.sandbox.workspace()).toMatchObject({
          effective: "shared",
          verification: "verified",
          gitControlProtection: "not-verified",
          complete: true,
        });
        await session.close();

        // A missing hooks directory is covered by a read-only tmpfs. The
        // session may run, while both planting a hook and replacing the
        // protected mount point remain impossible.
        const missing = makeProject(
          service.root,
          "hooks-missing",
          "[core]\n\thooksPath = .githooks\n",
        );
        const { session: missingSession } = await open({
          project: missing,
          key: service.key("alice"),
        });
        const missingAttempt = await bash(
          missingSession,
          missing,
          "if ( : > .githooks/pre-push ) 2>/dev/null; then echo planted; fi; if mv .githooks hooks-old 2>/dev/null; then echo moved; fi; if rmdir .githooks 2>/dev/null; then echo removed; fi; printf ordinary > ordinary.txt; echo protected",
        );
        expect(missingAttempt).toEqual({ exitCode: 0, output: "protected\n" });
        expect(existsSync(join(missing, ".githooks", "pre-push"))).toBe(false);
        expect(existsSync(join(missing, "hooks-old"))).toBe(false);
        expect(readFileSync(join(missing, "ordinary.txt"), "utf8")).toBe(
          "ordinary",
        );
        expect(missingSession.sandbox.workspace()).toMatchObject({
          effective: "shared",
          verification: "verified",
          gitControlProtection: "not-verified",
          complete: true,
        });
        await missingSession.close();
        expect(await service.sandboxes("alice")).toBe(0);
      }, 300_000);

      it("sends the stored credential only to the origin it was stored for", async () => {
        const project = makeProject(service.root, "origin");
        const requests: string[] = [];
        const stray = createServer((request, response) => {
          requests.push(request.url ?? "");
          response.end();
        });
        await new Promise<void>((resolve) =>
          stray.listen(0, "127.0.0.1", resolve),
        );
        const strayUrl = `http://127.0.0.1:${(stray.address() as { port: number }).port}`;
        try {
          const first = await open({ project, key: service.key("alice") });
          await first.session.close();
          // The runtime variable now names another host: nothing is sent, and
          // no container is made.
          await expect(
            open({
              project,
              url: strayUrl,
              state: first.state,
              store: first.store,
            }),
          ).rejects.toMatchObject({ code: "SANDBOX_UNAVAILABLE" });
          expect(requests).toEqual([]);
          expect(await service.sandboxes("alice")).toBe(0);
          expect(
            slot(first.state, first.store, [strayUrl]).status(),
          ).toMatchObject({ state: "origin-mismatch" });
          expect(
            slot(first.state, first.store, [service.url]).status(),
          ).toMatchObject({ state: "valid" });
        } finally {
          stray.close();
        }
      }, 300_000);

      it("marks a credential the service refuses as rejected, and asks for a new one", async () => {
        const project = makeProject(service.root, "rejected");
        const state = newState();
        const store = new MemorySecretStore();
        // A key the service never issued.
        const wrong = `sbxk_${"x".repeat(43)}`;
        const refused = await open({ project, key: wrong, state, store }).catch(
          (error: unknown) => error as { code?: string; message?: string },
        );
        expect(refused).toMatchObject({ code: "SANDBOX_UNAVAILABLE" });
        expect(JSON.stringify(refused)).not.toContain(wrong);
        expect(slot(state, store, [service.url]).status().state).toBe(
          "rejected",
        );
        // The next launch does not send it again, and says what to do.
        const again = await open({ project, state, store }).catch(
          (error: unknown) => error as { userAction?: string },
        );
        expect(again).toMatchObject({
          userAction: expect.stringMatching(/sandbox login/),
        });
        expect(await service.sandboxes("alice")).toBe(0);
        // A new key stored with sandbox login is used.
        const { session } = await open({
          project,
          key: service.key("alice"),
          state,
          store,
        });
        expect((await bash(session, project, "echo renewed")).output).toBe(
          "renewed\n",
        );
        await session.close();
      }, 300_000);
    });

    it("removes every container when the service stops", async () => {
      const project = makeProject(service.root, "shutdown");
      const held = await create(service, "alice", project);
      expect(held.status).toBe(201);
      const running = run(service, "alice", held.id, "sleep 30");
      await pause(500);
      const { leftover } = await service.stop();
      expect(leftover).toEqual([]);
      expect((await running).exit).toEqual({ exit: null, signal: "SIGKILL" });
    }, 120_000);
  },
);
