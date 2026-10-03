import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { platformStoreRefs } from "../../../tests/helpers/secret-store.js";
import {
  cliPath,
  fileStoreValues,
  type Installed,
  installDistribution,
  launcherCommand,
  leaks,
  scan,
  storeDescription,
  storeMode,
} from "./support/distribution.js";
import {
  accessTokenStatus,
  clearQueuedFaults,
  gatewayDeleteKey,
  gatewayKey,
  gatewayModels,
  queueToolCalls,
  refreshTokenStatus,
  upstreamRequests,
} from "./support/services.js";
import { referenceDirectory, type Stack, startStack } from "./support/stack.js";

// The AcmeCode reference distribution against the live reference stack, for one
// user, as the managed clean-machine flow (tests/e2e/managed-clean-machine.test.ts):
// build, install, launch, sign in on the real Keycloak authorization page,
// exchange the identity for a scoped credential at the reference broker, keep
// it in the secret store, discover models, send a request through LiteLLM,
// resume the session, `doctor`, run commands the model asks for inside the
// sandbox, update through a signed channel, roll back, renew a credential the
// gateway rejected, sign out, and uninstall. Needs Docker; run with
// `npm run test:reference` after `npm run build`.
//
// The distribution is the committed one with two edits its owner would make:
// the manifest lets the agent run shell commands in Build mode (as committed
// it asks before each one, which a headless run denies), and it pins a release
// key, so a channel signed with it can offer 1.1.0. The channel is served
// from a loopback directory: the update host is not part of the stack.
// The mock upstream is queued to ask for the tool calls that make the model
// run commands (`POST /__mock/faults`), because a client that sends its own
// prompt cannot make the mock ask. The same steps run against local fixtures
// on every OS in tests/e2e/managed-clean-machine.test.ts; what only this file
// proves is the live identity provider, broker and gateway.
//
// The tests follow one user's session in order, so a failure early on makes
// the later ones fail too: fix the first failure first.

const mode = storeMode();
const backend = storeDescription(mode);
const ALICE_MODELS = ["acme/coder", "acme/general"];
const ID = "acmecode-reference";
// The agent must not read this, however it is asked.
const SSH_CANARY = "ssh-private-key-reference-canary";
const escaped = (text: string) =>
  text.replace(/[.*+?^${}()|[\]\\]/g, (character) => `\\${character}`);

describe.skipIf(process.platform === "win32")(
  "AcmeCode on the reference stack",
  () => {
    let stack: Stack;
    let acme: Installed;
    // Every secret PiShip held at any point, for the leak scans.
    const seen = new Set<string>();
    const remember = async () => {
      const held = await acme.secrets();
      for (const value of held?.values ?? []) seen.add(value);
      return held;
    };

    beforeAll(async () => {
      console.info(
        mode === "system"
          ? `secret store under test: ${backend} (PISHIP_LIVE_SECRET_STORE=1)`
          : `secret store under test: ${backend} (the platform store runs with PISHIP_LIVE_SECRET_STORE=1)`,
      );
      stack = await startStack();
      acme = await installDistribution(stack, {
        name: "flow",
        commands: true,
        updates: true,
      });
    }, 600_000);

    afterAll(() => {
      acme?.remove();
      stack?.stop();
    }, 120_000);

    it("builds from the committed lock, which keeps templates and no secret", () => {
      const lock = readFileSync(
        join(referenceDirectory, "piship.lock"),
        "utf8",
      );
      expect(lock).toContain(`\${ACMECODE_OIDC_ISSUER}`);
      expect(lock).toContain(`\${ACMECODE_LLM_GATEWAY_URL}`);
      expect(lock).not.toContain(stack.issuer);
      expect(lock).not.toContain(stack.gatewayUrl);
      expect(lock).not.toMatch(/sk-[0-9a-f]{16}/);
      // `piship build` refuses a lock that no longer matches the manifest and
      // its resources, so this builds exactly what is committed.
      const out = mkdtempSync(join(tmpdir(), "piship-reference-committed-"));
      try {
        const built = spawnSync(
          process.execPath,
          [cliPath, "build", join(referenceDirectory, "piship.yaml")],
          { cwd: out, env: acme.env, encoding: "utf8" },
        );
        expect(built.status, built.stderr).toBe(0);
        expect(built.stderr).not.toContain("stale");
        expect(
          existsSync(join(out, "dist", "acmecode-reference", "piship.mjs")),
        ).toBe(true);
      } finally {
        rmSync(out, { recursive: true, force: true });
      }
    });

    it("is installed, and refuses to launch before sign-in", async () => {
      const version = await acme.run(["version"]);
      expect(version.stdout).toContain("AcmeCode 1.0.0");
      const before = await acme.run(["--smoke"]);
      expect(before.status).toBe(1);
      expect(before.stderr).toContain("IDENTITY_REQUIRED");
      expect(before.stderr).toContain(`${launcherCommand} login`);
    });

    it("signs Alice in on the Keycloak authorization page with PKCE and a loopback redirect", async () => {
      const login = await acme.login("alice");
      expect(login.status, login.stderr).toBe(0);
      expect(login.stdout).toContain(
        `Signed in as Alice Engineer (${stack.issuer})`,
      );
      expect(login.authorization).toMatchObject({
        clientId: "acmecode",
        responseType: "code",
        codeChallengeMethod: "S256",
        hasState: true,
        hasNonce: true,
      });
      expect(login.authorization.scope?.split(" ")).toContain("openid");
      // The manifest registers a port-less loopback URI; PiShip picks the port.
      expect(login.authorization.redirectUri).toMatch(
        /^http:\/\/127\.0\.0\.1:[1-9]\d{3,4}\/callback$/,
      );
      const principal = JSON.parse(
        readFileSync(
          join(acme.stateRoot, "identity", "principal.json"),
          "utf8",
        ),
      );
      expect(principal.issuer).toBe(stack.issuer);
      expect(principal.subject).toMatch(/^[0-9a-f-]{36}$/);
    });

    it(`exchanges the identity for a credential scoped to Alice's models and stores it in the secret store (${backend})`, async () => {
      const first = await acme.smoke();
      expect(first.resumed).toBe(false);
      expect(first.access).toMatchObject({
        identity: { issuer: stack.issuer },
        credential: { mode: "http-broker" },
        selectedModel: "acmecode-reference/acme/coder",
        allowedModels: ALICE_MODELS,
      });
      const { credentialId, expiresAt } = first.access.credential;
      expect(credentialId).toMatch(/^pb-[0-9a-f]{24}$/);
      const lifetime = Date.parse(expiresAt ?? "") - Date.now();
      expect(lifetime).toBeGreaterThan(60 * 60 * 1000);
      expect(lifetime).toBeLessThanOrEqual(24 * 60 * 60 * 1000);
      expect(first.access.removedEnvironment).toEqual(
        expect.arrayContaining(["OPENAI_API_KEY", "ANTHROPIC_API_KEY"]),
      );

      // What the broker asked the gateway for, read from the gateway itself.
      const record = await gatewayKey(stack, credentialId);
      expect(record).toMatchObject({
        models: expect.arrayContaining(ALICE_MODELS),
        teamId: null,
        metadata: { issued_by: "piship-reference-broker" },
      });
      expect([...(record?.models ?? [])].sort()).toEqual(ALICE_MODELS);
      expect(record?.userId).toMatch(/^oidc-[0-9a-f]{40}$/);

      // The stored credential is the key the gateway knows, and only that.
      const held = await remember();
      expect(held?.credentialId).toBe(credentialId);
      const listed = await gatewayModels(stack, held?.credential ?? "");
      expect(listed.status).toBe(200);
      expect([...listed.models].sort()).toEqual(ALICE_MODELS);

      const doctor = await acme.run(["doctor"]);
      expect(doctor.stdout).toMatch(
        new RegExp(`Secret Store\\n {2}[✓!] backend\\s+${backend}`),
      );
      // The file store holds the identity bundle and the credential; the
      // platform store leaves no secret file in the state directory.
      const directory = join(acme.stateRoot, "secrets");
      const files = existsSync(directory) ? readdirSync(directory) : [];
      expect(files).toHaveLength(mode === "file" ? 2 : 0);
    });

    it("lists the models Alice is entitled to", async () => {
      const models = await acme.run(["models"]);
      expect(models.status, models.stderr).toBe(0);
      expect(models.stdout).toMatch(
        /^\* acme\/coder\s+Acme Coder\s+available/m,
      );
      expect(models.stdout).toMatch(
        /^ {2}acme\/general\s+Acme General\s+available/m,
      );
    });

    it("sends a model request through LiteLLM with the brokered credential", async () => {
      expect((await acme.smoke()).resumed).toBe(true);
      const request = await acme.run(["--smoke-model"]);
      expect(request.status, request.stderr).toBe(0);
      expect(JSON.parse(request.stdout).modelRequest).toMatchObject({
        model: "acmecode-reference/acme/coder",
        text: "Reference mock reply from gpt-4.1.",
        stopReason: "stop",
      });
      // Alice may pick the other model she is entitled to.
      const general = await acme.run([
        "--model",
        "acme/general",
        "--smoke-model",
      ]);
      expect(general.status, general.stderr).toBe(0);
      expect(JSON.parse(general.stdout).modelRequest).toMatchObject({
        model: "acmecode-reference/acme/general",
        text: "Reference mock reply from gpt-4.1-mini.",
      });
      // The upstream saw both requests, as streams, after LiteLLM mapped the
      // gateway model names to its own.
      const upstream = await upstreamRequests(stack);
      expect(upstream.slice(-2)).toMatchObject([
        { model: "gpt-4.1", stream: true, status: 200 },
        { model: "gpt-4.1-mini", stream: true, status: 200 },
      ]);
    });

    it("renews a credential the gateway rejected", async () => {
      const before = await remember();
      if (!before) throw new Error("no credential is held");
      await gatewayDeleteKey(stack, before.credentialId);
      expect((await gatewayModels(stack, before.credential)).status).toBe(401);

      const renewed = await acme.run(["--smoke-model"]);
      expect(renewed.status, renewed.stderr).toBe(0);
      const result = JSON.parse(renewed.stdout);
      expect(result.access.credential.credentialId).not.toBe(
        before.credentialId,
      );
      expect(result.access.notices).toContain(
        "The gateway rejected the stored credential; a new credential was acquired",
      );
      expect(result.modelRequest.text).toBe(
        "Reference mock reply from gpt-4.1.",
      );
      const after = await remember();
      expect(after?.credential).not.toBe(before.credential);
      expect((await gatewayModels(stack, after?.credential ?? "")).status).toBe(
        200,
      );
    });

    it("reports the identity, credential, gateway, and secret store in doctor", async () => {
      const doctor = await acme.run(["doctor"]);
      expect(doctor.status, doctor.stdout + doctor.stderr).toBe(0);
      expect(doctor.stdout).toMatch(
        new RegExp(
          `Identity\\n {2}✓ mode\\s+oidc\\n {2}✓ session\\s+signed in\\n {2}✓ issuer\\s+${escaped(stack.issuer)}`,
        ),
      );
      expect(doctor.stdout).toMatch(/Credential\n {2}✓ provider\s+http-broker/);
      expect(doctor.stdout).toMatch(/✓ valid\s+\d+m remaining/);
      expect(doctor.stdout).toMatch(
        /Gateway\n(?: {2}.*\n)*? {2}✓ gateway\s+reachable \(2 listed; model providers not contacted\)/,
      );
      expect(doctor.stdout).toMatch(
        new RegExp(`Secret Store\\n {2}[✓!] backend\\s+${backend}`),
      );
      expect(doctor.stdout).toMatch(
        /✓ outbound\s+private-only: declared hosts only \(127\.0\.0\.1\)/,
      );
    });

    // The model's tool calls come from the mock upstream, queued one per
    // turn. The session keeps what each command answered.
    it("runs the commands the model asks for inside the sandbox, and refuses each escape", async () => {
      // The key is planted in the commands' home, which must be a throwaway.
      expect(acme.env.HOME).toBe(acme.home);
      const project = join(acme.temp, "project");
      const outside = join(acme.temp, "outside");
      const secretPath = join(acme.home, ".ssh", "id_rsa");
      mkdirSync(project);
      mkdirSync(outside);
      mkdirSync(join(acme.home, ".ssh"), { recursive: true });
      writeFileSync(secretPath, `${SSH_CANARY}\n`);
      let connections = 0;
      const listener = createServer((socket) => {
        connections += 1;
        socket.destroy();
      });
      await new Promise<void>((ready) =>
        listener.listen(0, "127.0.0.1", ready),
      );
      const port = (listener.address() as { port: number }).port;
      const node = JSON.stringify(process.execPath);
      const commands = [
        "echo sandboxed > from-bash.txt && cat from-bash.txt",
        `cat ${JSON.stringify(secretPath)}; echo exit=$?`,
        `echo x > ${JSON.stringify(join(outside, "bash-escape.txt"))}; echo exit=$?`,
        `${node} -e "require('net').connect(${port},'127.0.0.1').on('connect',()=>{console.log('CONNECTED');process.exit(0)}).on('error',e=>console.log('NETERR',e.code))"`,
      ];
      const before = (await upstreamRequests(stack)).length;
      let run: Awaited<ReturnType<Installed["run"]>>;
      try {
        await queueToolCalls(
          stack,
          commands.map((command) => ({ name: "bash", arguments: { command } })),
        );
        run = await acme.run(["--smoke-model"], {}, { cwd: project });
      } finally {
        await clearQueuedFaults(stack);
        await new Promise<void>((closed) => listener.close(() => closed()));
      }
      expect(run.status, run.stderr).toBe(0);
      const summary = JSON.parse(run.stdout);
      expect(summary.modelRequest).toMatchObject({
        model: "acmecode-reference/acme/coder",
        text: "Reference mock reply from gpt-4.1.",
        stopReason: "stop",
        toolResults: commands.length,
      });
      expect(summary.governance).toMatchObject({
        workflowMode: "build",
        sandbox: {
          level: "enforced",
          adapter:
            process.platform === "darwin"
              ? "macos-seatbelt"
              : "linux-bubblewrap",
          network: "deny",
        },
      });

      // LiteLLM asked the upstream once per tool call and once more for the
      // reply after the last result, all streamed.
      const upstream = (await upstreamRequests(stack)).slice(before);
      expect(upstream).toMatchObject([
        ...commands.map(() => ({
          model: "gpt-4.1",
          stream: true,
          status: 200,
          toolCall: "bash",
        })),
        { model: "gpt-4.1", stream: true, status: 200 },
      ]);
      expect(upstream.at(-1)).not.toHaveProperty("toolCall");

      // What each command answered, from the session Pi kept.
      const results = toolResults(summary.sessionDir);
      expect(results).toHaveLength(commands.length);
      expect(results[0]).toContain("sandboxed");
      expect(readFileSync(join(project, "from-bash.txt"), "utf8")).toBe(
        "sandboxed\n",
      );
      // Inside the workspace the command works. It cannot read the user's SSH
      // key, write outside the workspace, or reach the network.
      expect(results[1]).not.toContain(SSH_CANARY);
      expect(results[1]).toMatch(/exit=[1-9]/);
      expect(results[2]).toMatch(/exit=[1-9]/);
      expect(existsSync(join(outside, "bash-escape.txt"))).toBe(false);
      expect(results[3]).toContain("NETERR");
      expect(results[3]).not.toContain("CONNECTED");
      expect(connections).toBe(0);

      // Each command is an allowed tool call twice over, by the owner's tool
      // rule and its shell rule. The audit log holds metadata, never a command
      // line or the key, and the key is in no state the run wrote.
      const audit = readFileSync(
        join(acme.stateRoot, "logs", "audit.jsonl"),
        "utf8",
      );
      const allowed = audit
        .split("\n")
        .filter(Boolean)
        .map(
          (line) =>
            JSON.parse(line) as {
              event: string;
              resource?: string;
              rule?: string;
            },
        )
        .filter(
          (entry) =>
            entry.event === "tool.allowed" && entry.resource === "bash",
        );
      expect(allowed.map((entry) => entry.rule).sort()).toEqual(
        commands.flatMap(() => ["acme.shell", "acme.tools"]).sort(),
      );
      expect(audit).not.toContain(SSH_CANARY);
      expect(audit).not.toContain("echo sandboxed");
      expect(scan(acme.state, [SSH_CANARY])).toEqual([]);
      expect(scan(project, [SSH_CANARY])).toEqual([]);
    });

    it("updates through a signed channel and keeps the session, the identity, and the credential", async () => {
      const before = await acme.smoke();
      // Nothing is published yet: the channel offers no update.
      const empty = await acme.run(["update", "--check"]);
      expect(empty.status).toBe(1);
      expect(empty.stderr).toContain("UPDATE_FAILED");

      acme.publishUpdate();
      const long = { timeoutMs: 280_000 };
      const check = await acme.run(["update", "--check"], {}, long);
      expect(check.status, check.stderr).toBe(0);
      expect(check.stdout).toContain(
        "AcmeCode 1.1.0 is available on the stable channel (signed by acme-reference-e2e)",
      );
      expect((await acme.run(["version"])).stdout).toContain("AcmeCode 1.0.0");
      const updated = await acme.run(["update"], {}, long);
      expect(updated.status, updated.stderr).toBe(0);
      expect(updated.stdout).toContain(
        "Updated AcmeCode 1.0.0 -> 1.1.0 (stable, signed by acme-reference-e2e)",
      );
      expect((await acme.run(["version"])).stdout).toContain("AcmeCode 1.1.0");
      // The update host was asked for the signed channel and its archive only.
      expect(new Set(acme.updateRequests())).toEqual(
        new Set([
          // The root refresh asks for the next root first; its 404 ends it.
          "root/2.json",
          "stable.json",
          "stable.json.sig",
          `${ID}-1.1.0-${process.platform}-${process.arch}.tar.gz`,
        ]),
      );

      // The new release finds the session, the identity, and the credential
      // where the old one left them, and a request still goes through LiteLLM.
      const after = await acme.smoke();
      expect(after).toMatchObject({
        sessionId: before.sessionId,
        resumed: true,
        access: {
          identity: before.access.identity,
          credential: { credentialId: before.access.credential.credentialId },
          selectedModel: before.access.selectedModel,
        },
      });
      const request = await acme.run(["--smoke-model"]);
      expect(request.status, request.stderr).toBe(0);
      expect(JSON.parse(request.stdout).modelRequest).toMatchObject({
        text: "Reference mock reply from gpt-4.1.",
        stopReason: "stop",
      });
      const doctor = await acme.run(["doctor"]);
      expect(doctor.stdout).toMatch(/Supply Chain\n {2}✓ manifest\s+verified/);
      expect(doctor.stdout).toMatch(/Release\n {2}✓ release\s+verified/);
      expect(doctor.stdout).toMatch(/✓ active\s+1\.1\.0/);
      expect(doctor.stdout).toMatch(/✓ rollback\s+1\.0\.0 retained/);
      await remember();
    }, 600_000);

    it("rolls back keeping the session, and the credential the gateway still accepts", async () => {
      const before = await acme.smoke();
      const held = await remember();
      if (!held) throw new Error("no credential is held");
      const rollback = await acme.run(["rollback"], {}, { timeoutMs: 280_000 });
      expect(rollback.status, rollback.stderr).toBe(0);
      expect(rollback.stdout).toContain("Rolled back AcmeCode 1.1.0 -> 1.0.0");
      expect(rollback.stdout).toContain("credentials were not restored");
      expect((await acme.run(["version"])).stdout).toContain("AcmeCode 1.0.0");

      const after = await acme.smoke();
      expect(after).toMatchObject({
        sessionId: before.sessionId,
        resumed: true,
        access: {
          credential: { credentialId: before.access.credential.credentialId },
        },
      });
      // Rollback restored no secret, and the live one is still the gateway's.
      expect((await remember())?.credential).toBe(held.credential);
      expect((await gatewayModels(stack, held.credential)).status).toBe(200);
      const request = await acme.run(["--smoke-model"]);
      expect(request.status, request.stderr).toBe(0);
      expect(JSON.parse(request.stdout).modelRequest).toMatchObject({
        text: "Reference mock reply from gpt-4.1.",
        stopReason: "stop",
      });
    }, 600_000);

    it("keeps every secret out of the state directory, install home, artifact metadata, and output", async () => {
      const held = await remember();
      expect(seen.size).toBeGreaterThanOrEqual(5);
      expect(scan(acme.state, [...seen])).toEqual([]);
      expect(scan(acme.install, [...seen])).toEqual([]);
      expect(scan(join(acme.artifact, "metadata"), [...seen])).toEqual([]);
      expect(leaks(acme.output(), [...seen])).toEqual([]);
      expect(held?.credentialId).toBeTruthy();
      // The check finds what is there: the file store holds these secrets
      // (the credential and the three identity tokens).
      if (mode === "file")
        expect(
          leaks(fileStoreValues(acme.stateRoot).join("\n"), held?.values ?? []),
        ).toHaveLength(4);
    });

    it("signs out: revokes the credential and the identity tokens, and clears the secret store", async () => {
      const held = await remember();
      if (!held) throw new Error("no credential is held");
      const logout = await acme.run(["logout"]);
      expect(logout.status, logout.stderr).toBe(0);
      expect(logout.stdout).toContain("Signed out of AcmeCode.");

      // At the gateway, at the identity provider, and locally.
      expect((await gatewayModels(stack, held.credential)).status).toBe(401);
      expect(await gatewayKey(stack, held.credentialId)).toBeUndefined();
      expect(await accessTokenStatus(stack, held.accessToken)).toBe(401);
      expect(await refreshTokenStatus(stack, held.refreshToken)).toEqual({
        status: 400,
        error: "invalid_grant",
      });
      expect(await acme.secrets()).toBeUndefined();
      expect(fileStoreValues(acme.stateRoot)).toEqual([]);
      // Sessions are kept, and the next launch needs a new sign-in.
      expect(existsSync(join(acme.stateRoot, "sessions"))).toBe(true);
      expect((await acme.run(["--smoke"])).stderr).toContain(
        "IDENTITY_REQUIRED",
      );

      expect(scan(acme.state, [...seen])).toEqual([]);
      expect(scan(acme.install, [...seen])).toEqual([]);
      expect(leaks(acme.output(), [...seen])).toEqual([]);
      // Nothing is left in the platform store either.
      if (mode === "system")
        expect(platformStoreRefs(`piship:${ID}:`, acme.env)).toEqual([]);
    });

    it("uninstalls, keeping the user's sessions, and purges the state, leaving the machine as it was", async () => {
      const events = readFileSync(
        join(acme.stateRoot, "logs", "audit.jsonl"),
        "utf8",
      )
        .split("\n")
        .filter(Boolean)
        .map(
          (line) =>
            JSON.parse(line) as {
              event: string;
              decision?: string;
              detail?: Record<string, unknown>;
            },
        );
      const uninstall = acme.cli("uninstall", ID);
      expect(uninstall.status, uninstall.stderr).toBe(0);
      expect(existsSync(acme.command)).toBe(false);
      expect(existsSync(join(acme.install, "apps", ID))).toBe(false);
      // A reinstall would find the user's sessions and settings.
      expect(
        readdirSync(join(acme.stateRoot, "sessions")).length,
      ).toBeGreaterThan(0);

      // The audit trail tells the whole story, in order, and holds no secret.
      const order = [
        "identity.login",
        "credential.acquire",
        "session.start",
        "model.request",
        "tool.allowed",
        "runtime.update",
        "runtime.rollback",
        "credential.revoke",
        "identity.logout",
      ].map((name) => events.findIndex((entry) => entry.event === name));
      expect(
        order.every((index) => index >= 0),
        `audit events ${order}`,
      ).toBe(true);
      expect(order).toEqual([...order].sort((a, b) => a - b));
      expect(
        events.filter((entry) => entry.event === "runtime.update"),
      ).toEqual([
        expect.objectContaining({
          decision: "allowed",
          detail: {
            from: "1.0.0",
            to: "1.1.0",
            channel: "stable",
            key: "acme-reference-e2e",
          },
        }),
      ]);
      expect(
        events.filter((entry) => entry.event === "runtime.rollback"),
      ).toEqual([
        expect.objectContaining({
          decision: "allowed",
          detail: { from: "1.1.0", to: "1.0.0" },
        }),
      ]);
      expect(leaks(JSON.stringify(events), [...seen])).toEqual([]);

      // Purge removes what uninstall keeps: no state and no store entry is
      // left, and nothing of the run reads back.
      const purge = acme.cli("purge", ID, "--yes");
      expect(purge.status, purge.stderr).toBe(0);
      expect(existsSync(acme.stateRoot)).toBe(false);
      expect(await acme.secrets()).toBeUndefined();
      if (mode === "system")
        expect(platformStoreRefs(`piship:${ID}:`, acme.env)).toEqual([]);
      expect(existsSync(join(acme.home, ".pi"))).toBe(false);
      expect(scan(acme.home, [...seen])).toEqual([]);
    });
  },
);

/**
 * What each tool call answered, in order, from the Pi session files in
 * `sessionDir`.
 */
function toolResults(sessionDir: string): string[] {
  return readdirSync(sessionDir)
    .filter((name) => name.endsWith(".jsonl"))
    .sort()
    .flatMap((name) =>
      readFileSync(join(sessionDir, name), "utf8").split("\n").filter(Boolean),
    )
    .map(
      (line) =>
        JSON.parse(line) as { message?: { role?: string; content?: unknown } },
    )
    .filter((entry) => entry.message?.role === "toolResult")
    .map(({ message }) =>
      Array.isArray(message?.content)
        ? message.content
            .map((part: { text?: string }) => part.text ?? "")
            .join("")
        : String(message?.content ?? ""),
    );
}
