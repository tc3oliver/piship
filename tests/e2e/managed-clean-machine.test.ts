import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { createServer as createTcpServer } from "node:net";
import { join } from "node:path";
import { describe, expect, it, onTestFinished } from "vitest";
import { branded, type Result } from "../helpers/distribution.js";
import {
  lifecycleScenario,
  scan,
  target,
  windows,
} from "../helpers/lifecycle.js";
import { PRIMARY_STORAGE } from "../helpers/secret-store.js";

// Managed clean-machine flow (spec §30.4, decision D-11): one continuous run
// of a managed distribution from a machine that has nothing of it to a machine
// that has nothing of it again:
//
//   install, launch, login, credential acquire, model discovery,
//   authenticated model request, session resume, doctor, sandbox execution,
//   update, rollback, logout, uninstall
//
// "Same flow" means one installed distribution with one install home, state
// directory, secret store, Pi session, and set of fixture services, in this
// order: each step starts from what the one before it left, and every step
// asserts an outcome (exit status and output, the state on disk, the secret
// store, the audit log, or what the fixture services recorded). What each
// step means here, and what it does not prove:
//
// - install: the release archive is verified, then installed with the install
//   script shipped inside it, on a machine with no install, state directory,
//   or secret-store entry of the distribution.
// - launch: the installed command starts, and refuses to launch (`--smoke`) and
//   to list models signed out, before it contacts any service. The interactive
//   terminal UI needs a terminal; every launch here is Pi's headless
//   acceptance run.
// - login: PiShip runs the Authorization Code + PKCE sign-in against the
//   fixture identity provider and the test acts as the browser. There is no
//   sign-in form and no second factor: a live identity provider is the
//   Reference E2E's job (Ubuntu, examples/enterprise-reference).
// - credential acquire: the fixture broker turns the identity's access token
//   into a runtime credential that PiShip keeps in the secret store.
// - model discovery: `models` reads the gateway's list with that credential
//   and intersects it with the owner's allowlist and the entitlement.
// - authenticated model request: `--smoke-model` sends a real Pi request to the
//   fixture gateway, which answers only to the credential the broker issued.
//   The gateway is a fixture, not a model.
// - session resume: the next launch continues the same Pi session, which still
//   holds the model turn.
// - doctor: every group reports the state the flow has produced.
// - sandbox execution: on Linux (bubblewrap) and macOS (Seatbelt) Pi runs
//   commands the fixture gateway asks for through the distribution's required
//   native sandbox, and each escape it tries is refused. The demo as shipped
//   asks before every command, which a headless run resolves to a denial, so
//   this flow uses a copy whose owner allows shell commands in Build mode (see
//   `commands` in tests/helpers/lifecycle.ts). Windows has no native sandbox
//   backend (`unavailable`, docs/status.md): there the copy does not require
//   one, the flow asserts that the launch reports the sandbox as not required
//   and `doctor` reports no containment, and it runs no command and says so;
//   the refusal of a required sandbox on Windows is asserted in
//   governance.test.ts. A Linux or macOS host without a native sandbox fails
//   the flow at the first launch, as the distribution requires one; it does
//   not skip the step.
// - update, rollback: a signed channel on a loopback HTTP host offers 1.1.0;
//   the update is verified with the pinned key and rolled back, and the
//   session, the identity, and the runtime credential come through both.
// - logout: revokes the runtime credential at the broker and the tokens at the
//   identity provider, and clears the secret store; sessions are kept.
// - uninstall: removes the install and the command and keeps the user's
//   sessions and settings; `purge` then removes that state too, so the machine
//   is clean again.
//
// The secrets live in the platform store (macOS Keychain, Windows Credential
// Manager, Linux Secret Service) where PISHIP_LIVE_SECRET_STORE=1 says one is
// live, which is CI, and in the restricted file fallback everywhere else: a
// developer's own keychain is never touched. The other lifecycle scenarios
// run both storages; this flow runs the one it would ship with.
//
// Ubuntu also runs the same steps against the reference stack, a live Keycloak,
// credential broker, and LiteLLM in Docker Compose (Reference E2E,
// examples/enterprise-reference/tests/distribution-flow.test.ts). That is the
// only place a real identity provider and gateway are exercised; macOS and
// Windows have no Linux containers, so their evidence is this fixture flow.

const FLOW = [
  "install",
  "launch",
  "login",
  "credential acquire",
  "model discovery",
  "authenticated model request",
  "session resume",
  "doctor",
  "sandbox execution",
  "update",
  "rollback",
  "logout",
  "uninstall",
] as const;

const STORE_LABEL =
  PRIMARY_STORAGE === "file"
    ? "restricted plaintext file"
    : process.platform === "darwin"
      ? "macOS Keychain"
      : windows
        ? "Windows Credential Manager"
        : "Linux Secret Service";

// A personal key in the launching environment: a managed distribution removes
// it and never sends it, or writes it, anywhere.
const AMBIENT = {
  OPENAI_API_KEY: "sk-ambient-personal-key-clean-machine",
  ANTHROPIC_API_KEY: "sk-ant-ambient-personal-key-clean-machine",
};
// The agent must not read this, however it is asked.
const SSH_CANARY = "ssh-private-key-clean-machine-canary";

interface AuditEvent {
  readonly event: string;
  readonly resource?: string;
  readonly rule?: string;
  readonly decision?: string;
  readonly detail?: Record<string, unknown>;
}

describe(`managed clean-machine flow: ${PRIMARY_STORAGE} storage (local fixtures)`, () => {
  it("runs from install to uninstall as one flow on one machine", async () => {
    const s = await lifecycleScenario("clean-machine", {
      storage: PRIMARY_STORAGE,
      commands: true,
    });
    const { services } = s;
    const state = join(s.state, s.id);
    const project = join(s.temp, "project");
    mkdirSync(project);
    const covered: string[] = [];
    const done = (step: (typeof FLOW)[number], note = "") =>
      covered.push(note ? `${step} (${note})` : step);

    // The user launches from their project, so the sandbox's workspace is
    // the project and not the scenario's directory of homes.
    const run = async (args: string[], status = 0): Promise<Result> => {
      const result = await branded(s.command, args, {
        cwd: project,
        env: { ...s.env, ...AMBIENT },
        approve: (url) => services.approve(url),
      });
      expect(result.status, `${args.join(" ")}: ${result.stderr}`).toBe(status);
      return result;
    };
    const smoke = async () => JSON.parse((await run(["--smoke"])).stdout);
    const audit = (): AuditEvent[] =>
      readFileSync(join(state, "logs", "audit.jsonl"), "utf8")
        .split("\n")
        .filter(Boolean)
        .map((line) => JSON.parse(line) as AuditEvent);
    const issued = () => [
      ...services.state.credentials.keys(),
      ...services.state.accessTokens.keys(),
      ...services.state.refreshTokens.keys(),
    ];
    const chatRequests = () =>
      services.state.requests.filter((request: { path: string }) =>
        request.path.endsWith("/chat/completions"),
      );
    const sessionFiles = (sessionDir: string) =>
      readdirSync(sessionDir).filter((name) => name.endsWith(".jsonl"));

    // A clean machine: nothing of the distribution is installed, no state
    // directory exists, and the secret store holds nothing of it.
    expect(existsSync(s.command)).toBe(false);
    expect(existsSync(join(s.install, "apps", s.id))).toBe(false);
    expect(existsSync(state)).toBe(false);
    s.expectSecretStore([]);

    // install: the release is verified and installed with its own script.
    const verified = s.cli("verify-release", s.releases.first, "--json");
    expect(verified.status, verified.stderr).toBe(0);
    expect(JSON.parse(verified.stdout)).toMatchObject({
      distribution: { id: s.id, version: "1.0.0" },
      target,
    });
    await s.installFirst();
    expect(existsSync(s.command)).toBe(true);
    expect(existsSync(join(s.install, "apps", s.id, "1.0.0"))).toBe(true);
    done("install");

    // launch: the command starts, and signed out it refuses before it
    // contacts a service or writes a secret.
    const help = await run(["--help"]);
    expect(help.stdout).toContain("login | logout | doctor | models | version");
    const unsigned = await run(["--smoke"], 1);
    expect(unsigned.stderr).toContain("IDENTITY_REQUIRED");
    expect(unsigned.stderr).toContain(`${s.id} login`);
    expect((await run(["models"], 1)).stderr).toContain("IDENTITY_REQUIRED");
    expect(services.state.requests).toEqual([]);
    expect(existsSync(join(state, "identity", "session.json"))).toBe(false);
    s.expectSecretStore([]);
    done("launch", "signed out");

    // login: Authorization Code + PKCE against the identity provider.
    const login = await run(["login"]);
    expect(login.stdout).toContain("Signed in as Demo Developer");
    expect(login.stdout).toContain(`stored in ${STORE_LABEL}`);
    expect(login.stderr).toContain("code_challenge_method=S256");
    if (PRIMARY_STORAGE === "file")
      expect(login.stderr).toContain("plaintext file fallback");
    else expect(login.stderr).not.toContain("plaintext file fallback");
    expect(services.state.authorizations).toHaveLength(1);
    expect(services.state.authorizations[0]).toMatchObject({
      client_id: "demo-company-cli",
      response_type: "code",
      code_challenge_method: "S256",
      state: expect.any(String),
      nonce: expect.any(String),
    });
    expect(s.metadataRefs()).toEqual([
      `piship:${s.id}:identity#1`,
      `piship:${s.id}:inference#1`,
    ]);
    s.expectSecretStore();
    done("login");

    // credential acquire: the broker was asked once, with the identity's
    // access token, and its credential is what the first launch runs with.
    const brokerCalls = services.state.requests.filter(
      (request: { path: string }) =>
        request.path === "/broker/v1/llm-credential",
    );
    expect(brokerCalls).toHaveLength(1);
    expect([...services.state.accessTokens.keys()]).toContain(
      brokerCalls[0].authorization.replace("Bearer ", ""),
    );
    expect(services.state.credentials.size).toBe(1);
    const [credential] = [...services.state.credentials.keys()] as string[];
    expect([...services.state.credentials.values()]).toMatchObject([
      {
        subject: "demo-user-1",
        models: ["acme/coder", "acme/general"],
        revoked: false,
      },
    ]);
    const first = await smoke();
    expect(first.resumed).toBe(false);
    expect(first.access).toMatchObject({
      mode: "managed",
      identity: { subject: "demo-user-1" },
      credential: { mode: "http-broker", credentialId: "vk_demo_1" },
      selectedModel: `${s.id}/acme/coder`,
      allowedModels: ["acme/coder", "acme/general"],
    });
    const expiresAt = Date.parse(first.access.credential.expiresAt);
    expect(expiresAt).toBeGreaterThan(Date.now());
    expect(expiresAt).toBeLessThanOrEqual(Date.now() + 3600 * 1000);
    expect(first.access.removedEnvironment).toEqual(
      expect.arrayContaining(Object.keys(AMBIENT)),
    );
    const { sessionId, sessionDir } = first;
    s.expectSecretStore();
    done("credential acquire");

    // model discovery: the entitlement decides what is available, and the
    // gateway's list was read with the brokered credential.
    const models = await run(["models"]);
    expect(models.stdout).toMatch(
      /^\* acme\/coder\s+Acme Coder\s+available\s/m,
    );
    expect(models.stdout).toMatch(
      /^ {2}acme\/general\s+Acme General\s+available\s/m,
    );
    expect(models.stdout).toMatch(
      /^ {2}acme\/review\s+Acme Review\s+unavailable \(not included in the runtime credential entitlement\)/m,
    );
    const listed = services.state.requests.filter(
      (request: { method: string; path: string }) =>
        request.method === "GET" && request.path === "/gateway/v1/models",
    );
    expect(listed.length).toBeGreaterThan(0);
    for (const request of listed)
      expect(request.authorization).toBe(`Bearer ${credential}`);
    done("model discovery");

    // authenticated model request: a Pi request through the gateway, which
    // accepts only the broker's credential.
    const request = await run(["--smoke-model"]);
    expect(JSON.parse(request.stdout).modelRequest).toMatchObject({
      model: `${s.id}/acme/coder`,
      text: "Hello from acme/coder.",
      stopReason: "stop",
      toolResults: 0,
    });
    expect(chatRequests()).toHaveLength(1);
    expect(chatRequests()[0].authorization).toBe(`Bearer ${credential}`);
    expect(audit().map((event) => event.event)).toContain("model.request");
    s.expectSecretStore();
    done("authenticated model request");

    // session resume: the same session, which holds the model turn.
    const resumed = await smoke();
    expect(resumed).toMatchObject({ sessionId, resumed: true, sessionDir });
    expect(sessionFiles(sessionDir)).toHaveLength(1);
    expect(
      readFileSync(
        join(sessionDir, sessionFiles(sessionDir)[0] as string),
        "utf8",
      ),
    ).toContain("Hello from acme/coder.");
    done("session resume");

    // doctor: every group reports the state the flow has produced.
    const doctor = await run(["doctor"]);
    expect(doctor.stdout).toMatch(
      /Identity\n {2}✓ mode\s+oidc\n {2}✓ session\s+signed in/,
    );
    expect(doctor.stdout).toMatch(/Credential\n {2}✓ provider\s+http-broker/);
    expect(doctor.stdout).toMatch(/✓ valid\s+\d+m remaining/);
    expect(doctor.stdout).toMatch(
      /Gateway\n(?: {2}.*\n)*? {2}✓ gateway\s+reachable \(3 listed\)/,
    );
    expect(doctor.stdout).toMatch(
      new RegExp(
        `Secret Store\\n {2}${PRIMARY_STORAGE === "file" ? "!" : "✓"} backend\\s+${STORE_LABEL}`,
      ),
    );
    expect(doctor.stdout).toMatch(
      /✓ outbound\s+private-only: declared hosts only/,
    );
    expect(doctor.stdout).toMatch(
      windows ? /containment\s+not-required/ : /containment\s+enforced/,
    );
    expect(doctor.stdout).toMatch(
      windows ? /isolation\s+none/ : /isolation\s+local/,
    );
    expect(doctor.stdout).toMatch(/Release\n {2}✓ release\s+verified/);
    expect(doctor.stdout).toMatch(/✓ rollback\s+no retained release/);
    expect(doctor.stdout).toMatch(/Audit\n {2}✓ state\s+healthy/);
    done("doctor");

    // sandbox execution: commands the model asks for run inside the native
    // sandbox and cannot leave it.
    expect(first.governance.sandbox).toMatchObject(
      windows
        ? { level: "not-required" }
        : {
            level: "enforced",
            adapter:
              process.platform === "darwin"
                ? "macos-seatbelt"
                : "linux-bubblewrap",
            network: "deny",
          },
    );
    expect(first.governance.workflowMode).toBe("build");
    if (windows) {
      console.warn(
        "managed clean-machine flow: sandbox execution skipped on win32: there is no native sandbox backend (unavailable), so no command is run",
      );
      done("sandbox execution", "skipped on win32: no native backend");
    } else {
      mkdirSync(join(s.home, ".ssh"), { recursive: true });
      writeFileSync(join(s.home, ".ssh", "id_rsa"), `${SSH_CANARY}\n`);
      const secretPath = join(s.home, ".ssh", "id_rsa");
      const outside = join(s.temp, "outside");
      mkdirSync(outside);
      let connections = 0;
      const listener = createTcpServer((socket) => {
        connections += 1;
        socket.destroy();
      });
      await new Promise<void>((ready) =>
        listener.listen(0, "127.0.0.1", ready),
      );
      onTestFinished(
        () => new Promise<void>((closed) => listener.close(() => closed())),
      );
      const port = (listener.address() as { port: number }).port;
      const node = JSON.stringify(process.execPath);
      const commands = [
        "echo sandboxed > from-bash.txt && cat from-bash.txt",
        `cat ${JSON.stringify(secretPath)}; echo exit=$?`,
        `echo x > ${JSON.stringify(join(outside, "bash-escape.txt"))}; echo exit=$?`,
        `${node} -e "require('net').connect(${port},'127.0.0.1').on('connect',()=>{console.log('CONNECTED');process.exit(0)}).on('error',e=>console.log('NETERR',e.code))"`,
      ];
      services.knobs.gatewayMode = "script";
      services.knobs.toolScript = commands.map((command) => ({
        name: "bash",
        arguments: { command },
      }));
      services.state.toolResults = [];
      const scripted = await run(["--smoke-model"]);
      services.knobs.gatewayMode = "text";
      services.knobs.toolScript = [];
      const summary = JSON.parse(scripted.stdout);
      expect(summary.modelRequest).toMatchObject({
        stopReason: "stop",
        toolResults: commands.length,
      });
      expect(summary.governance.sandbox).toMatchObject({ level: "enforced" });
      const results = services.state.toolResults as string[];
      expect(results).toHaveLength(commands.length);
      // Inside the workspace the command works.
      expect(results[0]).toContain("sandboxed");
      expect(readFileSync(join(project, "from-bash.txt"), "utf8")).toBe(
        "sandboxed\n",
      );
      // It cannot read the user's SSH key, write outside the workspace, or
      // reach the network, and the model never sees the key.
      expect(results[1]).not.toContain(SSH_CANARY);
      expect(results[1]).toMatch(/exit=[1-9]/);
      expect(results[2]).toMatch(/exit=[1-9]/);
      expect(existsSync(join(outside, "bash-escape.txt"))).toBe(false);
      expect(results[3]).toContain("NETERR");
      expect(results[3]).not.toContain("CONNECTED");
      expect(connections).toBe(0);
      expect(JSON.stringify(services.state.requests)).not.toContain(SSH_CANARY);
      // The audit log records each command as allowed twice, by the owner's
      // tool rule and by its shell rule, and only as metadata: never a
      // command line or the canary.
      const allowed = audit().filter(
        (event) => event.event === "tool.allowed" && event.resource === "bash",
      );
      expect(allowed.map((event) => event.rule).sort()).toEqual(
        commands.flatMap(() => ["acme.shell", "acme.tools"]).sort(),
      );
      const log = readFileSync(join(state, "logs", "audit.jsonl"), "utf8");
      expect(log).not.toContain(SSH_CANARY);
      expect(log).not.toContain("echo sandboxed");
      done("sandbox execution", `${summary.governance.sandbox.adapter}`);
    }

    // From here on the session holds the sandbox turn. The fixture gateway
    // answers with the last tool result of the conversation it is sent, so a
    // request in the resumed session gets that result back: the session's
    // history reaches the model, through the update and the rollback too.
    // Without the sandbox step (Windows) it is still the plain greeting.
    const sessionReply = windows
      ? "Hello from acme/coder."
      : expect.stringMatching(/^Tool result received: [\s\S]*NETERR /);

    // update: a signed channel offers 1.1.0.
    const before = await smoke();
    expect(before).toMatchObject({ sessionId, resumed: true });
    s.publish(1);
    const check = await run(["update", "--check"]);
    expect(check.stdout).toContain(
      "AcmeCode 1.1.0 is available on the stable channel (signed by acme-e2e)",
    );
    expect((await run(["version"])).stdout).toContain("AcmeCode 1.0.0");
    const updated = await run(["update"]);
    expect(updated.stdout).toContain(
      "Updated AcmeCode 1.0.0 -> 1.1.0 (stable, signed by acme-e2e)",
    );
    expect((await run(["version"])).stdout).toContain("AcmeCode 1.1.0");
    expect(new Set(s.hostRequests)).toEqual(
      new Set([
        "stable.json",
        "stable.json.sig",
        `${s.id}-1.1.0-${target}.tar.gz`,
      ]),
    );
    // The new release finds the session, the identity, and the credential
    // where the old one left them.
    const updatedRun = await smoke();
    expect(updatedRun).toMatchObject({ sessionId, resumed: true });
    expect(updatedRun.access.credential.credentialId).toBe("vk_demo_1");
    expect(
      JSON.parse((await run(["--smoke-model"])).stdout).modelRequest,
    ).toMatchObject({ text: sessionReply, stopReason: "stop" });
    const updatedDoctor = await run(["doctor"]);
    expect(updatedDoctor.stdout).toMatch(
      /Supply Chain\n {2}✓ manifest\s+verified/,
    );
    expect(updatedDoctor.stdout).toMatch(/Release\n {2}✓ release\s+verified/);
    expect(updatedDoctor.stdout).toMatch(/✓ active\s+1\.1\.0/);
    expect(updatedDoctor.stdout).toMatch(/✓ rollback\s+1\.0\.0 retained/);
    s.expectSecretStore();
    done("update");

    // rollback: 1.0.0 again, with the session and the live credential kept.
    const rollback = await run(["rollback"]);
    expect(rollback.stdout).toContain("Rolled back AcmeCode 1.1.0 -> 1.0.0");
    expect(rollback.stdout).toContain("credentials were not restored");
    expect((await run(["version"])).stdout).toContain("AcmeCode 1.0.0");
    const rolledBack = await smoke();
    expect(rolledBack).toMatchObject({ sessionId, resumed: true });
    expect(rolledBack.access.credential.credentialId).toBe("vk_demo_1");
    expect(
      JSON.parse((await run(["--smoke-model"])).stdout).modelRequest,
    ).toMatchObject({ text: sessionReply, stopReason: "stop" });
    expect(services.state.credentials.size).toBe(1);
    s.expectSecretStore();
    done("rollback");

    // Every request the gateway served carried the broker's credential, and
    // no personal key of the launching environment reached any service.
    for (const item of [
      ...chatRequests(),
      ...services.state.requests.filter(
        (r: { path: string }) => r.path === "/gateway/v1/models",
      ),
    ])
      expect(item.authorization).toBe(`Bearer ${credential}`);
    for (const key of Object.values(AMBIENT))
      expect(JSON.stringify(services.state.requests)).not.toContain(key);

    // logout: the credential and the tokens are revoked where they were
    // issued, and nothing is left in the store.
    const tokens = issued();
    const logout = await run(["logout"]);
    expect(logout.stdout).toContain("Signed out of AcmeCode.");
    expect(services.state.revokedCredentials).toEqual(["vk_demo_1"]);
    expect(services.state.accessTokens.size).toBe(0);
    expect(services.state.refreshTokens.size).toBe(0);
    expect(existsSync(join(state, "identity", "session.json"))).toBe(false);
    expect(
      existsSync(join(state, "credentials-metadata", "inference.json")),
    ).toBe(false);
    s.expectSecretStore([]);
    expect(sessionFiles(sessionDir)).toHaveLength(1);
    expect((await run(["--smoke"], 1)).stderr).toContain("IDENTITY_REQUIRED");
    expect((await run(["models"], 1)).stderr).toContain("IDENTITY_REQUIRED");
    // No token, credential, or personal key of the flow is in the state
    // (sessions and audit log included), the project, the home, or either
    // retained release, and the agent's SSH key is in none of them either.
    // The install home is scanned once: it is by far the largest tree.
    const secrets = [...tokens, ...Object.values(AMBIENT)];
    expect(scan(state, [...secrets, SSH_CANARY])).toEqual([]);
    expect(scan(project, [...secrets, SSH_CANARY])).toEqual([]);
    expect(scan(s.install, [...secrets, SSH_CANARY])).toEqual([]);
    expect(scan(s.home, secrets)).toEqual([]);
    done("logout");

    // uninstall: the install and the command go, the user's sessions stay,
    // and the audit trail tells the whole story.
    const uninstall = s.cli("uninstall", s.id);
    expect(uninstall.status, uninstall.stderr).toBe(0);
    expect(existsSync(s.command)).toBe(false);
    expect(existsSync(join(s.install, "apps", s.id))).toBe(false);
    expect(sessionFiles(sessionDir)).toHaveLength(1);
    const events = audit();
    const order = [
      "identity.login",
      "credential.acquire",
      "session.start",
      "model.request",
      "runtime.update",
      "runtime.rollback",
      "credential.revoke",
      "identity.logout",
    ].map((name) => events.findIndex((event) => event.event === name));
    expect(
      order.every((index) => index >= 0),
      `audit events ${order}`,
    ).toBe(true);
    expect(order).toEqual([...order].sort((a, b) => a - b));
    expect(events.filter((event) => event.event === "runtime.update")).toEqual([
      expect.objectContaining({
        decision: "allowed",
        detail: {
          from: "1.0.0",
          to: "1.1.0",
          channel: "stable",
          key: "acme-e2e",
        },
      }),
    ]);
    expect(
      events.filter((event) => event.event === "credential.revoke"),
    ).toEqual([
      expect.objectContaining({
        detail: expect.objectContaining({
          credentialId: "vk_demo_1",
          reason: "logout",
          revocation: "revoked",
        }),
      }),
    ]);
    // Purge removes the state a reinstall would have kept: the machine is
    // clean again, in the file system and in the secret store.
    const purge = s.cli("purge", s.id, "--yes");
    expect(purge.status, purge.stderr).toBe(0);
    expect(existsSync(state)).toBe(false);
    s.expectSecretStore([]);
    expect(scan(s.temp, secrets)).toEqual([]);
    expect(existsSync(join(s.home, ".pi"))).toBe(false);
    done("uninstall", "and purge");

    // Every step of the flow ran, in order.
    console.info(
      `managed clean-machine flow (${process.platform}, ${PRIMARY_STORAGE} storage):\n  ${covered.join("\n  ")}`,
    );
    expect(covered.map((entry) => entry.split(" (")[0])).toEqual([...FLOW]);
    // The install, the update, and the rollback each unpack a release of
    // about 170 MB, and the install home is scanned once: on a busy disk that
    // takes minutes, so the flow gets more time than the slices of it.
  }, 1_200_000);
});
