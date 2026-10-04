import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { expect, it, onTestFinished } from "vitest";
// @ts-expect-error The stand-in model server is plain JavaScript.
import { startModelServer } from "../../examples/personal/local-model/model-server.mjs";
import {
  KEY_ID,
  type PersonalScenario,
  personalLocalScenario,
  personalScenario,
  scan,
  target,
} from "../helpers/lifecycle.js";

// The personal clean-machine flow (specification 30.4), once per personal
// example, in one continuous test each: install, launch, credential
// configure or delegate, model request, session resume, doctor, update,
// rollback, uninstall. Both start from an empty home and state, install the
// release with the script shipped inside it, update through a signed loopback
// channel, and reach a stand-in model server on loopback. The examples differ
// in who holds the credential: MyPi delegates it to Pi, MyPi Local keeps it in
// its own secret store. Each flow has a test file of its own, so Portable E2E
// can run the two on different runners.

interface ModelRequest {
  method: string;
  path: string;
  authorization?: string;
}

interface Smoke {
  sessionId: string;
  resumed: boolean;
  sessionDir: string;
  agentDir: string;
  modelRequest?: { model: string; text: string; stopReason: string };
  access: { credential: { mode: string }; selectedModel: string | null };
}

/** The whole persisted history of the acceptance session, as text. */
function sessionHistory(sessionDir: string): { files: number; text: string } {
  const files = readdirSync(sessionDir).filter((name) =>
    name.endsWith(".jsonl"),
  );
  return {
    files: files.length,
    text: files
      .map((name) => readFileSync(join(sessionDir, name), "utf8"))
      .join("\n"),
  };
}

/**
 * Every file under `directory` that holds `secret` as it is or as the file
 * secret store writes it (base64url, or base64), so a copy of the store's
 * file anywhere else in state shows up too.
 */
function holders(directory: string, secret: string): string[] {
  const forms = new Set([
    secret,
    Buffer.from(secret).toString("base64url"),
    Buffer.from(secret).toString("base64"),
  ]);
  return [
    ...new Set(
      scan(directory, [...forms]).map(
        (hit) => hit.split(" contains ")[0] as string,
      ),
    ),
  ].sort();
}

/** Under `root`, `secret` is only in the one file `store` holds it in. */
function expectOnlyInStore(root: string, store: string, secret: string): void {
  const files = holders(root, secret);
  expect(files).toHaveLength(1);
  expect(dirname(files[0] as string)).toBe(store);
}

/** The `<METHOD> <path>` of every request the model server has seen. */
function seen(requests: readonly ModelRequest[]): string[] {
  return requests.map((request) => `${request.method} ${request.path}`);
}

/** Uninstall keeps sessions, settings and credentials; only the install goes. */
function expectUninstalled(s: PersonalScenario, id: string): void {
  const uninstall = s.cli("uninstall", id);
  expect(uninstall.status, uninstall.stderr).toBe(0);
  expect(existsSync(s.command)).toBe(false);
  expect(existsSync(join(s.install, "apps", id))).toBe(false);
  expect(readdirSync(join(s.state, id, "sessions")).length).toBeGreaterThan(0);
  expect(existsSync(join(s.state, id, "state.json"))).toBe(true);
}

/** Offer 1.1.0 on the signed channel, check it, install it, and diagnose. */
async function update(s: PersonalScenario, name: string): Promise<void> {
  s.publish(1);
  const check = await s.run(["update", "--check"]);
  expect(check.status, check.stderr).toBe(0);
  expect(check.stdout).toContain(`${name} 1.1.0 is available`);
  expect((await s.run(["version"])).stdout).toContain(`${name} 1.0.0`);
  const updated = await s.run(["update"]);
  expect(updated.status, updated.stderr).toBe(0);
  expect(updated.stdout).toContain(
    `Updated ${name} 1.0.0 -> 1.1.0 (stable, signed by ${KEY_ID})`,
  );
  expect((await s.run(["version"])).stdout).toContain(`${name} 1.1.0`);
  const doctor = await s.run(["doctor"]);
  expect(doctor.status, doctor.stdout + doctor.stderr).toBe(0);
  expect(doctor.stdout).toMatch(/Release\n {2}✓ release\s+verified/);
  expect(doctor.stdout).toMatch(/rollback\s+1\.0\.0 retained/);
}

/** MyPi's flow; personal-clean-machine-mypi.test.ts runs it. */
export function myPiFlow(): void {
  it("MyPi: installs, delegates its credential to Pi, makes a model request, resumes the session, updates, rolls back, and uninstalls", async () => {
    const key = "sk-mypi-pi-native-owner-key";
    const server = await startModelServer({ key });
    onTestFinished(() => server.close());
    const requests = server.requests as ModelRequest[];
    const s = await personalScenario("clean-machine");
    // Provider keys in the environment and in the user's own ~/.pi must
    // never reach the model server: only Pi's sign-in kept in MyPi's state
    // may.
    const ambient = "sk-ambient-openai-key-e2e";
    const personal = "sk-personal-pi-auth-key-e2e";
    Object.assign(s.env, { OPENAI_API_KEY: ambient });
    mkdirSync(join(s.home, ".pi", "agent"), { recursive: true });
    const personalAuth = JSON.stringify({
      "mypi-fixture": { type: "api_key", key: personal },
    });
    writeFileSync(join(s.home, ".pi", "agent", "auth.json"), personalAuth);

    // Install: the consumer verifies the release, then installs it with the
    // script inside it, into an empty home.
    expect(existsSync(s.state)).toBe(false);
    const verified = s.cli("verify-release", s.releases.first, "--json");
    expect(verified.status, verified.stderr).toBe(0);
    expect(JSON.parse(verified.stdout)).toMatchObject({
      distribution: { id: "mypi", version: "1.0.0" },
      target,
    });
    await s.installFirst();
    expect(existsSync(s.command)).toBe(true);
    expect((await s.run(["version"])).stdout).toContain("Pi 1.0.2");

    // Launch: Pi starts on its pinned version with the declared resources
    // and no credential; the Pi-native access mode is reported.
    const launch = await s.run(["--smoke"]);
    expect(launch.status, launch.stderr).toBe(0);
    const first = JSON.parse(launch.stdout) as Smoke;
    expect(first).toMatchObject({
      initialized: true,
      piVersion: "1.0.2",
      resumed: false,
      skills: ["demo-skill"],
      access: {
        mode: "personal",
        identity: null,
        credential: { mode: "pi-native", credentialId: null },
        inference: "pi-native",
      },
      governance: { mcp: [{ id: "notes", state: "healthy" }] },
    });
    expect(requests).toEqual([]);

    // Credential delegation: MyPi has no sign-in of its own, so its commands
    // refuse and write nothing. The key lives where Pi's own sign-in puts
    // it, in the agent directory inside MyPi's state, next to the endpoint
    // Pi is configured with.
    const state = join(s.state, "mypi");
    for (const command of ["login", "logout"]) {
      const refused = await s.run([command]);
      expect(refused.status).toBe(1);
      expect(refused.stderr).toContain("POLICY_DENIED");
      expect(refused.stderr).toContain("delegates authentication to Pi");
    }
    expect(existsSync(join(state, "secrets"))).toBe(false);
    expect(existsSync(join(state, "identity"))).toBe(false);
    expect(realpathSync(first.agentDir)).toBe(
      realpathSync(join(state, "agent")),
    );
    // Until Pi is configured with the endpoint and a key, there is no model
    // to ask, whatever the environment and ~/.pi hold.
    const unconfigured = await s.run([
      "--model",
      "mypi-fixture/local/coder",
      "--smoke-model",
    ]);
    expect(unconfigured.status).toBe(1);
    expect(unconfigured.stderr).toContain("mypi-fixture/local/coder");
    expect(requests).toEqual([]);
    // A preference for a model Pi does not offer names its own undo, and
    // that undo works while the preference blocks launch.
    const typo = await s.run(["config", "set", "model", "mypi-fixture/typo"]);
    expect(typo.status, typo.stderr).toBe(0);
    const stale = await s.run(["--smoke"]);
    expect(stale.status).toBe(1);
    expect(stale.stderr).toContain(
      "Run mypi config unset model to remove the model preference",
    );
    const unset = await s.run(["config", "unset", "model"]);
    expect(unset.status, unset.stderr).toBe(0);
    writeFileSync(
      join(first.agentDir, "models.json"),
      JSON.stringify({
        providers: {
          "mypi-fixture": {
            baseUrl: server.url,
            api: "openai-completions",
            models: [
              {
                id: "local/coder",
                name: "Local Coder",
                contextWindow: 32000,
                maxTokens: 2048,
              },
            ],
          },
        },
      }),
    );
    writeFileSync(
      join(first.agentDir, "auth.json"),
      JSON.stringify({ "mypi-fixture": { type: "api_key", key } }),
      { mode: 0o600 },
    );

    // Model request: one real request from Pi to the endpoint, with the
    // delegated key, in the session the launch created.
    const request = await s.run([
      "--model",
      "mypi-fixture/local/coder",
      "--smoke-model",
    ]);
    expect(request.status, request.stderr).toBe(0);
    const asked = JSON.parse(request.stdout) as Smoke;
    expect(asked).toMatchObject({
      sessionId: first.sessionId,
      resumed: true,
      access: { credential: { mode: "pi-native" } },
      modelRequest: {
        model: "mypi-fixture/local/coder",
        text: "Hello from local/coder.",
        stopReason: "stop",
      },
    });
    expect(new Set(seen(requests))).toEqual(
      new Set(["POST /v1/chat/completions"]),
    );
    for (const item of requests)
      expect(item.authorization).toBe(`Bearer ${key}`);

    // Session resume: a later launch continues the same session, whose
    // stored history holds the model exchange.
    const resumed = await s.run(["--smoke"]);
    expect(resumed.status, resumed.stderr).toBe(0);
    expect(JSON.parse(resumed.stdout)).toMatchObject({
      sessionId: first.sessionId,
      resumed: true,
    });
    const history = sessionHistory(first.sessionDir);
    expect(history.files).toBe(1);
    expect(history.text).toContain("PiShip acceptance request");
    expect(history.text).toContain("Hello from local/coder.");

    // Doctor: the installed release, its trust, and the delegated credential.
    const doctor = await s.run(["doctor"]);
    expect(doctor.status, doctor.stdout + doctor.stderr).toBe(0);
    expect(doctor.stdout).toMatch(/state\s+delegated \(no PiShip secret\)/);
    expect(doctor.stdout).toMatch(/mcp notes\s+healthy \(stdio; 2 tool\(s\)\)/);
    expect(doctor.stdout).toMatch(/trusted keys\s+1/);
    expect(doctor.stdout).toMatch(/Release\n {2}✓ release\s+verified/);
    expect(doctor.stdout).toMatch(/Secret Store\n {2}- backend\s+not used/);

    // Update through the signed channel: the session and the delegated
    // credential carry over to 1.1.0.
    await update(s, "MyPi");
    const updatedRequest = await s.run([
      "--model",
      "mypi-fixture/local/coder",
      "--smoke-model",
    ]);
    expect(updatedRequest.status, updatedRequest.stderr).toBe(0);
    expect(JSON.parse(updatedRequest.stdout)).toMatchObject({
      sessionId: first.sessionId,
      resumed: true,
      modelRequest: { text: "Hello from local/coder.", stopReason: "stop" },
    });

    // Rollback: 1.0.0 again, with the same session and credential.
    const rollback = await s.run(["rollback"]);
    expect(rollback.status, rollback.stderr).toBe(0);
    expect(rollback.stdout).toContain("Rolled back MyPi 1.1.0 -> 1.0.0");
    expect((await s.run(["version"])).stdout).toContain("MyPi 1.0.0");
    const rolledBack = await s.run([
      "--model",
      "mypi-fixture/local/coder",
      "--smoke-model",
    ]);
    expect(rolledBack.status, rolledBack.stderr).toBe(0);
    expect(JSON.parse(rolledBack.stdout)).toMatchObject({
      sessionId: first.sessionId,
      resumed: true,
      modelRequest: { text: "Hello from local/coder.", stopReason: "stop" },
    });

    // Across the whole flow the model server saw only Pi's own key, the
    // update host only the signed channel, and PiShip kept the key nowhere:
    // it is in Pi's auth file alone, never copied by the update or rollback.
    expect(seen(requests)).toEqual(Array(3).fill("POST /v1/chat/completions"));
    for (const item of requests)
      expect(item.authorization).toBe(`Bearer ${key}`);
    const channelFiles = new Set([
      "root/2.json",
      "stable.json",
      "stable.json.sig",
      `mypi-1.1.0-${target}.tar.gz`,
    ]);
    expect(s.hostRequests.length).toBeGreaterThan(0);
    expect(s.hostRequests.filter((path) => !channelFiles.has(path))).toEqual(
      [],
    );
    expect(holders(s.state, key)).toEqual([join(state, "agent", "auth.json")]);
    expect(holders(s.state, ambient)).toEqual([]);
    expect(holders(s.state, personal)).toEqual([]);

    // Uninstall keeps sessions, state and Pi's credential, and leaves the
    // user's own ~/.pi as it was.
    expectUninstalled(s, "mypi");
    expect(readFileSync(join(state, "agent", "auth.json"), "utf8")).toContain(
      key,
    );
    expect(
      readFileSync(join(s.home, ".pi", "agent", "auth.json"), "utf8"),
    ).toBe(personalAuth);
    expect(existsSync(join(s.home, ".pi", "agent", "models.json"))).toBe(false);
  }, 1200000);
}

/** MyPi Local's flow; personal-clean-machine-local.test.ts runs it. */
export function myPiLocalFlow(): void {
  it("MyPi Local: installs, stores its key, makes a model request, resumes the session, updates, rolls back, and uninstalls", async () => {
    const key = "sk-mypi-local-clean-machine-key";
    const server = await startModelServer({ key });
    const requests = server.requests as ModelRequest[];
    onTestFinished(() => server.close());
    const s = await personalLocalScenario("clean-machine", server.url);
    const ambient = "sk-ambient-openai-key-e2e";
    Object.assign(s.env, { OPENAI_API_KEY: ambient });

    // Install: verify the release, then run the script shipped inside it.
    const verified = s.cli("verify-release", s.releases.first, "--json");
    expect(verified.status, verified.stderr).toBe(0);
    expect(JSON.parse(verified.stdout)).toMatchObject({
      distribution: { id: "mypi-local", version: "1.0.0" },
      target,
    });
    await s.installFirst();
    expect((await s.run(["version"])).stdout).toContain("Pi 1.0.2");

    // Launch: without a stored key the launch is refused before the endpoint
    // is contacted.
    const state = join(s.state, "mypi-local");
    const refused = await s.run(["--smoke"]);
    expect(refused.status).toBe(1);
    expect(refused.stderr).toContain("CREDENTIAL_REQUIRED");
    expect(requests).toEqual([]);

    // Credential configure: the user's key goes into the distribution's own
    // secret store, from standard input and never as an argument.
    const login = await s.run(["login"], `${key}\n`);
    expect(login.status, login.stderr).toBe(0);
    expect(login.stdout).toContain("No identity provider is configured");
    expect(existsSync(join(state, "secrets"))).toBe(true);
    expect(existsSync(join(state, "identity"))).toBe(false);
    expectOnlyInStore(s.state, join(state, "secrets"), key);
    const launch = await s.run(["--smoke"]);
    expect(launch.status, launch.stderr).toBe(0);
    const first = JSON.parse(launch.stdout) as Smoke;
    expect(first).toMatchObject({
      initialized: true,
      piVersion: "1.0.2",
      resumed: false,
      instructions: [expect.stringContaining("AGENTS.md")],
      access: {
        mode: "personal",
        identity: null,
        credential: { mode: "local-secret" },
        inference: "managed-endpoint",
        selectedModel: "mypi-local/local/coder",
      },
    });
    expect(realpathSync(first.agentDir)).toBe(
      realpathSync(join(state, "agent")),
    );
    expect(requests).toEqual([]);

    // Model request: one request straight to the local endpoint with the
    // stored key, in the session the launch created.
    const request = await s.run(["--smoke-model"]);
    expect(request.status, request.stderr).toBe(0);
    const asked = JSON.parse(request.stdout) as Smoke;
    expect(asked).toMatchObject({
      sessionId: first.sessionId,
      resumed: true,
      modelRequest: {
        model: "mypi-local/local/coder",
        text: "Hello from local/coder.",
        stopReason: "stop",
      },
    });
    expect(new Set(seen(requests))).toEqual(
      new Set(["POST /v1/chat/completions"]),
    );
    for (const item of requests)
      expect(item.authorization).toBe(`Bearer ${key}`);

    // Session resume: a later launch continues the same session, whose
    // stored history holds the model exchange.
    const resumed = await s.run(["--smoke"]);
    expect(resumed.status, resumed.stderr).toBe(0);
    expect(JSON.parse(resumed.stdout)).toMatchObject({
      sessionId: first.sessionId,
      resumed: true,
    });
    const history = sessionHistory(first.sessionDir);
    expect(history.files).toBe(1);
    expect(history.text).toContain("PiShip acceptance request");
    expect(history.text).toContain("Hello from local/coder.");

    // Doctor: the stored key is valid, doctor asks the endpoint which models
    // it lists, and the installed release verifies.
    const doctor = await s.run(["doctor"]);
    expect(doctor.status, doctor.stdout + doctor.stderr).toBe(0);
    expect(doctor.stdout).toMatch(
      /Credential\n {2}✓ provider\s+local-secret\n {2}✓ valid\s+no expiry/,
    );
    expect(doctor.stdout).toMatch(
      /Inference\n {2}✓ provider\s+openai-compatible/,
    );
    expect(doctor.stdout).toMatch(
      /Gateway\n {2}✓ endpoint\s+http:\/\/127\.0\.0\.1:\d+\n {2}✓ gateway\s+reachable \(1 listed; model providers not contacted\)/,
    );
    expect(doctor.stdout).toMatch(
      /Secret Store\n {2}! backend\s+restricted plaintext file/,
    );
    expect(doctor.stdout).toMatch(/Release\n {2}✓ release\s+verified/);
    expect(doctor.stdout).toMatch(/trusted keys\s+1/);
    expect(doctor.stdout).not.toContain(key);

    // Update through the signed channel: the stored key and the session
    // carry over to 1.1.0.
    await update(s, "MyPi Local");
    const updatedRequest = await s.run(["--smoke-model"]);
    expect(updatedRequest.status, updatedRequest.stderr).toBe(0);
    expect(JSON.parse(updatedRequest.stdout)).toMatchObject({
      sessionId: first.sessionId,
      resumed: true,
      modelRequest: { text: "Hello from local/coder.", stopReason: "stop" },
    });

    // Rollback: 1.0.0 again, with the same key and session.
    const rollback = await s.run(["rollback"]);
    expect(rollback.status, rollback.stderr).toBe(0);
    expect(rollback.stdout).toContain("Rolled back MyPi Local 1.1.0 -> 1.0.0");
    expect((await s.run(["version"])).stdout).toContain("MyPi Local 1.0.0");
    const rolledBack = await s.run(["--smoke-model"]);
    expect(rolledBack.status, rolledBack.stderr).toBe(0);
    expect(JSON.parse(rolledBack.stdout)).toMatchObject({
      sessionId: first.sessionId,
      resumed: true,
      modelRequest: { text: "Hello from local/coder.", stopReason: "stop" },
    });

    // Across the whole flow the model server saw only the stored key: three
    // chat requests, one per model request, and the model lists doctor asked
    // for. The update host saw only the signed channel, and the key is in
    // state only in the secret store's file, encoded or not: the update and
    // rollback records hold no copy.
    expect(
      seen(requests).filter((item) => item === "POST /v1/chat/completions"),
    ).toHaveLength(3);
    expect(new Set(seen(requests))).toEqual(
      new Set(["POST /v1/chat/completions", "GET /v1/models"]),
    );
    for (const item of requests)
      expect(item.authorization).toBe(`Bearer ${key}`);
    const channelFiles = new Set([
      "root/2.json",
      "stable.json",
      "stable.json.sig",
      `mypi-local-1.1.0-${target}.tar.gz`,
    ]);
    expect(s.hostRequests.length).toBeGreaterThan(0);
    expect(s.hostRequests.filter((path) => !channelFiles.has(path))).toEqual(
      [],
    );
    expectOnlyInStore(s.state, join(state, "secrets"), key);
    expect(holders(s.state, ambient)).toEqual([]);

    // Uninstall keeps sessions, state and the stored key for a reinstall,
    // and creates no ~/.pi.
    expectUninstalled(s, "mypi-local");
    expect(existsSync(join(state, "secrets"))).toBe(true);
    expect(existsSync(join(s.home, ".pi"))).toBe(false);
  }, 1200000);
}
