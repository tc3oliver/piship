import { spawnSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it, onTestFinished } from "vitest";
// @ts-expect-error The stand-in model server is plain JavaScript.
import { startModelServer } from "../../examples/personal/local-model/model-server.mjs";
import { branded, launcher } from "../helpers/distribution.js";
import { scan } from "../helpers/lifecycle.js";

const root = fileURLToPath(new URL("../../", import.meta.url));
const bin = join(root, "packages/cli/dist/bin.js");
const example = join(root, "examples", "personal", "local-model");

interface ModelRequest {
  method: string;
  path: string;
  authorization?: string;
}

// The MyPi Local variant: a personal distribution with no enterprise
// identity, a user-owned key in its own secret store, and a direct
// OpenAI-compatible endpoint on loopback, standing in for a local model
// server.
describe("personal local model variant (loopback model server)", () => {
  it("keeps its committed lock current, stores a local secret, calls the local endpoint directly, and resumes its session after logout and login", async () => {
    const key = "sk-mypi-local-owner-key";
    const server = await startModelServer({ key });
    const temp = mkdtempSync(join(tmpdir(), "piship-mypi-local-"));
    onTestFinished(async () => {
      await server.close();
      rmSync(temp, { recursive: true, force: true });
    });
    const directory = join(temp, "distribution");
    cpSync(example, directory, { recursive: true });
    const manifest = join(directory, "piship.yaml");
    // The system secret store needs a desktop keyring; use the personal
    // file store, which needs no plaintext acknowledgement.
    const source = readFileSync(manifest, "utf8");
    expect(source).toContain("  storage:\n    provider: system");
    writeFileSync(
      manifest,
      source.replace(
        "  storage:\n    provider: system",
        "  storage:\n    provider: file",
      ),
    );
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      MYPI_MODEL_URL: server.url,
      PISHIP_STATE_HOME: join(temp, "state"),
      HOME: join(temp, "home"),
      USERPROFILE: join(temp, "home"),
      OPENAI_API_KEY: "sk-ambient-openai-key-e2e",
    };
    delete env.PISHIP_BUILD_INPUT;
    const cli = (...args: string[]) =>
      spawnSync(process.execPath, [bin, ...args], {
        cwd: temp,
        env,
        encoding: "utf8",
      });

    // The committed example lock is current: locking the unmodified copy
    // reproduces it byte for byte.
    const committed = join(temp, "committed");
    cpSync(example, committed, { recursive: true });
    const relock = cli("lock", join(committed, "piship.yaml"));
    expect(relock.status, relock.stderr).toBe(0);
    expect(readFileSync(join(committed, "piship.lock"), "utf8")).toBe(
      readFileSync(join(example, "piship.lock"), "utf8"),
    );

    const validate = cli("validate", manifest);
    expect(validate.status, validate.stderr).toBe(0);
    expect(cli("lock", manifest).status).toBe(0);
    const build = cli("build", manifest);
    expect(build.status, build.stderr).toBe(0);
    const command = launcher(join(temp, "dist", "mypi-local"), "mypi-local");
    const run = (args: string[], input?: string) =>
      branded(command, args, {
        cwd: temp,
        env,
        ...(input ? { input } : {}),
      });

    // Without a stored key the endpoint is not called.
    const before = await run(["--smoke"]);
    expect(before.status).toBe(1);
    expect(before.stderr).toContain("CREDENTIAL_REQUIRED");
    const login = await run(["login"], `${key}\n`);
    expect(login.status, login.stderr).toBe(0);
    expect(login.stdout).toContain("No identity provider is configured");

    const smoke = await run(["--smoke-model"]);
    expect(smoke.status, smoke.stderr).toBe(0);
    const first = JSON.parse(smoke.stdout) as { sessionId: string };
    expect(first).toMatchObject({
      piVersion: "1.0.2",
      instructions: [expect.stringContaining("AGENTS.md")],
      access: {
        mode: "personal",
        identity: null,
        credential: { mode: "local-secret" },
        // The smoke summary's name for an openai-compatible endpoint.
        inference: "managed-endpoint",
        selectedModel: "mypi-local/local/coder",
      },
      modelRequest: {
        text: "Hello from local/coder.",
        stopReason: "stop",
      },
    });
    // Inference went straight to the local endpoint with the stored key,
    // never the ambient provider key.
    const requests = server.requests as ModelRequest[];
    const chat = requests.filter(
      (request) => request.path === "/v1/chat/completions",
    );
    expect(chat.length).toBeGreaterThan(0);
    for (const request of requests)
      expect(request.authorization).toBe(`Bearer ${key}`);

    // The key never lands in plain view in state, and logout removes it.
    expect(scan(join(temp, "state"), [key])).toEqual([]);
    const logout = await run(["logout"]);
    expect(logout.status, logout.stderr).toBe(0);
    expect((await run(["--smoke"])).stderr).toContain("CREDENTIAL_REQUIRED");

    // Signing in again resumes the earlier session: with no identity there
    // is no principal, so nothing about the user changed.
    const relogin = await run(["login"], `${key}\n`);
    expect(relogin.status, relogin.stderr).toBe(0);
    const resumed = await run(["--smoke"]);
    expect(resumed.status, resumed.stderr).toBe(0);
    expect(JSON.parse(resumed.stdout)).toMatchObject({
      sessionId: first.sessionId,
      resumed: true,
      access: { identity: null, credential: { mode: "local-secret" } },
    });
    expect(existsSync(join(temp, "state", "mypi-local", "identity"))).toBe(
      false,
    );
    expect(existsSync(join(temp, "home", ".pi"))).toBe(false);
  }, 600000);
});
