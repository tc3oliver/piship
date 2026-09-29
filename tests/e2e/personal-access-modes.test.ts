import { spawnSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it, onTestFinished } from "vitest";
// @ts-expect-error The deterministic fixture is plain JavaScript.
import { startLocalServices } from "../../examples/demo-company/fixtures/local-services.mjs";
import { branded, launcher } from "../helpers/distribution.js";
import { scan } from "../helpers/lifecycle.js";

const root = fileURLToPath(new URL("../../", import.meta.url));
const bin = join(root, "packages/cli/dist/bin.js");

type Services = Awaited<ReturnType<typeof startLocalServices>>;

// The personal example on an older schema (v1alpha2 access fields), migrated
// by the builder, with an OpenAI-compatible endpoint on the fixture gateway.
const PERSONAL_V1ALPHA2 = [
  "schema: piship/v1alpha2",
  "app:",
  "  id: mypi",
  "  name: MyPi",
  "  command: mypi",
  "  version: 1.0.0",
  "runtime:",
  '  pi: "0.87.1"',
  "deployment:",
  "  mode: personal",
  "variables:",
  "  - MYPI_GATEWAY_URL",
  "identity:",
  "  mode: none",
  "credential:",
  "  CREDENTIAL",
  "inference:",
  "  provider: openai-compatible",
  `  baseUrl: \${MYPI_GATEWAY_URL}`,
  "models:",
  "  default: acme/coder",
  "  allowed: [acme/coder]",
  "  catalog:",
  "    acme/coder:",
  "      name: Local Coder",
  "      contextWindow: 32000",
  "      maxOutputTokens: 2048",
  "resources:",
  "  instructions:",
  "    - ./resources/AGENTS.md",
  "  skills:",
  "    - ./resources/skills",
  "  extensions:",
  "    - ./resources/extensions/demo",
  "  prompts:",
  "    - ./resources/prompts",
  "",
].join("\n");

interface Smoke {
  sessionId: string;
  resumed: boolean;
}

// A personal distribution has no identity provider, so there is no principal
// to bind credentials to: sign-in, launch, and sign-out behave as before, no
// principal record is written, and sessions survive login, logout, and login
// again. Each mode needs its own build; on the v0.6 Release qualification
// (Ubuntu) these took 13 s and 9 s, and the comparable personal-local-model
// file took 19 s on macOS and 47 s on Windows, so they run on every target.
describe("personal access modes without enterprise identity (local fixtures)", () => {
  it.each([
    [
      "local-secret",
      "provider: local-secret\n  storage:\n    provider: file",
      "sk-personal-owner-sentinel",
    ],
    ["none", "provider: none", "piship-no-credential"],
  ])(
    "runs identity.mode none with %s credentials and resumes sessions across logout and login",
    async (mode, credential, acceptedKey) => {
      const services: Services = await startLocalServices({
        knobs: { acceptedKeys: [acceptedKey] },
      });
      const temp = mkdtempSync(join(tmpdir(), "piship-personal-modes-"));
      onTestFinished(async () => {
        await services.close();
        rmSync(temp, { recursive: true, force: true });
      });
      const directory = join(temp, "distribution");
      cpSync(join(root, "examples", "personal"), directory, {
        recursive: true,
      });
      const manifest = join(directory, "piship.yaml");
      writeFileSync(
        manifest,
        PERSONAL_V1ALPHA2.replace("CREDENTIAL", credential),
      );
      const env: NodeJS.ProcessEnv = {
        ...process.env,
        MYPI_GATEWAY_URL: services.gatewayUrl,
        PISHIP_STATE_HOME: join(temp, "state"),
        HOME: join(temp, "home"),
        USERPROFILE: join(temp, "home"),
        OPENAI_API_KEY: "sk-ambient-personal-key-e2e",
      };
      delete env.PISHIP_BUILD_INPUT;
      const cli = (...args: string[]) =>
        spawnSync(process.execPath, [bin, ...args], {
          cwd: temp,
          env,
          encoding: "utf8",
        });
      const validate = cli("validate", manifest);
      expect(validate.status, validate.stderr).toBe(0);
      expect(cli("lock", manifest).status).toBe(0);
      const build = cli("build", manifest);
      expect(build.status, build.stderr).toBe(0);
      const command = launcher(join(temp, "dist", "mypi"), "mypi");
      const run = (args: string[], input?: string) =>
        branded(command, args, {
          cwd: temp,
          env,
          ...(input ? { input } : {}),
        });
      const signIn = async () => {
        const login = await run(
          ["login"],
          mode === "local-secret" ? `${acceptedKey}\n` : undefined,
        );
        expect(login.status, login.stderr).toBe(0);
        expect(login.stdout).toContain("No identity provider is configured");
        if (mode === "none") expect(login.stdout).toContain("no stored secret");
      };
      const state = join(temp, "state", "mypi");

      if (mode === "local-secret")
        expect((await run(["--smoke"])).stderr).toContain(
          "CREDENTIAL_REQUIRED",
        );
      await signIn();
      const result = await run(["--smoke-model"]);
      expect(result.status, result.stderr).toBe(0);
      const first = JSON.parse(result.stdout) as Smoke;
      expect(first).toMatchObject({
        access: { mode: "personal", identity: null, credential: { mode } },
        modelRequest: { text: "Hello from acme/coder.", stopReason: "stop" },
      });
      const chat = services.state.requests.find((item: { path: string }) =>
        item.path.endsWith("/chat/completions"),
      );
      expect(chat.authorization).toBe(`Bearer ${acceptedKey}`);
      expect(scan(join(temp, "state"), ["sk-personal-owner-sentinel"])).toEqual(
        [],
      );

      // Sign out, then in again: the key (if any) is gone in between, and the
      // earlier session resumes afterwards.
      const logout = await run(["logout"]);
      expect(logout.status, logout.stderr).toBe(0);
      expect(logout.stdout).toContain("sessions were preserved");
      if (mode === "local-secret")
        expect((await run(["--smoke"])).stderr).toContain(
          "CREDENTIAL_REQUIRED",
        );
      await signIn();
      const again = await run(["--smoke"]);
      expect(again.status, again.stderr).toBe(0);
      expect(JSON.parse(again.stdout)).toMatchObject({
        sessionId: first.sessionId,
        resumed: true,
        access: { identity: null },
      });

      // No identity state at all: no session and no principal record.
      expect(existsSync(join(state, "identity"))).toBe(false);
    },
    600000,
  );
});
