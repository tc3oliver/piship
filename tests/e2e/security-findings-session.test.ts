import { spawnSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it, onTestFinished } from "vitest";
import { branded, launcher } from "../helpers/distribution.js";
import { scan } from "../helpers/lifecycle.js";

const root = fileURLToPath(new URL("../../", import.meta.url));
const bin = join(root, "packages/cli/dist/bin.js");
// An obvious fake, stored with `login` and sent as the gateway bearer.
const CREDENTIAL = "sk-piship-fake-echoed-credential-0123456789";

const MANIFEST = [
  "schema: piship/v1alpha2",
  "app:",
  "  id: mypi",
  "  name: MyPi",
  "  command: mypi",
  "  version: 1.0.0",
  "runtime:",
  '  pi: "1.1.0"',
  "deployment:",
  "  mode: personal",
  "variables:",
  "  - MYPI_GATEWAY_URL",
  "identity:",
  "  mode: none",
  "credential:",
  "  provider: local-secret",
  "  storage:",
  "    provider: file",
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
  "",
].join("\n");

/**
 * A careless gateway: it lists the model, and fails every completion with an
 * error that repeats the request's Authorization header.
 */
async function echoingGateway() {
  let completions = 0;
  const server: Server = createServer((request, response) => {
    request.resume();
    request.on("end", () => {
      response.setHeader("content-type", "application/json");
      if (request.method === "GET" && request.url?.endsWith("/models")) {
        response.end(
          JSON.stringify({
            object: "list",
            data: [{ id: "acme/coder", object: "model" }],
          }),
        );
        return;
      }
      completions += 1;
      response.statusCode = 500;
      response.end(
        JSON.stringify({
          error: {
            message: `upstream failure for Authorization: ${request.headers.authorization}`,
            type: "server_error",
          },
        }),
      );
    });
  });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  return {
    url: `http://127.0.0.1:${(server.address() as { port: number }).port}/v1`,
    get completions() {
      return completions;
    },
    close: () =>
      new Promise<void>((done) => {
        server.close(() => done());
        server.closeAllConnections();
      }),
  };
}

// Pi records a failed request's error text in the session file it writes
// under the state directory. PiShip redacts that text before Pi records it,
// so a gateway that echoes the credential into its error leaves nothing of it
// in `sessions/`, nor in anything else the run writes or prints.
describe("provider error text in Pi session files (local fixtures)", () => {
  it("keeps what a gateway echoes of the credential out of the session file", async () => {
    const gateway = await echoingGateway();
    const temp = realpathSync(
      mkdtempSync(join(tmpdir(), "piship-security-session-")),
    );
    onTestFinished(async () => {
      await gateway.close();
      rmSync(temp, { recursive: true, force: true });
    });
    const directory = join(temp, "distribution");
    cpSync(join(root, "examples", "personal"), directory, { recursive: true });
    const manifest = join(directory, "piship.yaml");
    writeFileSync(manifest, MANIFEST);
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      MYPI_GATEWAY_URL: gateway.url,
      PISHIP_STATE_HOME: join(temp, "state"),
      HOME: join(temp, "home"),
      USERPROFILE: join(temp, "home"),
    };
    delete env.PISHIP_BUILD_INPUT;
    const cli = (...args: string[]) =>
      spawnSync(process.execPath, [bin, ...args], {
        cwd: temp,
        env,
        encoding: "utf8",
      });
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
    const login = await run(["login"], `${CREDENTIAL}\n`);
    expect(login.status, login.stderr).toBe(0);

    const smoke = await run(["--smoke-model"]);
    expect(gateway.completions, "the gateway was asked").toBeGreaterThan(0);
    expect(smoke.status).toBe(1);
    expect(smoke.stderr).toContain("GATEWAY_UNREACHABLE");
    expect(smoke.stderr).toContain("upstream failure");
    expect(`${smoke.stdout}${smoke.stderr}`).not.toContain(CREDENTIAL);

    const sessions = join(temp, "state", "mypi", "sessions");
    expect(existsSync(sessions)).toBe(true);
    const recorded = readdirSync(sessions, {
      recursive: true,
      encoding: "utf8",
    })
      .filter((name) => name.endsWith(".jsonl"))
      .map((name) => readFileSync(join(sessions, name), "utf8"))
      .join("\n");
    // Pi recorded the failed request, with its error text redacted.
    expect(recorded).toContain('"errorMessage"');
    expect(recorded).toContain("upstream failure");
    // The file store under state/mypi/secrets keeps the credential
    // base64url-encoded, where it belongs; everything else holds none of it.
    expect(scan(join(temp, "state"), [CREDENTIAL])).toEqual([]);
  }, 600000);
});
