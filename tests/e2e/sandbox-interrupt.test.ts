import { spawnSync } from "node:child_process";
import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
// @ts-expect-error The deterministic fixture is plain JavaScript.
import { startLocalServices } from "../../examples/demo-company/fixtures/local-services.mjs";
import {
  CLAIMS,
  kubernetesServer,
} from "../../packages/sandbox/src/testing/kubernetes-server.js";
import { closeMockServers } from "../../packages/sandbox/src/testing/mock-server.js";
import { branded, launcher } from "../helpers/distribution.js";

// A Ctrl-C while the launch waits for a SandboxClaim from a warm pool with no
// ready pod: the claim is deleted at once, not left holding a pod until its
// shutdownTime, and the launch exits 130. Doctor's sandbox probe likewise.
const root = fileURLToPath(new URL("../../", import.meta.url));
const bin = join(root, "packages/cli/dist/bin.js");
const temporary: string[] = [];
const closers: (() => Promise<void> | void)[] = [];
afterEach(async () => {
  for (const close of closers.splice(0)) await close();
  await closeMockServers();
  for (const path of temporary.splice(0))
    rmSync(path, { recursive: true, force: true });
}, 180000);

// Windows cannot deliver SIGINT to a child process.
describe.skipIf(process.platform === "win32")(
  "interrupting a launch that waits for a sandbox (local fixtures)",
  () => {
    it("deletes the pending SandboxClaim, says what it waits for, and exits 130", async () => {
      const services = await startLocalServices();
      closers.push(() => services.close());
      const cluster = await kubernetesServer(undefined, { neverReady: true });
      const temp = realpathSync(
        mkdtempSync(join(tmpdir(), "piship-sandbox-interrupt-")),
      );
      temporary.push(temp);
      const directory = join(temp, "distribution");
      cpSync(join(root, "examples", "demo-company"), directory, {
        recursive: true,
      });
      const manifest = join(directory, "piship.yaml");
      const source = readFileSync(manifest, "utf8")
        .replace(
          "provider: system",
          "provider: file\n    acknowledgePlaintext: true",
        )
        .replace("127.0.0.1:8765", "127.0.0.1")
        .replace(
          "  - ACMECODE_LLM_GATEWAY_URL\n",
          "  - ACMECODE_LLM_GATEWAY_URL\n  - ACMECODE_SANDBOX_URL\n",
        )
        .replace(
          /sandbox:\n {2}required: (true|false)\n/,
          [
            "sandbox:",
            "  required: true",
            "  provider: kubernetes-agent-sandbox",
            `  endpoint: \${ACMECODE_SANDBOX_URL}`,
            `  router: \${ACMECODE_SANDBOX_URL}`,
            "  namespace: agents",
            "  template: python-pool",
            "  credential: none",
            "",
          ].join("\n"),
        )
        .replace(
          "  network:\n    mode: deny\n",
          "  network:\n    mode: allow\n",
        );
      for (const marker of [
        "credential: none",
        "  network:\n    mode: allow\n",
      ])
        if (!source.includes(marker))
          throw new Error(`patch failed: ${marker}`);
      writeFileSync(manifest, source);
      const home = join(temp, "home");
      mkdirSync(home, { recursive: true });
      const env: NodeJS.ProcessEnv = {
        ...process.env,
        ...services.env(),
        ACMECODE_SANDBOX_URL: cluster.url,
        PISHIP_STATE_HOME: join(temp, "state"),
        PISHIP_NO_BROWSER: "1",
        HOME: home,
        USERPROFILE: home,
      };
      delete env.PISHIP_BUILD_INPUT;
      delete env.PISHIP_SANDBOX_ADAPTER;
      for (const step of ["lock", "build"]) {
        const done = spawnSync(process.execPath, [bin, step, manifest], {
          cwd: temp,
          env,
          encoding: "utf8",
        });
        expect(done.status, done.stderr).toBe(0);
      }
      const command = launcher(join(temp, "dist", "acmecode"), "acmecode");
      const project = join(temp, "project");
      mkdirSync(project, { recursive: true });
      const run = (args: string[], interrupt = false) =>
        branded(command, args, {
          cwd: project,
          env,
          approve: (url) => services.approve(url),
          timeoutMs: 60_000,
          ...(interrupt ? { interruptOnStderr: /Ctrl-C cancels/ } : {}),
        });
      const login = await run(["login"]);
      expect(login.status, login.stderr).toBe(0);

      // Doctor probes the sandbox with a fresh claim, cancelled the same way.
      for (const args of [["--smoke"], ["doctor"]]) {
        const from = cluster.requests.length;
        const done = await run(args, true);
        expect(done.stderr).toContain(
          "Notice: requesting a sandbox from warm pool python-pool in namespace agents; waiting up to 120 s for it to become ready (Ctrl-C cancels).",
        );
        expect(done.status, done.stderr).toBe(130);
        const created = cluster.requests
          .slice(from)
          .find(
            (request) => request.method === "POST" && request.path === CLAIMS,
          );
        const name = JSON.parse(created?.body.toString() ?? "{}").metadata
          ?.name;
        expect(name).toMatch(/^piship-/);
        expect(cluster.requests.at(-1)).toMatchObject({
          method: "DELETE",
          path: `${CLAIMS}/${name}`,
        });
      }
    }, 180000);
  },
);
