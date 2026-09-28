import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { join, relative, sep } from "node:path";
import { describe, expect, it, onTestFinished } from "vitest";
import { KEY_ID, personalScenario, target } from "../helpers/lifecycle.js";

/** Every file under `directory` with its content, keyed by relative path. */
function snapshot(directory: string): Record<string, string> {
  const files: Record<string, string> = {};
  const visit = (path: string) => {
    for (const name of readdirSync(path)) {
      const child = join(path, name);
      if (statSync(child).isDirectory()) visit(child);
      else
        files[relative(directory, child).split(sep).join("/")] = readFileSync(
          child,
          "utf8",
        );
    }
  };
  visit(directory);
  return files;
}

function inside(child: string, parent: string): boolean {
  const path = relative(realpathSync(parent), realpathSync(child));
  return path !== "" && !path.startsWith("..") && !path.includes(":");
}

/**
 * A proxy that answers every request with 502 and records it. The scenario
 * points the proxy variables at it (loopback excluded), so any outbound
 * request through a proxy-aware client shows up here.
 */
async function trapProxy(): Promise<{ url: string; hits: string[] }> {
  const hits: string[] = [];
  const server = createServer((request, response) => {
    hits.push(`${request.method} ${request.url}`);
    response.writeHead(502).end();
  });
  server.on("connect", (request, socket) => {
    hits.push(`CONNECT ${request.url}`);
    socket.end("HTTP/1.1 502 Bad Gateway\r\n\r\n");
  });
  await new Promise<void>((resolve) =>
    server.listen(0, "127.0.0.1", () => resolve()),
  );
  onTestFinished(
    () => new Promise<void>((resolve) => server.close(() => resolve())),
  );
  return {
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    hits,
  };
}

interface Smoke {
  piVersion: string;
  sessionId: string;
  resumed: boolean;
  agentDir: string;
  skills: string[];
  access: unknown;
  governance: { mcp: unknown; audit: unknown };
}

// The personal reference distribution through its whole lifecycle, with no
// enterprise infrastructure: no identity provider, broker, gateway, audit
// backend, or private network. The only service is a loopback update host.
describe("personal lifecycle (no enterprise infrastructure)", () => {
  it("installs a release, runs Pi-native with a local MCP server, updates, rolls back, and uninstalls keeping state and ~/.pi", async () => {
    const s = await personalScenario("lifecycle");
    const proxy = await trapProxy();
    Object.assign(s.env, {
      HTTP_PROXY: proxy.url,
      HTTPS_PROXY: proxy.url,
      http_proxy: proxy.url,
      https_proxy: proxy.url,
      NO_PROXY: "127.0.0.1,localhost,::1",
      no_proxy: "127.0.0.1,localhost,::1",
    });

    // The user's own Pi setup, which the distribution must neither read
    // nor change.
    const pi = join(s.home, ".pi", "agent");
    mkdirSync(join(pi, "skills", "ambient"), { recursive: true });
    writeFileSync(
      join(pi, "skills", "ambient", "SKILL.md"),
      "---\nname: ambient\ndescription: Must not load\n---\n",
    );
    writeFileSync(join(pi, "settings.json"), '{"theme":"light"}\n');
    writeFileSync(join(pi, "auth.json"), "{}\n");
    const personalPi = snapshot(join(s.home, ".pi"));

    // The consumer checks the release, then installs it with its own script.
    const verified = s.cli("verify-release", s.releases.first, "--json");
    expect(verified.status, verified.stderr).toBe(0);
    expect(JSON.parse(verified.stdout)).toMatchObject({
      distribution: { id: "mypi", version: "1.0.0" },
      target,
    });
    await s.installFirst();
    const version = await s.run(["version"]);
    expect(version.stdout).toContain("MyPi 1.0.0");
    expect(version.stdout).toContain("Pi 0.87.1");

    // Pi starts on the exact pinned version with the declared personal
    // resources, Pi-native access, and the declared MCP server healthy. No
    // model request is made.
    const smoke = await s.run(["--smoke"]);
    expect(smoke.status, smoke.stderr).toBe(0);
    const first = JSON.parse(smoke.stdout) as Smoke;
    const expected = {
      piVersion: "0.87.1",
      safeTool: "read",
      skills: ["demo-skill"],
      extensions: 1,
      prompts: ["demo"],
      themes: ["mypi"],
      access: {
        mode: "personal",
        identity: null,
        credential: { mode: "pi-native", credentialId: null },
        inference: "pi-native",
      },
      governance: {
        policy: "mypi@1",
        sandbox: { level: "not-required" },
        mcp: [
          {
            id: "notes",
            state: "healthy",
            tools: ["mcp__notes__list_notes", "mcp__notes__read_note"],
          },
        ],
        audit: "disabled",
      },
    };
    expect(first).toMatchObject({ ...expected, resumed: false });
    expect(inside(first.agentDir, join(s.state, "mypi"))).toBe(true);

    const doctor = await s.run(["doctor"]);
    expect(doctor.status, doctor.stdout + doctor.stderr).toBe(0);
    expect(doctor.stdout).toMatch(/mode\s+none/);
    expect(doctor.stdout).toMatch(/state\s+delegated \(no PiShip secret\)/);
    expect(doctor.stdout).toMatch(/provider\s+pi-native/);
    expect(doctor.stdout).toMatch(/mcp notes\s+healthy \(stdio; 2 tool\(s\)\)/);
    expect(doctor.stdout).toMatch(/audit\s+audit: disabled/);
    expect(doctor.stdout).toMatch(/trusted keys\s+1/);

    // The installed lock declares no enterprise endpoint: no identity,
    // broker, or gateway, and the update source is the only variable.
    const inspected = s.cli("inspect", "mypi");
    expect(inspected.status, inspected.stderr).toBe(0);
    const inspect = JSON.parse(inspected.stdout);
    expect(inspect).toMatchObject({
      app: { id: "mypi", version: "1.0.0" },
      deployment: { mode: "personal" },
      runtime: { version: "0.87.1" },
      access: {
        identity: { mode: "none" },
        credential: { provider: "pi-native" },
        inference: { provider: "pi-native" },
        models: { allowed: [] },
        variables: ["MYPI_UPDATE_SOURCE"],
      },
      governance: {
        manifest: {
          mcp: {
            mode: "explicit",
            servers: [
              {
                id: "notes",
                transport: "stdio",
                module: "./resources/mcp/notes-server.mjs",
              },
            ],
          },
        },
      },
    });
    expect(inspect.access.identity.oidc).toBeUndefined();
    expect(inspect.access.credential.broker).toBeUndefined();
    expect(inspect.access.inference.baseUrl).toBeUndefined();
    expect(inspect.artifact).toContain(join("apps", "mypi", "1.0.0"));

    // A signed update from the loopback channel keeps the session.
    s.publish(1);
    const updated = await s.run(["update"]);
    expect(updated.status, updated.stderr).toBe(0);
    expect(updated.stdout).toContain(
      `Updated MyPi 1.0.0 -> 1.1.0 (stable, signed by ${KEY_ID})`,
    );
    expect((await s.run(["version"])).stdout).toContain("MyPi 1.1.0");
    const afterUpdate = await s.run(["--smoke"]);
    expect(afterUpdate.status, afterUpdate.stderr).toBe(0);
    expect(JSON.parse(afterUpdate.stdout)).toMatchObject({
      ...expected,
      sessionId: first.sessionId,
      resumed: true,
    });
    expect((await s.run(["doctor"])).stdout).toMatch(
      /rollback\s+1\.0\.0 retained/,
    );

    // Rolling back returns to 1.0.0 with the same session.
    const rollback = await s.run(["rollback"]);
    expect(rollback.status, rollback.stderr).toBe(0);
    expect(rollback.stdout).toContain("Rolled back MyPi 1.1.0 -> 1.0.0");
    expect((await s.run(["version"])).stdout).toContain("MyPi 1.0.0");
    const afterRollback = await s.run(["--smoke"]);
    expect(afterRollback.status, afterRollback.stderr).toBe(0);
    expect(JSON.parse(afterRollback.stdout)).toMatchObject({
      ...expected,
      sessionId: first.sessionId,
      resumed: true,
    });

    // Nothing but the channel was contacted, and no enterprise state exists.
    const channelFiles = new Set([
      "stable.json",
      "stable.json.sig",
      `mypi-1.1.0-${target}.tar.gz`,
    ]);
    expect(s.hostRequests.length).toBeGreaterThan(0);
    expect(s.hostRequests.filter((path) => !channelFiles.has(path))).toEqual(
      [],
    );
    expect(proxy.hits).toEqual([]);
    // Control: a request that does leave the machine reaches the trap.
    const outbound = await s.run([
      "update",
      "--check",
      "--from",
      "https://updates.example.invalid/",
    ]);
    expect(outbound.status).toBe(1);
    expect(proxy.hits).toEqual(["CONNECT updates.example.invalid:443"]);
    const state = join(s.state, "mypi");
    for (const enterprise of [
      "identity",
      "credentials-metadata",
      "secrets",
      join("logs", "audit.jsonl"),
    ])
      expect(existsSync(join(state, enterprise)), enterprise).toBe(false);

    // Uninstall removes the install and keeps sessions and settings.
    const uninstall = s.cli("uninstall", "mypi");
    expect(uninstall.status, uninstall.stderr).toBe(0);
    expect(existsSync(s.command)).toBe(false);
    expect(existsSync(join(s.install, "apps", "mypi"))).toBe(false);
    expect(readdirSync(join(state, "sessions")).length).toBeGreaterThan(0);
    expect(existsSync(join(state, "state.json"))).toBe(true);

    // The user's personal Pi configuration is untouched.
    expect(snapshot(join(s.home, ".pi"))).toEqual(personalPi);
  }, 900000);
});
