import { spawnSync } from "node:child_process";
import {
  cpSync,
  createReadStream,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
// @ts-expect-error The deterministic fixture is plain JavaScript.
import { startLocalServices } from "../../examples/demo-company/fixtures/local-services.mjs";
import { branded, type Result } from "../helpers/distribution.js";

// Production lifecycle evidence on the current platform: build two releases of
// the demo, install the first from its archive with the shipped install script,
// update through a signed loopback channel, roll back, and reject tampering.
const root = fileURLToPath(new URL("../../", import.meta.url));
const bin = join(root, "packages/cli/dist/bin.js");
const windows = process.platform === "win32";
const target = `${process.platform}-${process.arch}`;
const temporary: string[] = [];
const closers: (() => Promise<void> | void)[] = [];
afterEach(async () => {
  for (const close of closers.splice(0)) await close();
  for (const path of temporary.splice(0))
    rmSync(path, { recursive: true, force: true });
}, 180000);

type Services = Awaited<ReturnType<typeof startLocalServices>>;

function scan(directory: string, secrets: readonly string[]): string[] {
  const hits: string[] = [];
  const visit = (path: string) => {
    for (const name of readdirSync(path)) {
      const child = join(path, name);
      if (statSync(child).isDirectory()) {
        if (name !== "node_modules") visit(child);
      } else {
        const text = readFileSync(child, "latin1");
        for (const secret of secrets)
          if (secret && text.includes(secret))
            hits.push(`${child} contains ${secret.slice(0, 10)}…`);
      }
    }
  };
  visit(directory);
  return hits;
}

/** Serve a directory over loopback HTTP, the way a company update host would. */
async function serve(directory: string): Promise<string> {
  const server = createServer((request, response) => {
    const name = decodeURIComponent(
      new URL(request.url ?? "/", "http://127.0.0.1").pathname.slice(1),
    );
    const path = join(directory, name);
    if (!name || name.includes("/") || !existsSync(path)) {
      response.writeHead(404).end();
      return;
    }
    response.writeHead(200, { "content-length": statSync(path).size });
    createReadStream(path).pipe(response);
  });
  await new Promise<void>((resolve) =>
    server.listen(0, "127.0.0.1", () => resolve()),
  );
  closers.push(
    () => new Promise<void>((resolve) => server.close(() => resolve())),
  );
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}/`;
}

describe("production lifecycle (local fixtures)", () => {
  it("installs a release, updates through a signed channel, rolls back, and rejects tampering", async () => {
    const services: Services = await startLocalServices();
    closers.push(() => services.close());
    const temp = mkdtempSync(join(tmpdir(), "piship-lifecycle-e2e-"));
    temporary.push(temp);
    const directory = join(temp, "distribution");
    cpSync(join(root, "examples", "demo-company"), directory, {
      recursive: true,
    });
    const home = join(temp, "home");
    mkdirSync(home, { recursive: true });
    // On POSIX the install home is reached through a symlink, as macOS
    // temporary directories are (/var -> /private/var).
    const installHome = join(temp, "install");
    if (!windows) {
      mkdirSync(join(temp, "install-real"));
      symlinkSync(join(temp, "install-real"), installHome);
    }
    const channelDir = join(temp, "channel");
    mkdirSync(channelDir);
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      ...services.env(),
      ACMECODE_UPDATE_SOURCE: await serve(channelDir),
      PISHIP_STATE_HOME: join(temp, "state"),
      PISHIP_INSTALL_HOME: installHome,
      PISHIP_BIN_HOME: join(temp, "bin"),
      PISHIP_NO_BROWSER: "1",
      HOME: home,
      USERPROFILE: home,
    };
    delete env.PISHIP_BUILD_INPUT;
    delete env.PISHIP_SANDBOX_ADAPTER;
    const cli = (...args: string[]) => {
      const done = spawnSync(process.execPath, [bin, ...args], {
        cwd: temp,
        env,
        encoding: "utf8",
      });
      return { status: done.status, stdout: done.stdout, stderr: done.stderr };
    };

    // The owner generates a signing key and pins its public half.
    const key = join(temp, "keys", "release.pem");
    mkdirSync(join(temp, "keys"));
    const keygen = cli("keygen", key, "--id", "acme-e2e");
    expect(keygen.status, keygen.stderr).toBe(0);
    const publicKey = /publicKey: (\S+)/.exec(keygen.stdout)?.[1];
    expect(publicKey).toBeTruthy();
    const manifest = join(directory, "piship.yaml");
    let source = readFileSync(manifest, "utf8")
      .replace(
        "provider: system",
        "provider: file\n    acknowledgePlaintext: true",
      )
      .replace("127.0.0.1:8765", "127.0.0.1")
      .replace(
        "    keys: []",
        `    keys:\n      - id: acme-e2e\n        publicKey: ${publicKey}`,
      );
    if (windows)
      source = source.replace(
        "  required: true\n  filesystem:",
        "  required: false\n  filesystem:",
      );
    writeFileSync(manifest, source);

    const release = (version: string) => {
      writeFileSync(
        manifest,
        readFileSync(manifest, "utf8").replace(
          /^ {2}version: \d+\.\d+\.\d+$/m,
          `  version: ${version}`,
        ),
      );
      const lock = cli("lock", manifest);
      expect(lock.status, lock.stderr).toBe(0);
      const built = cli("release", manifest, "--out", join(temp, version));
      expect(built.status, built.stderr).toBe(0);
      expect(built.stdout).toContain(`acmecode-${version}-${target}`);
      return join(
        temp,
        version,
        "releases",
        `acmecode-${version}-${target}.tar.gz`,
      );
    };
    const first = release("1.0.0");
    // The release wraps exactly the payload `piship build` produces.
    const built = cli("build", manifest);
    expect(built.status, built.stderr).toBe(0);
    expect(
      readFileSync(
        join(
          temp,
          "1.0.0",
          "releases",
          `acmecode-1.0.0-${target}`,
          "payload",
          "metadata",
          "inventory.json",
        ),
      ),
    ).toEqual(
      readFileSync(
        join(temp, "dist", "acmecode", "metadata", "inventory.json"),
      ),
    );
    const second = release("1.1.0");
    const verified = cli("verify-release", first, "--json");
    expect(verified.status, verified.stderr).toBe(0);
    expect(JSON.parse(verified.stdout)).toMatchObject({
      distribution: { id: "acmecode", version: "1.0.0" },
      target,
    });

    // Install 1.0.0 with the install script shipped inside the release.
    const extracted = join(temp, "download");
    mkdirSync(extracted);
    expect(
      spawnSync("tar", ["-xzf", first, "-C", extracted], { encoding: "utf8" })
        .status,
    ).toBe(0);
    const releaseDir = join(extracted, `acmecode-1.0.0-${target}`);
    const installed = windows
      ? spawnSync(
          "powershell.exe",
          [
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            join(releaseDir, "install.ps1"),
          ],
          { cwd: temp, env, encoding: "utf8" },
        )
      : spawnSync("sh", [join(releaseDir, "install.sh")], {
          cwd: temp,
          env,
          encoding: "utf8",
        });
    expect(installed.status, installed.stderr).toBe(0);
    expect(installed.stdout).toContain("Installed acmecode@1.0.0");
    const command = join(temp, "bin", windows ? "acmecode.cmd" : "acmecode");
    const run = (args: string[]): Promise<Result> =>
      branded(command, args, {
        cwd: temp,
        env,
        approve: (url) => services.approve(url),
      });
    expect((await run(["version"])).stdout).toContain("AcmeCode 1.0.0");

    // Sign in, use it, and keep a session across the update.
    const login = await run(["login"]);
    expect(login.status, login.stderr).toBe(0);
    const session = await run(["--smoke"]);
    expect(session.status, session.stderr).toBe(0);
    const sessionId = JSON.parse(session.stdout).sessionId;
    services.knobs.gatewayMode = "text";
    const model = await run(["--smoke-model"]);
    expect(model.status, model.stderr).toBe(0);

    // Nothing is published yet: the channel does not exist.
    const empty = await run(["update", "--check"]);
    expect(empty.status).toBe(1);
    expect(empty.stderr).toContain("UPDATE_FAILED");

    // Publish 1.1.0 on the signed stable channel.
    cpSync(second, join(channelDir, `acmecode-1.1.0-${target}.tar.gz`));
    const sign = (sequence: number) =>
      cli(
        "sign-channel",
        channelDir,
        join(channelDir, `acmecode-1.1.0-${target}.tar.gz`),
        "--channel",
        "stable",
        "--key",
        key,
        "--key-id",
        "acme-e2e",
        "--sequence",
        String(sequence),
      );
    const signed = sign(1);
    expect(signed.status, signed.stderr).toBe(0);
    const check = await run(["update", "--check"]);
    expect(check.status, check.stderr).toBe(0);
    expect(check.stdout).toContain("AcmeCode 1.1.0 is available");
    expect((await run(["version"])).stdout).toContain("AcmeCode 1.0.0");

    // A tampered archive with intact metadata is refused and changes nothing.
    const archive = join(channelDir, `acmecode-1.1.0-${target}.tar.gz`);
    const good = readFileSync(archive);
    const bad = Buffer.from(good);
    bad[bad.length - 100] = (bad[bad.length - 100] ?? 0) ^ 0xff;
    writeFileSync(archive, bad);
    const tampered = await run(["update"]);
    expect(tampered.status).toBe(1);
    expect(tampered.stderr).toContain("INTEGRITY_FAILED");
    expect((await run(["version"])).stdout).toContain("AcmeCode 1.0.0");
    writeFileSync(archive, good);

    // Metadata changed after signing is refused as well.
    const metadata = join(channelDir, "stable.json");
    const signedMetadata = readFileSync(metadata, "utf8");
    writeFileSync(
      metadata,
      signedMetadata.replace('"sequence": 1', '"sequence": 9'),
    );
    const forged = await run(["update"]);
    expect(forged.status).toBe(1);
    expect(forged.stderr).toContain("INTEGRITY_FAILED");
    writeFileSync(metadata, signedMetadata);

    const updated = await run(["update"]);
    expect(updated.status, updated.stderr).toBe(0);
    expect(updated.stdout).toContain("Updated AcmeCode 1.0.0 -> 1.1.0");
    expect((await run(["version"])).stdout).toContain("AcmeCode 1.1.0");
    const resumed = await run(["--smoke"]);
    expect(resumed.status, resumed.stderr).toBe(0);
    expect(JSON.parse(resumed.stdout)).toMatchObject({
      sessionId,
      resumed: true,
    });
    const doctor = await run(["doctor"]);
    expect(doctor.stdout).toContain("Supply Chain");
    expect(doctor.stdout).toMatch(/release\s+verified/);
    expect(doctor.stdout).toMatch(/rollback\s+1\.0\.0 retained/);

    // Roll back while signed in: sessions come back, credentials are never
    // restored from anywhere.
    const secrets = [
      ...services.state.credentials.keys(),
      ...services.state.accessTokens.keys(),
      ...services.state.refreshTokens.keys(),
    ];
    expect(secrets.length).toBeGreaterThan(2);
    const rollback = await run(["rollback"]);
    expect(rollback.status, rollback.stderr).toBe(0);
    expect(rollback.stdout).toContain("Rolled back AcmeCode 1.1.0 -> 1.0.0");
    expect((await run(["version"])).stdout).toContain("AcmeCode 1.0.0");
    const afterRollback = await run(["--smoke"]);
    expect(afterRollback.status, afterRollback.stderr).toBe(0);
    expect(JSON.parse(afterRollback.stdout)).toMatchObject({
      sessionId,
      resumed: true,
    });

    // The company revokes every credential and token server-side, without a
    // local logout: the rolled-back release cannot use or renew them.
    for (const entry of services.state.credentials.values())
      entry.revoked = true;
    services.state.accessTokens.clear();
    services.state.refreshTokens.clear();
    const revoked = await run(["--smoke-model"]);
    expect(revoked.status).toBe(1);
    expect(revoked.stderr).toMatch(/IDENTITY_|CREDENTIAL_/);
    expect(revoked.stderr).toMatch(/login/);

    // Signing in again works and still resumes the same session.
    const relogin = await run(["login"]);
    expect(relogin.status, relogin.stderr).toBe(0);
    const again = await run(["--smoke-model"]);
    expect(again.status, again.stderr).toBe(0);
    secrets.push(
      ...services.state.credentials.keys(),
      ...services.state.accessTokens.keys(),
      ...services.state.refreshTokens.keys(),
    );
    const logout = await run(["logout"]);
    expect(logout.status, logout.stderr).toBe(0);
    expect((await run(["--smoke"])).stderr).toContain("IDENTITY_REQUIRED");
    expect(scan(join(temp, "state"), secrets)).toEqual([]);
    expect(scan(join(temp, "install"), secrets)).toEqual([]);
    // The user's personal Pi configuration is never touched.
    expect(existsSync(join(home, ".pi"))).toBe(false);

    // After a newer sequence is seen, replaying older signed metadata is refused.
    const signature = `${metadata}.sig`;
    const older = [readFileSync(metadata), readFileSync(signature)] as const;
    const newer = sign(2);
    expect(newer.status, newer.stderr).toBe(0);
    expect((await run(["update", "--check"])).status).toBe(0);
    writeFileSync(metadata, older[0]);
    writeFileSync(signature, older[1]);
    const replayed = await run(["update", "--check"]);
    expect(replayed.status).toBe(1);
    expect(replayed.stderr).toContain("refusing a replayed channel");

    const uninstall = cli("uninstall", "acmecode");
    expect(uninstall.status, uninstall.stderr).toBe(0);
    expect(existsSync(command)).toBe(false);
    expect(existsSync(join(temp, "install", "apps", "acmecode"))).toBe(false);
    // Uninstall keeps sessions and settings for a later reinstall.
    expect(
      readdirSync(join(temp, "state", "acmecode", "sessions")).length,
    ).toBeGreaterThan(0);
    expect(existsSync(join(temp, "state", "acmecode", "state.json"))).toBe(
      true,
    );
  }, 900000);
});
