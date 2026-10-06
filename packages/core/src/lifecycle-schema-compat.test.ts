// Releases built from different manifest schemas, installed and updated by
// this PiShip: a release that predates piship/v1 must still install and
// verify, and an installation on it must update to a piship/v1 release and
// roll back to the old one with its bytes untouched.
import { createHash } from "node:crypto";
import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  currentTarget,
  EVIDENCED_TARGETS,
  lockManifest,
  payloadInventory,
  verifyPayload,
} from "./index.js";
import { installDistribution, readInstallReceipt } from "./install/index.js";
import {
  buildRelease,
  type CommandResult,
  signChannel,
} from "./release/index.js";
import { generateSigningKey } from "./signing.js";
import {
  rollbackDistribution,
  type UpdateOptions,
  updateDistribution,
} from "./update/index.js";

const BUILD_INPUT = process.env.PISHIP_BUILD_INPUT as string;
const KEY = generateSigningKey("test-release");
const ID = "acmepi";
const HOST_EVIDENCED = EVIDENCED_TARGETS.includes(currentTarget());

const roots: string[] = [];
const ENV_KEYS = [
  "PISHIP_INSTALL_HOME",
  "PISHIP_BIN_HOME",
  "PISHIP_STATE_HOME",
  "SOURCE_DATE_EPOCH",
];
let savedEnv: Record<string, string | undefined> = {};

beforeEach(() => {
  savedEnv = Object.fromEntries(ENV_KEYS.map((key) => [key, process.env[key]]));
  process.env.SOURCE_DATE_EPOCH = "1767225600";
  const home = temp("piship-home-");
  process.env.PISHIP_INSTALL_HOME = join(home, "install");
  process.env.PISHIP_BIN_HOME = join(home, "bin");
  process.env.PISHIP_STATE_HOME = join(home, "state");
});
afterEach(() => {
  for (const [key, value] of Object.entries(savedEnv))
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

function temp(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  roots.push(dir);
  return dir;
}
function write(path: string, content: string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content);
}
const sha256 = (path: string) =>
  createHash("sha256").update(readFileSync(path)).digest("hex");

function manifestSource(schema: string, version: string): string {
  return `schema: ${schema}
app:
  id: ${ID}
  name: AcmePi
  command: ${ID}
  version: ${version}
runtime:
  pi: "1.0.3"
deployment:
  mode: personal
variables:
  - ACMEPI_UPDATE_SOURCE
resources:
  instructions:
    user: [./resources/AGENTS.md]
updates:
  channel: stable
  channels: [stable]
  source: \${ACMEPI_UPDATE_SOURCE}
  rollback: true
  trust:
    bootstrap:
      version: 1
      expires: 2099-01-01T00:00:00Z
      keys:
        - id: ${KEY.id}
          publicKey: ${KEY.publicKey}
      roles:
        root: { keyIds: [${KEY.id}], threshold: 1 }
        channel: { keyIds: [${KEY.id}], threshold: 1 }
release:
  bundle: false
  strip: false
`;
}

function fakeAssemble(manifestPath: string, outputRoot: string): string {
  const base = dirname(resolve(manifestPath));
  const lock = JSON.parse(readFileSync(join(base, "piship.lock"), "utf8")) as {
    app: { id: string; command: string };
    resources: { path: string }[];
  };
  const out = join(outputRoot, lock.app.id);
  mkdirSync(out, { recursive: true });
  cpSync(manifestPath, join(out, "piship.yaml"));
  cpSync(join(base, "piship.lock"), join(out, "piship.lock"));
  cpSync(
    join(BUILD_INPUT, "package-lock.json"),
    join(out, "package-lock.json"),
  );
  for (const resource of lock.resources)
    write(
      join(out, "resources", resource.path),
      readFileSync(join(base, resource.path), "utf8"),
    );
  write(
    join(out, "metadata", "target.json"),
    `${JSON.stringify({ platform: process.platform, arch: process.arch }, null, 2)}\n`,
  );
  write(
    join(out, "bin", lock.app.command),
    "#!/usr/bin/env node\nconsole.log('payload');\n",
  );
  write(
    join(out, "node_modules", "alpha", "package.json"),
    JSON.stringify({ name: "alpha", version: "1.0.0", license: "MIT" }),
  );
  write(
    join(out, "node_modules", "@piship", "core", "dist", "index.js"),
    `export { holdRuntimeLease } from ${JSON.stringify(pathToFileURL(resolve("packages/core/dist/index.js")).href)};\n`,
  );
  write(
    join(out, "node_modules", "@piship", "core", "package.json"),
    '{"type":"module"}\n',
  );
  write(
    join(out, "metadata", "inventory.json"),
    `${JSON.stringify(payloadInventory(out), null, 2)}\n`,
  );
  return out;
}

function fakeRun(
  payload: string,
  _command: string,
  args: readonly string[],
): CommandResult {
  const lock = JSON.parse(
    readFileSync(join(payload, "piship.lock"), "utf8"),
  ) as {
    app: { name: string; version: string };
    runtime: { version: string };
  };
  if (args[0] === "version")
    return {
      status: 0,
      stdout: `${lock.app.name} ${lock.app.version}\nPi ${lock.runtime.version} (PiShip 0.1.0)\n`,
      stderr: "",
    };
  if (args[0] === "--smoke")
    return { status: 0, stdout: '{"initialized":true}\n', stderr: "" };
  if (args[0] === "capabilities")
    return { status: 0, stdout: "[]\n", stderr: "" };
  return { status: 2, stdout: "", stderr: `unexpected ${args.join(" ")}` };
}

const signatureAuditor = () => ({
  status: 1,
  stdout: JSON.stringify({
    error: { summary: "found no installed dependencies to audit", detail: "" },
  }),
  stderr: "",
});

async function release(schema: string, version: string) {
  const dir = temp("piship-project-");
  write(join(dir, "resources", "AGENTS.md"), `# AcmePi ${version}\n`);
  const path = join(dir, "piship.yaml");
  writeFileSync(path, manifestSource(schema, version));
  lockManifest(path);
  return buildRelease(path, {
    outputRoot: join(dir, "dist"),
    assemble: fakeAssemble,
    runTest: fakeRun,
    scanner: () => ({ auditReportVersion: 2, vulnerabilities: {} }),
    signatureAuditor,
  });
}

async function channelOffering(archive: string, sequenceFrom?: string) {
  const directory = temp("piship-channel-");
  if (sequenceFrom) {
    cpSync(join(sequenceFrom, "stable.json"), join(directory, "stable.json"));
    cpSync(
      join(sequenceFrom, "stable.json.sig"),
      join(directory, "stable.json.sig"),
    );
  }
  await signChannel({
    directory,
    channel: "stable",
    archives: [archive],
    privateKeyPem: KEY.privateKeyPem,
    keyId: KEY.id,
  });
  return directory;
}

const appsDir = () =>
  join(process.env.PISHIP_INSTALL_HOME as string, "apps", ID);

describe.runIf(HOST_EVIDENCED)("releases across manifest schemas", () => {
  it("installs a piship/v1alpha6 release, verifying it as before", async () => {
    const built = await release("piship/v1alpha6", "1.0.0");
    const receipt = await installDistribution(built.archive);
    const installed = join(appsDir(), "1.0.0");
    expect(receipt.active).toBe("1.0.0");
    expect(receipt.releases[0]?.release).toMatchObject({
      lockSha256: built.metadata.lockSha256,
      archiveSha256: built.sha256,
    });
    expect(verifyPayload(installed).app.version).toBe("1.0.0");
    expect(
      JSON.parse(readFileSync(join(installed, "piship.lock"), "utf8")),
    ).toMatchObject({
      schema: "piship-lock/v1alpha6",
      manifest: { schema: "piship/v1alpha6" },
    });
  });

  it("installs a piship/v1 release", async () => {
    const built = await release("piship/v1", "1.0.0");
    const receipt = await installDistribution(built.archive);
    const installed = join(appsDir(), "1.0.0");
    expect(receipt.active).toBe("1.0.0");
    expect(verifyPayload(installed).app.version).toBe("1.0.0");
    expect(
      JSON.parse(readFileSync(join(installed, "piship.lock"), "utf8")),
    ).toMatchObject({
      schema: "piship-lock/v1",
      manifest: { schema: "piship/v1" },
    });
  });

  it("updates a piship/v1alpha6 installation to a piship/v1 release and rolls back, leaving the old release untouched", async () => {
    const a = await release("piship/v1alpha6", "1.0.0");
    const b = await release("piship/v1", "1.1.0");
    const offeredA = await channelOffering(a.archive);
    const offeredB = await channelOffering(b.archive, offeredA);
    const options: UpdateOptions = { source: offeredB, runCheck: fakeRun };

    await installDistribution(a.archive, true);
    const oldLock = join(appsDir(), "1.0.0", "piship.lock");
    const lockHash = sha256(oldLock);

    const result = await updateDistribution(ID, options);
    expect(result).toMatchObject({
      status: "updated",
      from: "1.0.0",
      to: "1.1.0",
    });
    expect(readInstallReceipt(ID)).toMatchObject({
      active: "1.1.0",
      previous: "1.0.0",
    });
    expect(verifyPayload(join(appsDir(), "1.1.0")).app.version).toBe("1.1.0");
    expect(
      JSON.parse(readFileSync(join(appsDir(), "1.1.0", "piship.lock"), "utf8")),
    ).toMatchObject({ schema: "piship-lock/v1" });
    // The older release is still the byte-identical, verifiable release.
    expect(sha256(oldLock)).toBe(lockHash);
    expect(verifyPayload(join(appsDir(), "1.0.0")).app.version).toBe("1.0.0");

    await rollbackDistribution(ID, { runCheck: fakeRun });
    expect(readInstallReceipt(ID)).toMatchObject({ active: "1.0.0" });
    expect(sha256(oldLock)).toBe(lockHash);
    expect(verifyPayload(join(appsDir(), "1.0.0")).app.version).toBe("1.0.0");
  });
});
