import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { PISHIP_VERSION } from "../compatibility.js";
import { inventory } from "../payload.js";
import { formatChecksums } from "../supply-chain.js";
import { buildRuntimeRelease } from "./runtime.js";
import {
  isRuntimeRelease,
  RUNTIME_FILES,
  runtimeReleaseName,
  verifyRuntimeRelease,
} from "./index.js";
import { hash, writeJson } from "./shared.js";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});
function temp(): string {
  const dir = mkdtempSync(join(tmpdir(), "piship-runtime-"));
  roots.push(dir);
  return dir;
}
function write(path: string, content: string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content);
}

/** A runtime tree without npm: one package, the npm lock, and the inventory. */
function fakeAssemble(extra?: (payload: string) => void) {
  return (payload: string): void => {
    cpSync(
      join(process.env.PISHIP_BUILD_INPUT as string, "package-lock.json"),
      join(payload, "package-lock.json"),
    );
    write(
      join(payload, "node_modules", "alpha", "package.json"),
      JSON.stringify({ name: "alpha", version: "1.0.0", license: "MIT" }),
    );
    write(join(payload, "node_modules", "alpha", "LICENSE"), "MIT License\n");
    extra?.(payload);
    writeJson(join(payload, "metadata", "inventory.json"), inventory(payload));
  };
}

function build(extra?: (payload: string) => void) {
  return buildRuntimeRelease({
    outputRoot: temp(),
    assemble: fakeAssemble(extra),
    runTest: () => ({ status: 0, stdout: `${PISHIP_VERSION}\n`, stderr: "" }),
    scanner: () => ({ auditReportVersion: 2, vulnerabilities: {} }),
    signatureAuditor: () => ({
      status: 0,
      stdout: JSON.stringify({ invalid: [], missing: [] }),
      stderr: "",
    }),
    now: () => new Date("2026-06-01T00:00:00Z"),
  });
}

describe("runtime release", () => {
  it("builds a runtime archive that verifies, with the fields a pack binds", async () => {
    const built = await build();
    expect(built.name).toBe(
      runtimeReleaseName(`${process.platform}-${process.arch}`),
    );
    expect(isRuntimeRelease(built.archive)).toBe(true);
    expect(isRuntimeRelease(built.directory)).toBe(true);
    expect(built.metadata).toMatchObject({
      schema: "piship-runtime/v1",
      pishipVersion: PISHIP_VERSION,
      target: `${process.platform}-${process.arch}`,
      qualification: "qualified",
      strip: true,
      bundle: true,
      nodeMin: "22.19.0",
      searchTools: {},
    });
    expect(built.metadata.npmLockSha256).toBe(
      hash(
        readFileSync(
          join(process.env.PISHIP_BUILD_INPUT as string, "package-lock.json"),
        ),
      ),
    );
    const verified = await verifyRuntimeRelease(built.archive, {
      requireTarget: true,
      expectedSha256: built.sha256,
    });
    expect(verified.metadata).toEqual(built.metadata);
    expect(verified.archiveSha256).toBe(built.sha256);
    verified.cleanup();
    (await verifyRuntimeRelease(built.directory)).cleanup();
  });

  it("rejects a wrong digest and a flipped archive byte", async () => {
    const built = await build();
    await expect(
      verifyRuntimeRelease(built.archive, { expectedSha256: "0".repeat(64) }),
    ).rejects.toMatchObject({ code: "INTEGRITY_FAILED" });
    const bytes = readFileSync(built.archive);
    bytes[bytes.length - 20] = (bytes[bytes.length - 20] ?? 0) ^ 0xff;
    rmSync(`${built.archive}.sha256`);
    writeFileSync(built.archive, bytes);
    await expect(
      verifyRuntimeRelease(built.archive, { expectedSha256: built.sha256 }),
    ).rejects.toMatchObject({ code: "INTEGRITY_FAILED" });
  });

  it("rejects a modified payload file, runtime.json, and checksums line", async () => {
    const built = await build();
    const payloadFile = join(
      built.directory,
      "payload",
      "node_modules",
      "alpha",
      "LICENSE",
    );
    const original = readFileSync(payloadFile);
    writeFileSync(payloadFile, "tampered\n");
    await expect(verifyRuntimeRelease(built.directory)).rejects.toThrow(
      /inventory|checksum/i,
    );
    writeFileSync(payloadFile, original);
    (await verifyRuntimeRelease(built.directory)).cleanup();
    const json = join(built.directory, "runtime.json");
    const text = readFileSync(json, "utf8");
    writeFileSync(json, text.replace(PISHIP_VERSION, "9.9.9"));
    await expect(verifyRuntimeRelease(built.directory)).rejects.toThrow(
      /Checksum mismatch/,
    );
    writeFileSync(json, text);
    const checksums = join(built.directory, "checksums.txt");
    const lines = readFileSync(checksums, "utf8");
    writeFileSync(
      checksums,
      lines.replace(/^[0-9a-f]/, (c) => (c === "0" ? "1" : "0")),
    );
    await expect(verifyRuntimeRelease(built.directory)).rejects.toMatchObject({
      code: "INTEGRITY_FAILED",
    });
  });

  it("refuses a runtime for another target when the target must match, and still verifies it otherwise", async () => {
    const built = await build();
    const foreign = process.platform === "linux" ? "win32" : "linux";
    const payload = join(built.directory, "payload");
    writeJson(join(payload, "metadata", "target.json"), {
      platform: foreign,
      arch: process.arch,
    });
    writeJson(join(payload, "metadata", "inventory.json"), inventory(payload));
    const metadata = JSON.parse(
      readFileSync(join(built.directory, "runtime.json"), "utf8"),
    );
    metadata.target = `${foreign}-${process.arch}`;
    metadata.inventory.sha256 = hash(
      readFileSync(join(payload, "metadata", "inventory.json")),
    );
    writeJson(join(built.directory, "runtime.json"), metadata);
    writeFileSync(
      join(built.directory, "checksums.txt"),
      formatChecksums(built.directory, [...RUNTIME_FILES]),
    );
    await expect(
      verifyRuntimeRelease(built.directory, { requireTarget: true }),
    ).rejects.toThrow(/not this machine/);
    (await verifyRuntimeRelease(built.directory)).cleanup();
  });

  it("refuses a payload that carries distribution files", async () => {
    const built = await build((payload) =>
      write(join(payload, "piship.lock"), "{}\n"),
    );
    await expect(verifyRuntimeRelease(built.directory)).rejects.toThrow(
      /distribution files/,
    );
  });

  it("refuses a failed launch test", async () => {
    await expect(
      buildRuntimeRelease({
        outputRoot: temp(),
        assemble: fakeAssemble(),
        runTest: () => ({ status: 1, stdout: "", stderr: "boom" }),
        scanner: () => ({ auditReportVersion: 2, vulnerabilities: {} }),
        signatureAuditor: () => ({
          status: 0,
          stdout: '{"invalid":[],"missing":[]}',
          stderr: "",
        }),
      }),
    ).rejects.toThrow(/runtime-version failed/);
  });
});
