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
import type { LockedSearchTool, LockedSearchTools } from "../lock-schema.js";
import {
  SEARCH_TOOL_SPECS,
  searchToolAsset,
  searchToolFileName,
} from "../search-tools/index.js";
import { SEARCH_TOOLS } from "@piship/schema";
import { createArchive } from "../archive.js";
import { compareReleases } from "./reproducibility.js";
import { PISHIP_VERSION } from "../compatibility.js";
import { inventory } from "../payload.js";
import { formatChecksums } from "../supply-chain.js";
import { buildRuntimeRelease } from "./runtime.js";
import {
  releaseKind,
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
    write(
      join(payload, "node_modules", "@piship", "core", "package.json"),
      JSON.stringify({ name: "@piship/core", version: PISHIP_VERSION }),
    );
    extra?.(payload);
    writeJson(join(payload, "metadata", "inventory.json"), inventory(payload));
  };
}

/** Places `tools/fd` and `tools/rg` and pins the catalog versions, without the network. */
function fakeSearchTools(payload: string, target: string): LockedSearchTools {
  const locked: Record<string, LockedSearchTool> = {};
  for (const tool of SEARCH_TOOLS) {
    const { defaultVersion: version, source } = SEARCH_TOOL_SPECS[tool];
    write(join(payload, "tools", searchToolFileName(tool, target)), tool);
    write(
      join(payload, "tools", "licenses", tool, "LICENSE"),
      `${tool} license\n`,
    );
    locked[tool] = {
      version,
      source,
      targets: {
        [target]: {
          url: searchToolAsset(tool, version, target).url,
          archive: `sha256-${hash(tool)}`,
          entry: tool,
          binary: hash(tool),
          size: tool.length,
        },
      },
    };
  }
  return locked;
}

/** Rewrites a built runtime directory and seals it again: inventory, runtime.json, checksums. */
function reseal(
  directory: string,
  change: (payload: string, metadata: Record<string, unknown>) => void,
): void {
  const payload = join(directory, "payload");
  const json = join(directory, "runtime.json");
  const metadata = JSON.parse(readFileSync(json, "utf8"));
  change(payload, metadata);
  writeJson(join(payload, "metadata", "inventory.json"), inventory(payload));
  metadata.inventory.sha256 = hash(
    readFileSync(join(payload, "metadata", "inventory.json")),
  );
  writeJson(json, metadata);
  writeFileSync(
    join(directory, "checksums.txt"),
    formatChecksums(directory, [...RUNTIME_FILES]),
  );
}

function build(extra?: (payload: string) => void) {
  return buildRuntimeRelease({
    outputRoot: temp(),
    assemble: fakeAssemble(extra),
    bundleSearchTools: fakeSearchTools,
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
    expect(await releaseKind(built.archive)).toBe("runtime");
    expect(await releaseKind(built.directory)).toBe("runtime");
    // Routed by content, not by name.
    const renamed = join(dirname(built.archive), "anything-0.0.0-x.tar.gz");
    expect(await releaseKind(join(temp(), "missing"))).toBe("release");
    expect(renamed).not.toBe(built.archive);
    expect(built.metadata).toMatchObject({
      schema: "piship-runtime/v1",
      pishipVersion: PISHIP_VERSION,
      target: `${process.platform}-${process.arch}`,
      qualification: "qualified",
      strip: true,
      bundle: true,
      nodeMin: "22.19.0",
      searchTools: { fd: "10.5.0", rg: "15.2.0" },
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

  it("refuses a runtime for another target when the target must match", async () => {
    const built = await build();
    const foreign = process.platform === "linux" ? "win32" : "linux";
    reseal(built.directory, (payload, metadata) => {
      writeJson(join(payload, "metadata", "target.json"), {
        platform: foreign,
        arch: process.arch,
      });
      metadata.target = `${foreign}-${process.arch}`;
    });
    await expect(
      verifyRuntimeRelease(built.directory, { requireTarget: true }),
    ).rejects.toThrow(/not this machine/);
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

  it("binds the PiShip and Pi versions to the payload", async () => {
    const built = await build();
    reseal(built.directory, (payload) =>
      write(
        join(payload, "node_modules", "@piship", "core", "package.json"),
        JSON.stringify({ name: "@piship/core", version: "9.9.9" }),
      ),
    );
    await expect(verifyRuntimeRelease(built.directory)).rejects.toThrow(
      /PiShip version/,
    );
    const other = await build();
    reseal(other.directory, (_payload, metadata) => {
      (metadata.pi as { version: string }).version = "0.0.1";
    });
    await expect(verifyRuntimeRelease(other.directory)).rejects.toThrow(
      /Pi version/,
    );
  });

  it("covers the search tools in the SBOM and notices, and binds their versions", async () => {
    const built = await build();
    const sbom = readFileSync(join(built.directory, "sbom.spdx.json"), "utf8");
    expect(sbom).toContain("pkg:github/sharkdp/fd@v10.5.0");
    expect(
      readFileSync(
        join(built.directory, "licenses", "THIRD_PARTY_NOTICES.txt"),
        "utf8",
      ),
    ).toContain("fd license");
    reseal(built.directory, (_payload, metadata) => {
      metadata.searchTools = { fd: "1.0.0", rg: "15.2.0" };
    });
    await expect(verifyRuntimeRelease(built.directory)).rejects.toThrow(
      /search tools/,
    );
  });

  it("rejects unexpected top-level entries, in a directory and an archive", async () => {
    const built = await build();
    write(join(built.directory, "extra.txt"), "x");
    await expect(verifyRuntimeRelease(built.directory)).rejects.toThrow(
      /unexpected entries/,
    );
    rmSync(join(built.directory, "extra.txt"));
    write(join(built.directory, "licenses", "extra.txt"), "x");
    await expect(verifyRuntimeRelease(built.directory)).rejects.toThrow(
      /licenses\/extra.txt/,
    );
    rmSync(join(built.directory, "licenses", "extra.txt"));
    write(join(built.directory, "install.sh"), "#!/bin/sh\n");
    const archive = join(temp(), `${built.name}.tar.gz`);
    await createArchive(built.directory, built.name, archive);
    await expect(verifyRuntimeRelease(archive)).rejects.toThrow(/install.sh/);
  });

  it("compares two builds of the runtime by their payloads", async () => {
    const first = await build();
    const second = await build();
    expect(await compareReleases(first.archive, second.archive)).toMatchObject({
      distribution: "piship-runtime",
      version: PISHIP_VERSION,
      payloadEqual: true,
      archiveEqual: true,
    });
    const other = await build((payload) =>
      write(join(payload, "extra.txt"), "x"),
    );
    const report = await compareReleases(first.archive, other.archive);
    expect(report.payloadEqual).toBe(false);
    expect(report.payloadDifferences).toContain("extra.txt");
  });
});
