import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  type SpdxDocument,
  formatChecksums,
  generateNotices,
  generateSbom,
  listPayloadPackages,
  sriToSpdxChecksums,
  verifyChecksums,
  verifyNotices,
  verifySbom,
} from "./supply-chain.js";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

function write(root: string, path: string, content: string) {
  mkdirSync(dirname(join(root, path)), { recursive: true });
  writeFileSync(join(root, path), content);
}

function pkg(
  root: string,
  path: string,
  manifest: Record<string, unknown>,
  files: Record<string, string> = {},
) {
  write(root, `${path}/package.json`, JSON.stringify(manifest));
  for (const [name, content] of Object.entries(files))
    write(root, `${path}/${name}`, content);
}

const SHA512 = createHash("sha512").update("alpha").digest();

function payload(): string {
  const root = mkdtempSync(join(tmpdir(), "piship-supply-"));
  roots.push(root);
  pkg(
    root,
    "node_modules/alpha",
    { name: "alpha", version: "1.0.0", license: "MIT" },
    { LICENSE: "MIT License\nalpha\n", "NOTICE.md": "alpha notice\n" },
  );
  pkg(
    root,
    "node_modules/alpha/node_modules/beta",
    { name: "beta", version: "2.0.0", license: "(MIT OR Apache-2.0)" },
    { "LICENCE.txt": "beta licence\n" },
  );
  pkg(
    root,
    "node_modules/@scope/gamma",
    { name: "@scope/gamma", version: "3.1.0", license: "SEE LICENSE IN x" },
    { COPYING: "gamma copying\n", "readme.md": "not a license\n" },
  );
  pkg(root, "node_modules/beta", {
    name: "beta",
    version: "1.5.0",
    license: { type: "ISC" },
  });
  pkg(root, "node_modules/.bin/ignored", { name: "ignored", version: "0.0.1" });
  pkg(root, "node_modules/nameless", { version: "0.0.1" });
  write(root, "piship.yaml", "schema: piship/v1alpha4\n");
  return root;
}

function sbomFor(root: string, created = "2026-01-01T00:00:00Z") {
  return generateSbom({
    payloadDir: root,
    distribution: { id: "mypi", name: "My Pi", version: "0.1.0" },
    target: "linux-x64",
    created,
    lockPackages: [
      {
        path: "node_modules/alpha",
        version: "1.0.0",
        integrity: `sha512-${SHA512.toString("base64")}`,
        resolved: "https://registry.npmjs.org/alpha/-/alpha-1.0.0.tgz",
      },
      {
        path: "node_modules/@scope/gamma",
        version: "3.1.0",
        integrity: "sha1-AAECAwQFBgcICQoLDA0ODxAREhM=",
      },
    ],
  });
}

const clone = (value: unknown) =>
  JSON.parse(JSON.stringify(value)) as SpdxDocument;

describe("listPayloadPackages", () => {
  it("lists scoped and nested packages with license files, sorted", () => {
    const root = payload();
    expect(listPayloadPackages(root)).toEqual([
      {
        name: "@scope/gamma",
        version: "3.1.0",
        path: "node_modules/@scope/gamma",
        license: "SEE LICENSE IN x",
        licenseFiles: ["node_modules/@scope/gamma/COPYING"],
      },
      {
        name: "alpha",
        version: "1.0.0",
        path: "node_modules/alpha",
        license: "MIT",
        licenseFiles: [
          "node_modules/alpha/LICENSE",
          "node_modules/alpha/NOTICE.md",
        ],
      },
      {
        name: "beta",
        version: "2.0.0",
        path: "node_modules/alpha/node_modules/beta",
        license: "(MIT OR Apache-2.0)",
        licenseFiles: ["node_modules/alpha/node_modules/beta/LICENCE.txt"],
      },
      {
        name: "beta",
        version: "1.5.0",
        path: "node_modules/beta",
        license: "ISC",
        licenseFiles: [],
      },
    ]);
  });

  it("rejects an unreadable package manifest", () => {
    const root = payload();
    write(root, "node_modules/broken/package.json", "{");
    expect(() => listPayloadPackages(root)).toThrow(/not readable JSON/);
  });
});

describe("SBOM", () => {
  it("describes every payload package as SPDX 2.3", () => {
    const root = payload();
    const sbom = sbomFor(root);
    expect(sbom.spdxVersion).toBe("SPDX-2.3");
    expect(sbom.dataLicense).toBe("CC0-1.0");
    expect(sbom.name).toBe("mypi-0.1.0-linux-x64");
    expect(sbom.documentNamespace).toMatch(
      /^https:\/\/piship\.dev\/spdx\/mypi\/0\.1\.0\/linux-x64\/[0-9a-f]{64}$/,
    );
    expect(sbom.creationInfo).toEqual({
      created: "2026-01-01T00:00:00Z",
      creators: ["Tool: piship"],
    });
    expect(sbom.packages[0]).toMatchObject({
      SPDXID: "SPDXRef-Distribution",
      name: "My Pi",
      versionInfo: "0.1.0",
      primaryPackagePurpose: "APPLICATION",
    });
    const ids = sbom.packages.map((item) => item.SPDXID);
    expect(new Set(ids).size).toBe(ids.length);
    for (const id of ids) expect(id).toMatch(/^SPDXRef-[A-Za-z0-9.-]+$/);
    const byPath = Object.fromEntries(
      sbom.packages.slice(1).map((item) => [item.sourceInfo, item]),
    );
    expect(byPath["payload:node_modules/alpha"]).toMatchObject({
      downloadLocation: "https://registry.npmjs.org/alpha/-/alpha-1.0.0.tgz",
      licenseDeclared: "MIT",
      licenseConcluded: "NOASSERTION",
      filesAnalyzed: false,
      supplier: "NOASSERTION",
      checksums: [
        { algorithm: "SHA512", checksumValue: SHA512.toString("hex") },
      ],
    });
    expect(byPath["payload:node_modules/@scope/gamma"]).toMatchObject({
      downloadLocation: "NOASSERTION",
      licenseDeclared: "NOASSERTION",
      checksums: [
        {
          algorithm: "SHA1",
          checksumValue: "000102030405060708090a0b0c0d0e0f10111213",
        },
      ],
      externalRefs: [
        {
          referenceCategory: "PACKAGE-MANAGER",
          referenceType: "purl",
          referenceLocator: "pkg:npm/%40scope/gamma@3.1.0",
        },
      ],
    });
    expect(
      byPath["payload:node_modules/alpha/node_modules/beta"],
    ).toMatchObject({ licenseDeclared: "(MIT OR Apache-2.0)" });
    expect(byPath["payload:node_modules/beta"]?.checksums).toBeUndefined();
    expect(sbom.relationships).toHaveLength(sbom.packages.length);
    expect(sbom.relationships[0]).toEqual({
      spdxElementId: "SPDXRef-DOCUMENT",
      relationshipType: "DESCRIBES",
      relatedSpdxElement: "SPDXRef-Distribution",
    });
    verifySbom(root, sbom);
  });

  it("is deterministic", () => {
    const root = payload();
    expect(JSON.stringify(sbomFor(root))).toBe(JSON.stringify(sbomFor(root)));
  });

  it("converts SRI integrity to hex", () => {
    const sha256 = createHash("sha256").update("x").digest();
    expect(
      sriToSpdxChecksums(
        `sha512-${SHA512.toString("base64")} sha256-${sha256.toString("base64")} md5-abc`,
      ),
    ).toEqual([
      { algorithm: "SHA256", checksumValue: sha256.toString("hex") },
      { algorithm: "SHA512", checksumValue: SHA512.toString("hex") },
    ]);
  });

  it("fails when the SBOM omits a payload package", () => {
    const root = payload();
    const sbom = clone(sbomFor(root));
    const packages = sbom.packages.filter((item) => item.name !== "alpha");
    expect(() => verifySbom(root, { ...sbom, packages })).toThrow(
      "SBOM is missing alpha@1.0.0 (node_modules/alpha)",
    );
  });

  it("fails when the payload gains a package", () => {
    const root = payload();
    const sbom = sbomFor(root);
    pkg(root, "node_modules/delta", { name: "delta", version: "1.0.0" });
    expect(() => verifySbom(root, sbom)).toThrow(/missing delta@1.0.0/);
  });

  it("fails when the SBOM lists a package the payload lacks", () => {
    const root = payload();
    const sbom = sbomFor(root);
    rmSync(join(root, "node_modules/beta"), { recursive: true });
    expect(() => verifySbom(root, sbom)).toThrow(/not in the payload/);
  });

  it("fails on wrong version or a missing relationship", () => {
    const root = payload();
    const sbom = clone(sbomFor(root));
    expect(() =>
      verifySbom(root, { ...sbom, spdxVersion: "SPDX-2.2" }),
    ).toThrow(/SPDX-2.3/);
    expect(() =>
      verifySbom(root, {
        ...sbom,
        relationships: sbom.relationships.slice(0, -1),
      }),
    ).toThrow(/DEPENDS_ON/);
    expect(() =>
      verifySbom(root, { ...sbom, relationships: sbom.relationships.slice(1) }),
    ).toThrow(/DESCRIBES/);
  });
});

describe("notices", () => {
  it.each(["linux", "win32"])(
    "covers bundled tools and their shipped licenses on %s",
    (platform) => {
      const root = payload();
      const target = `${platform}-x64`;
      write(
        root,
        "metadata/target.json",
        JSON.stringify({ platform, arch: "x64" }),
      );
      const searchTools = Object.fromEntries(
        [
          ["fd", "10.5.0", "https://github.com/sharkdp/fd"],
          ["rg", "14.1.1", "https://github.com/BurntSushi/ripgrep"],
        ].map(([name, version, source]) => [
          name,
          {
            version,
            source,
            targets: {
              [target]: {
                url: `${source}/releases/download/v${version}/tool.zip`,
                archive: `sha256-${"a".repeat(64)}`,
              },
            },
          },
        ]),
      );
      write(root, "piship.lock", JSON.stringify({ searchTools }));
      write(root, "tools/licenses/fd/LICENSE-MIT", "fd MIT license");
      write(root, "tools/licenses/rg/COPYING", "rg license");
      write(root, "tools/licenses/rg/readme.md", "not a license");
      const { text, index } = generateNotices(root, listPayloadPackages(root));
      expect(index.packages).toHaveLength(6);
      expect(index.packages).toEqual(
        expect.arrayContaining([
          {
            name: "fd",
            version: "10.5.0",
            license: null,
            files: ["tools/licenses/fd/LICENSE-MIT"],
          },
          {
            name: "rg",
            version: "14.1.1",
            license: null,
            files: ["tools/licenses/rg/COPYING"],
          },
        ]),
      );
      expect(text).toContain("fd MIT license");
      expect(text).toContain("rg license");
      expect(text).not.toContain("not a license");
      verifyNotices(sbomFor(root), index);
    },
  );

  it("reproduces license files and indexes every package", () => {
    const root = payload();
    const { text, index } = generateNotices(root, listPayloadPackages(root));
    expect(text.split("\n")[0]).toBe(
      "Third-party notices for this PiShip distribution payload",
    );
    expect(text).toContain("alpha@1.0.0 (MIT)");
    expect(text).toContain("MIT License\nalpha");
    expect(text).toContain("alpha notice");
    expect(text).toContain("beta licence");
    expect(text).toContain(
      "No license file is shipped with this package. Declared license: ISC.",
    );
    expect(text).not.toContain("not a license");
    expect(index.schema).toBe("piship-notices/v1");
    expect(index.packages).toHaveLength(4);
    verifyNotices(sbomFor(root), index);
  });

  it("fails when an SBOM package has no notices entry", () => {
    const root = payload();
    const { index } = generateNotices(root, listPayloadPackages(root));
    expect(() =>
      verifyNotices(sbomFor(root), {
        ...index,
        packages: index.packages.filter((item) => item.name !== "alpha"),
      }),
    ).toThrow("Notices are missing alpha@1.0.0");
    expect(() => verifyNotices(sbomFor(root), { packages: [] })).toThrow(
      /piship-notices\/v1/,
    );
  });
});

// The SBOM and the notices describe the logical dependency graph the payload
// carries, not its files. Bundling a runtime, sharing identical dependencies
// between Pi packages, and placing files from a shared store all change which
// files are on disk; none of them may change what these documents list, the
// license text they reproduce, or the source and integrity they record.
describe("the logical dependency graph under a smaller file layout", () => {
  const SHA512_LEAF = createHash("sha512").update("leaf").digest();
  const integrity = `sha512-${SHA512_LEAF.toString("base64")}`;
  const resolved = "https://registry.npmjs.org/leaf/-/leaf-1.0.0.tgz";

  /** A Pi package root of its own with `leaf` as its one dependency. */
  function vendoredLeaf(root: string, id: string, layout: "full" | "stand-in") {
    write(
      root,
      `pi-packages/${id}/package-lock.json`,
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          "": { name: id, version: "1.0.0" },
          "node_modules/leaf": { version: "1.0.0", resolved, integrity },
          "node_modules/linked": { link: true, resolved: "../x" },
        },
      }),
    );
    const dir = `pi-packages/${id}/node_modules/leaf`;
    const manifest = JSON.stringify({
      name: "leaf",
      version: "1.0.0",
      license: "MIT",
    });
    write(root, `${dir}/package.json`, manifest);
    write(root, `${dir}/LICENSE`, "MIT leaf\n");
    write(
      root,
      `${dir}/index.js`,
      layout === "full"
        ? "export const leaf = 1;\n"
        : 'export * from "../../../.shared/leaf@1.0.0-abcdef123456/index.js";\n',
    );
  }

  const sbomOf = (root: string) =>
    generateSbom({
      payloadDir: root,
      distribution: { id: "devcode", name: "DevCode", version: "1.0.0" },
      target: "linux-x64",
      created: "2026-01-01T00:00:00Z",
      lockPackages: [],
    });

  /** What the documents say, with nothing that is the file layout's own. */
  function logical(root: string) {
    const listed = listPayloadPackages(root);
    const sbom = sbomOf(root);
    verifySbom(root, sbom, listed);
    const { text, index } = generateNotices(root, listed);
    verifyNotices(sbom, index);
    return { listed, sbom, text, index };
  }

  it("lists a shared dependency at every place that uses it, with the same source, integrity, and license text", () => {
    const full = payload();
    vendoredLeaf(full, "a", "full");
    vendoredLeaf(full, "b", "full");
    const shared = payload();
    vendoredLeaf(shared, "a", "stand-in");
    vendoredLeaf(shared, "b", "stand-in");
    // The one real copy, outside any package's node_modules.
    write(
      shared,
      "pi-packages/.shared/leaf@1.0.0-abcdef123456/package.json",
      JSON.stringify({ name: "leaf", version: "1.0.0", license: "MIT" }),
    );
    write(
      shared,
      "pi-packages/.shared/leaf@1.0.0-abcdef123456/index.js",
      "export const leaf = 1;\n",
    );
    write(
      shared,
      "pi-packages/.shared/leaf@1.0.0-abcdef123456/LICENSE",
      "MIT leaf\n",
    );
    const before = logical(full);
    const after = logical(shared);
    expect(after.listed).toEqual(before.listed);
    expect(after.sbom.packages).toEqual(before.sbom.packages);
    expect(after.index).toEqual(before.index);
    expect(after.text).toBe(before.text);
    // Each place that uses leaf is a package of its own in the graph, and the
    // shared directory is not a second one.
    const leaves = after.sbom.packages.filter((item) => item.name === "leaf");
    expect(leaves.map((item) => item.sourceInfo)).toEqual([
      "payload:pi-packages/a/node_modules/leaf",
      "payload:pi-packages/b/node_modules/leaf",
    ]);
    for (const item of leaves)
      expect(item).toMatchObject({
        downloadLocation: resolved,
        licenseDeclared: "MIT",
        checksums: [
          { algorithm: "SHA512", checksumValue: SHA512_LEAF.toString("hex") },
        ],
      });
    expect(after.text.match(/MIT leaf/g)).toHaveLength(2);
  });

  it("records the source and integrity of a Pi package's dependency from its lockfile, and ignores an entry for another version", () => {
    const root = payload();
    vendoredLeaf(root, "a", "full");
    const [item] = sbomOf(root).packages.filter((p) => p.name === "leaf");
    expect(item).toMatchObject({ downloadLocation: resolved });
    // A lockfile entry for another version says nothing about the installed one.
    write(
      root,
      "pi-packages/a/package-lock.json",
      JSON.stringify({
        packages: {
          "node_modules/leaf": { version: "2.0.0", resolved, integrity },
        },
      }),
    );
    const [other] = sbomOf(root).packages.filter((p) => p.name === "leaf");
    expect(other?.downloadLocation).toBe("NOASSERTION");
    expect(other?.checksums).toBeUndefined();
  });

  it("keeps listing the packages a bundled runtime no longer has files for, and reproduces their license text", () => {
    const root = mkdtempSync(join(tmpdir(), "piship-supply-bundled-"));
    roots.push(root);
    // After bundling, the runtime's JavaScript is in a few files; what
    // remains of each package is its license, and bundle.json is the record of
    // the packages that were bundled.
    const components = [
      {
        name: "alpha",
        version: "1.0.0",
        path: "node_modules/alpha",
        license: "MIT",
        licenseFiles: ["node_modules/alpha/LICENSE"],
      },
      {
        name: "beta",
        version: "2.0.0",
        path: "node_modules/alpha/node_modules/beta",
        license: "ISC",
        licenseFiles: [],
      },
    ];
    write(
      root,
      "metadata/bundle.json",
      JSON.stringify({ format: "x", components }),
    );
    write(root, "node_modules/alpha/LICENSE", "MIT License\nalpha\n");
    write(root, "runtime/main.js", "// everything is in here\n");
    const { listed, sbom, text, index } = logical(root);
    expect(listed).toEqual(components);
    expect(sbom.packages.map((item) => item.name)).toEqual([
      "DevCode",
      "alpha",
      "beta",
    ]);
    expect(index.packages.map((item) => item.name)).toEqual(["alpha", "beta"]);
    expect(text).toContain("MIT License\nalpha");
    expect(text).toContain(
      "No license file is shipped with this package. Declared license: ISC.",
    );
  });
});

describe("checksums", () => {
  function tree() {
    const root = payload();
    write(root, "release.json", "{}\n");
    write(root, "licenses/index.json", "[]\n");
    return root;
  }

  it("round trips sorted sha256sum lines", () => {
    const root = tree();
    const text = formatChecksums(root, ["release.json", "licenses/index.json"]);
    expect(text).toBe(
      [
        `${createHash("sha256").update("[]\n").digest("hex")}  licenses/index.json`,
        `${createHash("sha256").update("{}\n").digest("hex")}  release.json`,
        "",
      ].join("\n"),
    );
    expect(verifyChecksums(root, text, { required: ["release.json"] })).toEqual(
      ["licenses/index.json", "release.json"],
    );
  });

  it("rejects mismatches, missing files, traversal, and malformed lines", () => {
    const root = tree();
    const text = formatChecksums(root, ["release.json", "licenses/index.json"]);
    const zero = "0".repeat(64);
    expect(() =>
      verifyChecksums(root, text, { required: ["install.sh"] }),
    ).toThrow(/required file install.sh/);
    write(root, "release.json", '{"tampered":true}\n');
    expect(() => verifyChecksums(root, text)).toThrow(
      "Checksum mismatch for release.json",
    );
    rmSync(join(root, "licenses/index.json"));
    expect(() => verifyChecksums(root, text)).toThrow(/missing: licenses/);
    for (const bad of [
      `${zero}  ../outside`,
      `${zero}  /etc/passwd`,
      `${zero}  a/./b`,
      `${zero}  a\\b`,
    ])
      expect(() => verifyChecksums(root, bad)).toThrow(/relative posix path/);
    expect(() => verifyChecksums(root, `${zero} release.json`)).toThrow(
      /malformed/,
    );
    expect(() => verifyChecksums(root, "")).toThrow(/empty/);
    write(root, "release.json", "{}\n");
    const line = formatChecksums(root, ["release.json"]);
    expect(() => verifyChecksums(root, `${line}${line}`)).toThrow(/twice/);
    expect(() => formatChecksums(root, ["../x"])).toThrow(/relative posix/);
  });
});
