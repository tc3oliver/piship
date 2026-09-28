import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  readFileSync,
  readdirSync,
  realpathSync,
} from "node:fs";
import { join, relative, sep } from "node:path";
import { PiShipError } from "@piship/contracts";

export interface PayloadPackage {
  readonly name: string;
  readonly version: string;
  /** Payload-relative posix directory, such as `node_modules/@scope/x`. */
  readonly path: string;
  readonly license: string | null;
  /** Payload-relative posix paths of LICENSE, LICENCE, COPYING, and NOTICE files in the package root. */
  readonly licenseFiles: readonly string[];
}

function fail(message: string): never {
  throw new PiShipError("INTEGRITY_FAILED", message, {
    component: "supply-chain",
  });
}

const posix = (path: string) => path.split(sep).join("/");
const LICENSE_FILE = /^(licen[cs]e|copying|notice)/i;

function declaredLicense(manifest: Record<string, unknown>): string | null {
  const license = manifest.license;
  if (typeof license === "string" && license.trim()) return license.trim();
  if (
    license &&
    typeof license === "object" &&
    typeof (license as { type?: unknown }).type === "string"
  )
    return (license as { type: string }).type;
  return null;
}

function readPackage(
  payloadDir: string,
  directory: string,
): PayloadPackage | null {
  const file = join(directory, "package.json");
  if (!existsSync(file)) return null;
  let manifest: Record<string, unknown>;
  try {
    manifest = JSON.parse(readFileSync(file, "utf8")) as Record<
      string,
      unknown
    >;
  } catch {
    return fail(
      `Payload package manifest is not readable JSON: ${posix(relative(payloadDir, file))}`,
    );
  }
  if (typeof manifest.name !== "string" || typeof manifest.version !== "string")
    return null;
  const path = posix(relative(payloadDir, directory));
  return {
    name: manifest.name,
    version: manifest.version,
    path,
    license: declaredLicense(manifest),
    licenseFiles: readdirSync(directory, { withFileTypes: true })
      .filter((entry) => entry.isFile() && LICENSE_FILE.test(entry.name))
      .map((entry) => `${path}/${entry.name}`)
      .sort(),
  };
}

/**
 * Every installed package under payload node_modules (nested and scoped),
 * sorted by path. Only real directories are walked; symlinks are not followed.
 */
export function listPayloadPackages(payloadDir: string): PayloadPackage[] {
  const found: PayloadPackage[] = [];
  const visitPackage = (directory: string) => {
    const item = readPackage(payloadDir, directory);
    if (!item) return;
    found.push(item);
    visitModules(join(directory, "node_modules"));
  };
  const visitModules = (modules: string) => {
    if (!existsSync(modules) || !lstatSync(modules).isDirectory()) return;
    for (const entry of readdirSync(modules, { withFileTypes: true })) {
      if (!entry.isDirectory() || entry.name.startsWith(".")) continue;
      const directory = join(modules, entry.name);
      if (!entry.name.startsWith("@")) {
        visitPackage(directory);
        continue;
      }
      for (const scoped of readdirSync(directory, { withFileTypes: true }))
        if (scoped.isDirectory() && !scoped.name.startsWith("."))
          visitPackage(join(directory, scoped.name));
    }
  };
  visitModules(join(payloadDir, "node_modules"));
  return found.sort((a, b) => compare(a.path, b.path));
}

function compare(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

export interface SpdxChecksum {
  readonly algorithm: "SHA1" | "SHA256" | "SHA512";
  readonly checksumValue: string;
}
export interface SpdxPackage {
  readonly SPDXID: string;
  readonly name: string;
  readonly versionInfo: string;
  readonly downloadLocation: string;
  readonly filesAnalyzed: false;
  readonly licenseConcluded: string;
  readonly licenseDeclared: string;
  readonly copyrightText: "NOASSERTION";
  readonly supplier: "NOASSERTION";
  readonly primaryPackagePurpose?: "APPLICATION" | "LIBRARY";
  /** `payload:<path>` for payload packages; the payload-relative install directory. */
  readonly sourceInfo?: string;
  readonly checksums?: readonly SpdxChecksum[];
  readonly externalRefs?: readonly {
    readonly referenceCategory: "PACKAGE-MANAGER";
    readonly referenceType: "purl";
    readonly referenceLocator: string;
  }[];
}
export interface SpdxRelationship {
  readonly spdxElementId: string;
  readonly relationshipType: "DESCRIBES" | "DEPENDS_ON";
  readonly relatedSpdxElement: string;
}
export interface SpdxDocument {
  readonly spdxVersion: "SPDX-2.3";
  readonly dataLicense: "CC0-1.0";
  readonly SPDXID: "SPDXRef-DOCUMENT";
  readonly name: string;
  readonly documentNamespace: string;
  readonly creationInfo: {
    readonly created: string;
    readonly creators: readonly string[];
  };
  readonly packages: readonly SpdxPackage[];
  readonly relationships: readonly SpdxRelationship[];
}

export interface SbomInput {
  readonly payloadDir: string;
  readonly distribution: {
    readonly id: string;
    readonly name: string;
    readonly version: string;
  };
  readonly target: string;
  /** RFC3339 creation time. */
  readonly created: string;
  readonly lockPackages: readonly {
    readonly path: string;
    readonly version: string;
    readonly integrity: string;
    readonly resolved?: string;
  }[];
}

const DOCUMENT_ID = "SPDXRef-DOCUMENT";
const DISTRIBUTION_ID = "SPDXRef-Distribution";
const SOURCE_PREFIX = "payload:";

/** True for a simple SPDX expression: identifiers, AND/OR/WITH, and parentheses. */
function isSpdxExpression(value: string): boolean {
  const tokens = value.match(/\(|\)|[^\s()]+/g) ?? [];
  if (tokens.length === 0) return false;
  let index = 0;
  const identifier = (token: string | undefined) =>
    !!token &&
    /^[A-Za-z0-9][A-Za-z0-9.+-]*$/.test(token) &&
    !["AND", "OR", "WITH", "UNLICENSED"].includes(token);
  const primary = (): boolean => {
    if (tokens[index] === "(") {
      index++;
      if (!expression() || tokens[index] !== ")") return false;
      index++;
      return true;
    }
    if (!identifier(tokens[index])) return false;
    index++;
    if (tokens[index] === "WITH") {
      index++;
      if (!identifier(tokens[index])) return false;
      index++;
    }
    return true;
  };
  const expression = (): boolean => {
    if (!primary()) return false;
    while (tokens[index] === "AND" || tokens[index] === "OR") {
      index++;
      if (!primary()) return false;
    }
    return true;
  };
  return expression() && index === tokens.length;
}

const SRI_ALGORITHMS = {
  sha1: "SHA1",
  sha256: "SHA256",
  sha512: "SHA512",
} as const;

/** Convert SRI `sha512-<base64>` tokens into SPDX hex checksums. */
export function sriToSpdxChecksums(integrity: string): SpdxChecksum[] {
  const checksums: SpdxChecksum[] = [];
  for (const token of integrity.split(/\s+/).filter(Boolean)) {
    const [, algorithm, digest] =
      /^(sha1|sha256|sha512)-([A-Za-z0-9+/]+={0,2})$/.exec(token) ?? [];
    if (!algorithm || !digest) continue;
    checksums.push({
      algorithm: SRI_ALGORITHMS[algorithm as keyof typeof SRI_ALGORITHMS],
      checksumValue: Buffer.from(digest, "base64").toString("hex"),
    });
  }
  return checksums.sort((a, b) => compare(a.algorithm, b.algorithm));
}

function purl(name: string, version: string): string {
  const encoded = name.split("/").map(encodeURIComponent).join("/");
  return `pkg:npm/${encoded}@${encodeURIComponent(version)}`;
}

/** Allocates SPDX-safe ids; callers pass packages in path order so suffixes are stable. */
function spdxIdAllocator(): (item: PayloadPackage) => string {
  const used = new Set<string>([DOCUMENT_ID, DISTRIBUTION_ID]);
  return (item) => {
    const base = `SPDXRef-Package-${`${item.name}-${item.version}`.replace(/[^A-Za-z0-9.-]+/g, "-").replace(/^-+|-+$/g, "")}`;
    let id = base;
    for (let suffix = 2; used.has(id); suffix++) id = `${base}-${suffix}`;
    used.add(id);
    return id;
  };
}

function packageListDigest(packages: readonly PayloadPackage[]): string {
  const list = packages.map(({ path, name, version }) => ({
    path,
    name,
    version,
  }));
  return createHash("sha256").update(JSON.stringify(list)).digest("hex");
}

/** A deterministic SPDX 2.3 JSON document for every package in the payload. */
export function generateSbom(input: SbomInput): SpdxDocument {
  const packages = listPayloadPackages(input.payloadDir);
  const { id, version } = input.distribution;
  const lock = new Map(input.lockPackages.map((item) => [item.path, item]));
  const spdxId = spdxIdAllocator();
  const entries: SpdxPackage[] = packages.map((item) => {
    const locked = lock.get(item.path);
    const checksums = locked ? sriToSpdxChecksums(locked.integrity) : [];
    return {
      SPDXID: spdxId(item),
      name: item.name,
      versionInfo: item.version,
      downloadLocation: locked?.resolved || "NOASSERTION",
      filesAnalyzed: false,
      licenseConcluded: "NOASSERTION",
      licenseDeclared:
        item.license && isSpdxExpression(item.license)
          ? item.license
          : "NOASSERTION",
      copyrightText: "NOASSERTION",
      supplier: "NOASSERTION",
      sourceInfo: `${SOURCE_PREFIX}${item.path}`,
      ...(checksums.length ? { checksums } : {}),
      externalRefs: [
        {
          referenceCategory: "PACKAGE-MANAGER",
          referenceType: "purl",
          referenceLocator: purl(item.name, item.version),
        },
      ],
    };
  });
  return {
    spdxVersion: "SPDX-2.3",
    dataLicense: "CC0-1.0",
    SPDXID: DOCUMENT_ID,
    name: `${id}-${version}-${input.target}`,
    documentNamespace: `https://piship.dev/spdx/${encodeURIComponent(id)}/${encodeURIComponent(version)}/${encodeURIComponent(input.target)}/${packageListDigest(packages)}`,
    creationInfo: { created: input.created, creators: ["Tool: piship"] },
    packages: [
      {
        SPDXID: DISTRIBUTION_ID,
        name: input.distribution.name,
        versionInfo: version,
        downloadLocation: "NOASSERTION",
        filesAnalyzed: false,
        licenseConcluded: "NOASSERTION",
        licenseDeclared: "NOASSERTION",
        copyrightText: "NOASSERTION",
        supplier: "NOASSERTION",
        primaryPackagePurpose: "APPLICATION",
      },
      ...entries,
    ],
    relationships: [
      {
        spdxElementId: DOCUMENT_ID,
        relationshipType: "DESCRIBES",
        relatedSpdxElement: DISTRIBUTION_ID,
      },
      ...entries.map((entry) => ({
        spdxElementId: DISTRIBUTION_ID,
        relationshipType: "DEPENDS_ON" as const,
        relatedSpdxElement: entry.SPDXID,
      })),
    ],
  };
}

function sbomPackages(sbom: unknown): {
  document: SpdxDocument;
  packages: SpdxPackage[];
} {
  if (!sbom || typeof sbom !== "object" || Array.isArray(sbom))
    fail("SBOM is not a JSON object");
  const document = sbom as SpdxDocument;
  if (document.spdxVersion !== "SPDX-2.3")
    fail("SBOM spdxVersion must be SPDX-2.3");
  if (document.SPDXID !== DOCUMENT_ID)
    fail(`SBOM SPDXID must be ${DOCUMENT_ID}`);
  if (
    !Array.isArray(document.packages) ||
    !Array.isArray(document.relationships)
  )
    fail("SBOM must list packages and relationships");
  const packages = document.packages.filter(
    (item) => item?.SPDXID !== DISTRIBUTION_ID,
  );
  if (packages.length === document.packages.length)
    fail("SBOM does not describe the distribution package");
  for (const item of packages)
    if (
      !item ||
      typeof item.SPDXID !== "string" ||
      typeof item.name !== "string" ||
      typeof item.versionInfo !== "string"
    )
      fail("SBOM package entries need SPDXID, name, and versionInfo");
  return { document, packages };
}

/**
 * Check that the SBOM lists exactly the packages installed in the payload.
 * Each payload package is matched by name, version, and its `payload:<path>`
 * sourceInfo.
 */
export function verifySbom(payloadDir: string, sbom: unknown): void {
  const { document, packages } = sbomPackages(sbom);
  const described = new Map<string, SpdxPackage>();
  const seenIds = new Set<string>();
  for (const item of packages) {
    if (seenIds.has(item.SPDXID)) fail(`SBOM repeats SPDXID ${item.SPDXID}`);
    seenIds.add(item.SPDXID);
    const path =
      typeof item.sourceInfo === "string" &&
      item.sourceInfo.startsWith(SOURCE_PREFIX)
        ? item.sourceInfo.slice(SOURCE_PREFIX.length)
        : fail(`SBOM package ${item.name} has no payload path`);
    described.set(`${item.name}@${item.versionInfo} (${path})`, item);
  }
  const relationships = new Set(
    document.relationships.map(
      (item) =>
        `${item?.spdxElementId} ${item?.relationshipType} ${item?.relatedSpdxElement}`,
    ),
  );
  if (!relationships.has(`${DOCUMENT_ID} DESCRIBES ${DISTRIBUTION_ID}`))
    fail("SBOM is missing the DESCRIBES relationship for the distribution");
  const installed = new Set<string>();
  for (const item of listPayloadPackages(payloadDir)) {
    const key = `${item.name}@${item.version} (${item.path})`;
    installed.add(key);
    const entry = described.get(key);
    if (!entry) fail(`SBOM is missing ${key}`);
    if (!relationships.has(`${DISTRIBUTION_ID} DEPENDS_ON ${entry.SPDXID}`))
      fail(`SBOM is missing the DEPENDS_ON relationship for ${key}`);
  }
  for (const key of described.keys())
    if (!installed.has(key))
      fail(`SBOM lists ${key}, which is not in the payload`);
}

export interface NoticeEntry {
  readonly name: string;
  readonly version: string;
  readonly license: string | null;
  readonly files: readonly string[];
}

const RULE = "=".repeat(78);
const THIN = "-".repeat(78);

/** Third-party notices text and a machine-readable index for the payload. */
export function generateNotices(
  payloadDir: string,
  packages: readonly PayloadPackage[],
): {
  readonly text: string;
  readonly index: {
    readonly schema: "piship-notices/v1";
    readonly packages: readonly NoticeEntry[];
  };
} {
  const sorted = [...packages].sort(
    (a, b) =>
      compare(a.path, b.path) ||
      compare(a.name, b.name) ||
      compare(a.version, b.version),
  );
  const sections = sorted.map((item) => {
    const declared = item.license ?? "no declared license";
    const lines = [
      RULE,
      `${item.name}@${item.version} (${declared})`,
      item.path,
    ];
    if (item.licenseFiles.length === 0)
      lines.push(
        "",
        `No license file is shipped with this package. Declared license: ${declared}.`,
      );
    for (const file of item.licenseFiles) {
      const content = readFileSync(join(payloadDir, file), "utf8");
      lines.push(THIN, `File: ${file}`, THIN, content.replace(/\s+$/, ""));
    }
    return lines.join("\n");
  });
  const text = [
    "Third-party notices for this PiShip distribution payload",
    "",
    `This file reproduces the license and notice files of the ${sorted.length} packages installed under node_modules.`,
    "",
    ...sections.map((section) => `${section}\n`),
  ].join("\n");
  return {
    text,
    index: {
      schema: "piship-notices/v1",
      packages: sorted.map((item) => ({
        name: item.name,
        version: item.version,
        license: item.license,
        files: item.licenseFiles,
      })),
    },
  };
}

/** Check that every SBOM package other than the distribution has a notices entry. */
export function verifyNotices(sbom: SpdxDocument, index: unknown): void {
  const { packages } = sbomPackages(sbom);
  const value = index as { schema?: unknown; packages?: unknown } | null;
  if (
    !value ||
    typeof value !== "object" ||
    value.schema !== "piship-notices/v1" ||
    !Array.isArray(value.packages)
  )
    fail("Notices index is not a piship-notices/v1 document");
  const listed = new Set(
    (value.packages as { name?: unknown; version?: unknown }[]).map(
      (item) => `${item?.name}@${item?.version}`,
    ),
  );
  for (const item of packages)
    if (!listed.has(`${item.name}@${item.versionInfo}`))
      fail(`Notices are missing ${item.name}@${item.versionInfo}`);
}

function checkRelativePath(path: string): void {
  if (
    !path ||
    path.startsWith("/") ||
    path.includes("\\") ||
    /^[A-Za-z]:/.test(path) ||
    path.split("/").some((part) => part === "" || part === "." || part === "..")
  )
    fail(
      `Checksum path must be a relative posix path inside the root: ${path}`,
    );
}

function fileDigest(root: string, path: string): string {
  const file = join(root, ...path.split("/"));
  if (!existsSync(file) || !lstatSync(file).isFile())
    fail(`Checksummed file is missing: ${path}`);
  const real = realpathSync(file);
  const base = realpathSync(root);
  if (real !== base && !real.startsWith(`${base}${sep}`))
    fail(`Checksummed file resolves outside the root: ${path}`);
  return createHash("sha256").update(readFileSync(file)).digest("hex");
}

/** sha256sum-format lines `<hex>  <path>\n` for files under root, sorted by path. */
export function formatChecksums(
  root: string,
  files: readonly string[],
): string {
  const sorted = [...files].sort(compare);
  return sorted
    .map((path, index) => {
      checkRelativePath(path);
      if (index > 0 && sorted[index - 1] === path)
        fail(`Checksum path is listed twice: ${path}`);
      return `${fileDigest(root, path)}  ${path}\n`;
    })
    .join("");
}

/** Verify a sha256sum-format checksums file under root; returns the verified paths. */
export function verifyChecksums(
  root: string,
  text: string,
  options: { readonly required?: readonly string[] } = {},
): string[] {
  const lines = text.split("\n");
  if (lines.at(-1) === "") lines.pop();
  if (lines.length === 0) fail("Checksums file is empty");
  const verified: string[] = [];
  const seen = new Set<string>();
  for (const [index, line] of lines.entries()) {
    const [, digest, path] = /^([0-9a-f]{64}) {2}(.+)$/.exec(line) ?? [];
    if (!digest || !path) fail(`Checksums line ${index + 1} is malformed`);
    checkRelativePath(path);
    if (seen.has(path)) fail(`Checksum path is listed twice: ${path}`);
    seen.add(path);
    if (fileDigest(root, path) !== digest)
      fail(`Checksum mismatch for ${path}`);
    verified.push(path);
  }
  for (const path of options.required ?? [])
    if (!seen.has(path)) fail(`Checksums do not cover required file ${path}`);
  return verified;
}
