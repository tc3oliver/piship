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
import { SEARCH_TOOLS } from "@piship/schema";
import { searchToolFileName } from "./search-tools/catalog.js";

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

/**
 * The package in `directory`, from one listing of it, or null when it has no
 * readable name and version. `modules` is its own `node_modules` when it has a
 * real one.
 */
function readPackage(
  payloadDir: string,
  directory: string,
): { item: PayloadPackage; modules: string | undefined } | null {
  const entries = readdirSync(directory, { withFileTypes: true });
  const file = join(directory, "package.json");
  if (
    !entries.some(
      (entry) => entry.name === "package.json" && !entry.isDirectory(),
    )
  )
    return null;
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
    item: {
      name: manifest.name,
      version: manifest.version,
      path,
      license: declaredLicense(manifest),
      licenseFiles: entries
        .filter((entry) => entry.isFile() && LICENSE_FILE.test(entry.name))
        .map((entry) => `${path}/${entry.name}`)
        .sort(),
    },
    modules: entries.some(
      (entry) => entry.name === "node_modules" && entry.isDirectory(),
    )
      ? join(directory, "node_modules")
      : undefined,
  };
}

/**
 * Every installed package under payload node_modules (nested and scoped),
 * sorted by path. Only real directories are walked; symlinks are not followed.
 */
export function listPayloadPackages(payloadDir: string): PayloadPackage[] {
  const bundle = join(payloadDir, "metadata", "bundle.json");
  if (existsSync(bundle)) {
    const metadata = JSON.parse(readFileSync(bundle, "utf8")) as {
      components?: PayloadPackage[];
    };
    if (Array.isArray(metadata.components)) return metadata.components;
  }
  const found: PayloadPackage[] = [];
  const visitPackage = (directory: string) => {
    const read = readPackage(payloadDir, directory);
    if (!read) return;
    found.push(read.item);
    if (read.modules) visitModules(read.modules);
  };
  const visitModules = (modules: string) => {
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
  const top = join(payloadDir, "node_modules");
  if (existsSync(top) && lstatSync(top).isDirectory()) visitModules(top);
  // Vendored Pi packages: each has its own npm root under pi-packages/<id>.
  const vendored = join(payloadDir, "pi-packages");
  if (existsSync(vendored) && lstatSync(vendored).isDirectory())
    for (const entry of readdirSync(vendored, { withFileTypes: true }))
      if (entry.isDirectory()) {
        const modules = join(vendored, entry.name, "node_modules");
        if (existsSync(modules) && lstatSync(modules).isDirectory())
          visitModules(modules);
      }
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
  /** The payload's packages, when the caller has already listed them. */
  readonly packages?: readonly PayloadPackage[];
  readonly lockPackages: readonly {
    readonly path: string;
    readonly version: string;
    readonly integrity: string;
    readonly resolved?: string;
  }[];
}

/** A bundled search tool of a payload, as its lock and target record it. */
interface PayloadSearchTool {
  readonly name: string;
  readonly version: string;
  /** Payload-relative path of the executable, such as `tools/fd`. */
  readonly path: string;
  readonly url: string;
  /** Hex SHA-256 of the upstream archive. */
  readonly archive: string;
  readonly purl: string;
}

/**
 * The bundled search tools of a payload, from its `piship.lock` and target.
 * Empty for a payload without them.
 */
function payloadSearchTools(payloadDir: string): PayloadSearchTool[] {
  const lockPath = join(payloadDir, "piship.lock");
  const targetPath = join(payloadDir, "metadata", "target.json");
  if (!existsSync(lockPath) || !existsSync(targetPath)) return [];
  const lock = JSON.parse(readFileSync(lockPath, "utf8")) as {
    searchTools?: Record<
      string,
      {
        version: string;
        source: string;
        targets: Record<string, { url: string; archive: string }>;
      }
    >;
  };
  const { platform, arch } = JSON.parse(readFileSync(targetPath, "utf8")) as {
    platform: string;
    arch: string;
  };
  const target = `${platform}-${arch}`;
  return SEARCH_TOOLS.flatMap((tool) => {
    const locked = lock.searchTools?.[tool];
    const entry = locked?.targets[target];
    if (!locked || !entry) return [];
    const tag = new URL(entry.url).pathname.split("/").at(-2) ?? locked.version;
    return [
      {
        name: tool,
        version: locked.version,
        path: `tools/${searchToolFileName(tool, target)}`,
        url: entry.url,
        archive: entry.archive.replace(/^sha256-/, ""),
        purl: `pkg:github/${new URL(locked.source).pathname.slice(1)}@${encodeURIComponent(tag)}`,
      },
    ];
  });
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
function spdxIdAllocator(): (item: {
  readonly name: string;
  readonly version: string;
}) => string {
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

type LockedSource = SbomInput["lockPackages"][number];

/**
 * The registry source and integrity of the dependencies of each vendored Pi
 * package, from the npm lockfile that ships beside it
 * (`pi-packages/<id>/package-lock.json`), keyed by the payload path the
 * dependency has under `pi-packages/<id>/node_modules`. Read from the
 * lockfile and not from the files on disk, so the SBOM records the same
 * source and integrity whether a copy of the dependency is a full package, a
 * shared stand-in, or has been bundled away.
 */
function vendoredLockPackages(payloadDir: string): LockedSource[] {
  const vendored = join(payloadDir, "pi-packages");
  if (!existsSync(vendored) || !lstatSync(vendored).isDirectory()) return [];
  const found: LockedSource[] = [];
  for (const entry of readdirSync(vendored, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    let lockfile: { packages?: Record<string, unknown> };
    try {
      lockfile = JSON.parse(
        readFileSync(join(vendored, entry.name, "package-lock.json"), "utf8"),
      );
    } catch {
      continue;
    }
    for (const [key, value] of Object.entries(lockfile.packages ?? {})) {
      const item = value as {
        version?: unknown;
        integrity?: unknown;
        resolved?: unknown;
        link?: unknown;
      } | null;
      if (
        !key.startsWith("node_modules/") ||
        item?.link ||
        typeof item?.version !== "string" ||
        typeof item.integrity !== "string"
      )
        continue;
      found.push({
        path: `pi-packages/${entry.name}/${key}`,
        version: item.version,
        integrity: item.integrity,
        ...(typeof item.resolved === "string"
          ? { resolved: item.resolved }
          : {}),
      });
    }
  }
  return found;
}

/** A deterministic SPDX 2.3 JSON document for every package in the payload. */
export function generateSbom(input: SbomInput): SpdxDocument {
  const packages = input.packages ?? listPayloadPackages(input.payloadDir);
  const { id, version } = input.distribution;
  const lock = new Map(
    [...vendoredLockPackages(input.payloadDir), ...input.lockPackages].map(
      (item) => [item.path, item],
    ),
  );
  const spdxId = spdxIdAllocator();
  const entries: SpdxPackage[] = packages.map((item) => {
    const found = lock.get(item.path);
    // A lock entry for another version says nothing about this package.
    const locked = found?.version === item.version ? found : undefined;
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
  // Bundled search tools: upstream executables outside node_modules.
  for (const tool of payloadSearchTools(input.payloadDir))
    entries.push({
      SPDXID: spdxId(tool),
      name: tool.name,
      versionInfo: tool.version,
      downloadLocation: tool.url,
      filesAnalyzed: false,
      licenseConcluded: "NOASSERTION",
      licenseDeclared: "NOASSERTION",
      copyrightText: "NOASSERTION",
      supplier: "NOASSERTION",
      sourceInfo: `${SOURCE_PREFIX}${tool.path}`,
      checksums: [{ algorithm: "SHA256", checksumValue: tool.archive }],
      externalRefs: [
        {
          referenceCategory: "PACKAGE-MANAGER",
          referenceType: "purl",
          referenceLocator: tool.purl,
        },
      ],
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
export function verifySbom(
  payloadDir: string,
  sbom: unknown,
  listed: readonly PayloadPackage[] = listPayloadPackages(payloadDir),
): void {
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
  for (const item of [...listed, ...payloadSearchTools(payloadDir)]) {
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
  // Bundled search tools are release content outside node_modules. Include
  // them here to match the SBOM; their licenses ship under tools/licenses.
  const toolPackages: PayloadPackage[] = payloadSearchTools(payloadDir).map(
    (tool) => {
      const dir = join(payloadDir, "tools", "licenses", tool.name);
      return {
        name: tool.name,
        version: tool.version,
        path: tool.path,
        license: null,
        licenseFiles: existsSync(dir)
          ? readdirSync(dir, { withFileTypes: true })
              .filter(
                (entry) => entry.isFile() && LICENSE_FILE.test(entry.name),
              )
              .map((entry) => `tools/licenses/${tool.name}/${entry.name}`)
              .sort()
          : [],
      };
    },
  );
  const sorted = [...packages, ...toolPackages].sort(
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
    `This file reproduces the license and notice files of the ${sorted.length} packages and bundled tools installed in this payload.`,
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
