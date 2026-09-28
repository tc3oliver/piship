// Trust-classed resources: resources.<kind>.{builtin,certified,company,user}.
import {
  BUILTIN_EXTENSIONS,
  type BuiltinExtension,
  type CertifiedEvidence,
  DECLARABLE_RESOURCE_CLASSES,
  type DeclarableResourceClass,
  type DeclaredResource,
  type GovernanceResources,
  RESOURCE_KINDS,
  type ResourceKind,
} from "../governance.js";
import { checkUrl } from "../access.js";
import {
  conflict,
  exactPiVersion,
  fail,
  isRecord,
  type Json,
  list,
  oneOf,
  optionalRecord,
  plainString,
  record,
  relativePath,
  semver,
} from "./fields.js";

export const CERTIFIED_FIELDS = [
  "source",
  "integrity",
  "license",
  "pi",
  "platforms",
] as const;
const PLATFORMS = ["linux", "darwin", "win32"] as const;
const EVIDENCE_ID = /^[a-z0-9][a-z0-9._-]{0,127}$/;

export function evidence(
  item: Json,
  path: string,
  id: string,
  version: string,
): CertifiedEvidence {
  const source = plainString(item.source, `${path}.source`, 1024);
  if (source.includes("://")) checkUrl(source, `${path}.source`);
  const integrity = plainString(item.integrity, `${path}.integrity`, 128);
  if (!/^sha256-[0-9a-f]{64}$/.test(integrity))
    fail(
      `${path}.integrity`,
      "Expected sha256- followed by 64 lowercase hexadecimal characters",
    );
  const license = plainString(item.license, `${path}.license`, 128);
  if (!/^[A-Za-z0-9][A-Za-z0-9.+() -]*$/.test(license))
    fail(`${path}.license`, "Expected an SPDX license expression");
  const pi = list(item.pi, `${path}.pi`, exactPiVersion);
  if (!pi.length)
    fail(
      `${path}.pi`,
      "List the exact Pi versions the item was reviewed against",
    );
  const platforms = list(item.platforms, `${path}.platforms`, (entry, at) =>
    oneOf(entry, at, PLATFORMS),
  );
  return { id, version, source, integrity, license, pi, platforms };
}

function certifiedResource(entry: unknown, path: string, kind: ResourceKind) {
  const item = record(entry, path, [
    "path",
    "id",
    "version",
    ...CERTIFIED_FIELDS,
  ]);
  const id = plainString(item.id, `${path}.id`, 128);
  if (!EVIDENCE_ID.test(id))
    fail(`${path}.id`, "IDs use lowercase letters, digits, and . _ -");
  const resource: DeclaredResource = {
    kind,
    class: "certified",
    path: relativePath(item.path, `${path}.path`),
    certified: evidence(
      item,
      path,
      id,
      semver(item.version, `${path}.version`),
    ),
  };
  return resource;
}

function parseKind(
  kind: ResourceKind,
  value: unknown,
): { declared: DeclaredResource[]; builtin: BuiltinExtension[] } {
  const path = `resources.${kind}`;
  if (Array.isArray(value))
    fail(
      path,
      "piship/v1alpha3 and piship/v1alpha4 resources map a trust class (certified, company, user) to entries; run piship migrate to convert a flat list",
    );
  if (!isRecord(value)) fail(path, "Expected an object");
  for (const key of ["upstream", "project"])
    if (value[key] !== undefined)
      fail(
        `${path}.${key}`,
        key === "upstream"
          ? "upstream resources come from the pinned Pi package and cannot be declared"
          : "project resources are discovered in the workspace and governed by policy.projectTrust; they cannot be declared",
      );
  if (value.builtin !== undefined && kind !== "extensions")
    fail(
      `${path}.builtin`,
      "builtin entries are only valid under resources.extensions",
    );
  const section = record(value, path, [
    ...(kind === "extensions" ? ["builtin"] : []),
    ...DECLARABLE_RESOURCE_CLASSES,
  ]);
  const builtin = list(section.builtin, `${path}.builtin`, (entry, at) => {
    const name = plainString(entry, at, 64);
    if (!(BUILTIN_EXTENSIONS as readonly string[]).includes(name))
      fail(
        at,
        `Expected a builtin extension: ${BUILTIN_EXTENSIONS.join(", ")}`,
      );
    return name as BuiltinExtension;
  });
  const declared: DeclaredResource[] = [];
  const classes: DeclarableResourceClass[] = ["certified", "company", "user"];
  for (const trust of classes) {
    const at = `${path}.${trust}`;
    const entries =
      trust === "certified"
        ? list(
            section.certified,
            at,
            (entry, entryPath) => certifiedResource(entry, entryPath, kind),
            (entry) => entry.path,
          )
        : list(section[trust], at, relativePath).map(
            (item): DeclaredResource => ({ kind, class: trust, path: item }),
          );
    for (const [index, entry] of entries.entries()) {
      const entryPath =
        trust === "certified" ? `${at}[${index}].path` : `${at}[${index}]`;
      for (const other of declared) {
        if (other.path === entry.path)
          conflict(
            entryPath,
            `${entry.path} is already declared as ${other.class}; a path has exactly one trust class`,
          );
        if (
          entry.path.startsWith(`${other.path}/`) ||
          other.path.startsWith(`${entry.path}/`)
        )
          conflict(
            entryPath,
            `${entry.path} overlaps ${other.path} (${other.class}); nested roots cannot mix trust classes`,
          );
      }
      declared.push(entry);
    }
  }
  return { declared, builtin };
}

export function parseGovernanceResources(value: unknown): GovernanceResources {
  const resources = optionalRecord(
    value ?? undefined,
    "resources",
    RESOURCE_KINDS,
  );
  const declared: DeclaredResource[] = [];
  const builtin: BuiltinExtension[] = [];
  for (const kind of RESOURCE_KINDS) {
    if (resources[kind] === undefined || resources[kind] === null) continue;
    const parsed = parseKind(kind, resources[kind]);
    declared.push(...parsed.declared);
    builtin.push(...parsed.builtin);
  }
  return { declared, builtin };
}
