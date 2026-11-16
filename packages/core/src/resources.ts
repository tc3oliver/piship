import { lstatSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { locateInSource, type Manifest, ManifestError } from "@piship/schema";
import { hash } from "./digest.js";
import type { LockedResource } from "./lock-schema.js";

/**
 * Whether a declared resource exists. A path that cannot be examined (a
 * directory the user may not enter, say) is reported as that, not as missing.
 */
function resourcePresent(
  absolute: string,
  field: string,
  declared: string,
): boolean {
  try {
    statSync(absolute);
    return true;
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT" || code === "ENOTDIR") return false;
    throw new ManifestError(
      "invalid field",
      field,
      `${declared} cannot be read (${code ?? "error"}); check its permissions`,
    );
  }
}

function walkResource(root: string, current: string, output: string[]): void {
  const stat = lstatSync(current);
  if (stat.isSymbolicLink())
    throw new ManifestError(
      "unsafe path/name",
      current,
      "Resource symlinks are not allowed",
    );
  if (stat.isDirectory()) {
    for (const child of readdirSync(current).sort())
      walkResource(root, join(current, child), output);
    return;
  }
  if (!stat.isFile())
    throw new ManifestError(
      "invalid field",
      current,
      "Expected a regular file or directory",
    );
  output.push(relative(root, current).split(sep).join("/"));
}
function adapterDeclarations(manifest: Manifest): [string, string][] {
  const output: [string, string][] = [];
  const access = manifest.access;
  if (access?.identity.mode === "adapter")
    output.push(["identity.adapter", access.identity.adapter]);
  if (access?.credential.adapter)
    output.push(["credential.adapter", access.credential.adapter]);
  const governance = manifest.governance;
  if (governance?.policy.adapter)
    output.push(["policy.adapter", governance.policy.adapter]);
  for (const server of governance?.mcp.servers ?? [])
    if (server.module)
      output.push([`mcp.servers.${server.id}.module`, server.module]);
  if (governance?.sandbox.adapter)
    output.push(["sandbox.adapter", governance.sandbox.adapter]);
  return output;
}
/**
 * Declared roots per kind, including capability-provider roots for v1alpha3,
 * each with the manifest field that declares it.
 */
function declaredRoots(
  manifest: Manifest,
): [LockedResource["kind"], string, string | undefined, string][] {
  const output: [LockedResource["kind"], string, string | undefined, string][] =
    [];
  const governance = manifest.governance;
  for (const kind of [
    "instructions",
    "skills",
    "extensions",
    "prompts",
    "themes",
  ] as const) {
    if (governance) {
      const seen = new Map<string, number>();
      for (const item of governance.resources.declared.filter(
        (entry) => entry.kind === kind,
      )) {
        const index = seen.get(item.class) ?? 0;
        seen.set(item.class, index + 1);
        const field = `resources.${kind}.${item.class}[${index}]`;
        output.push([
          kind,
          item.path,
          item.class,
          item.class === "certified" ? `${field}.path` : field,
        ]);
      }
    } else
      manifest.resources[kind].forEach((declared, index) => {
        output.push([kind, declared, undefined, `resources.${kind}[${index}]`]);
      });
  }
  for (const capability of governance?.capabilities ?? [])
    if (capability.provider?.path)
      output.push([
        "providers",
        capability.provider.path,
        capability.provider.class,
        "resources.providers",
      ]);
  return output;
}
export function resolveResources(
  manifest: Manifest,
  manifestPath: string,
): LockedResource[] {
  try {
    return resolveResourceFiles(manifest, manifestPath);
  } catch (error) {
    // A problem found here has no position yet; the manifest text has one.
    if (!(error instanceof ManifestError) || error.position) throw error;
    let source: string;
    try {
      source = readFileSync(manifestPath, "utf8");
    } catch {
      throw error;
    }
    throw locateInSource(error, source);
  }
}
function resolveResourceFiles(
  manifest: Manifest,
  manifestPath: string,
): LockedResource[] {
  const base = dirname(resolve(manifestPath));
  const output: LockedResource[] = [];
  for (const [kind, declared, cls, field] of declaredRoots(manifest)) {
    const absolute = resolve(base, declared);
    if (!absolute.startsWith(`${base}${sep}`))
      throw new ManifestError(
        "unsafe path/name",
        field,
        `Path escapes manifest directory: ${declared}`,
      );
    if (!resourcePresent(absolute, field, declared))
      throw new ManifestError(
        "missing resource",
        field,
        `${declared} does not exist`,
      );
    let component = base;
    for (const segment of relative(base, absolute).split(sep)) {
      component = join(component, segment);
      if (lstatSync(component).isSymbolicLink())
        throw new ManifestError(
          "unsafe path/name",
          field,
          `Resource symlinks are not allowed: ${declared}`,
        );
    }
    if (kind === "instructions" && !lstatSync(absolute).isFile())
      throw new ManifestError(
        "invalid field",
        field,
        `${declared} must be a file`,
      );
    const files: string[] = [];
    walkResource(base, absolute, files);
    if (files.length === 0)
      throw new ManifestError(
        "missing resource",
        field,
        `${declared} is empty`,
      );
    if (
      (kind === "extensions" || kind === "providers") &&
      !files.some((file) => /\.[cm]?[jt]s$/.test(file))
    )
      throw new ManifestError(
        "invalid field",
        field,
        `${declared} has no JavaScript or TypeScript extension entry`,
      );
    // Pi loads a directory through its index file, package.json
    // `pi.extensions`, or the files of its `extensions/` subdirectory.
    const root = `${relative(base, absolute).split(sep).join("/")}/`;
    if (
      (kind === "extensions" || kind === "providers") &&
      lstatSync(absolute).isDirectory() &&
      !["index.ts", "index.js", "package.json"].some((entry) =>
        files.includes(`${root}${entry}`),
      ) &&
      !files.some((file) => file.startsWith(`${root}extensions/`))
    )
      throw new ManifestError(
        "invalid field",
        field,
        `${declared} is a directory without index.ts or index.js; name the extension file itself, add an index file, put the extensions in an extensions/ folder inside it, or list the entries in a package.json "pi.extensions"`,
      );
    for (const file of files)
      output.push({
        kind,
        path: file,
        sha256: hash(readFileSync(join(base, file))),
        ...(cls ? { class: cls } : {}),
      });
  }
  for (const [field, declared] of adapterDeclarations(manifest)) {
    const absolute = resolve(base, declared);
    if (!absolute.startsWith(`${base}${sep}`))
      throw new ManifestError(
        "unsafe path/name",
        field,
        `Path escapes manifest directory: ${declared}`,
      );
    if (!resourcePresent(absolute, field, declared))
      throw new ManifestError(
        "missing resource",
        field,
        `${declared} does not exist`,
      );
    let component = base;
    for (const segment of relative(base, absolute).split(sep)) {
      component = join(component, segment);
      if (lstatSync(component).isSymbolicLink())
        throw new ManifestError(
          "unsafe path/name",
          field,
          `Adapter symlinks are not allowed: ${declared}`,
        );
    }
    if (!lstatSync(absolute).isFile())
      throw new ManifestError(
        "invalid field",
        field,
        `${declared} must be a file`,
      );
    const path = relative(base, absolute).split(sep).join("/");
    output.push({
      kind: "adapters",
      path,
      sha256: hash(readFileSync(absolute)),
    });
  }
  output.sort(
    (a, b) => a.kind.localeCompare(b.kind) || a.path.localeCompare(b.path),
  );
  const seen = new Set<string>();
  for (const item of output) {
    const key = `${item.kind}:${item.path}`;
    if (seen.has(key))
      throw new ManifestError(
        "invalid field",
        `resources.${item.kind}`,
        `Duplicate resource: ${item.path}`,
      );
    seen.add(key);
  }
  return output;
}
