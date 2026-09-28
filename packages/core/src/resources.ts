import { existsSync, lstatSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { type Manifest, ManifestError } from "@piship/schema";
import { hash } from "./digest.js";
import type { LockedResource } from "./lock-schema.js";

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
/** Declared roots per kind, including capability-provider roots for v1alpha3. */
function declaredRoots(
  manifest: Manifest,
): [LockedResource["kind"], string, string | undefined][] {
  const output: [LockedResource["kind"], string, string | undefined][] = [];
  const governance = manifest.governance;
  for (const kind of [
    "instructions",
    "skills",
    "extensions",
    "prompts",
    "themes",
  ] as const) {
    if (governance)
      for (const item of governance.resources.declared.filter(
        (entry) => entry.kind === kind,
      ))
        output.push([kind, item.path, item.class]);
    else
      for (const declared of manifest.resources[kind])
        output.push([kind, declared, undefined]);
  }
  for (const capability of governance?.capabilities ?? [])
    if (capability.provider?.path)
      output.push([
        "providers",
        capability.provider.path,
        capability.provider.class,
      ]);
  return output;
}
export function resolveResources(
  manifest: Manifest,
  manifestPath: string,
): LockedResource[] {
  const base = dirname(resolve(manifestPath));
  const output: LockedResource[] = [];
  for (const [kind, declared, cls] of declaredRoots(manifest)) {
    const absolute = resolve(base, declared);
    if (!absolute.startsWith(`${base}${sep}`))
      throw new ManifestError(
        "unsafe path/name",
        `resources.${kind}`,
        `Path escapes manifest directory: ${declared}`,
      );
    if (!existsSync(absolute))
      throw new ManifestError(
        "missing resource",
        `resources.${kind}`,
        `${declared} does not exist`,
      );
    let component = base;
    for (const segment of relative(base, absolute).split(sep)) {
      component = join(component, segment);
      if (lstatSync(component).isSymbolicLink())
        throw new ManifestError(
          "unsafe path/name",
          `resources.${kind}`,
          `Resource symlinks are not allowed: ${declared}`,
        );
    }
    if (kind === "instructions" && !lstatSync(absolute).isFile())
      throw new ManifestError(
        "invalid field",
        `resources.${kind}`,
        `${declared} must be a file`,
      );
    const files: string[] = [];
    walkResource(base, absolute, files);
    if (files.length === 0)
      throw new ManifestError(
        "missing resource",
        `resources.${kind}`,
        `${declared} is empty`,
      );
    if (
      (kind === "extensions" || kind === "providers") &&
      !files.some((file) => /\.[cm]?[jt]s$/.test(file))
    )
      throw new ManifestError(
        "invalid field",
        `resources.${kind}`,
        `${declared} has no JavaScript or TypeScript extension entry`,
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
    if (!existsSync(absolute))
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
