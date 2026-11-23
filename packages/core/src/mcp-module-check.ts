import { existsSync, readFileSync } from "node:fs";
import { builtinModules } from "node:module";
import { dirname, resolve } from "node:path";
import type { Manifest, ValidationDiagnostic } from "@piship/schema";

const BUILTIN = new Set(builtinModules);
// One character class between the keyword and the quote, so the scan stays linear.
const SPECIFIER =
  /(?:\bfrom|\bimport|\brequire)[\s(]*["']([^"'\n]{1,256})["']/g;

/** An import a single locked file cannot satisfy once it is installed. */
function external(specifier: string): boolean {
  if (specifier.startsWith("./") || specifier.startsWith("../")) return true;
  if (specifier.startsWith("node:") || specifier.startsWith("/")) return false;
  if (/^[a-z][a-z0-9+.-]*:/i.test(specifier)) return false;
  return !BUILTIN.has(specifier.split("/")[0] ?? specifier);
}

/** The sibling-file and npm imports of a module file, if it exists. */
function externalImports(file: string, allowed?: string): string[] {
  if (!existsSync(file)) return [];
  const found = new Set<string>();
  for (const match of readFileSync(file, "utf8").matchAll(SPECIFIER))
    if (match[1] && match[1] !== allowed && external(match[1]))
      found.add(match[1]);
  return [...found];
}

/**
 * MCP server and adapter modules that import a sibling file or an npm
 * package. Only the module file itself is locked and packaged, so such a
 * module runs from the source tree but fails with ERR_MODULE_NOT_FOUND once
 * installed. An adapter may import `@piship/adapter-sdk`, which the payload
 * carries.
 * shortcut: a text scan, so an import named in a comment or string also
 * counts; parse the module if that misleads authors.
 */
export function mcpModuleWarnings(
  manifest: Pick<Manifest, "governance"> & Partial<Pick<Manifest, "access">>,
  manifestPath: string,
): ValidationDiagnostic[] {
  const base = dirname(resolve(manifestPath));
  const modules: [string, string, string | undefined][] = [];
  for (const server of manifest.governance?.mcp.servers ?? [])
    if (server.module)
      modules.push([
        `mcp.servers.${server.id}.module`,
        server.module,
        undefined,
      ]);
  const identity = manifest.access?.identity;
  for (const [path, module] of [
    [
      "identity.adapter",
      identity?.mode === "adapter" ? identity.adapter : undefined,
    ],
    ["credential.adapter", manifest.access?.credential?.adapter],
    ["sandbox.adapter", manifest.governance?.sandbox?.adapter],
    ["policy.adapter", manifest.governance?.policy?.adapter],
  ] as const)
    if (module) modules.push([path, module, "@piship/adapter-sdk"]);
  const warnings: ValidationDiagnostic[] = [];
  for (const [path, module, allowed] of modules) {
    const found = externalImports(resolve(base, module), allowed);
    if (found.length)
      warnings.push({
        path,
        message: `${module} imports ${found.join(", ")}, but only this one file is packaged, so it fails with ERR_MODULE_NOT_FOUND once installed; bundle it into one file (esbuild ${module} --bundle --platform=node --format=esm --outfile=<out>.mjs)`,
      });
  }
  return warnings;
}
