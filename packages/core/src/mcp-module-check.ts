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

/**
 * MCP server modules that import a sibling file or an npm package. Only the
 * module file itself is locked and packaged, so such a server runs from the
 * source tree but fails with ERR_MODULE_NOT_FOUND once installed.
 * shortcut: a text scan, so an import named in a comment or string also
 * counts; parse the module if that misleads authors.
 */
export function mcpModuleWarnings(
  manifest: Pick<Manifest, "governance">,
  manifestPath: string,
): ValidationDiagnostic[] {
  const base = dirname(resolve(manifestPath));
  const warnings: ValidationDiagnostic[] = [];
  for (const server of manifest.governance?.mcp.servers ?? []) {
    if (!server.module) continue;
    const file = resolve(base, server.module);
    if (!existsSync(file)) continue;
    const found = new Set<string>();
    for (const match of readFileSync(file, "utf8").matchAll(SPECIFIER))
      if (match[1] && external(match[1])) found.add(match[1]);
    if (found.size)
      warnings.push({
        path: `mcp.servers.${server.id}.module`,
        message: `${server.module} imports ${[...found].join(", ")}, but only this one file is packaged, so the server fails with ERR_MODULE_NOT_FOUND once installed; bundle it into one file (esbuild ${server.module} --bundle --platform=node --format=esm --outfile=<out>.mjs)`,
      });
  }
  return warnings;
}
