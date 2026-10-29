import { cpSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const repository = fileURLToPath(new URL("../../", import.meta.url));

/**
 * A copy of the personal example in `directory` plus a local TypeScript Pi
 * package `ts` with `pretranspile: true`; returns the manifest path. The
 * search tools are left out, so it needs no network. Not locked yet.
 */
export function pretranspileProject(directory: string): string {
  cpSync(join(repository, "examples", "personal"), directory, {
    recursive: true,
  });
  const manifest = join(directory, "piship.yaml");
  writeFileSync(
    manifest,
    readFileSync(manifest, "utf8")
      .replace(
        /^ {2}# fd and rg ship[^\n]*\n[^\n]*\n {2}searchTools:\n {4}mode: bundled\n/m,
        "",
      )
      .replace(
        /^resources:\n/m,
        `resources:
  packages:
    - id: ts
      source: local
      path: ./packages/ts
      class: user
      pretranspile: true
`,
      )
      .replace(
        /^policy:\n/m,
        "packageTrust:\n  local: { paths: [./packages] }\n\npolicy:\n",
      ),
  );
  const files = {
    "packages/ts/package.json": JSON.stringify({
      name: "ts",
      version: "1.0.0",
      type: "module",
      pi: { extensions: ["./extensions"] },
    }),
    "packages/ts/extensions/main.ts": `import { value } from "../lib/values.js";
export default () => value;
`,
    "packages/ts/lib/values.ts": "export const value: number = 2;\n",
  };
  for (const [path, content] of Object.entries(files)) {
    const target = join(directory, path);
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, content);
  }
  return manifest;
}
