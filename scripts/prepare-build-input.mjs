import { cpSync, mkdirSync, readdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const workspace = fileURLToPath(new URL("../", import.meta.url));
const input = join(workspace, "packages", "core", "dist", "build-input");
rmSync(input, { recursive: true, force: true });
mkdirSync(input, { recursive: true });
for (const name of ["package.json", "package-lock.json"])
  cpSync(join(workspace, name), join(input, name));
for (const name of [
  "schema",
  "contracts",
  "policy",
  "audit",
  "sandbox",
  "mcp",
  "identity",
  "credentials",
  "inference",
  "core",
  "pi",
  "cli",
]) {
  const source = join(workspace, "packages", name);
  const target = join(input, "packages", name);
  mkdirSync(target, { recursive: true });
  cpSync(join(source, "package.json"), join(target, "package.json"));
  if (name === "core") {
    mkdirSync(join(target, "dist"), { recursive: true });
    for (const entry of readdirSync(join(source, "dist")))
      if (entry !== "build-input")
        cpSync(join(source, "dist", entry), join(target, "dist", entry), {
          recursive: true,
        });
  } else
    cpSync(join(source, "dist"), join(target, "dist"), { recursive: true });
}
