import { rmSync } from "node:fs";

for (const name of ["schema", "core", "pi", "cli"]) {
  rmSync(new URL(`../packages/${name}/dist/`, import.meta.url), {
    recursive: true,
    force: true,
  });
}
