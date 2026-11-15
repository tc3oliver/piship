// `npm run relock:examples`: reruns `piship lock` for every example that has
// a piship.lock. The locks record the versions of PiShip's runtime
// dependencies, so a dependency bump (a Dependabot PR included) leaves them
// stale until this runs. Needs `npm run build` first.
import { execFileSync } from "node:child_process";
import { readdirSync } from "node:fs";
import { dirname, join } from "node:path";

const cli = join("packages", "cli", "dist", "bin.js");
for (const lock of readdirSync("examples", { recursive: true })
  .filter((path) => path.split(/[\\/]/).at(-1) === "piship.lock")
  .filter((path) => !path.split(/[\\/]/).includes("node_modules"))
  .sort()) {
  const manifest = join("examples", dirname(lock), "piship.yaml");
  console.log(`piship lock ${manifest}`);
  execFileSync(process.execPath, [cli, "lock", manifest], { stdio: "inherit" });
}
