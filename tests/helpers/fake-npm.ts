import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join, resolve } from "node:path";

// The release gates call `npm audit --json` and `npm audit signatures --json`
// (packages/core/src/release/scans.ts). An E2E scenario whose subject is not
// the registry builds its releases with this `npm` first on the PATH of the
// CLI it spawns, so an unreachable registry cannot fail it. The product is not
// changed: it still spawns `npm` from PATH and still fails closed without a
// report (scans.test.ts). Only the test that owns the child's environment can
// put the fake there. The reports are the shape npm prints for a tree with no
// advisories and no invalid signature. Every other subcommand reaches the real
// npm; an `audit` form the gates do not use fails loudly.
// Under PISHIP_REQUIRE_REGISTRY=1 (CI) nothing is faked: the gates run against
// the real registry, as before. tests/e2e/registry-gates.test.ts always does.

const AUDIT_V2 = {
  auditReportVersion: 2,
  vulnerabilities: {},
  metadata: {
    vulnerabilities: {
      info: 0,
      low: 0,
      moderate: 0,
      high: 0,
      critical: 0,
      total: 0,
    },
  },
};
const SIGNATURES = { invalid: [], missing: [] };

// Runs as the fake's npm-cli.js, so it takes nothing from this module.
const SCRIPT = `
const { spawnSync } = require("node:child_process");
const { delimiter, dirname, resolve } = require("node:path");
const args = process.argv.slice(2);
const fakeDir = resolve(dirname(process.argv[1]), "..", "..", "..");
const same = (a, b) => process.platform === "win32" ? a.toLowerCase() === b.toLowerCase() : a === b;
const printed = (report) => { process.stdout.write(JSON.stringify(report)); process.exit(0); };
// PISHIP_FAKE_NPM_HANG=<file>: \`ci\` and \`install\` start a child that never
// ends, write its pid to <file>, and hang, as npm does on a dead registry.
if (process.env.PISHIP_FAKE_NPM_HANG && (args[0] === "ci" || args[0] === "install")) {
  const child = require("node:child_process").spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { stdio: "ignore" });
  require("node:fs").writeFileSync(process.env.PISHIP_FAKE_NPM_HANG, String(child.pid));
  setInterval(() => {}, 1000);
} else if (args[0] === "audit") {
  const rest = args.slice(1).filter((arg) => !/^--registry=/.test(arg));
  const is = (...want) => rest.length === want.length && want.every((arg, i) => rest[i] === arg);
  if (is("--omit=dev", "--json")) printed(${JSON.stringify(AUDIT_V2)});
  if (is("signatures", "--omit=dev", "--json")) printed(${JSON.stringify(SIGNATURES)});
  process.stderr.write("fake npm: unknown audit form: npm " + args.join(" ") + "\\n");
  process.exit(2);
} else {
  const PATH = (process.env.PATH || process.env.Path || "").split(delimiter).filter((entry) => !same(resolve(entry), fakeDir)).join(delimiter);
  const real = spawnSync("npm", args, { stdio: "inherit", shell: process.platform === "win32", env: { ...process.env, PATH, Path: PATH } });
  process.exit(real.status ?? 1);
}
`;

let directory: string | undefined;

function fakeDirectory(): string {
  if (directory) return directory;
  const root = mkdtempSync(join(tmpdir(), "piship-fake-npm-"));
  const cli = join(root, "node_modules", "npm", "bin");
  mkdirSync(cli, { recursive: true });
  writeFileSync(join(cli, "npm-cli.js"), SCRIPT);
  // `npm` for PATH lookups on POSIX; `npm.cmd` for cmd.exe, and for the
  // product's Windows invocation, which runs node on node_modules/npm/bin/npm-cli.js
  // beside it (windows-npm.ts).
  writeFileSync(
    join(root, "npm"),
    `#!/bin/sh\nexec "${process.execPath}" "$(dirname "$0")/node_modules/npm/bin/npm-cli.js" "$@"\n`,
    { mode: 0o755 },
  );
  writeFileSync(
    join(root, "npm.cmd"),
    `@"${process.execPath}" "%~dp0node_modules\\npm\\bin\\npm-cli.js" %*\r\n`,
  );
  process.once("exit", () => rmSync(root, { recursive: true, force: true }));
  directory = root;
  return root;
}

/** `env` with the fake `npm` first on PATH, unless CI requires the registry. */
export function withFakeNpm(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  if (env.PISHIP_REQUIRE_REGISTRY === "1") return env;
  const key = Object.keys(env).find((name) => /^path$/i.test(name)) ?? "PATH";
  return {
    ...env,
    [key]: [fakeDirectory(), env[key]].filter(Boolean).join(delimiter),
  };
}

/** Whether `npm` can reach the registry now (npm's own environment). */
export function registryReachable(): boolean {
  const ping = spawnSync(
    "npm",
    ["ping", "--fetch-retries=0", "--fetch-timeout=10000"],
    { shell: process.platform === "win32", stdio: "ignore", timeout: 30_000 },
  );
  return ping.status === 0;
}

/** The directory of the fake, for the test of the fake itself. */
export const fakeNpmDirectory = () => resolve(fakeDirectory());
