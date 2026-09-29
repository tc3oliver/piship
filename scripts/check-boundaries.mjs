import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const root = fileURLToPath(new URL("../", import.meta.url));
const packagesDir = join(root, "packages");
// Every directory under packages/ with a package.json is checked; a new
// package fails until it is given an explicit entry in allowedLocal.
const packages = readdirSync(packagesDir, { withFileTypes: true })
  .filter(
    (entry) =>
      entry.isDirectory() &&
      existsSync(join(packagesDir, entry.name, "package.json")),
  )
  .map((entry) => entry.name)
  .sort();
// Identity, credentials, and inference are separate contracts: none of them
// may import another, and only core orchestrates them.
// Policy, audit, sandbox, and MCP are governance leaves: MCP spawns stdio
// servers through the sandbox, and only core and pi compose them.
const allowedLocal = {
  schema: ["@piship/contracts"],
  contracts: [],
  policy: ["@piship/contracts", "@piship/schema"],
  audit: ["@piship/contracts"],
  sandbox: ["@piship/contracts"],
  mcp: ["@piship/contracts", "@piship/sandbox"],
  identity: ["@piship/contracts"],
  credentials: ["@piship/contracts"],
  inference: ["@piship/contracts"],
  core: [
    "@piship/schema",
    "@piship/contracts",
    "@piship/identity",
    "@piship/credentials",
    "@piship/inference",
    "@piship/policy",
    "@piship/audit",
  ],
  pi: [
    "@piship/core",
    "@piship/schema",
    "@piship/contracts",
    "@piship/policy",
    "@piship/sandbox",
    "@piship/mcp",
    "@piship/audit",
  ],
  cli: ["@piship/core", "@piship/schema", "@piship/contracts"],
  // The adapter SDK re-exports public contracts and wraps customBackend();
  // it never reaches into core or Pi. The conformance kits test an adapter
  // the way a company would, through the SDK only.
  "adapter-sdk": ["@piship/contracts", "@piship/sandbox"],
  "adapter-conformance": ["@piship/adapter-sdk"],
  tests: [
    "@piship/core",
    "@piship/pi",
    "@piship/schema",
    "@piship/contracts",
    "@piship/identity",
    "@piship/credentials",
    "@piship/inference",
    "@piship/policy",
    "@piship/audit",
    "@piship/sandbox",
    "@piship/mcp",
  ],
};
// Workspace imports that appear only inside source text a package generates,
// never as imports of the package itself. They run from an installed payload,
// where every workspace package is linked, so they are exempt from
// allowedLocal and from package.json declarations. Any other generated
// import, and any entry here that no longer appears, fails the check.
const generatedImports = {
  core: [
    // Payload launcher (bin/<command>): verifies the payload with core, then
    // hands off to the Pi seam; core itself never imports @piship/pi.
    "@piship/core",
    "@piship/pi",
    // Payload launcher error path: formats a failure without loading Pi.
    "@piship/contracts",
    // Portable CLI entry (piship.mjs) shipped inside the payload; core never
    // imports the CLI, which depends on core.
    "@piship/cli",
  ],
};
const PI_DEPENDENCY = "@earendil-works/pi-coding-agent";
const DEPENDENCY_SECTIONS = [
  "dependencies",
  "devDependencies",
  "peerDependencies",
  "optionalDependencies",
];
const failures = [];

for (const name of packages)
  if (!allowedLocal[name])
    failures.push(
      `packages/${name}: add an explicit allowedLocal entry to scripts/check-boundaries.mjs`,
    );
for (const name of Object.keys(allowedLocal))
  if (name !== "tests" && !packages.includes(name))
    failures.push(
      `scripts/check-boundaries.mjs: allowedLocal lists ${name}, which is not a package`,
    );

// The pinned Pi version is the one compatibility/pi.json records; the pi
// package's dependency must name a supported or candidate version there.
const piMatrix = JSON.parse(
  readFileSync(join(root, "compatibility", "pi.json"), "utf8"),
);
const knownPiVersions = Object.entries(piMatrix.versions ?? {})
  .filter(([, entry]) => ["supported", "candidate"].includes(entry?.status))
  .map(([version]) => version);

/** The package a path belongs to, or undefined outside packages/. */
function packageOf(path) {
  const parts = relative(root, path).split(sep);
  return parts[0] === "packages" && parts.length > 1 ? parts[1] : undefined;
}

function checkSpecifier(specifier, file, owner) {
  if (
    specifier.startsWith("@piship/") &&
    !allowedLocal[owner]?.includes(specifier)
  ) {
    failures.push(`${file}: forbidden workspace import ${specifier}`);
  }
  if (
    !specifier.includes("@earendil-works/pi-") &&
    !/[/\\]pi-(?:coding-agent|agent-core|ai|tui)[/\\]/.test(specifier)
  ) {
    return;
  }
  if (owner !== "pi") {
    failures.push(`${file}: only packages/pi may import ${specifier}`);
  }
  if (!/^@earendil-works\/pi-[^/]+$/.test(specifier)) {
    failures.push(
      `${file}: Pi imports must use a public package root: ${specifier}`,
    );
  }
}

/**
 * A relative import never reaches into another package's directory; that
 * would bypass its public exports and the dependency map. Shared test
 * helpers and example fixtures outside packages/ stay reachable.
 */
function checkRelative(specifier, path, owner) {
  if (!specifier.startsWith(".")) return;
  const target = packageOf(resolve(dirname(path), specifier));
  if (target !== undefined && target !== owner)
    failures.push(
      `${relative(root, path)}: relative import ${specifier} crosses into packages/${target}; import @piship/${target} instead`,
    );
}

const GENERATED_IMPORT =
  /(?:\bimport\s*\(\s*|\bfrom\s+)\\?["'`](@piship\/[a-z0-9-]+)\\?["'`]/g;

function walk(directory, owner, imported, generated) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (entry.name === "dist" || entry.name === "node_modules") continue;
    const file = join(directory, entry.name);
    if (entry.isDirectory()) {
      walk(file, owner, imported, generated);
      continue;
    }
    if (!/\.(?:[cm]?[jt]sx?)$/.test(entry.name)) continue;
    const isTest = /\.test\.[cm]?[jt]sx?$/.test(entry.name);
    const source = ts.createSourceFile(
      file,
      readFileSync(file, "utf8"),
      ts.ScriptTarget.Latest,
      true,
    );
    const visit = (node) => {
      let specifier;
      if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) {
        specifier = node.moduleSpecifier;
      } else if (
        ts.isCallExpression(node) &&
        (node.expression.kind === ts.SyntaxKind.ImportKeyword ||
          (ts.isIdentifier(node.expression) &&
            node.expression.text === "require"))
      ) {
        specifier = node.arguments[0];
      } else if (
        !isTest &&
        generated &&
        (ts.isStringLiteral(node) ||
          ts.isNoSubstitutionTemplateLiteral(node) ||
          ts.isTemplateHead(node) ||
          ts.isTemplateMiddle(node) ||
          ts.isTemplateTail(node))
      ) {
        for (const match of node.text.matchAll(GENERATED_IMPORT)) {
          const name = match[1];
          generated.add(name);
          if (!generatedImports[owner]?.includes(name))
            failures.push(
              `${relative(root, file)}: generated source imports ${name}; list it in generatedImports with a reason`,
            );
        }
      }
      if (specifier && ts.isStringLiteralLike(specifier)) {
        checkSpecifier(specifier.text, relative(root, file), owner);
        checkRelative(specifier.text, file, owner);
        if (specifier.text.startsWith("@piship/"))
          imported?.add(specifier.text);
      }
      ts.forEachChild(node, visit);
    };
    visit(source);
  }
}

for (const name of packages) {
  const packageDir = join(packagesDir, name);
  const manifest = JSON.parse(
    readFileSync(join(packageDir, "package.json"), "utf8"),
  );
  const declared = new Set();
  for (const section of DEPENDENCY_SECTIONS) {
    for (const [dependency, version] of Object.entries(
      manifest[section] ?? {},
    )) {
      checkSpecifier(dependency, `packages/${name}/package.json`, name);
      if (dependency.startsWith("@piship/")) declared.add(dependency);
      if (
        dependency.startsWith("@earendil-works/pi-") &&
        !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version)
      ) {
        failures.push(
          `packages/${name}/package.json: Pi dependency ${dependency} needs an exact version`,
        );
      }
      if (dependency === PI_DEPENDENCY && !knownPiVersions.includes(version)) {
        failures.push(
          `packages/${name}/package.json: pinned ${PI_DEPENDENCY} ${version} is not a supported or candidate version in compatibility/pi.json (${knownPiVersions.join(", ") || "none"})`,
        );
      }
    }
  }
  const imported = new Set();
  const generated = new Set();
  walk(join(packageDir, "src"), name, imported, generated);
  for (const dependency of declared)
    if (!imported.has(dependency))
      failures.push(
        `packages/${name}/package.json: ${dependency} is declared but never imported by packages/${name}/src`,
      );
  for (const expected of generatedImports[name] ?? [])
    if (!generated.has(expected))
      failures.push(
        `scripts/check-boundaries.mjs: generatedImports.${name} lists ${expected}, which packages/${name}/src no longer generates`,
      );
}
walk(join(root, "tests"), "tests");

const rootManifest = JSON.parse(
  readFileSync(join(root, "package.json"), "utf8"),
);
for (const section of DEPENDENCY_SECTIONS) {
  for (const dependency of Object.keys(rootManifest[section] ?? {})) {
    if (dependency.startsWith("@earendil-works/pi-")) {
      failures.push(`package.json: only packages/pi may declare ${dependency}`);
    }
  }
}

if (failures.length > 0) {
  for (const failure of failures) console.error(failure);
  process.exitCode = 1;
} else {
  console.log("Package and Pi import boundaries passed.");
}
