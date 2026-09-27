import { readFileSync, readdirSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const root = fileURLToPath(new URL("../", import.meta.url));
const packages = ["schema", "core", "pi", "cli"];
const allowedLocal = {
  schema: [],
  core: ["@piship/schema"],
  pi: ["@piship/core", "@piship/schema"],
  cli: ["@piship/core", "@piship/pi", "@piship/schema"],
  tests: ["@piship/core", "@piship/pi", "@piship/schema"],
};
const failures = [];

function checkSpecifier(specifier, file, owner) {
  if (
    specifier.startsWith("@piship/") &&
    !allowedLocal[owner].includes(specifier)
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

function walk(directory, owner) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (entry.name === "dist" || entry.name === "node_modules") continue;
    const file = join(directory, entry.name);
    if (entry.isDirectory()) {
      walk(file, owner);
      continue;
    }
    if (!/\.(?:[cm]?[jt]sx?)$/.test(entry.name)) continue;
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
      }
      if (specifier && ts.isStringLiteralLike(specifier)) {
        checkSpecifier(specifier.text, relative(root, file), owner);
      }
      ts.forEachChild(node, visit);
    };
    visit(source);
  }
}

for (const name of packages) {
  const packageDir = join(root, "packages", name);
  const manifest = JSON.parse(
    readFileSync(join(packageDir, "package.json"), "utf8"),
  );
  for (const section of [
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies",
  ]) {
    for (const [dependency, version] of Object.entries(
      manifest[section] ?? {},
    )) {
      checkSpecifier(dependency, `packages/${name}/package.json`, name);
      if (
        dependency.startsWith("@earendil-works/pi-") &&
        !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version)
      ) {
        failures.push(
          `packages/${name}/package.json: Pi dependency ${dependency} needs an exact version`,
        );
      }
      if (
        dependency === "@earendil-works/pi-coding-agent" &&
        version !== "0.87.1"
      ) {
        failures.push("Pi production dependency must be exactly 0.87.1");
      }
    }
  }
  walk(join(packageDir, "src"), name);
}
walk(join(root, "tests"), "tests");

const rootManifest = JSON.parse(
  readFileSync(join(root, "package.json"), "utf8"),
);
for (const section of [
  "dependencies",
  "devDependencies",
  "peerDependencies",
  "optionalDependencies",
]) {
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
