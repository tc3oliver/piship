import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { readManifest, readManifestDocument } from "@piship/schema";
import { describe, expect, it } from "vitest";

// The sandbox variant of the AcmeCode reference distribution
// (examples/enterprise-reference/sandbox) is the reference manifest with its
// commands run in the organization's container sandbox service. It sits in
// its own directory because a lock is `piship.lock` next to its manifest and
// a manifest cannot reach outside its directory, so it repeats the reference
// manifest, its two resources, and its Pi package. This keeps the repetition honest on every
// pull request, without Docker: what the variant changes is exactly the
// sandbox, and its adapter is one file that imports only the SDK.

const reference = fileURLToPath(
  new URL("../examples/enterprise-reference/", import.meta.url),
);
const sandbox = join(reference, "sandbox");

type Document = {
  variables: string[];
  sandbox: Record<string, unknown> & { network: unknown; required: unknown };
} & Record<string, unknown>;

function files(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) =>
    entry.isDirectory()
      ? files(join(directory, entry.name))
      : [join(directory, entry.name)],
  );
}

describe("the sandbox variant of the reference distribution", () => {
  // The documents as written, so a section is compared as its author wrote it.
  const base = readManifestDocument(join(reference, "piship.yaml")) as Document;
  const variant = readManifestDocument(
    join(sandbox, "piship.yaml"),
  ) as Document;

  it("is a manifest PiShip accepts", () => {
    expect(() => readManifest(join(sandbox, "piship.yaml"))).not.toThrow();
  });

  it("changes the sandbox and one runtime variable, and nothing else", () => {
    const {
      variables: baseVariables,
      sandbox: baseSandbox,
      ...baseRest
    } = base;
    const {
      variables: variantVariables,
      sandbox: variantSandbox,
      ...variantRest
    } = variant;
    expect(variantRest).toEqual(baseRest);
    expect(variantVariables).toEqual([
      ...baseVariables,
      "ACMECODE_SANDBOX_URL",
    ]);
    // The path and network rules stay the reference's; the provider, the
    // adapter, the endpoint, and the credential are what change.
    expect(variantSandbox).toEqual({
      ...baseSandbox,
      provider: "custom",
      adapter: "./acme-container-sandbox.mjs",
      endpoint: `\${ACMECODE_SANDBOX_URL}`,
      credential: "stored",
    });
    expect(variantSandbox.required).toBe(true);
    expect(variantSandbox.network).toEqual({ mode: "deny" });
  });

  it("installs under the reference's own ID and launcher, apart from the demo company's", () => {
    const app = (document: Document) =>
      document.app as { id: string; command: string };
    const demo = readManifestDocument(
      fileURLToPath(
        new URL("../examples/demo-company/piship.yaml", import.meta.url),
      ),
    ) as Document;
    // The variant is the same distribution: the same ID and command as the
    // reference, in the manifest and in the lock built from it.
    expect(app(variant).id).toBe(app(base).id);
    expect(app(variant).command).toBe(app(base).command);
    expect(app(base).command).toBe("acmecode-reference");
    for (const directory of [reference, sandbox]) {
      const lock = JSON.parse(
        readFileSync(join(directory, "piship.lock"), "utf8"),
      ) as { app: { id: string; command: string } };
      expect(lock.app).toMatchObject(app(base));
    }
    // What the reference launcher must never share with the demo company's:
    // installing one would otherwise replace the other's command.
    expect(app(base).command).not.toBe(app(demo).command);
    expect(app(base).id).not.toBe(app(demo).id);
  });

  it.each(["resources", "packages"])(
    "carries the same %s as the reference distribution",
    (directory) => {
      const names = (root: string) =>
        files(join(root, directory)).map((path) =>
          relative(join(root, directory), path),
        );
      expect(names(sandbox).sort()).toEqual(names(reference).sort());
      for (const name of names(reference))
        expect(readFileSync(join(sandbox, directory, name), "utf8")).toBe(
          readFileSync(join(reference, directory, name), "utf8"),
        );
    },
  );

  it("has an adapter that is one file importing only the SDK and Node built-ins", () => {
    const source = readFileSync(
      join(sandbox, "acme-container-sandbox.mjs"),
      "utf8",
    );
    const specifiers = [...source.matchAll(/\bfrom\s+["']([^"']+)["']/g)].map(
      (match) => match[1],
    );
    expect(specifiers.length).toBeGreaterThan(0);
    for (const specifier of specifiers)
      expect(
        specifier === "@piship/adapter-sdk" || specifier?.startsWith("node:"),
        `imports ${specifier}`,
      ).toBe(true);
    // No dynamic import or require, and no sibling file.
    expect(source).not.toMatch(/\bimport\s*\(/);
    expect(source).not.toMatch(/\brequire\s*\(/);
    expect(source).not.toMatch(/from\s+["']\./);
  });
});
