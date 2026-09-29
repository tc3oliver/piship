import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import * as contracts from "@piship/contracts";
import * as sandbox from "@piship/sandbox";
import ts from "typescript";
import { describe, expect, it } from "vitest";
import * as sdk from "./index.js";

const packageDir = fileURLToPath(new URL("../", import.meta.url));

/** Every module specifier a file imports or re-exports, dynamic ones included. */
function specifiers(file: string): string[] {
  const source = ts.createSourceFile(
    file,
    readFileSync(file, "utf8"),
    ts.ScriptTarget.Latest,
    true,
  );
  const found: string[] = [];
  const visit = (node: ts.Node) => {
    if (
      (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) &&
      node.moduleSpecifier &&
      ts.isStringLiteralLike(node.moduleSpecifier)
    )
      found.push(node.moduleSpecifier.text);
    else if (
      ts.isCallExpression(node) &&
      node.expression.kind === ts.SyntaxKind.ImportKeyword &&
      node.arguments[0] &&
      ts.isStringLiteralLike(node.arguments[0])
    )
      found.push(node.arguments[0].text);
    else if (
      ts.isImportTypeNode(node) &&
      ts.isLiteralTypeNode(node.argument) &&
      ts.isStringLiteral(node.argument.literal)
    )
      found.push(node.argument.literal.text);
    ts.forEachChild(node, visit);
  };
  visit(source);
  return found;
}

const files = (directory: string, pattern: RegExp) =>
  readdirSync(join(packageDir, directory))
    .filter((name) => pattern.test(name))
    .map((name) => join(packageDir, directory, name));

// The public package roots the SDK may re-export from.
const PUBLIC_ROOTS = ["@piship/contracts", "@piship/sandbox"];
const OWN = [
  "ADAPTER_KINDS",
  "defineAuditSink",
  "defineCredentialAdapter",
  "defineIdentityAdapter",
  "defineSandboxAdapter",
  "withTimeout",
];

describe("the SDK surface", () => {
  it("exports exactly the curated values", () => {
    expect(Object.keys(sdk).sort()).toEqual(
      [
        ...OWN,
        "AUDIT_BATCH_SCHEMA",
        "AUDIT_EVENT_SCHEMA",
        "AUDIT_EVENT_TYPES",
        "HOST_FILESYSTEM_ISOLATION",
        "PISHIP_ERROR_CODES",
        "PiShipError",
        "REDACTED_TEXT",
        "RETAINED_CLAIMS",
        "SANDBOX_GUARANTEES",
        "SecretValue",
        "formatError",
        "isPiShipError",
        "isSecretValue",
        "parseRetryAfter",
        "principalKey",
        "redact",
        "redactValue",
        "samePrincipal",
      ].sort(),
    );
  });

  it("re-exports the public packages' own values, never a copy", () => {
    for (const [name, value] of Object.entries(sdk)) {
      if (OWN.includes(name)) continue;
      const source =
        (contracts as Record<string, unknown>)[name] ??
        (sandbox as Record<string, unknown>)[name];
      expect(value, name).toBe(source);
    }
    // One SecretValue class: a secret an adapter makes is PiShip's own.
    expect(new sdk.SecretValue("adapter-made-secret")).toBeInstanceOf(
      contracts.SecretValue,
    );
  });

  it("imports only public package roots, never Pi or an internal path", () => {
    const checked = [
      ...files("src", /^(?!.*\.test\.ts$).*\.ts$/),
      ...files("dist", /\.d\.ts$/),
      ...files("dist", /\.js$/),
    ];
    expect(checked.length).toBeGreaterThanOrEqual(6);
    for (const file of checked)
      for (const specifier of specifiers(file))
        expect(
          PUBLIC_ROOTS.includes(specifier) ||
            /^\.\/[a-z-]+\.js$/.test(specifier),
          `${file} imports ${specifier}`,
        ).toBe(true);
    const manifest = JSON.parse(
      readFileSync(join(packageDir, "package.json"), "utf8"),
    ) as { exports: Record<string, unknown>; dependencies: object };
    // No deep imports into the SDK either: the root is its only entry point.
    expect(Object.keys(manifest.exports)).toEqual(["."]);
    expect(Object.keys(manifest.dependencies).sort()).toEqual(PUBLIC_ROOTS);
  });

  it("keeps every example adapter a single file", () => {
    const examples = files("examples", /\.mjs$/);
    expect(examples.map((file) => file.split(/[/\\]/).pop()).sort()).toEqual([
      "audit-sink.mjs",
      "credential.mjs",
      "identity.mjs",
      "sandbox.mjs",
    ]);
    // A sibling file is not packaged with the adapter, and a bare import
    // resolves only from the payload's node_modules.
    for (const file of examples)
      for (const specifier of specifiers(file))
        expect(
          specifier === "@piship/adapter-sdk" || specifier.startsWith("node:"),
          `${file} imports ${specifier}`,
        ).toBe(true);
  });
});

describe("the define helpers", () => {
  const context = {
    distributionId: "acme",
    fetch: async () => new Response(null),
  };

  it("return identity and credential factories and audit sinks unchanged", () => {
    const identity = () => ({ kind: "x", login: async () => ({}) as never });
    const credential = () => ({
      mode: "adapter" as const,
      requiresIdentity: false,
      acquire: async () => null,
    });
    const sink = { write: async () => {} };
    expect(sdk.defineIdentityAdapter(identity)).toBe(identity);
    expect(sdk.defineCredentialAdapter(credential)).toBe(credential);
    expect(sdk.defineAuditSink(sink)).toBe(sink);
  });

  it("checks a sandbox backend as the loader does and fixes its provider", async () => {
    const instance = {
      exec: async () => ({ exitCode: 0 }),
      dispose: async () => {},
    };
    const backend = await sdk.defineSandboxAdapter(async (received) => {
      expect(received).toBe(context);
      return {
        id: "acme-sandbox",
        available: async () => ({ available: true as const }),
        capabilities: () => ({
          isolation: "remote" as const,
          planes: [sdk.HOST_FILESYSTEM_ISOLATION],
          network: ["deny" as const],
          localProcesses: false,
        }),
        prepare: async () => instance,
      };
    })(context);
    expect(backend).toMatchObject({ id: "acme-sandbox", provider: "custom" });
    expect(await backend.available()).toEqual({ available: true });
    const prepared = await backend.prepare({ profile: {} as never });
    expect(await prepared.exec({} as never, {} as never)).toEqual({
      exitCode: 0,
    });
    // The loader applies the same check to what the factory returns.
    expect(sandbox.customBackend(backend)).toMatchObject({
      id: "acme-sandbox",
      provider: "custom",
    });
  });

  it("rejects a malformed sandbox backend", async () => {
    const valid = {
      id: "acme-sandbox",
      available: async () => ({ available: true as const }),
      capabilities: () => ({
        isolation: "local" as const,
        planes: [],
        network: [],
        localProcesses: false,
      }),
      prepare: async () => ({}) as never,
    };
    await expect(
      sdk.defineSandboxAdapter(() => ({ ...valid, id: "native" }))(context),
    ).rejects.toThrow("reserved for a built-in backend");
    await expect(
      sdk.defineSandboxAdapter(() => ({ ...valid, id: "Not An Id" }))(context),
    ).rejects.toThrow("short lowercase identifier");
    const { prepare: _prepare, ...partial } = valid;
    await expect(
      sdk.defineSandboxAdapter(() => partial as never)(context),
    ).rejects.toThrow("prepare() is missing");
    const backend = await sdk.defineSandboxAdapter(() => valid)(context);
    await expect(backend.prepare({ profile: {} as never })).rejects.toThrow(
      "exec() and dispose()",
    );
  });
});

describe("withTimeout", () => {
  it("times out on its own", async () => {
    const signal = sdk.withTimeout(10);
    await new Promise((resolve) => signal.addEventListener("abort", resolve));
    expect((signal.reason as Error).name).toBe("TimeoutError");
  });

  it("composes with the caller's cancellation, which stays distinguishable", async () => {
    const caller = new AbortController();
    const signal = sdk.withTimeout(60_000, caller.signal);
    expect(signal.aborted).toBe(false);
    caller.abort();
    expect(signal.aborted).toBe(true);
    expect((signal.reason as Error).name).toBe("AbortError");
    const late = new AbortController();
    const timed = sdk.withTimeout(10, late.signal);
    await new Promise((resolve) => timed.addEventListener("abort", resolve));
    // A timeout leaves the caller's signal alone: retryable, not cancelled.
    expect(late.signal.aborted).toBe(false);
    expect((timed.reason as Error).name).toBe("TimeoutError");
  });
});
