import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { seamEvidence } from "@piship/policy";
import { DATA_CONTRACT_VERSION, migrateManifestSource } from "@piship/schema";
import { afterEach, describe, expect, it } from "vitest";
import {
  LOCK_SCHEMA_V1ALPHA5,
  LOCK_SCHEMA_V1ALPHA6,
  lockManifest,
  requireCurrentLock,
  resolveLock,
} from "./index.js";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

const V5 = `schema: piship/v1alpha5
app: { id: acmepi, name: AcmePi, command: acmepi, version: 1.0.0 }
runtime: { pi: "1.0.2" }
deployment: { mode: personal }
identity: { mode: none }
credential: { provider: none }
inference:
  provider: openai-compatible
  baseUrl: https://gateway.acme.example/v1
models:
  default: acme/coder
  allowed: [acme/coder]
  catalog:
    acme/coder: { name: Acme Coder, contextWindow: 128000, maxOutputTokens: 8192 }
resources:
  instructions:
    user: [./resources/AGENTS.md]
policy:
  defaults:
    - { id: models, action: model.use, resource: "acme/**", effect: allow }
mcp:
  servers:
    docs:
      transport: stdio
      module: ./mcp/docs.mjs
      tools: { deny: [delete_document] }
updates: { channel: stable, channels: [stable] }
`;

const V6 = V5.replace("schema: piship/v1alpha5", "schema: piship/v1alpha6")
  .replace("  allowed: [acme/coder]", "  allowed: [acme/coder, acme/auto]")
  .replace(
    "  catalog:\n",
    "  catalog:\n    acme/auto:\n      name: Acme Auto\n      contextWindow: 128000\n      maxOutputTokens: 8192\n      virtual: { router: acme-router, routes: [acme/coder] }\n",
  )
  .replace(
    "      tools: { deny: [delete_document] }",
    "      tools: { delete_document: hidden }",
  );

function project(source: string): string {
  const dir = mkdtempSync(join(tmpdir(), "piship-lock-v6-"));
  roots.push(dir);
  mkdirSync(join(dir, "resources"));
  writeFileSync(join(dir, "resources", "AGENTS.md"), "# AcmePi\n");
  mkdirSync(join(dir, "mcp"));
  writeFileSync(join(dir, "mcp", "docs.mjs"), "export {};\n");
  const path = join(dir, "piship.yaml");
  writeFileSync(path, source);
  return path;
}

describe("lock piship-lock/v1alpha6", () => {
  it("is deterministic and records the v1alpha6 sections", () => {
    const path = project(V6);
    const first = readFileSync(lockManifest(path), "utf8");
    expect(readFileSync(lockManifest(path), "utf8")).toBe(first);
    const lock = requireCurrentLock(path);
    expect(lock.schema).toBe(LOCK_SCHEMA_V1ALPHA6);
    expect(lock.manifest.schema).toBe("piship/v1alpha6");
    expect(lock.manifest.sha256).toMatch(/^sha256-[0-9a-f]{64}$/);
    expect(lock.virtualModels).toEqual([
      { id: "acme/auto", router: "acme-router", routes: ["acme/coder"] },
    ]);
    expect(lock.data).toEqual({ contract: DATA_CONTRACT_VERSION });
    expect(lock.enforcement).toEqual(seamEvidence(lock.runtime.version));
    expect(lock.enforcement?.seams["web.request"]).toBe("none");
    expect(lock.governance?.manifest.mcp.servers[0]).toMatchObject({
      class: "user",
      exposure: "direct",
      toolExposure: [{ pattern: "delete_document", exposure: "hidden" }],
      tools: { allow: [], deny: [] },
    });
    expect(lock.governance?.manifest.policy.defaults[0]?.action).toBe(
      "model.select",
    );
  });

  it("records no virtual models when none is declared", () => {
    const lock = resolveLock(project(migrateManifestSource(V5).source));
    expect(lock.schema).toBe(LOCK_SCHEMA_V1ALPHA6);
    expect(lock).not.toHaveProperty("virtualModels");
    expect(lock.data).toEqual({ contract: DATA_CONTRACT_VERSION });
  });

  it("still writes a piship-lock/v1alpha5 for a v1alpha5 manifest", () => {
    const lock = resolveLock(project(V5));
    expect(lock.schema).toBe(LOCK_SCHEMA_V1ALPHA5);
    expect(lock).not.toHaveProperty("data");
    expect(lock).not.toHaveProperty("enforcement");
    expect(lock).not.toHaveProperty("virtualModels");
    // model.use is read as model.select at parse time.
    expect(lock.governance?.manifest.policy.defaults[0]?.action).toBe(
      "model.select",
    );
    expect(lock.governance?.manifest.mcp.servers[0]).not.toHaveProperty(
      "class",
    );
  });

  it("keeps the policy and the hidden tools across the v1alpha5 -> v1alpha6 migration", () => {
    const before = resolveLock(project(V5));
    const after = resolveLock(project(migrateManifestSource(V5).source));
    expect(before.governance?.manifest.mcp.servers[0]?.tools.deny).toEqual([
      "delete_document",
    ]);
    expect(after.governance?.manifest.mcp.servers[0]?.toolExposure).toEqual([
      { pattern: "delete_document", exposure: "hidden" },
    ]);
    expect(after.governance?.manifest.policy).toEqual({
      ...before.governance?.manifest.policy,
      acknowledgeUnenforced: [],
    });
  });
});
