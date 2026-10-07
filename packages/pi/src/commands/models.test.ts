import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

const prepared = vi.hoisted(() => ({
  value: { activated: null } as { activated: unknown },
}));
vi.mock("../launch/context.js", () => ({
  prepareAccess: vi.fn(async () => prepared.value),
}));

import type { LaunchContext } from "../launch/context.js";
import { runModels } from "./models.js";

const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0))
    rmSync(dir, { recursive: true, force: true });
});

function context(access?: object, models?: object) {
  const agentDir = mkdtempSync(join(tmpdir(), "piship-models-"));
  dirs.push(agentDir);
  if (models)
    writeFileSync(join(agentDir, "models.json"), JSON.stringify(models));
  const out: string[] = [];
  const ctx = {
    metadata: { app: { id: "acmepi", command: "acmepi" }, access },
    agentDir,
    out: (message: string) => out.push(message),
  } as unknown as LaunchContext;
  return { ctx, out };
}

const PROVIDERS = {
  providers: {
    acme: {
      baseUrl: "http://127.0.0.1:9/v1",
      apiKey: "not-a-real-key",
      api: "openai-completions",
      models: [{ id: "coder", name: "Acme Coder" }, { id: "fast" }],
    },
  },
};

describe("models for a Pi-native distribution", () => {
  it("lists what Pi can use here, offline, instead of sending the user to /model", async () => {
    prepared.value = { activated: null };
    const { ctx, out } = context(undefined, PROVIDERS);
    await runModels(ctx);
    const text = out.join("\n");
    expect(text).toMatch(/Models Pi can use here/);
    expect(text).toContain("acme/coder");
    expect(text).toContain("acme/fast");
  });

  it("lists the owner's allowlist with the catalog names, the default, and what needs a sign-in", async () => {
    prepared.value = { activated: null };
    const { ctx, out } = context(
      {
        models: {
          default: "acme/coder",
          allowed: ["acme/coder", "other/model"],
          catalog: [{ id: "acme/coder", name: "Acme Coder" }],
        },
      },
      PROVIDERS,
    );
    await runModels(ctx);
    expect(out[0]).toMatch(/Models this distribution allows/);
    expect(out[1]).toMatch(/^\* acme\/coder +Acme Coder +ready$/);
    expect(out[2]).toMatch(/^ {2}other\/model +needs \/login$/);
  });

  it("says how to set a provider up when there is nothing to list", async () => {
    prepared.value = { activated: null };
    const { ctx, out } = context(undefined);
    await runModels(ctx);
    expect(out.join("\n")).toMatch(
      /no model has a provider set up yet.*\/login/,
    );
  });
});
