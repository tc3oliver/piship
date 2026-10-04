import { join } from "node:path";
import { ModelRuntime } from "@earendil-works/pi-coding-agent";
import type { DistributionLock } from "@piship/core";
import { describe, expect, it } from "vitest";
import { governModelRuntime, type VirtualModelRule } from "../governance.js";
import { registerVirtualModels, virtualModelRules } from "./virtual-models.js";

const model = (id: string) => ({
  id,
  name: id,
  reasoning: false,
  input: ["text" as const],
  cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
  contextWindow: 64000,
  maxTokens: 4096,
});
const DIST = "/opt/acme";
const ROUTER = join(DIST, "resources", "extensions", "router.ts");
const RULE: VirtualModelRule = {
  provider: "acmecode",
  id: "acme/auto",
  routes: [{ provider: "acmecode", id: "acme/coder" }],
  router: "./extensions/router.ts",
  routerPath: ROUTER,
};

async function runtime() {
  const modelRuntime = await ModelRuntime.create({
    modelsPath: null,
    refreshOnCreate: false,
    allowModelNetwork: false,
  });
  modelRuntime.registerProvider("acmecode", {
    name: "AcmeCode",
    baseUrl: "http://127.0.0.1:9/v1",
    api: "openai-completions",
    models: [model("acme/coder")],
  });
  const governed = governModelRuntime(
    modelRuntime,
    {
      kind: "managed-endpoint",
      providerId: "acmecode",
      allowedModelIds: ["acme/coder", "acme/auto"],
      dispatchModelIds: ["acme/coder"],
      apiKey: async () => "sk-unit",
    },
    undefined,
    [RULE],
  );
  return { modelRuntime, governed };
}

/** A resource loader whose extensions queued these registrations. */
function loaded(...pending: { id: string; extensionPath: string }[]) {
  const runtime = {
    pendingVirtualModelRegistrations: pending.map(({ id, extensionPath }) => ({
      definition: {
        provider: "acmecode",
        id,
        name: id,
        route: () => ({
          model: model("acme/coder") as never,
          thinkingLevel: "off" as const,
        }),
      },
      extensionPath,
    })),
  };
  return { loader: { getExtensions: () => ({ runtime }) as never }, runtime };
}

describe("virtual model registration at load", () => {
  it("registers a declared virtual model from its declared router and empties Pi's queue", async () => {
    const { modelRuntime, governed } = await runtime();
    const { loader, runtime: extensions } = loaded({
      id: "acme/auto",
      extensionPath: ROUTER,
    });
    registerVirtualModels(loader, governed, modelRuntime, [RULE]);
    expect(modelRuntime.getModel("acmecode", "acme/auto")?.api).toBe(
      "pi-virtual",
    );
    expect(extensions.pendingVirtualModelRegistrations).toEqual([]);
  });

  it("fails the load for an undeclared id, another extension, or a physical id", async () => {
    const { modelRuntime, governed } = await runtime();
    expect(() =>
      registerVirtualModels(
        loaded({ id: "acme/other", extensionPath: ROUTER }).loader,
        governed,
        modelRuntime,
        [RULE],
      ),
    ).toThrow(
      expect.objectContaining({
        code: "MODEL_DENIED",
        message: expect.stringContaining("not in models.catalog"),
      }),
    );
    expect(() =>
      registerVirtualModels(
        loaded({
          id: "acme/auto",
          extensionPath: join(DIST, "resources", "extensions", "other.ts"),
        }).loader,
        governed,
        modelRuntime,
        [RULE],
      ),
    ).toThrow(
      expect.objectContaining({
        code: "POLICY_DENIED",
        message: expect.stringContaining(
          "its declared router is ./extensions/router.ts",
        ),
      }),
    );
    // A router declared as something that resolves to no built extension.
    expect(() =>
      registerVirtualModels(
        loaded({ id: "acme/auto", extensionPath: ROUTER }).loader,
        governed,
        modelRuntime,
        [
          {
            provider: RULE.provider,
            id: RULE.id,
            routes: RULE.routes,
            router: "package:platform",
          },
        ],
      ),
    ).toThrow(expect.objectContaining({ code: "POLICY_DENIED" }));
    const physical = { ...RULE, id: "acme/coder" };
    expect(() =>
      registerVirtualModels(
        loaded({ id: "acme/coder", extensionPath: ROUTER }).loader,
        governed,
        modelRuntime,
        [physical],
      ),
    ).toThrow(
      expect.objectContaining({
        code: "CONFIG_INVALID",
        message: expect.stringContaining("conflicts with a physical model"),
      }),
    );
    expect(modelRuntime.getModel("acmecode", "acme/auto")).toBeUndefined();
  });

  it("leaves a declared virtual model its router never registered unavailable, which a launch on it refuses", async () => {
    const { modelRuntime, governed } = await runtime();
    registerVirtualModels(loaded().loader, governed, modelRuntime, [RULE]);
    // runtime.ts refuses a launch model getModel does not return with
    // MODEL_UNAVAILABLE.
    expect(modelRuntime.getModel("acmecode", "acme/auto")).toBeUndefined();
  });

  it("resolves the router of each declared virtual model to its built path", () => {
    const catalog = (router: string) => ({
      catalog: [
        {
          id: "acme/auto",
          virtual: { router, routes: ["acme/coder", "acme/general"] },
        },
        { id: "acme/coder" },
      ],
    });
    const lock = (router: string) =>
      ({
        access: { models: catalog(router) },
        declared: {
          extensions: ["./extensions/router.ts", "./certified/router"],
        },
        governance: {
          certified: [
            {
              kind: "extensions",
              path: "./certified/router",
              evidence: { id: "company-router" },
            },
          ],
        },
      }) as unknown as DistributionLock;
    expect(
      virtualModelRules(lock("./extensions/router.ts"), DIST, "acmecode"),
    ).toEqual([
      {
        provider: "acmecode",
        id: "acme/auto",
        routes: [
          { provider: "acmecode", id: "acme/coder" },
          { provider: "acmecode", id: "acme/general" },
        ],
        router: "./extensions/router.ts",
        routerPath: ROUTER,
      },
    ]);
    expect(
      virtualModelRules(lock("company-router"), DIST, "acmecode")[0]
        ?.routerPath,
    ).toBe(join(DIST, "resources", "certified", "router"));
    for (const router of ["./extensions/undeclared.ts", "package:platform"])
      expect(
        virtualModelRules(lock(router), DIST, "acmecode")[0],
      ).not.toHaveProperty("routerPath");
    // Pi-native: provider/id keys.
    const native = {
      access: {
        models: {
          catalog: [
            {
              id: "company/auto",
              virtual: {
                router: "./extensions/router.ts",
                routes: ["anthropic/claude-x"],
              },
            },
          ],
        },
      },
      declared: { extensions: ["./extensions/router.ts"] },
    } as unknown as DistributionLock;
    expect(virtualModelRules(native, DIST)[0]).toMatchObject({
      provider: "company",
      id: "auto",
      routes: [{ provider: "anthropic", id: "claude-x" }],
    });
  });
});
