import { describe, expect, it } from "vitest";
import type { DistributionLock } from "./index.js";
import { virtualRouteProblems } from "./release/gates.js";

const lock = (
  mode: "managed" | "personal",
  virtual: { id: string; router: string; routes: string[] },
) =>
  ({
    deployment: { mode },
    declared: { extensions: ["./extensions/router.ts"] },
    governance: {
      certified: [
        {
          kind: "extensions",
          path: "./certified/router",
          evidence: { id: "company-router" },
        },
      ],
    },
    access: {
      models: {
        allowed: ["acme/coder", "acme/auto", "acme/classify"],
        catalog: [
          { id: "acme/coder", type: "chat" },
          {
            id: "acme/auto",
            type: "chat",
            virtual: { router: virtual.router, routes: virtual.routes },
          },
          { id: "acme/classify", type: "classifier" },
        ],
      },
    },
    virtualModels: [virtual],
  }) as unknown as DistributionLock;

describe("release gate: virtual model routes", () => {
  it("passes closed routes over allowed physical chat models and a declared router", () => {
    for (const router of ["./extensions/router.ts", "company-router"])
      expect(
        virtualRouteProblems(
          lock("managed", { id: "acme/auto", router, routes: ["acme/coder"] }),
        ),
      ).toEqual([]);
  });

  it("fails a route outside the allowlist or the physical chat catalog, and an undeclared router", () => {
    expect(
      virtualRouteProblems(
        lock("managed", {
          id: "acme/auto",
          router: "package:platform",
          routes: ["acme/general", "acme/classify", "acme/auto"],
        }),
      ),
    ).toEqual([
      "virtual model acme/auto routes to acme/general, which is not allowed",
      "virtual model acme/auto routes to acme/classify, which is not a physical chat model of the catalog",
      "virtual model acme/auto routes to acme/auto, which is not a physical chat model of the catalog",
      "virtual model acme/auto names router package:platform, which is not a declared extension",
    ]);
    // Personal: Pi's catalog serves the routes; the router is still checked.
    expect(
      virtualRouteProblems(
        lock("personal", {
          id: "acme/auto",
          router: "./extensions/missing.ts",
          routes: ["anthropic/claude-x"],
        }),
      ),
    ).toEqual([
      "virtual model acme/auto names router ./extensions/missing.ts, which is not a declared extension",
    ]);
  });
});
