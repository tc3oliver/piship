// Declarations the sandbox kit refuses although PiShip accepts them. Each
// is a deliberate point where the kit holds a backend to more than PiShip
// enforces (docs/adapter-sdk.md, "Where a kit is stricter than PiShip"):
// PiShip drops a guarantee that cannot apply, or refuses a declaration only
// under the policy it cannot serve, while the kit refuses the declaration
// itself, since a company writing one has misunderstood the contract.
import { testSandboxAdapter } from "@piship/adapter-conformance";
import type { SandboxBackend, SandboxCapabilities } from "@piship/adapter-sdk";
import {
  capabilityMismatch,
  claimedGuarantees,
  HOST_FILESYSTEM_ISOLATION,
} from "@piship/sandbox";
import { describe, expect, it } from "vitest";

function declaring(capabilities: SandboxCapabilities): SandboxBackend {
  return {
    id: "declaration-only",
    provider: "custom",
    available: async () => ({ available: true }),
    capabilities: () => capabilities,
    prepare: async () => {
      throw new Error("not prepared: only the declaration is checked");
    },
  };
}

async function kitVerdict(capabilities: SandboxCapabilities) {
  const report = await testSandboxAdapter(declaring(capabilities), {
    only: ["capabilities"],
  });
  return report.results.find((result) => result.behavior === "capabilities");
}

describe("where the sandbox kit is stricter than PiShip", () => {
  it("a local backend that claims host-filesystem-isolation: PiShip drops the claim, the kit refuses it", async () => {
    const capabilities: SandboxCapabilities = {
      isolation: "local",
      planes: [
        "filesystem-read-deny",
        "filesystem-write-allowlist",
        "network-deny",
        "environment-filter",
        HOST_FILESYSTEM_ISOLATION,
      ],
      network: ["deny", "allow"],
      localProcesses: false,
    };
    expect(capabilityMismatch(capabilities, "deny")).toBeUndefined();
    expect(claimedGuarantees(capabilities, "deny")).not.toContain(
      HOST_FILESYSTEM_ISOLATION,
    );
    expect(await kitVerdict(capabilities)).toMatchObject({
      status: "failed",
      reason: expect.stringMatching(
        /a local backend runs commands on this host, so it cannot claim host-filesystem-isolation/,
      ),
    });
  });

  it("network-deny claimed without listing deny: PiShip refuses it only under a deny policy, the kit always", async () => {
    const capabilities: SandboxCapabilities = {
      isolation: "remote",
      planes: [HOST_FILESYSTEM_ISOLATION, "network-deny", "environment-filter"],
      network: ["allow"],
      localProcesses: false,
    };
    expect(capabilityMismatch(capabilities, "allow")).toBeUndefined();
    expect(capabilityMismatch(capabilities, "deny")).toMatch(
      /does not provide network-deny/,
    );
    expect(await kitVerdict(capabilities)).toMatchObject({
      status: "failed",
      reason: expect.stringMatching(
        /claims network-deny but does not list network mode deny/,
      ),
    });
  });
});
