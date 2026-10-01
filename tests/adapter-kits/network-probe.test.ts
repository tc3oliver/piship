import { mkdirSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { testSandboxAdapter } from "@piship/adapter-conformance";
import {
  activateSandbox,
  capabilityMismatch,
  networkProbe,
  type SandboxBackend,
  type SandboxCapabilities,
} from "@piship/sandbox";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  MALFORMED_NETWORK_PROBES,
  WELL_FORMED_NETWORK_PROBES,
} from "./malformed-network-probes.js";

// The sandbox conformance kit and PiShip validate a remote backend's
// networkProbe separately: the kit when an author runs it, PiShip at every
// activation. A probe one accepts and the other refuses would let a backend
// pass the kit and then fail in the field, or worse, let PiShip place a host
// the kit never vetted into a shell command. One list goes through both.

/** A remote snapshot backend that is otherwise well formed. */
const REMOTE: SandboxCapabilities = {
  isolation: "remote",
  planes: ["host-filesystem-isolation", "network-deny", "environment-filter"],
  network: ["deny", "allow"],
  localProcesses: false,
};

const declaring = (probe: unknown): SandboxCapabilities =>
  ({ ...REMOTE, networkProbe: probe }) as SandboxCapabilities;

/** A backend that declares `probe` and records whether anything was prepared. */
function backendWith(probe: unknown): {
  backend: SandboxBackend;
  prepared: () => number;
} {
  let prepared = 0;
  return {
    backend: {
      id: "acme-probe",
      provider: "custom",
      available: async () => ({ available: true }),
      capabilities: () => declaring(probe),
      prepare: async () => {
        prepared++;
        throw new Error("prepare is not part of this test");
      },
    },
    prepared: () => prepared,
  };
}

/** What the kit's capabilities check says about the declaration. */
async function kitVerdict(probe: unknown) {
  const report = await testSandboxAdapter(backendWith(probe).backend, {
    only: ["capabilities"],
  });
  const result = report.results.find(
    (item) => item.behavior === "capabilities",
  );
  return { status: result?.status, reason: result?.reason ?? "" };
}

let root: string;
beforeEach(() => {
  root = realpathSync(mkdtempSync(join(tmpdir(), "piship-network-probe-")));
  mkdirSync(join(root, "ws"));
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

const activate = (backend: SandboxBackend) =>
  activateSandbox(
    {
      required: true,
      filesystem: { read: { deny: [] }, write: { allow: ["workspace"] } },
      network: { mode: "deny" },
      environment: { allow: ["PATH"] },
    },
    {
      workspace: join(root, "ws"),
      homeDir: join(root, "home"),
      backend,
      env: { PATH: "/usr/bin" },
    },
  );

describe.each(MALFORMED_NETWORK_PROBES)(
  "a malformed network probe: %s",
  (_name, probe) => {
    it("is refused by PiShip's validation, in either network mode", () => {
      expect(networkProbe(declaring(probe))).toEqual({
        invalid: expect.any(String),
      });
      for (const mode of ["deny", "allow"] as const)
        expect(capabilityMismatch(declaring(probe), mode)).toMatch(
          /malformed network probe/,
        );
    });

    it("fails PiShip's activation closed before anything is prepared", async () => {
      const { backend, prepared } = backendWith(probe);
      await expect(activate(backend)).rejects.toMatchObject({
        code: "SANDBOX_UNAVAILABLE",
        message: expect.stringContaining("malformed network probe"),
      });
      expect(prepared()).toBe(0);
    });

    it("is refused by the conformance kit", async () => {
      const verdict = await kitVerdict(probe);
      expect(verdict.status).toBe("failed");
      expect(verdict.reason).toMatch(/malformed network probe/);
    });
  },
);

describe.each(WELL_FORMED_NETWORK_PROBES)(
  "a well-formed network probe: %s",
  (_name, probe) => {
    it("is accepted by PiShip's validation", () => {
      expect(networkProbe(declaring(probe))).toEqual({ probe });
      expect(capabilityMismatch(declaring(probe), "deny")).toBeUndefined();
    });

    it("is accepted by the conformance kit", async () => {
      expect(await kitVerdict(probe)).toEqual({ status: "passed", reason: "" });
    });
  },
);
