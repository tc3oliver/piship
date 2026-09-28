import type { GovernanceManifest } from "@piship/schema";
import type { Collector } from "../collector.js";

export function sandbox(
  out: Collector,
  b: GovernanceManifest,
  a: GovernanceManifest,
): void {
  const x = b.sandbox;
  const y = a.sandbox;
  out.scalar("sandbox", "sandbox required", x?.required, y?.required, (_, r) =>
    r === "false"
      ? ["high", "Sandbox no longer fails closed when unavailable."]
      : ["medium", "Sandbox becomes required."],
  );
  out.set(
    "sandbox",
    "sandbox filesystem.read.deny",
    x?.filesystem?.read?.deny,
    y?.filesystem?.read?.deny,
    ["medium", "Denies reading an additional path."],
    ["high", "Sandboxed processes may read this path."],
  );
  out.set(
    "sandbox",
    "sandbox filesystem.write.allow",
    x?.filesystem?.write?.allow,
    y?.filesystem?.write?.allow,
    ["high", "Sandboxed processes may write an additional path."],
    ["medium", "Removes a writable path."],
  );
  out.scalar(
    "sandbox",
    "sandbox network",
    x?.network?.mode,
    y?.network?.mode,
    (_, m) =>
      m === "allow"
        ? ["high", "Sandboxed processes may reach the network."]
        : ["medium", "Sandboxed processes lose network access."],
  );
  out.set(
    "sandbox",
    "sandbox environment.allow",
    x?.environment?.allow,
    y?.environment?.allow,
    ["high", "Passes an additional environment variable into the sandbox."],
    ["medium", "Passes fewer environment variables into the sandbox."],
  );
}
