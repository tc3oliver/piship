import type { Collector } from "../collector.js";
import type { AnyLock } from "../types.js";
import { audit } from "./audit.js";
import { capabilities } from "./capabilities.js";
import { mcp } from "./mcp.js";
import { policy } from "./policy.js";
import { sandbox } from "./sandbox.js";
import { trustEvidence } from "./trust.js";

export function governance(out: Collector, b: AnyLock, a: AnyLock): void {
  const x = b.governance;
  const y = a.governance;
  if (!x && !y) return;
  if (!x || !y) {
    out.push(
      "policy",
      y ? "added" : "removed",
      "governance",
      y
        ? ["medium", "Adds governance: policy, MCP, sandbox, and audit."]
        : ["high", "Removes governance: policy, MCP, sandbox, and audit."],
    );
    return;
  }
  trustEvidence(out, x, y);
  capabilities(out, x.manifest, y.manifest);
  policy(out, x.manifest, y.manifest, {
    before: b.deployment?.mode,
    after: a.deployment?.mode,
  });
  mcp(out, x.manifest, y.manifest);
  sandbox(out, x.manifest, y.manifest);
  audit(out, x.manifest, y.manifest);
}
