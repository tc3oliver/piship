// config explain for MCP servers with httpTransport: http-allowed and
// identity headers: names and claims only, never a header value.
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type { GovernanceManifest } from "@piship/schema";
import { afterEach, describe, expect, it } from "vitest";
import { explainConfiguration } from "./access/index.js";
import { resolveLock } from "./index.js";

const DEMO = fileURLToPath(
  new URL("../../../examples/demo-company/piship.yaml", import.meta.url),
);
const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

describe("config explain for MCP plain HTTP and identity headers", () => {
  it("shows the transport and header names, and nothing for other servers", async () => {
    const lock = resolveLock(DEMO);
    const manifest = lock.governance?.manifest as GovernanceManifest;
    const docs = manifest.mcp.servers[0];
    if (!docs) throw new Error("the demo declares an MCP server");
    const governance: GovernanceManifest = {
      ...manifest,
      mcp: {
        ...manifest.mcp,
        servers: [
          docs,
          {
            ...docs,
            id: "tickets",
            transport: "streamable-http",
            url: "http://10.20.30.40/mcp",
            httpTransport: "http-allowed",
            headers: {
              "X-Company-User": { identityClaim: "preferred_username" },
            },
          },
        ],
      },
    };
    const stateDir = mkdtempSync(join(tmpdir(), "piship-mcp-explain-"));
    roots.push(stateDir);
    const rows = await explainConfiguration({
      app: lock.app as never,
      mode: "managed",
      access: lock.access,
      stateDir,
      distributionDir: stateDir,
      schema: lock.manifest.schema,
      governance,
    });
    const mcpRows = rows.filter((row) => row.key.startsWith("mcp.servers."));
    expect(mcpRows).toEqual([
      expect.objectContaining({
        key: "mcp.servers.tickets.httpTransport",
        value: "http-allowed",
        note: expect.stringContaining("unencrypted"),
      }),
      expect.objectContaining({
        key: "mcp.servers.tickets.headers",
        value: ["X-Company-User: preferred_username"],
      }),
    ]);
  });
});
