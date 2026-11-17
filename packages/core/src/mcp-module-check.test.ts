import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Manifest } from "@piship/schema";
import { afterEach, describe, expect, it } from "vitest";
import { mcpModuleWarnings } from "./mcp-module-check.js";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

/** Warnings for one MCP server whose module file holds `source`. */
function check(source: string) {
  const dir = mkdtempSync(join(tmpdir(), "piship-mcp-module-"));
  roots.push(dir);
  writeFileSync(join(dir, "server.mjs"), source);
  const governance = {
    mcp: { servers: [{ id: "weather", module: "./server.mjs" }] },
  } as unknown as NonNullable<Manifest["governance"]>;
  return mcpModuleWarnings({ governance }, join(dir, "piship.yaml"));
}

describe("MCP server modules", () => {
  it("accepts a self-contained file that uses only Node built-ins", () => {
    expect(
      check(
        'import { readFileSync } from "node:fs";\nimport path from "path";\nconst os = require("os");\nawait import("node:fs/promises");\nimport "fs/promises";\n',
      ),
    ).toEqual([]);
  });

  it("warns about a sibling file or an npm package", () => {
    const [warning, ...rest] = check(
      'import { Server } from "@modelcontextprotocol/sdk/server/index.js";\nimport data from \'./data.mjs\';\nconst z = require("zod");\nconst lazy = await import("../lazy.mjs");\nexport * from "node:path";\n',
    );
    expect(rest).toEqual([]);
    expect(warning?.path).toBe("mcp.servers.weather.module");
    expect(warning?.message).toContain(
      "imports @modelcontextprotocol/sdk/server/index.js, ./data.mjs, zod, ../lazy.mjs,",
    );
    expect(warning?.message).toContain("--bundle --platform=node --format=esm");
  });
});
