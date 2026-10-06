// `config explain` states the precedence the policy engine applies to user
// rules in config/policy.json: narrowing only in managed mode, replacing a
// default in personal mode.
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { runConfig } from "./branded/config.js";
import type { BrandedContext } from "./branded/context.js";
import { resolveLock } from "./index.js";

const example = (name: string) =>
  fileURLToPath(
    new URL(`../../../examples/${name}/piship.yaml`, import.meta.url),
  );

let temp: string;
beforeEach(() => {
  temp = mkdtempSync(join(tmpdir(), "piship-branded-config-"));
});
afterEach(() => {
  rmSync(temp, { recursive: true, force: true });
});

async function policyNote(
  name: string,
  mode: BrandedContext["mode"],
): Promise<string> {
  const manifest = example(name);
  const out: string[] = [];
  await runConfig(
    {
      metadata: resolveLock(manifest),
      distributionDir: dirname(manifest),
      stateDir: temp,
      mode,
      out: (message) => out.push(message),
      err: () => {},
    },
    ["explain", "--json"],
  );
  const rows = JSON.parse(out.join("\n")) as { key: string; note?: string }[];
  const policy = rows.find((row) => row.key === "policy");
  expect(policy?.note).toBeDefined();
  return policy?.note as string;
}

describe("config explain policy guidance", () => {
  it("says managed user rules only narrow and never relax", async () => {
    const note = await policyNote("demo-company", "managed");
    expect(note).toContain("narrowing only");
    expect(note).toContain("may tighten a default");
    expect(note).toContain("never relax a default or an enforced rule");
    expect(note).toContain("allow rules are ignored");
    expect(note).not.toContain("may relax");
  });

  it("says personal user rules may relax a default but not an enforced rule", async () => {
    const note = await policyNote("personal", "personal");
    expect(note).toContain("take a matching default's place");
    expect(note).toContain("may relax it");
    expect(note).toContain("never override an enforced rule");
    expect(note).not.toContain("narrowing only");
  });
});

describe("config explain header and schema", () => {
  async function explain(name: string): Promise<string> {
    const manifest = example(name);
    const out: string[] = [];
    await runConfig(
      {
        metadata: resolveLock(manifest),
        distributionDir: dirname(manifest),
        stateDir: temp,
        mode: "managed",
        out: (message) => out.push(message),
        err: () => {},
      },
      ["explain"],
    );
    return out.join("\n");
  }

  it("shows the manifest's own schema, not v1alpha2 for every managed manifest", async () => {
    const text = await explain("demo-company");
    expect(text).toMatch(/^schema\s+"piship\/v1"/m);
    expect(text).not.toContain("piship/v1alpha2");
  });

  it("states precedence highest first, with user preferences above defaults", async () => {
    const header = (await explain("demo-company")).split("\n")[0];
    expect(header).toContain(
      "Distribution Enforced > User Preferences > Distribution Defaults",
    );
  });
});
