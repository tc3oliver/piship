import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { windowsNpmInvocation } from "./windows-npm.js";

const roots: string[] = [];

function npmDirectory(options: { node?: boolean; cli?: boolean } = {}) {
  const root = mkdtempSync(join(tmpdir(), "piship-npm-"));
  roots.push(root);
  writeFileSync(join(root, "npm.cmd"), "");
  if (options.cli !== false) {
    mkdirSync(join(root, "node_modules", "npm", "bin"), { recursive: true });
    writeFileSync(join(root, "node_modules", "npm", "bin", "npm-cli.js"), "");
  }
  if (options.node) writeFileSync(join(root, "node.exe"), "");
  return root;
}

afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

describe("windowsNpmInvocation", () => {
  it("runs the first npm on PATH through node with the arguments as an array", () => {
    const first = npmDirectory({ node: true });
    const second = npmDirectory({ node: true });
    const args = ["audit", '--registry=https://r.example/" & calc & "', "%X%"];
    const invocation = windowsNpmInvocation(args, {
      Path: [join(first, "missing"), first, second].join(delimiter),
    });
    expect(invocation.file).toBe(join(first, "node.exe"));
    expect(invocation.args).toEqual([
      join(first, "node_modules", "npm", "bin", "npm-cli.js"),
      ...args,
    ]);
  });

  it("uses the running node when none sits beside the shim", () => {
    const directory = npmDirectory();
    expect(windowsNpmInvocation([], { PATH: directory }).file).toBe(
      process.execPath,
    );
  });

  it("skips a shim without npm's CLI next to it", () => {
    const broken = npmDirectory({ cli: false });
    const working = npmDirectory();
    expect(
      windowsNpmInvocation(["-v"], {
        PATH: [broken, working].join(delimiter),
      }).args[0],
    ).toBe(join(working, "node_modules", "npm", "bin", "npm-cli.js"));
  });

  it("prefers the npm in npm's global prefix, as npm.cmd does", () => {
    const upgraded = npmDirectory();
    const bundled = npmDirectory();
    writeFileSync(
      join(bundled, "node_modules", "npm", "bin", "npm-prefix.js"),
      `console.log(${JSON.stringify(upgraded)})`,
    );
    expect(windowsNpmInvocation(["-v"], { PATH: bundled }).args[0]).toBe(
      join(upgraded, "node_modules", "npm", "bin", "npm-cli.js"),
    );
  });

  it("keeps the shim's own npm when the global prefix has none", () => {
    const bundled = npmDirectory();
    const empty = mkdtempSync(join(tmpdir(), "piship-npm-prefix-"));
    roots.push(empty);
    writeFileSync(
      join(bundled, "node_modules", "npm", "bin", "npm-prefix.js"),
      `console.log(${JSON.stringify(empty)})`,
    );
    expect(windowsNpmInvocation([], { PATH: bundled }).args[0]).toBe(
      join(bundled, "node_modules", "npm", "bin", "npm-cli.js"),
    );
  });

  it("reads quoted entries and ignores relative ones", () => {
    const directory = npmDirectory();
    expect(
      windowsNpmInvocation([], {
        PATH: [".", "tools", `"${directory}"`].join(delimiter),
      }).args[0],
    ).toBe(join(directory, "node_modules", "npm", "bin", "npm-cli.js"));
  });

  it("fails when PATH has no npm", () => {
    expect(() => windowsNpmInvocation([], { PATH: "" })).toThrow(
      /npm was not found on PATH/,
    );
  });
});
