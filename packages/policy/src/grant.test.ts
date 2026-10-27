import { describe, expect, it } from "vitest";
import {
  type GrantAsk,
  type GrantLimits,
  grantCovers,
  type TaskGrant,
  validateGrant,
} from "./grant.js";

const NOW = Date.parse("2026-10-26T12:00:00Z");
const FUTURE = "2026-10-26T13:00:00Z";

const grant = (scope: TaskGrant["scope"], expiresAt = FUTURE): TaskGrant => ({
  id: "g1",
  task: "t",
  createdBy: "user-command",
  expiresAt,
  scope,
  inheritToSubagents: false,
});
const ask = (over: Partial<GrantAsk> & { resource: string }): GrantAsk => ({
  action: "filesystem.write",
  resolvedResource: over.resource,
  keepsPrompt: false,
  effect: "ask",
  ...over,
});
const bare = (resource: string): GrantAsk => ({
  action: "filesystem.write",
  resource,
  keepsPrompt: false,
  effect: "ask",
});
const covers = (
  g: TaskGrant,
  asks: GrantAsk[],
  p: "posix" | "win32" = "posix",
) => grantCovers(g, asks, NOW, p);

describe("grantCovers", () => {
  const paths = grant({ paths: ["/a/b"] });

  it("covers a path inside the root, with trailing slashes", () => {
    expect(covers(paths, [ask({ resource: "/a/b" })])).toBe(true);
    expect(covers(paths, [ask({ resource: "/a/b/c/d.txt" })])).toBe(true);
    expect(
      covers(grant({ paths: ["/a/b/"] }), [ask({ resource: "/a/b/c" })]),
    ).toBe(true);
  });

  it("does not cover a sibling sharing a prefix", () => {
    expect(covers(paths, [ask({ resource: "/a/bc" })])).toBe(false);
  });

  it("takes the lexical form under an alias of a root, the resolved form only under the root", () => {
    const aliased = {
      ...grant({ paths: ["/private/var/w"] }),
      pathAliases: ["/var/w"],
    };
    expect(
      covers(aliased, [
        ask({
          resource: "/var/w/a.ts",
          resolvedResource: "/private/var/w/a.ts",
        }),
      ]),
    ).toBe(true);
    // The alias never stands for the resolved form.
    expect(
      covers(aliased, [
        ask({ resource: "/var/w/a.ts", resolvedResource: "/var/w/a.ts" }),
      ]),
    ).toBe(false);
    expect(
      covers(aliased, [
        ask({
          resource: "/var/other/a.ts",
          resolvedResource: "/private/var/w/a.ts",
        }),
      ]),
    ).toBe(false);
    expect(
      covers(grant({ paths: ["/private/var/w"] }), [
        ask({
          resource: "/var/w/a.ts",
          resolvedResource: "/private/var/w/a.ts",
        }),
      ]),
    ).toBe(false);
  });

  it("does not cover when the realpath leaves the root", () => {
    expect(
      covers(paths, [
        ask({ resource: "/a/b/link", resolvedResource: "/etc/passwd" }),
      ]),
    ).toBe(false);
    expect(
      covers(paths, [
        ask({ resource: "/a/b/link", resolvedResource: "/a/b/real" }),
      ]),
    ).toBe(true);
  });

  it("does not cover a path ask without a resolved resource", () => {
    expect(covers(paths, [bare("/a/b/c")])).toBe(false);
  });

  it("does not cover a path with .. or a relative path", () => {
    expect(covers(paths, [ask({ resource: "/a/b/x/../y" })])).toBe(false);
    expect(covers(paths, [ask({ resource: "b/c" })])).toBe(false);
  });

  it("is case sensitive on posix and insensitive on win32", () => {
    expect(covers(paths, [ask({ resource: "/A/b/c" })])).toBe(false);
    const w = grant({ paths: ["C:\\work\\proj"] });
    expect(covers(w, [ask({ resource: "C:\\work\\proj\\src" })], "win32")).toBe(
      true,
    );
    expect(covers(w, [ask({ resource: "c:\\WORK\\proj\\src" })], "win32")).toBe(
      true,
    );
    expect(covers(w, [ask({ resource: "C:\\work\\project" })], "win32")).toBe(
      false,
    );
    expect(covers(w, [ask({ resource: "D:\\work\\proj" })], "win32")).toBe(
      false,
    );
    const unc = grant({ paths: ["\\\\srv\\share\\proj"] });
    expect(
      covers(unc, [ask({ resource: "\\\\srv\\share\\proj\\a" })], "win32"),
    ).toBe(true);
    expect(
      covers(unc, [ask({ resource: "\\\\srv\\share\\proj2" })], "win32"),
    ).toBe(false);
  });

  it("never covers a deny or an allow", () => {
    expect(covers(paths, [ask({ resource: "/a/b/c", effect: "deny" })])).toBe(
      false,
    );
    expect(covers(paths, [ask({ resource: "/a/b/c", effect: "allow" })])).toBe(
      false,
    );
  });

  it("never covers an ask that keeps its prompt", () => {
    expect(
      covers(paths, [ask({ resource: "/a/b/c", keepsPrompt: true })]),
    ).toBe(false);
  });

  it("does not cover an ask with no keepsPrompt, or a .. in its realpath", () => {
    const g = grant({ tools: ["edit"] });
    const noFlag = {
      action: "tool.execute",
      resource: "edit",
      effect: "ask",
    } as unknown as GrantAsk;
    expect(covers(g, [noFlag])).toBe(false);
    expect(
      covers(paths, [
        ask({ resource: "/a/b/c", resolvedResource: "/a/b/x/../y" }),
      ]),
    ).toBe(false);
  });

  it("does not cover an expired or unparsable grant", () => {
    const at = new Date(NOW).toISOString();
    expect(
      covers(grant({ paths: ["/a/b"] }, at), [ask({ resource: "/a/b/c" })]),
    ).toBe(false);
    expect(
      covers(grant({ paths: ["/a/b"] }, "soon"), [ask({ resource: "/a/b/c" })]),
    ).toBe(false);
  });

  it("grants nothing for an empty or absent scope kind, or no asks", () => {
    expect(covers(grant({ paths: [] }), [ask({ resource: "/a/b" })])).toBe(
      false,
    );
    expect(
      covers(grant({}), [ask({ action: "tool.execute", resource: "x" })]),
    ).toBe(false);
    expect(covers(paths, [])).toBe(false);
  });

  it("requires every ask of a combined prompt to be inside the scope", () => {
    const g = grant({ paths: ["/a/b"], tools: ["write"] });
    const tool = ask({ action: "tool.execute", resource: "write" });
    expect(covers(g, [tool, ask({ resource: "/a/b/x" })])).toBe(true);
    expect(covers(g, [tool, ask({ resource: "/a/other" })])).toBe(false);
    expect(
      covers(g, [tool, ask({ action: "shell.execute", resource: "ls" })]),
    ).toBe(false);
  });

  it("matches tools, MCP servers/tools and hosts exactly", () => {
    const g = grant({
      tools: ["edit"],
      mcp: [{ server: "gh", tools: ["list"] }, { server: "all" }],
      hosts: ["api.x.com:443", "*.y.com"],
    });
    const a = (action: string, resource: string) => ask({ action, resource });
    expect(covers(g, [a("tool.execute", "edit")])).toBe(true);
    expect(covers(g, [a("tool.execute", "edit2")])).toBe(false);
    expect(covers(g, [a("mcp.tool.call", "gh:list")])).toBe(true);
    expect(covers(g, [a("mcp.tool.call", "gh:listAll")])).toBe(false);
    expect(covers(g, [a("mcp.tool.call", "ghx:list")])).toBe(false);
    expect(covers(g, [a("mcp.tool.call", "all:anything")])).toBe(true);
    expect(covers(g, [a("network.connect", "api.x.com:443")])).toBe(true);
    expect(covers(g, [a("network.connect", "api.x.com")])).toBe(false);
    expect(covers(g, [a("web.request", "a.y.com")])).toBe(true);
    expect(covers(g, [a("web.request", "y.com")])).toBe(false);
    expect(covers(g, [a("web.request", "evily.com")])).toBe(false);
  });

  it("compares a URL by host[:port] with default ports filled in", () => {
    const g = grant({ hosts: ["good.com", "api.x.com:8443"] });
    const web = (resource: string) => ask({ action: "web.request", resource });
    expect(covers(g, [web("https://good.com/a?b=1")])).toBe(true);
    expect(covers(g, [web("http://GOOD.com:80/")])).toBe(true);
    expect(covers(g, [web("https://good.com:443/")])).toBe(true);
    expect(covers(g, [web("https://good.com:8443/")])).toBe(false);
    expect(covers(g, [web("https://api.x.com:8443/p")])).toBe(true);
    expect(covers(g, [web("https://api.x.com/p")])).toBe(false);
    expect(covers(g, [web("good.com")])).toBe(true);
    const gp = grant({ hosts: ["good.com:443"] });
    expect(covers(gp, [web("https://good.com/")])).toBe(true);
    expect(covers(gp, [web("http://good.com/")])).toBe(false);
  });

  it("does not cover URL host tricks", () => {
    const g = grant({ hosts: ["good.com"] });
    const web = (resource: string) => ask({ action: "web.request", resource });
    expect(covers(g, [web("https://good.com@evil.com/")])).toBe(false);
    expect(covers(g, [web("https://user:pw@good.com/")])).toBe(false);
    expect(covers(g, [web("https://evil.com/good.com")])).toBe(false);
    expect(covers(g, [web("https://good.com.evil.com/")])).toBe(false);
    expect(covers(g, [web("evil.com@good.com")])).toBe(false);
    expect(covers(g, [web("https://")])).toBe(false);
  });

  it("does not let a wildcard host match a path, query or fragment trick", () => {
    const g = grant({ hosts: ["*.y.com"] });
    const web = (resource: string) => ask({ action: "web.request", resource });
    for (const r of [
      "evil.com/x.y.com",
      "evil.com?.y.com",
      "evil.com#.y.com",
      "x.y.com.",
    ])
      expect(covers(g, [web(r)])).toBe(false);
    expect(covers(g, [web("X.Y.com")])).toBe(true);
  });

  it("a wildcard covers only default ports unless the pattern names one", () => {
    const g = grant({ hosts: ["*.y.com"] });
    const web = (resource: string) => ask({ action: "web.request", resource });
    expect(covers(g, [web("https://x.y.com/")])).toBe(true);
    expect(covers(g, [web("x.y.com:443")])).toBe(true);
    expect(covers(g, [web("x.y.com:22")])).toBe(false);
    expect(covers(g, [web("https://x.y.com:8080/")])).toBe(false);
    const p = grant({ hosts: ["*.y.com:8080"] });
    expect(covers(p, [web("https://x.y.com:8080/")])).toBe(true);
    expect(covers(p, [web("https://x.y.com/")])).toBe(false);
  });

  it("covers only http(s)/ws(s) URLs unless a port is explicit", () => {
    const web = (resource: string) => ask({ action: "web.request", resource });
    for (const g of [
      grant({ hosts: ["*.y.com"] }),
      grant({ hosts: ["x.y.com"] }),
    ])
      for (const r of [
        "ftp://x.y.com:21/",
        "ssh://x.y.com",
        "redis://x.y.com",
        "x.y.com:22",
      ])
        expect(covers(g, [web(r)])).toBe(false);
    const g = grant({ hosts: ["x.y.com", "z.y.com:8080"] });
    expect(covers(g, [web("ws://x.y.com/")])).toBe(true);
    expect(covers(g, [web("wss://x.y.com/")])).toBe(true);
    expect(covers(g, [web("http://z.y.com:8080/")])).toBe(true);
    expect(covers(g, [web("http://z.y.com:9090/")])).toBe(false);
  });

  it("does not fold non-ASCII look-alikes into a bare host", () => {
    const g = grant({ hosts: ["k.com"] });
    expect(
      covers(g, [ask({ action: "web.request", resource: "\u212A.com" })]),
    ).toBe(false);
  });

  it("git is a stub that never covers", () => {
    const g = grant({ git: [{ remote: "origin", branches: ["feat"] }] });
    expect(
      covers(g, [ask({ action: "git.push", resource: "origin/feat" })]),
    ).toBe(false);
  });
});

describe("validateGrant", () => {
  const limits: GrantLimits = {
    now: NOW,
    maxTtlMs: 2 * 3600_000,
    forbiddenRoots: [
      { path: "/home/u", mode: "self-and-above" },
      { path: "/home/u/.state", mode: "subtree" },
    ],
    wildcardHosts: false,
    platform: "posix",
  };
  const errs = (scope: TaskGrant["scope"], expiresAt = FUTURE, l = limits) =>
    validateGrant(grant(scope, expiresAt), l);

  it("accepts a sane grant", () => {
    expect(errs({ paths: ["/work/proj"], hosts: ["a.com"] })).toEqual([]);
  });

  it("allows inheritance only for manifest-sourced grants", () => {
    const ordinary = grant({ paths: ["/work/proj"] });
    expect(
      validateGrant({ ...ordinary, inheritToSubagents: true }, limits),
    ).toContain("only manifest grants may be inherited by subagents");
    expect(
      validateGrant(
        { ...ordinary, createdBy: "manifest", inheritToSubagents: true },
        limits,
      ),
    ).toEqual([]);
    expect(
      validateGrant(
        { ...ordinary, createdBy: "untrusted" } as unknown as TaskGrant,
        limits,
      ),
    ).toContain("grant source is invalid");
    expect(
      validateGrant(
        { ...ordinary, inheritToSubagents: "yes" } as unknown as TaskGrant,
        limits,
      ),
    ).toContain("grant inheritance flag must be boolean");
  });

  it.each([
    ["/"],
    ["/home/u"],
    ["/home"],
    ["/home/u/.state"],
    ["/home/u/.state/sub"],
    ["rel/dir"],
    ["/a/../b"],
    ["/a/*"],
    ["/a/b?"],
    ["/a/[x]"],
    ["/a/{b,c}"],
  ])("refuses path root %s", (root) => {
    expect(errs({ paths: [root] })).not.toEqual([]);
  });

  it("allows a project below home but not below the state dir", () => {
    expect(errs({ paths: ["/home/u/proj"] })).toEqual([]);
    expect(errs({ paths: ["/home/u/.states"] })).toEqual([]);
  });

  it("refuses a windows drive root", () => {
    expect(
      errs({ paths: ["C:\\"] }, FUTURE, { ...limits, platform: "win32" }),
    ).not.toEqual([]);
  });

  it("refuses a windows share root, short names and trailing dots", () => {
    const w = { ...limits, platform: "win32" as const };
    expect(errs({ paths: ["\\\\srv\\share"] }, FUTURE, w)).not.toEqual([]);
    expect(errs({ paths: ["\\\\srv\\share\\proj"] }, FUTURE, w)).toEqual([]);
    expect(errs({ paths: ["C:\\Users\\OLIVER~1"] }, FUTURE, w)).not.toEqual([]);
    const home = {
      ...w,
      forbiddenRoots: [
        { path: "C:\\Users\\oliver", mode: "self-and-above" as const },
      ],
    };
    expect(errs({ paths: ["C:\\Users\\oliver."] }, FUTURE, home)).not.toEqual(
      [],
    );
    expect(errs({ paths: ["C:\\Users"] }, FUTURE, home)).not.toEqual([]);
    for (const r of [
      "\\\\?\\C:\\Users\\x",
      "\\\\.\\C:\\Users\\x",
      "\\Users\\x",
    ])
      expect(errs({ paths: [r] }, FUTURE, home)).not.toEqual([]);
  });

  it("refuses missing, past and over-cap expiry", () => {
    expect(errs({}, "")).not.toEqual([]);
    expect(errs({}, "2026-10-26T11:00:00Z")).not.toEqual([]);
    expect(errs({}, "2026-10-26T15:00:00Z")).not.toEqual([]);
  });

  it("refuses wildcard hosts unless allowed", () => {
    expect(errs({ hosts: ["*.x.com"] })).not.toEqual([]);
    expect(
      errs({ hosts: ["*.x.com"] }, FUTURE, { ...limits, wildcardHosts: true }),
    ).toEqual([]);
    const wild = { ...limits, wildcardHosts: true };
    for (const h of ["*.0.0.1", "*.com", "*.", "*..com", "*.x.com:8080x"])
      expect(errs({ hosts: [h] }, FUTURE, wild)).not.toEqual([]);
    expect(errs({ hosts: ["*.x.com:8080"] }, FUTURE, wild)).toEqual([]);
    expect(
      errs({ hosts: ["x.*"] }, FUTURE, { ...limits, wildcardHosts: true }),
    ).not.toEqual([]);
  });

  it("refuses default branches", () => {
    const git = (b: string) => ({ git: [{ remote: "origin", branches: [b] }] });
    expect(errs(git("main"))).not.toEqual([]);
    expect(errs(git("master"))).not.toEqual([]);
    expect(
      errs(git("trunk"), FUTURE, { ...limits, defaultBranch: "trunk" }),
    ).not.toEqual([]);
    expect(errs(git("feat/x"))).toEqual([]);
  });

  it("refuses globs in tool names and server ids", () => {
    expect(errs({ tools: ["ed*"] })).not.toEqual([]);
    expect(errs({ mcp: [{ server: "a:b" }] })).not.toEqual([]);
  });

  it("refuses a scope whose shape is not the declared one", () => {
    const loose = (scope: unknown) => errs(scope as TaskGrant["scope"]);
    expect(loose({ tools: "bashread" })).not.toEqual([]);
    expect(loose({ paths: "/work/proj" })).not.toEqual([]);
    expect(loose({ hosts: [1] })).not.toEqual([]);
    expect(loose({ mcp: [{ server: "s", tools: "t" }] })).not.toEqual([]);
    expect(loose({ git: [{ remote: "o", branches: "feat" }] })).not.toEqual([]);
    expect(loose({ shell: ["rm"] })).toEqual(["unknown scope kind: shell"]);
    expect(loose(null)).toEqual(["scope is not an object"]);
    expect(
      validateGrant(
        { ...grant({ tools: ["t"] }), id: undefined } as unknown as TaskGrant,
        limits,
      ),
    ).toEqual(["grant id is missing"]);
    expect(
      validateGrant(
        { ...grant({ paths: ["/work/proj"] }), pathAliases: ["/home/u"] },
        limits,
      ),
    ).not.toEqual([]);
    expect(
      validateGrant(
        {
          ...grant({ paths: ["/work/proj"] }),
          pathAliases: "/w",
        } as unknown as TaskGrant,
        limits,
      ),
    ).not.toEqual([]);
  });
});

describe("grantCovers with a scope of the wrong shape", () => {
  it("covers nothing through a string where a list belongs", () => {
    const loose = (scope: unknown) => grant(scope as TaskGrant["scope"]);
    // `"bashread".includes("bash")` would match; a list compares exactly.
    expect(
      covers(loose({ tools: "bashread" }), [
        ask({ action: "tool.execute", resource: "bash" }),
      ]),
    ).toBe(false);
    expect(
      covers(loose({ mcp: [{ server: "s", tools: "search-all" }] }), [
        ask({ action: "mcp.tool.call", resource: "s:search" }),
      ]),
    ).toBe(false);
  });
});

describe("a command scope", () => {
  const errs = (scope: TaskGrant["scope"]) =>
    validateGrant(grant(scope), {
      now: NOW,
      maxTtlMs: 2 * 3600_000,
      forbiddenRoots: [],
      wildcardHosts: false,
      platform: "posix",
    });
  const shell = grant({ commands: ["npm", "pytest", "git"] });
  const run = (command: string) =>
    covers(shell, [ask({ action: "shell.execute", resource: command })]);

  it("covers one plain command that starts with a granted program", () => {
    expect(run("npm test")).toBe(true);
    expect(run("pytest -q")).toBe(true);
    expect(run("  git status --short")).toBe(true);
    expect(run("git diff 'src/a b.ts'")).toBe(true);
    expect(run("npm\ttest")).toBe(true);
    // Arguments may be globs; only the program must be spelled out.
    expect(run("pytest tests/test_*.py")).toBe(true);
    expect(run("pytest *")).toBe(true);
    // Only a space or tab separates words; another blank keeps one word.
    expect(run("npm\u00a0test")).toBe(false);
  });

  it.each([
    "npm test && curl x",
    "npm test; rm -rf ~",
    "npm test | sh",
    "npm test > ../x",
    "npm test $(curl x)",
    "npm test `id`",
    "npm test $HOME",
    "npm run 'a;b'",
    "npm test\ncurl x",
    "(npm test)",
    "bash x.sh",
    "env FOO=1 npm test",
    "FOO=1 npm test",
    "NPM test",
    "./npm test",
    "git push origin feat",
    "git push",
    "git {push,origin} main",
    "git pu?h origin main",
    "git --attr-source HEAD push origin main",
    "n?m test",
    "{git,x} status",
  ])("does not cover %s", (command) => {
    expect(run(command)).toBe(false);
  });

  it("refuses a wrapper, a path, or a glob as a program", () => {
    for (const program of [
      "bash",
      "env",
      "sudo",
      "xargs",
      "Bash",
      "bash.exe",
      "BASH.EXE",
      "cmd.bat",
      "ash",
      "nu",
      "yash",
      "mksh",
      "/usr/bin/npm",
      "np*",
      "npm test",
    ])
      expect(errs({ commands: [program] })).not.toEqual([]);
    expect(errs({ commands: ["npm", "cargo", "go", "make"] })).toEqual([]);
  });
});

describe("a tool ask that comes with another ask", () => {
  const files = grant({ paths: ["/a/b"] });
  const tool = (over: Partial<GrantAsk> = {}): GrantAsk => ({
    action: "tool.execute",
    resource: "write",
    keepsPrompt: false,
    effect: "ask",
    companion: true,
    ...over,
  });

  it("is covered with a covered ask, never alone, and never when it keeps its prompt", () => {
    expect(covers(files, [tool(), ask({ resource: "/a/b/c" })])).toBe(true);
    expect(covers(files, [tool()])).toBe(false);
    expect(covers(files, [tool(), ask({ resource: "/elsewhere" })])).toBe(
      false,
    );
    expect(
      covers(files, [tool({ keepsPrompt: true }), ask({ resource: "/a/b/c" })]),
    ).toBe(false);
    expect(
      covers(files, [tool({ companion: false }), ask({ resource: "/a/b/c" })]),
    ).toBe(false);
  });
});
