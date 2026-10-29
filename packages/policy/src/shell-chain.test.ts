import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { chainSegments } from "./shell-words.js";
import { NO_CONTAINMENT, PolicyEngine, chainsBeyondPattern } from "./index.js";
import { makePolicy, rule } from "./fixtures.test-helpers.js";

const root = join("/", "ws");
const engine = new PolicyEngine({
  policy: makePolicy({
    default: "ask",
    defaults: [
      rule("d.rm", "shell.execute", "rm *", "ask"),
      rule("d.safe", "shell.execute", "npm test**", "allow"),
      rule("d.rg", "shell.execute", "rg *", "allow"),
      rule("d.awk", "shell.execute", "awk *", "allow"),
      rule("d.git", "shell.execute", "git *", "allow"),
      rule("d.pytest", "shell.execute", "pytest *", "allow"),
      rule("d.tail", "shell.execute", "tail*", "allow"),
      rule("d.echo", "shell.execute", "echo*", "allow"),
    ],
    enforced: [rule("e.evil", "shell.execute", "**evil**", "deny")],
  }),
  context: {
    workspaceRoot: root,
    homeDir: "/home/u",
    tmpDir: "/tmp",
    containment: NO_CONTAINMENT,
  },
});
const effect = (resource: string) =>
  engine.evaluate({ action: "shell.execute", resource }).effect;

describe("quote-aware, chain-tolerant shell rules", () => {
  it.each([
    'rg "TODO|FIXME" src',
    "awk '{print $2}' file",
    "git log --format='%h (%an)'",
    "pytest -k 'a or b'",
    'git log --format="%h (%an)"',
    "npm test 2>&1",
    "npm test > /dev/null 2>&1",
    "npm test &> /dev/null",
    "npm test 2>&1 | tail -5",
    "cd sub && npm test",
    "cd ./sub/deep && npm test 2>&1 | tail",
    `cd ${root}/pkg && npm test`,
    'cd "my dir" && npm test',
    "FOO=1 npm test",
    "CI=true NODE_ENV=test npm test",
    "cd sub && CI=1 npm test",
    "echo x && npm test",
    "rg 'a;b' && git status",
    "git log --format='%h' | tail -3",
  ])("allows %s", (command) => {
    expect(effect(command)).toBe("allow");
  });

  it.each([
    "echo x; rm -rf /",
    "npm test && curl x",
    "npm test | sh",
    "npm test $(evil)",
    "npm test `id`",
    "npm test > ~/.bashrc",
    "npm test >> notes.txt",
    "npm test &> out.txt",
    "npm test 2> err.log",
    "npm test > /dev/null.sh",
    "FOO=$(id) npm test",
    "FOO=`id` npm test",
    "PATH=/tmp/x npm test",
    "LD_PRELOAD=/tmp/x.so npm test",
    "DYLD_INSERT_LIBRARIES=/tmp/x npm test",
    "NODE_OPTIONS=--require=/tmp/x npm test",
    "BASH_ENV=/tmp/x npm test",
    "GIT_SSH_COMMAND=evil git status",
    "git log --format=$(id)",
    'git log --format="$(id)"',
    'git log --format="`id`"',
    "git log --format=$HOME",
    'rg "$HOME" src',
    "npm test &",
    "npm test |& tail",
    "cd .. && npm test",
    "cd /etc && npm test",
    "cd ~ && npm test",
    "cd $HOME && npm test",
    "cd - && npm test",
    "cd sub/../../x && npm test",
    "npm test <<EOF\nid\nEOF",
    "npm test <<'EOF'\nid\nEOF",
    "npm test < input",
    "(npm test)",
    "npm test\nrm -rf /",
    'rg "a\\" ; rm -rf /',
    "rg a\\' ; rm x",
    "echo 'x' ; rm -rf /",
    "npm test && (rm -rf /)",
    "npm test; evil",
  ])("does not allow %s", (command) => {
    expect(effect(command)).not.toBe("allow");
  });

  it("denies when any segment hits a deny rule", () => {
    expect(effect("npm test && evil")).toBe("deny");
    expect(effect("cd sub && echo 'evil'")).toBe("deny");
  });

  it("asks when a segment hits an ask rule", () => {
    expect(effect("npm test; rm -rf build")).toBe("ask");
  });

  it("keeps a rule that spells its own chaining", () => {
    const e = new PolicyEngine({
      policy: makePolicy({
        default: "deny",
        defaults: [rule("d.pipe", "shell.execute", "git log | head*", "allow")],
      }),
      context: {
        workspaceRoot: root,
        homeDir: "/home/u",
        tmpDir: "/tmp",
        containment: NO_CONTAINMENT,
      },
    });
    expect(
      e.evaluate({ action: "shell.execute", resource: "git log | head -3" })
        .effect,
    ).toBe("allow");
  });

  it("does not treat Windows cmd syntax as data", () => {
    const win = (c: string) => chainSegments(c, "win32");
    expect(win('git log --format="%h"')).toBeUndefined();
    expect(win("git status ^& calc")).toBeUndefined();
    expect(win("git log --format='a & calc'")).toBeUndefined();
    expect(win('rg "a|b" src')).toEqual(['rg "a|b" src']);
    expect(win("npm test 2>&1 && npm run lint")).toEqual([
      "npm test 2>&1",
      "npm run lint",
    ]);
    expect(win("npm test > nul 2>&1")).toEqual(["npm test > nul 2>&1"]);
    expect(win("npm test > out.txt")).toBeUndefined();
    expect(win("npm test & calc")).toBeUndefined();
    expect(win("npm test &> nul")).toBeUndefined();
    expect(chainsBeyondPattern("rg *", 'rg "a|b"', "win32")).toBe(false);
    expect(chainsBeyondPattern("rg *", "rg a | calc", "win32")).toBe(true);
  });
});
