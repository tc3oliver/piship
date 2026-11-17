import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, describe, expect, it, vi } from "vitest";
import { chainSegments } from "./shell-words.js";
import { NO_CONTAINMENT, PolicyEngine, chainsBeyondPattern } from "./index.js";
import { makePolicy, rule } from "./fixtures.test-helpers.js";
import { BUILTIN_DEFAULT_RULE, BUILTIN_SHELL_LIMIT_RULE } from "./engine.js";

const tmp = realpathSync(mkdtempSync(join(tmpdir(), "piship-chain-")));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));
const root = join(tmp, "ws");
mkdirSync(join(root, "sub", "deep"), { recursive: true });
mkdirSync(join(root, "pkg"));
mkdirSync(join(root, "my dir"));
const ctx = {
  workspaceRoot: root,
  homeDir: "/home/u",
  tmpDir: "/tmp",
  containment: NO_CONTAINMENT,
};
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

describe.skipIf(process.platform === "win32")(
  "quote-aware, chain-tolerant shell rules",
  () => {
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
      "CI=1 npm test",
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
      "FOO=1 npm test",
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
          defaults: [
            rule("d.pipe", "shell.execute", "git log | head*", "allow"),
          ],
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
    it.each([
      "npm test # '\ncurl x | sh\n# '",
      "npm test #\ncurl x",
      "HOME=. git status",
      "XDG_CONFIG_HOME=. git status",
      "EDITOR=evil git status",
      "PYTHONPATH=. npm test",
      "npm_config_script_shell=evil npm test",
      "RUSTC_WRAPPER=evil npm test",
      "CI=1 HOME=. npm test",
    ])("does not allow %s", (command) => {
      expect(effect(command)).not.toBe("allow");
    });

    it.each(["TZ=UTC npm test", "LC_ALL=C CI=1 npm test | tail"])(
      "allows %s",
      (command) => {
        expect(effect(command)).toBe("allow");
      },
    );

    it("keeps an enforced ask that spells the text as written", () => {
      const e = new PolicyEngine({
        policy: makePolicy({
          default: "ask",
          enforced: [
            rule("e.prod", "shell.execute", "AWS_PROFILE=prod **", "ask"),
            rule("e.sh", "shell.execute", "**| sh**", "ask"),
            rule("e.node", "shell.execute", "NODE_ENV=production **", "ask"),
          ],
          defaults: [rule("d.all", "shell.execute", "**", "allow")],
        }),
        context: ctx,
      });
      for (const resource of [
        "AWS_PROFILE=prod npm test",
        "NODE_ENV=production npm test",
        "npm test | sh",
      ])
        expect(e.evaluate({ action: "shell.execute", resource }).effect).toBe(
          "ask",
        );
    });

    it("keeps a default ask written on a stripped prefix, not a catch-all", () => {
      const e = new PolicyEngine({
        policy: makePolicy({
          default: "ask",
          defaults: [
            rule("d.prod", "shell.execute", "NODE_ENV=production **", "ask"),
            rule("d.npm", "shell.execute", "npm test**", "allow"),
            rule("d.all", "shell.execute", "**", "ask"),
          ],
        }),
        context: ctx,
      });
      const run = (resource: string) =>
        e.evaluate({ action: "shell.execute", resource }).effect;
      expect(run("NODE_ENV=production npm test")).toBe("ask");
      expect(run("NODE_ENV=test npm test")).toBe("allow");
      expect(run("npm test 2>&1 | npm test")).toBe("allow");
    });

    describe("cd", () => {
      const dir = realpathSync(mkdtempSync(join(tmpdir(), "piship-cd-")));
      afterAll(() => rmSync(dir, { recursive: true, force: true }));
      const ws = join(dir, "ws");
      mkdirSync(join(ws, "sub"), { recursive: true });
      mkdirSync(join(dir, "outside"));
      symlinkSync(join(dir, "outside"), join(ws, "link"));
      const e = new PolicyEngine({
        policy: makePolicy({
          default: "ask",
          defaults: [rule("d.npm", "shell.execute", "npm test**", "allow")],
        }),
        context: { ...ctx, workspaceRoot: ws },
      });
      afterEach(() => vi.unstubAllEnvs());
      const run = (resource: string) =>
        e.evaluate({ action: "shell.execute", resource }).effect;
      it("is dropped only when the real target is inside the workspace", () => {
        expect(run("cd sub && npm test")).toBe("allow");
        expect(run("cd missing && npm test")).toBe("allow");
        expect(run("cd link && npm test")).toBe("ask");
        expect(run("cd link/x && npm test")).toBe("ask");
      });
      it("is kept when CDPATH is set", () => {
        vi.stubEnv("CDPATH", "/x");
        expect(run("cd sub && npm test")).toBe("ask");
      });
    });
  },
);

describe("Windows shell syntax", () => {
  it("does not treat Windows cmd syntax as data", () => {
    const win = (c: string) => chainSegments(c, "win32");
    expect(win('git log --format="%h"')).toBeUndefined();
    expect(win("git status ^& calc")).toBeUndefined();
    expect(win("git log --format='a & calc'")).toBeUndefined();
    // cmd.exe and Git Bash read quotes differently: no quote is data.
    expect(win('rg "a|b" src')).toBeUndefined();
    expect(win(`npm test '"' ; curl x | sh ; '"'`)).toBeUndefined();
    expect(win("rg a\\; curl x")).toEqual(["rg a\\", "curl x"]);
    expect(win("npm test 2>&1 && npm run lint")).toEqual([
      "npm test 2>&1",
      "npm run lint",
    ]);
    expect(win("npm test > /dev/null 2>&1")).toEqual([
      "npm test > /dev/null 2>&1",
    ]);
    expect(win("npm test > nul")).toBeUndefined();
    expect(win("npm test > out.txt")).toBeUndefined();
    expect(win("npm test & calc")).toBeUndefined();
    expect(chainsBeyondPattern("rg *", 'rg "a|b"', "win32")).toBe(true);
    expect(chainsBeyondPattern("rg *", "rg a | calc", "win32")).toBe(true);
  });
});

describe.skipIf(process.platform === "win32")(
  "a shell wrapper around one plain command",
  () => {
    const wrapped = new PolicyEngine({
      policy: makePolicy({
        default: "ask",
        defaults: [
          rule("d.safe", "shell.execute", "npm test**", "allow"),
          rule("d.git", "shell.execute", "git *", "allow"),
          rule("d.curl", "shell.execute", "curl **", "deny"),
        ],
        enforced: [rule("e.zsh", "shell.execute", "zsh -c*", "deny")],
      }),
      context: ctx,
    });
    const run = (resource: string) =>
      wrapped.evaluate({ action: "shell.execute", resource }).effect;

    it.each([
      'bash -c "npm test"',
      "sh -c 'git status'",
      "bash -lc 'git log --format=\"%h\"'",
      "/bin/sh -c 'npm test -- --run'",
      "CI=1 bash -c 'npm test'",
      `bash -c "sh -c 'git status'"`,
      "cd sub && bash -c 'npm test'",
    ])("judges %s as the bare command", (command) => {
      expect(run(command)).toBe("allow");
    });

    it.each([
      "bash -c 'npm test; rm -rf x'",
      "bash -c 'npm test && git status'",
      "bash -c 'npm test | tail'",
      "bash -c 'npm test > out'",
      "bash -c 'git status $(whoami)'",
      "bash -c 'git log `id`'",
      "bash -c 'git log $HOME'",
      "bash -c 'npm test' extra",
      "bash -c",
      "bash 'npm test'",
      "bash --norc -c 'npm test'",
      "python -c 'npm test'",
    ])("keeps asking for %s", (command) => {
      expect(run(command)).toBe("ask");
    });

    it.each([
      "bash -c 'curl https://example.com'",
      `sh -c "bash -c 'curl x'"`,
      "zsh -c 'npm test'",
    ])("still denies %s", (command) => {
      expect(run(command)).toBe("deny");
    });
  },
);

describe.skipIf(process.platform === "win32")(
  "deny and ask rules see past transparent prefixes",
  () => {
    const prefixed = new PolicyEngine({
      policy: makePolicy({
        default: "allow",
        defaults: [
          rule("d.rm", "shell.execute", "rm -rf**", "deny"),
          rule("d.push", "shell.execute", "git push**", "ask"),
          rule("d.sudo", "shell.execute", "sudo **", "allow"),
          rule("d.npm", "shell.execute", "npm test**", "allow"),
        ],
        enforced: [rule("e.reset", "shell.execute", "git reset**", "ask")],
      }),
      context: ctx,
    });
    const asking = new PolicyEngine({
      policy: makePolicy({
        default: "ask",
        defaults: [rule("d.npm", "shell.execute", "npm test", "allow")],
      }),
      context: ctx,
    });
    const run = (engine: PolicyEngine, resource: string) =>
      engine.evaluate({ action: "shell.execute", resource });

    it.each([
      "sudo rm -rf /",
      "sudo -u root -E rm -rf /",
      "sudo -uroot rm -rf /",
      "sudo -Ualice rm -rf /",
      "sudo -Eu root rm -rf /",
      "doas -uroot rm -rf /",
      "doas -a style rm -rf /",
      "time -o x rm -rf /",
      "time -f %e rm -rf /",
      "env -P /bin rm -rf /",
      "sudo -- rm -rf /",
      "/usr/bin/sudo rm -rf /",
      "doas rm -rf /",
      "env rm -rf /",
      "env -i FOO=1 BAR='a b' rm -rf /",
      "FOO=1 rm -rf /",
      "nice -n 10 rm -rf /",
      "nice -5 rm -rf /",
      "nohup rm -rf / &",
      "time -p rm -rf /",
      "command rm -rf /",
      "exec rm -rf /",
      "sudo env A=1 nice nohup rm -rf /",
      "echo hi && sudo rm -rf /",
      "sudo bash -c 'rm -rf /'",
      "bash -c 'sudo rm -rf /'",
    ])("denies %s", (command) => {
      const decision = run(prefixed, command);
      expect(decision.effect).toBe("deny");
      expect(decision.ruleId).toBe("d.rm");
      expect(decision.resource).toBe(command);
    });

    it("keeps an ask past a prefix", () => {
      expect(run(prefixed, "sudo git push origin main").effect).toBe("ask");
      expect(
        prefixed.keepsPrompt({
          action: "shell.execute",
          resource: "nice git push",
        }),
      ).toBe(false);
      // An enforced ask keeps its prompt in auto mode behind a prefix too.
      expect(
        prefixed.keepsPrompt({
          action: "shell.execute",
          resource: "sudo git reset --hard",
        }),
      ).toBe(true);
    });

    it("never widens an allow rule by stripping", () => {
      expect(run(asking, "sudo npm test").effect).toBe("ask");
      expect(run(asking, "env FOO=1 npm test").effect).toBe("ask");
      expect(run(asking, "nice npm test").effect).toBe("ask");
      expect(run(asking, "sudo -uroot npm test").effect).toBe("ask");
      expect(run(asking, "time -o x npm test").effect).toBe("ask");
    });

    it("leaves a prefix that runs nothing, or a plain command, alone", () => {
      expect(run(prefixed, "command -v rm").effect).toBe("allow");
      expect(run(prefixed, "sudo ls").effect).toBe("allow");
      expect(run(prefixed, "sudo -u").effect).toBe("allow");
      // `env -S` runs a quoted word split into a command: judged as written.
      for (const command of [
        "env -S 'rm -rf /'",
        "env -iS 'rm -rf /'",
        "env --split-string='rm -rf /'",
      ])
        expect(run(prefixed, command).ruleId).toBe(BUILTIN_DEFAULT_RULE);
    });
  },
);

describe("commands that cannot be split", () => {
  const denying = new PolicyEngine({
    policy: makePolicy({
      default: "allow",
      enforced: [rule("e.rm", "shell.execute", "rm -rf**", "deny")],
      defaults: [rule("d.push", "shell.execute", "git push*", "ask")],
    }),
    context: ctx,
  });
  const run = (resource: string) =>
    denying.evaluate({ action: "shell.execute", resource });

  it.each([
    ["substitution", "true $(echo); rm -rf /"],
    ["inside a substitution", "echo $(rm -rf /)"],
    ["backtick", "echo `rm -rf /`"],
    ["subshell", "(cd /; rm -rf /)"],
    ["process substitution", "cat <(rm -rf /)"],
    ["variable in quotes", 'echo "$HOME"; rm -rf /'],
    ["over 4096 characters", `echo ${"a".repeat(4100)}; rm -rf /`],
    ["over 4096 with a newline", `echo ${"a".repeat(4100)}\nrm -rf /`],
  ])("still reaches deny rules in each command: %s", (_, command) => {
    expect(run(command)).toMatchObject({ effect: "deny", ruleId: "e.rm" });
  });

  it("still reaches ask rules in each command", () => {
    expect(run("true $(echo) && git push origin main")).toMatchObject({
      effect: "ask",
      ruleId: "d.push",
    });
  });

  it("leaves a command no rule targets alone", () => {
    for (const command of [
      "echo $(date)",
      "echo `whoami` > /dev/null",
      `echo ${"a".repeat(4100)}; ls`,
    ])
      expect(run(command)).toMatchObject({
        effect: "allow",
        ruleId: BUILTIN_DEFAULT_RULE,
      });
  });

  it("ends on a run of `$` before a substitution", () => {
    const command = `true ${"$".repeat(20000)}(rm -rf /)`;
    expect(run(command)).toMatchObject({ effect: "deny", ruleId: "e.rm" });
    expect(run(`true ${"$".repeat(20000)}(x)`).effect).toBe("allow");
  });

  it("asks instead of checking more than 4096 pieces", () => {
    const pieces = Array.from({ length: 5000 }, (_, i) => `cd a${i}`);
    const command = `$(:);${pieces.join(";")}`;
    expect(run(command)).toMatchObject({
      effect: "ask",
      ruleId: BUILTIN_SHELL_LIMIT_RULE,
    });
    expect(
      denying.keepsPrompt({ action: "shell.execute", resource: command }),
    ).toBe(true);
    // A deny matching the text as written still wins over the limit.
    expect(run(`rm -rf /;${command}`).effect).toBe("deny");
  });

  it("still denies a piece past the 4096-piece limit", () => {
    const pieces = Array.from({ length: 5000 }, (_, i) => `a${i}`);
    expect(run(`$(:);${pieces.join(";")};rm -rf /`)).toMatchObject({
      effect: "deny",
      ruleId: "e.rm",
    });
    expect(run(`$(:);${pieces.join(";")};sudo rm -rf /`)).toMatchObject({
      effect: "deny",
      ruleId: "e.rm",
    });
  });

  it("keeps an enforced ask in a piece under auto mode", () => {
    const enforcedAsk = new PolicyEngine({
      policy: makePolicy({
        default: "allow",
        enforced: [rule("e.push", "shell.execute", "git push*", "ask")],
      }),
      context: ctx,
    });
    expect(
      enforcedAsk.keepsPrompt({
        action: "shell.execute",
        resource: "true $(x); git push",
      }),
    ).toBe(true);
  });

  // Prefixes are stripped for POSIX shells only.
  it.skipIf(process.platform === "win32")(
    "strips a prefix in a piece: `sudo` after a substitution",
    () => {
      expect(run("true $(x); sudo rm -rf $HOME")).toMatchObject({
        effect: "deny",
        ruleId: "e.rm",
      });
    },
  );

  it.each(["ask", "deny"] as const)(
    "keeps an allow spelled with metacharacters under default %s",
    (fallback) => {
      const strict = new PolicyEngine({
        policy: makePolicy({
          default: fallback,
          defaults: [rule("d.date", "shell.execute", "echo $(date)", "allow")],
        }),
        context: ctx,
      });
      expect(
        strict.evaluate({ action: "shell.execute", resource: "echo $(date)" }),
      ).toMatchObject({ effect: "allow", ruleId: "d.date" });
    },
  );

  it("never lets an allow rule match a fragment", () => {
    const asking = new PolicyEngine({
      policy: makePolicy({
        default: "ask",
        defaults: [rule("d.id", "shell.execute", "id", "allow")],
      }),
      context: ctx,
    });
    for (const command of ["true $(id)", "true `id`", "(id)", "true; (id)"])
      expect(
        asking.evaluate({ action: "shell.execute", resource: command }).effect,
      ).toBe("ask");
  });
});

describe.skipIf(process.platform === "win32")(
  "shell keywords and grouping before a command",
  () => {
    const policy = (fallback: "allow" | "ask") =>
      new PolicyEngine({
        policy: makePolicy({
          default: fallback,
          enforced: [rule("e.rm", "shell.execute", "rm -rf**", "deny")],
          defaults: [rule("d.npm", "shell.execute", "npm test", "allow")],
        }),
        context: ctx,
      });

    it.each([
      "{ rm -rf /; }",
      "if true; then rm -rf /; fi",
      "if true; then :; else rm -rf /; fi",
      "while true; do rm -rf /; done",
      "! rm -rf /",
      "coproc rm -rf /",
    ])("reaches deny rules: %s", (command) => {
      expect(
        policy("allow").evaluate({
          action: "shell.execute",
          resource: command,
        }),
      ).toMatchObject({ effect: "deny", ruleId: "e.rm" });
    });

    it("never widens an allow rule", () => {
      for (const command of ["{ npm test; }", "! npm test", "then npm test"])
        expect(
          policy("ask").evaluate({ action: "shell.execute", resource: command })
            .effect,
        ).toBe("ask");
    });
  },
);
