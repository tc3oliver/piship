// The one PowerShell a launch's Windows credential requests go through: its
// framing and lifecycle against a stand-in process that speaks the same line
// protocol, the store's use of it, and (where a PowerShell is installed) the
// service half of the real script on top of an in-memory credential store.
import { spawn as nodeSpawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SecretValue } from "@piship/contracts";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  type CommandRunner,
  type CredentialHelper,
  createPowerShellHelper,
  createSecretStore,
  HelperUnavailable,
  helperScript,
  secretStoreUnreachable,
  WINDOWS_NATIVE,
  WindowsCredentialSecretStore,
} from "./index.js";

let temp: string;
beforeEach(() => {
  temp = mkdtempSync(join(tmpdir(), "piship-ps-helper-"));
});
afterEach(() => rmSync(temp, { recursive: true, force: true }));

/**
 * A Node program that answers the helper protocol the way the script does:
 * ready line, then one answer line per request, with an in-memory credential
 * store. Targets starting `die` end the process before answering, `slow` ones
 * never answer, `bad` ones fail, and FAKE_MODE chooses how it starts.
 */
const FAKE = `
const lines = require("node:readline").createInterface({ input: process.stdin });
const store = new Map();
const b64 = (text) => (text === "" ? "-" : Buffer.from(text, "utf8").toString("base64"));
if (process.env.FAKE_MODE === "unsupported") { console.log("PISHIP-CRED UNSUPPORTED language-mode"); process.exit(3); }
if (process.env.FAKE_MODE === "silent-exit") process.exit(1);
console.log("PISHIP-CRED READY");
require("node:fs").appendFileSync(process.env.FAKE_LOG, "started " + process.pid + "\\n");
lines.on("line", (line) => {
  const [id, op, target, value] = line.split(" ");
  require("node:fs").appendFileSync(process.env.FAKE_LOG, "request " + op + " " + target + " " + value + "\\n");
  if (target.startsWith("die")) process.exit(1);
  if (target.startsWith("slow")) return;
  if (target.startsWith("bad")) return console.log(id + " 1 - " + b64("CredRead 5"));
  if (op === "put") { store.set(target, value === "-" ? "" : value); return console.log(id + " 0 - -"); }
  if (op === "delete") { store.delete(target); return console.log(id + " 0 - -"); }
  if (!store.has(target)) return console.log(id + " 44 - -");
  console.log(id + " 0 " + b64(store.get(target)) + " -");
});
lines.on("close", () => process.exit(0));
`;

function fake(
  options: Partial<Parameters<typeof createPowerShellHelper>[0]> = {},
) {
  const program = join(temp, "fake-powershell.js");
  writeFileSync(program, FAKE);
  const log = join(temp, "log");
  writeFileSync(log, "");
  const spawns: { command: string; args: readonly string[] }[] = [];
  const counting = ((
    command: string,
    args: readonly string[],
    spawnOptions,
  ) => {
    spawns.push({ command, args });
    return nodeSpawn(command, [...args], {
      ...spawnOptions,
      env: { ...process.env, ...spawnOptions?.env, FAKE_LOG: log },
    });
  }) as typeof nodeSpawn;
  const helper = createPowerShellHelper({
    command: process.execPath,
    args: [program],
    spawn: counting,
    ...options,
  });
  return { helper, spawns, log };
}

const started = (log: string) =>
  readFileSync(log, "utf8")
    .split("\n")
    .filter((line) => line.startsWith("started"));

describe("the PowerShell helper's protocol", () => {
  it("starts nothing until the first request, then one process serves every request", async () => {
    const { helper, spawns, log } = fake();
    expect(spawns).toHaveLength(0);
    const target = "piship:acme:identity";
    expect(await helper.request("get", target)).toMatchObject({ status: 44 });
    await helper.request("put", target, "c2VjcmV0");
    // Concurrent reads share the process and come back in order.
    const replies = await Promise.all(
      Array.from({ length: 6 }, () => helper.request("get", target)),
    );
    for (const reply of replies)
      expect(reply).toEqual({ status: 0, stdout: "c2VjcmV0", stderr: "" });
    await helper.request("delete", target);
    expect(await helper.request("get", target)).toMatchObject({ status: 44 });
    expect(spawns).toHaveLength(1);
    expect(started(log)).toHaveLength(1);
  });

  it("puts the value on stdin only, never in the arguments", async () => {
    const { helper, spawns, log } = fake();
    const value = randomBytes(24).toString("base64url");
    await helper.request("put", "piship:acme:inference#1", value);
    expect(JSON.stringify(spawns)).not.toContain(value);
    expect(readFileSync(log, "utf8")).toContain(value);
  });

  it("carries a failure's message, and answers an empty value as empty", async () => {
    const { helper } = fake();
    expect(await helper.request("get", "bad-ref")).toEqual({
      status: 1,
      stdout: "",
      stderr: "CredRead 5",
    });
    await helper.request("put", "piship:acme:x", "");
    expect(await helper.request("get", "piship:acme:x")).toEqual({
      status: 0,
      stdout: "",
      stderr: "",
    });
  });

  it("reports a machine PowerShell cannot serve as unavailable, once, and does not ask again", async () => {
    const { helper, spawns } = fake({
      spawn: ((command: string, args: readonly string[], spawnOptions) => {
        spawns.push({ command, args });
        return nodeSpawn(command, [...args], {
          ...spawnOptions,
          env: { ...process.env, FAKE_MODE: "unsupported" },
        });
      }) as typeof nodeSpawn,
    });
    await expect(helper.request("get", "piship:a")).rejects.toBeInstanceOf(
      HelperUnavailable,
    );
    await expect(helper.request("get", "piship:a")).rejects.toThrow(
      /language-mode/,
    );
    expect(spawns).toHaveLength(1);
  });

  it("reports a PowerShell that is missing, or ends before it is ready, as unavailable", async () => {
    const missing = createPowerShellHelper({
      command: join(temp, "no-such-powershell"),
    });
    await expect(missing.request("get", "piship:a")).rejects.toBeInstanceOf(
      HelperUnavailable,
    );
    const silent = fake({
      spawn: ((command: string, args: readonly string[], spawnOptions) =>
        nodeSpawn(command, [...args], {
          ...spawnOptions,
          env: { ...process.env, FAKE_MODE: "silent-exit" },
        })) as typeof nodeSpawn,
    });
    await expect(silent.helper.request("get", "piship:a")).rejects.toThrow(
      /ended before/,
    );
  });

  it("fails a request whose process dies, without calling it unavailable, and starts a new one for the next", async () => {
    const { helper, spawns } = fake();
    await helper.request("put", "piship:a", "dg==");
    const error = await helper.request("get", "die-now").catch((e) => e);
    expect(error).toBeInstanceOf(Error);
    expect(error).not.toBeInstanceOf(HelperUnavailable);
    // A fresh process has none of the earlier state, and works.
    expect(await helper.request("get", "piship:a")).toMatchObject({
      status: 44,
    });
    expect(spawns).toHaveLength(2);
  });

  it("gives up on a request that is never answered", async () => {
    const { helper } = fake({ requestTimeoutMs: 300 });
    await expect(helper.request("get", "slow-one")).rejects.toThrow(
      /did not answer/,
    );
    expect(await helper.request("get", "piship:b")).toMatchObject({
      status: 44,
    });
  });

  it("ends after being idle and starts again on demand", async () => {
    const { helper, spawns } = fake({ idleMs: 150 });
    await helper.request("get", "piship:a");
    await new Promise((done) => setTimeout(done, 500));
    await helper.request("get", "piship:a");
    expect(spawns).toHaveLength(2);
  });

  it("never keeps the process alive while it is idle", () => {
    const program = join(temp, "fake-powershell.js");
    writeFileSync(program, FAKE);
    writeFileSync(join(temp, "log"), "");
    const script = `
      const { createPowerShellHelper } = await import("@piship/credentials");
      const helper = createPowerShellHelper({ command: process.execPath, args: [${JSON.stringify(program)}], idleMs: 60000 });
      await helper.request("get", "piship:a");
    `;
    const started = Date.now();
    const result = spawnSync(
      process.execPath,
      ["--input-type=module", "-e", script],
      {
        encoding: "utf8",
        timeout: 20_000,
        cwd: process.cwd(),
        env: { ...process.env, FAKE_LOG: join(temp, "log") },
      },
    );
    expect(result.status, result.stderr).toBe(0);
    expect(Date.now() - started).toBeLessThan(15_000);
  });
});

describe("the Windows store with a helper", () => {
  const secret = new SecretValue("sk-helper-secret-value");
  const encoded = Buffer.from(secret.reveal()).toString("base64url");

  /** A helper double with an in-memory store, counting what it is asked. */
  function inMemory() {
    const items = new Map<string, string>();
    const requests: { op: string; target: string; value?: string }[] = [];
    const helper: CredentialHelper = {
      async request(op, target, value) {
        requests.push({ op, target, ...(value ? { value } : {}) });
        if (op === "put") items.set(target, value ?? "");
        else if (op === "delete") items.delete(target);
        else if (!items.has(target))
          return { status: 44, stdout: "", stderr: "" };
        else return { status: 0, stdout: items.get(target) ?? "", stderr: "" };
        return { status: 0, stdout: "", stderr: "" };
      },
    };
    return { helper, items, requests };
  }
  const neverRun: CommandRunner = () => {
    throw new Error("the per-request PowerShell must not run");
  };

  it("asks for the helper at the first request, not when it is made, and reads, writes and deletes through it", async () => {
    const { helper, items, requests } = inMemory();
    let made = 0;
    const store = new WindowsCredentialSecretStore(neverRun, {
      helper: () => {
        made += 1;
        return helper;
      },
    });
    expect(made).toBe(0);
    const ref = "piship:acmecode:inference#1";
    expect(await store.get(ref)).toBeNull();
    await store.put(ref, secret);
    expect(items.get(`piship:${ref}`)).toBe(encoded);
    expect((await store.get(ref))?.reveal()).toBe(secret.reveal());
    await store.delete(ref);
    expect(await store.get(ref)).toBeNull();
    expect(requests.map((request) => request.op)).toEqual([
      "get",
      "put",
      "get",
      "delete",
      "get",
    ]);
  });

  it("serves a batch of reads, concurrent ones included, from the same helper", async () => {
    const { helper, items, requests } = inMemory();
    const store = new WindowsCredentialSecretStore(neverRun, {
      helper: () => helper,
    });
    for (let index = 0; index < 5; index += 1)
      items.set(
        `piship:piship:acme:item#${index}`,
        Buffer.from(`secret-${index}`).toString("base64url"),
      );
    const values = await Promise.all(
      [0, 1, 2, 3, 4].map((index) => store.get(`piship:acme:item#${index}`)),
    );
    expect(values.map((value) => value?.reveal())).toEqual(
      [0, 1, 2, 3, 4].map((index) => `secret-${index}`),
    );
    expect(requests).toHaveLength(5);
  });

  it("keeps the secret out of the request's target and out of any argument", async () => {
    const { helper, requests } = inMemory();
    const store = new WindowsCredentialSecretStore(neverRun, {
      helper: () => helper,
    });
    await store.put("piship:acmecode:inference#1", secret);
    expect(requests[0]?.target).not.toContain(encoded);
    expect(requests[0]?.value).toBe(encoded);
  });

  it("uses the per-request PowerShell when the helper is unavailable, and says so only through the old errors", async () => {
    const calls: string[] = [];
    const run: CommandRunner = (_command, _args, stdin) => {
      calls.push((stdin ?? "").split("\n")[0] ?? "");
      return { status: 44, stdout: "", stderr: "" };
    };
    const store = new WindowsCredentialSecretStore(run, {
      helper: () => ({
        request: () => Promise.reject(new HelperUnavailable("constrained")),
      }),
    });
    expect(await store.get("piship:acmecode:inference#1")).toBeNull();
    expect(calls).toEqual(["get"]);
  });

  it("does not repeat a request whose helper failed after it was sent", async () => {
    let asked = 0;
    const store = new WindowsCredentialSecretStore(neverRun, {
      helper: () => ({
        request: async () => {
          asked += 1;
          throw new Error("the PowerShell credential helper ended mid-request");
        },
      }),
    });
    await expect(
      store.put("piship:acmecode:inference#1", secret),
    ).rejects.toMatchObject({ code: "SECRET_STORE_UNAVAILABLE" });
    expect(asked).toBe(1);
  });

  // Where powershell.exe does not exist the helper cannot start, the store
  // runs the per-request script, and the answer is the one it always gave.
  it.runIf(process.platform !== "win32")(
    "reports a missing PowerShell as an unreachable store, as before the helper",
    async () => {
      const store = createSecretStore({
        provider: "system",
        fileDirectory: temp,
        platform: "win32",
      });
      const error = await store
        .get("piship:acmecode:inference#1")
        .catch((e) => e);
      expect(error).toMatchObject({ code: "SECRET_STORE_UNAVAILABLE" });
      expect(secretStoreUnreachable(error)).toBe(true);
    },
  );

  it("turns a helper failure status into the store's usual error", async () => {
    const store = new WindowsCredentialSecretStore(neverRun, {
      helper: () => ({
        request: async () => ({ status: 1, stdout: "", stderr: "CredRead 5" }),
      }),
    });
    await expect(
      store.get("piship:acmecode:inference#1"),
    ).rejects.toMatchObject({
      code: "SECRET_STORE_UNAVAILABLE",
      message: expect.stringContaining("CredRead 5"),
    });
  });
});

// The service half of the real script (framing, chunking, errors, the
// constrained-language check) on a PowerShell, with the Win32 half replaced
// by an in-memory credential store. On Windows this is Windows PowerShell
// 5.1; elsewhere pwsh, when it is installed.
const powershell = (() => {
  for (const command of process.platform === "win32"
    ? ["powershell.exe"]
    : ["pwsh"]) {
    const probe = spawnSync(
      command,
      [
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "$PSVersionTable.PSVersion.Major",
      ],
      { encoding: "utf8" },
    );
    if (probe.status === 0) return command;
  }
  return undefined;
})();

const IN_MEMORY_NATIVE = `
$memory = @{}
function CredWrite($target, $text) {
  if ($target -like '*denied') { return 5 }
  $memory[$target] = $text
  return 0
}
function CredRead($target) {
  if ($target -like '*boom') { throw 'CredRead 5' }
  if ($memory.ContainsKey($target)) { return $memory[$target] }
  return $null
}
function CredDelete($target) { $memory.Remove($target); return 0 }
`;

describe.runIf(powershell !== undefined)(
  `the real service loop on ${powershell ?? "PowerShell"}`,
  () => {
    function helper(script = helperScript(IN_MEMORY_NATIVE)) {
      return createPowerShellHelper({
        command: powershell as string,
        script,
        startTimeoutMs: 120_000,
        requestTimeoutMs: 120_000,
      });
    }

    it("round-trips a value, answers a missing one as missing, and deletes", async () => {
      const served = helper();
      const ref = "piship:acme:inference#1";
      expect(await served.request("get", ref)).toMatchObject({ status: 44 });
      const value = randomBytes(30).toString("base64url");
      expect(await served.request("put", ref, value)).toMatchObject({
        status: 0,
      });
      expect(await served.request("get", ref)).toEqual({
        status: 0,
        stdout: value,
        stderr: "",
      });
      expect(await served.request("delete", ref)).toMatchObject({ status: 0 });
      expect(await served.request("get", ref)).toMatchObject({ status: 44 });
    }, 180_000);

    it("splits a value larger than one credential into parts, joins it, and removes stale parts", async () => {
      const served = helper();
      const ref = "piship:acme:identity";
      const large = randomBytes(7000).toString("base64url");
      await served.request("put", ref, large);
      expect(await served.request("get", ref)).toEqual({
        status: 0,
        stdout: large,
        stderr: "",
      });
      // Smaller again: the parts that are no longer needed go.
      await served.request("put", ref, "small");
      expect(await served.request("get", ref)).toMatchObject({
        stdout: "small",
      });
      await served.request("put", ref, large);
      await served.request("delete", ref);
      expect(await served.request("get", ref)).toMatchObject({ status: 44 });
    }, 180_000);

    it("reports a failure with its message and keeps serving", async () => {
      const served = helper();
      expect(await served.request("get", "piship:acme:boom")).toEqual({
        status: 1,
        stdout: "",
        stderr: "CredRead 5",
      });
      expect(await served.request("put", "piship:acme:denied", "dg")).toEqual({
        status: 1,
        stdout: "",
        stderr: "CredWrite 5",
      });
      expect(await served.request("get", "piship:acme:other")).toMatchObject({
        status: 44,
      });
    }, 180_000);

    it("says a constrained language mode is unsupported instead of failing", async () => {
      const served = helper(
        `$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'\n${helperScript(IN_MEMORY_NATIVE)}`,
      );
      await expect(served.request("get", "piship:a")).rejects.toThrow(
        /language-mode/,
      );
    }, 180_000);

    it("says a native layer that cannot be set up is unsupported instead of failing", async () => {
      const served = helper(
        helperScript("throw 'the calls could not be defined'"),
      );
      await expect(served.request("get", "piship:a")).rejects.toBeInstanceOf(
        HelperUnavailable,
      );
    }, 180_000);
  },
);

// The Win32 half of the real script: the types it emits, which PowerShell can
// define on any system (Windows binds the calls when they are first made).
describe.runIf(powershell !== undefined)(
  `the emitted CREDENTIAL structure on ${powershell ?? "PowerShell"}`,
  () => {
    function run(body: string) {
      const script = `$ErrorActionPreference = 'Stop'\n${WINDOWS_NATIVE}\n${body}`;
      return spawnSync(
        powershell as string,
        [
          "-NoProfile",
          "-NonInteractive",
          "-ExecutionPolicy",
          "Bypass",
          "-EncodedCommand",
          Buffer.from(script, "utf16le").toString("base64"),
        ],
        { encoding: "utf8", timeout: 120_000 },
      );
    }

    it("lays the structure out as Windows' CREDENTIALW", () => {
      const result = run(`
$offsetOf = $marshal.GetMethod('OffsetOf', [System.Type[]]@([System.Type], [string]))
$layout = [ordered]@{ pointer = [System.IntPtr]::Size; size = $sizeOf.Invoke($null, @($credType)) }
foreach ($name in 'Flags','Type','TargetName','Comment','LastWrittenLow','CredentialBlobSize','CredentialBlob','Persist','AttributeCount','Attributes','TargetAlias','UserName') {
  $layout[$name] = [int]($offsetOf.Invoke($null, @($credType, $name)).ToInt64())
}
[Console]::Out.WriteLine(($layout | ConvertTo-Json -Compress))
`);
      expect(result.status, result.stderr).toBe(0);
      const layout = JSON.parse(
        result.stdout.trim().split("\n").at(-1) as string,
      );
      // The offsets of CREDENTIALW in wincred.h.
      if (layout.pointer === 8)
        expect(layout).toEqual({
          pointer: 8,
          size: 80,
          Flags: 0,
          Type: 4,
          TargetName: 8,
          Comment: 16,
          LastWrittenLow: 24,
          CredentialBlobSize: 32,
          CredentialBlob: 40,
          Persist: 48,
          AttributeCount: 52,
          Attributes: 56,
          TargetAlias: 64,
          UserName: 72,
        });
      else
        expect(layout).toMatchObject({
          pointer: 4,
          size: 52,
          CredentialBlobSize: 24,
          CredentialBlob: 28,
          UserName: 48,
        });
    }, 180_000);

    it.runIf(process.platform === "win32")(
      "binds the calls: a credential that does not exist reads as absent and deletes as done",
      () => {
        const result = run(`
$target = 'piship:layout-check:' + [guid]::NewGuid().ToString('N')
$read = CredRead $target
$delete = CredDelete $target
[Console]::Out.WriteLine(($null -eq $read).ToString() + ' ' + $delete)
`);
        expect(result.status, result.stderr).toBe(0);
        expect(result.stdout.trim().split("\n").at(-1)).toBe("True 0");
      },
      180_000,
    );
  },
);
