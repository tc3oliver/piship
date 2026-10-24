// A compiled copy of the Job Object supervisor, so that starting a governed
// child on Windows does not start PowerShell and compile C# every time. The
// first use compiles the same source with the csc.exe that ships with
// Windows, proves the result by running a child through it, and keeps it
// under the state home. Anything that goes wrong returns undefined and the
// caller uses the PowerShell supervisor, which is slower but needs nothing.

import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { JOB_SOURCE } from "./windows-job-source.js";

const MAIN_SOURCE = `
public static class PiShipJobMain {
  public static int Main() {
    try {
      string text = Encoding.UTF8.GetString(Convert.FromBase64String(Environment.GetEnvironmentVariable("PISHIP_JOB_REQUEST")));
      var serializer = new System.Web.Script.Serialization.JavaScriptSerializer();
      serializer.MaxJsonLength = int.MaxValue;
      var request = (System.Collections.Generic.Dictionary<string, object>)serializer.DeserializeObject(text);
      var start = new ProcessStartInfo();
      start.FileName = (string)request["file"];
      start.WorkingDirectory = (string)request["cwd"];
      start.UseShellExecute = false;
      start.EnvironmentVariables.Clear();
      foreach (var entry in (System.Collections.Generic.Dictionary<string, object>)request["env"])
        start.EnvironmentVariables[entry.Key] = Convert.ToString(entry.Value);
      var args = new System.Collections.Generic.List<string>();
      foreach (object arg in (System.Collections.IEnumerable)request["args"]) args.Add(Convert.ToString(arg));
      return PiShipJob.Run(start, args.ToArray());
    } catch (Exception error) {
      Console.Error.WriteLine("PISHIP_WINDOWS_JOB_ERROR: " + error.Message);
      return 127;
    }
  }
}
`;

/** The complete C# source the helper is compiled from. */
export const HELPER_SOURCE = JOB_SOURCE + MAIN_SOURCE;

const RECORD_SCHEMA = "piship-job-helper/v1";
const UNAVAILABLE_SCHEMA = "piship-job-helper-unavailable/v1";
/** A failed attempt is not retried for this long. */
const UNAVAILABLE_MS = 24 * 60 * 60 * 1000;
const COMPILE_TIMEOUT_MS = 30_000;
const SELF_TEST_TIMEOUT_MS = 15_000;
const SELF_TEST_EXIT_CODE = 3;

type RunResult = { status: number | null; error?: Error };
/** Test seam: run an executable to completion. */
export type RunSync = (
  file: string,
  args: string[],
  env: NodeJS.ProcessEnv,
  timeoutMs: number,
) => RunResult;

const runSync: RunSync = (file, args, env, timeoutMs) => {
  const result = spawnSync(file, args, {
    env,
    windowsHide: true,
    stdio: "ignore",
    timeout: timeoutMs,
  });
  return {
    status: result.status,
    ...(result.error && { error: result.error }),
  };
};

export interface HelperOptions {
  readonly host: NodeJS.ProcessEnv;
  /** The absolute Windows directory, already validated by the caller. */
  readonly systemRoot: string;
  readonly run?: RunSync;
}

function sha256(bytes: Buffer | string): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function stateRoot(host: NodeJS.ProcessEnv): string {
  return resolve(host.PISHIP_STATE_HOME ?? join(homedir(), ".piship"));
}

/** Directory of one version of the source; a name no distribution id can take. */
export function helperDirectory(host: NodeJS.ProcessEnv): string {
  return join(
    stateRoot(host),
    ".job-helper",
    sha256(HELPER_SOURCE).slice(0, 16),
  );
}

function compilerPath(root: string): string | undefined {
  for (const framework of ["Framework64", "Framework"]) {
    const candidate = join(
      root,
      "Microsoft.NET",
      framework,
      "v4.0.30319",
      "csc.exe",
    );
    if (existsSync(candidate)) return candidate;
  }
  return undefined;
}

function recordedName(dir: string): string | undefined {
  try {
    return JSON.parse(readFileSync(join(dir, "helper.json"), "utf8")).exe;
  } catch {
    return undefined;
  }
}

/** The recorded helper, when its bytes still match the record. */
function verified(dir: string): string | undefined {
  try {
    const record = JSON.parse(readFileSync(join(dir, "helper.json"), "utf8"));
    if (
      record?.schema !== RECORD_SCHEMA ||
      !/^jobhelper-[0-9a-f]{16}\.exe$/.test(record.exe) ||
      !/^[0-9a-f]{64}$/.test(record.sha256)
    )
      return undefined;
    const file = join(dir, record.exe);
    return sha256(readFileSync(file)) === record.sha256 ? file : undefined;
  } catch {
    return undefined;
  }
}

function recentlyUnavailable(dir: string): boolean {
  try {
    const marker = join(dir, "unavailable.json");
    return Date.now() - statSync(marker).mtimeMs < UNAVAILABLE_MS;
  } catch {
    return false;
  }
}

function markUnavailable(dir: string, reason: string): void {
  try {
    mkdirSync(dir, { recursive: true });
    writeFileSync(
      join(dir, "unavailable.json"),
      `${JSON.stringify({ schema: UNAVAILABLE_SCHEMA, reason })}\n`,
    );
  } catch {
    // Not being able to remember a failure only costs a retry.
  }
}

/**
 * The path of a verified compiled supervisor, or undefined when there is none
 * and one cannot be made here. Set PISHIP_WINDOWS_JOB_HELPER=off to refuse it.
 */
export function windowsJobHelper(options: HelperOptions): string | undefined {
  const { host, systemRoot } = options;
  if (host.PISHIP_WINDOWS_JOB_HELPER === "off") return undefined;
  const dir = helperDirectory(host);
  const existing = verified(dir);
  if (existing !== undefined) return existing;
  const csc = compilerPath(systemRoot);
  if (csc === undefined || recentlyUnavailable(dir)) return undefined;
  const run = options.run ?? runSync;
  const work = join(
    dir,
    `.build-${process.pid}-${randomBytes(4).toString("hex")}`,
  );
  try {
    mkdirSync(work, { recursive: true });
    const source = join(work, "job.cs");
    const built = join(work, "jobhelper.exe");
    writeFileSync(source, HELPER_SOURCE);
    const env: NodeJS.ProcessEnv = {
      SystemRoot: systemRoot,
      WINDIR: systemRoot,
    };
    for (const name of ["TEMP", "TMP"]) if (host[name]) env[name] = host[name];
    const compiled = run(
      csc,
      [
        "/nologo",
        "/target:exe",
        "/optimize+",
        "/r:System.Web.Extensions.dll",
        `/out:${built}`,
        source,
      ],
      env,
      COMPILE_TIMEOUT_MS,
    );
    if (compiled.status !== 0 || !existsSync(built)) {
      markUnavailable(dir, "the helper did not compile");
      return undefined;
    }
    // Run a child through it before anyone relies on it: an application
    // control policy that refuses the new executable shows up here.
    const probe = Buffer.from(
      JSON.stringify({
        file: process.execPath,
        args: ["-e", `process.exit(${SELF_TEST_EXIT_CODE})`],
        cwd: systemRoot,
        env: { SystemRoot: systemRoot, WINDIR: systemRoot },
      }),
    ).toString("base64");
    const tested = run(
      built,
      [],
      { SystemRoot: systemRoot, WINDIR: systemRoot, PISHIP_JOB_REQUEST: probe },
      SELF_TEST_TIMEOUT_MS,
    );
    if (tested.status !== SELF_TEST_EXIT_CODE) {
      markUnavailable(dir, "the compiled helper did not run a child");
      return undefined;
    }
    const digest = sha256(readFileSync(built));
    const name = `jobhelper-${digest.slice(0, 16)}.exe`;
    renameSync(built, join(dir, name));
    const record = join(dir, `helper.json.${randomBytes(4).toString("hex")}`);
    writeFileSync(
      record,
      `${JSON.stringify({ schema: RECORD_SCHEMA, exe: name, sha256: digest })}\n`,
    );
    renameSync(record, join(dir, "helper.json"));
    // Compiles are not byte-for-byte reproducible, so two processes that
    // raced each keep their own file; drop the others once one is recorded.
    const keep = new Set([name, recordedName(dir)]);
    for (const entry of readdirSync(dir))
      if (/^jobhelper-[0-9a-f]{16}\.exe$/.test(entry) && !keep.has(entry))
        try {
          rmSync(join(dir, entry));
        } catch {
          // still running, or another process just recorded it
        }
    return verified(dir);
  } catch {
    markUnavailable(dir, "the helper could not be installed");
    return undefined;
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}
