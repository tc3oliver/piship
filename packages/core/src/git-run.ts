// Run git and collect its output. runGit is internal; resolveGit is exported for Pi's remote workspace.
import { execFile } from "node:child_process";
import { statSync } from "node:fs";
import { delimiter, isAbsolute, join } from "node:path";

// On Windows libuv searches the working directory before PATH, so a repository
// can plant git.exe. Resolve git from absolute PATH entries first. core cannot
// import @piship/mcp's findOnPath (check:boundaries), hence this small copy.
export function resolveGit(
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
): string {
  if (platform !== "win32") return "git";
  // Only .exe and .com: Node refuses to spawn .bat/.cmd without a shell.
  for (const entry of (env.PATH ?? env.Path ?? "").split(delimiter)) {
    // Windows PATH entries may be quoted ("C:\Program Files\Git\cmd").
    const directory = entry.replace(/^"(.*)"$/, "$1");
    if (isAbsolute(directory))
      for (const extension of [".exe", ".com"]) {
        const candidate = join(directory, `git${extension}`);
        try {
          if (statSync(candidate).isFile()) return candidate;
        } catch {}
      }
  }
  throw new Error("git was not found on PATH");
}

export function runGit(
  cwd: string,
  args: readonly string[],
  input?: Buffer,
): Promise<{ stdout: Buffer; stderr: string; code: number }> {
  return new Promise((resolve, reject) => {
    const child = execFile(
      resolveGit(),
      [...args],
      { cwd, encoding: "buffer", maxBuffer: 256 * 1024 * 1024 },
      (error, stdout, stderr) => {
        const code =
          error === null ? 0 : typeof error.code === "number" ? error.code : -1;
        if (code === -1) reject(error);
        else resolve({ stdout, stderr: stderr.toString("utf8"), code });
      },
    );
    child.stdin?.end(input);
  });
}
