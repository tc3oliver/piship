// Run git and collect its output. Internal: not re-exported from the package.
import { execFile } from "node:child_process";

export function runGit(
  cwd: string,
  args: readonly string[],
  input?: Buffer,
): Promise<{ stdout: Buffer; stderr: string; code: number }> {
  return new Promise((resolve, reject) => {
    const child = execFile(
      "git",
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
