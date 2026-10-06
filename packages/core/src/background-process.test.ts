import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { startBackgroundProcess } from "./background-process.js";

const roots: string[] = [];
const temp = () => {
  const root = mkdtempSync(join(tmpdir(), "piship-background-"));
  roots.push(root);
  return root;
};
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

const sleep = (ms: number) =>
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);

describe("startBackgroundProcess", () => {
  it("runs the process while this thread does other work, then reports its success", () => {
    const cwd = temp();
    const marker = join(cwd, "started");
    const job = startBackgroundProcess(
      process.execPath,
      [
        "-e",
        `require("node:fs").writeFileSync("started", "1"); setTimeout(() => {}, 300);`,
      ],
      cwd,
    );
    // The process is already running here, before anything waits for it.
    const deadline = Date.now() + 20_000;
    while (!existsSync(marker) && Date.now() < deadline) sleep(10);
    expect(existsSync(marker)).toBe(true);
    expect(job.wait()).toEqual({ status: 0, output: "" });
    // Waiting again gives the same answer.
    expect(job.wait().status).toBe(0);
  });

  it("reports a failure's exit status and the end of its error output", () => {
    const cwd = temp();
    const job = startBackgroundProcess(
      process.execPath,
      ["-e", `console.error("a".repeat(100000) + "THE END"); process.exitCode = 3;`],
      cwd,
    );
    const outcome = job.wait();
    expect(outcome.status).toBe(3);
    expect(outcome.output.trimEnd().endsWith("THE END")).toBe(true);
    expect(outcome.output.length).toBeLessThanOrEqual(64 * 1024);
  });

  it("reports a process that cannot start", () => {
    const outcome = startBackgroundProcess(
      join(temp(), "no-such-program"),
      [],
      temp(),
    ).wait();
    expect(outcome.status).not.toBe(0);
    expect(outcome.output).toMatch(/ENOENT/);
  });
});
