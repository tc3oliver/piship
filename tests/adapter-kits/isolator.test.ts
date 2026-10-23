import { existsSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect } from "vitest";
import { isolator, runIsolated } from "./isolator.js";
import { itIsolated } from "./isolator-gate.js";

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

itIsolated(isolator)(
  "killProcess stops the command however soon after the start it comes",
  async () => {
    // Bubblewrap forks the command; a kill of bubblewrap alone, soon after
    // the start, used to leave the command running to write its marker.
    const leaks: number[] = [];
    await Promise.all(
      [0, 2, 5, 10, 20, 30, 40, 60].flatMap((delay) =>
        Array.from({ length: 10 }, async () => {
          const root = realpathSync(mkdtempSync(join(tmpdir(), "kill-")));
          try {
            const run = runIsolated(
              { root, network: "deny", hostProcesses: true },
              root,
              `sleep 1; printf late > ${root}/marker`,
              {},
              () => undefined,
              () => undefined,
            );
            await sleep(delay);
            run.killProcess();
            await run.exited;
            await sleep(1_500);
            if (existsSync(join(root, "marker"))) leaks.push(delay);
          } finally {
            rmSync(root, { recursive: true, force: true });
          }
        }),
      ),
    );
    expect(leaks).toEqual([]);
  },
  30_000,
);
