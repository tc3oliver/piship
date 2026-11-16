import {
  existsSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
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
    // The command writes it once released after the kill, not after a fixed
    // time: starting all 80 takes long enough on a loaded host that the
    // first ones would write it before their kill even comes.
    const leaks: number[] = [];
    await Promise.all(
      [0, 2, 5, 10, 20, 30, 40, 60].flatMap((delay) =>
        Array.from({ length: 10 }, async () => {
          const root = realpathSync(mkdtempSync(join(tmpdir(), "kill-")));
          try {
            const run = runIsolated(
              { root, network: "deny", hostProcesses: true },
              root,
              `until [ -e ${root}/go ]; do sleep 0.01; done; printf late > ${root}/marker`,
              {},
              () => undefined,
              () => undefined,
            );
            await sleep(delay);
            run.killProcess();
            writeFileSync(join(root, "go"), "");
            // A command that outlived the kill holds the output pipes, so
            // the run ends only after it wrote its marker.
            await run.exited;
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

itIsolated(isolator)(
  "killGroup stops a background job the command forks as the kill lands",
  async () => {
    // A SIGKILL to a process group can miss a child the shell is forking at
    // that moment (seen on macOS), which then wrote its marker and failed the
    // kit's timeout behavior for a backend that does stop the group.
    const leaks: number[] = [];
    for (let batch = 0; batch < 20; batch++)
      await Promise.all(
        Array.from({ length: 20 }, async (_, index) => {
          const root = realpathSync(mkdtempSync(join(tmpdir(), "killpg-")));
          try {
            let run: ReturnType<typeof runIsolated> | undefined;
            const started = new Promise<void>((resolve) => {
              run = runIsolated(
                { root, network: "deny", hostProcesses: true },
                root,
                `echo started; ( until [ -e ${root}/go ]; do sleep 0.01; done; printf late > ${root}/marker ) & wait`,
                {},
                () => resolve(),
                () => undefined,
              );
            });
            await started;
            await sleep(index % 4);
            run?.killGroup();
            // Well past killGroup's second signal, even on a loaded host.
            await sleep(400);
            writeFileSync(join(root, "go"), "");
            // A job that outlived the kill holds the output pipes, so the
            // run ends only after it wrote its marker.
            await run?.exited;
            if (existsSync(join(root, "marker")))
              leaks.push(batch * 20 + index);
          } finally {
            rmSync(root, { recursive: true, force: true });
          }
        }),
      );
    expect(leaks).toEqual([]);
  },
  60_000,
);
