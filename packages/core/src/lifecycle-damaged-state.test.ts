// Update and rollback over each versioned state file the migration check
// reads, left empty or cut short (a crash mid-write, a full disk). None may
// leave either operation refusing forever: the state marker is rebuilt,
// credential metadata is cleared and reacquired, a torn audit line is kept in
// place, and preferences, which cannot be rebuilt, are refused with the exact
// path and the way out, and are never deleted.
import { createHash } from "node:crypto";
import { existsSync, readFileSync, renameSync } from "node:fs";
import { join } from "node:path";
import { MemorySecretStore } from "@piship/credentials";
import { describe, expect, it } from "vitest";
import {
  HOST_EVIDENCED,
  ID,
  fakeRun,
  installed,
  launch,
  rejection,
  stateDir,
  useLifecycleHomes,
  write,
} from "../../../tests/helpers/lifecycle-faults.js";
import { readInstallReceipt } from "./install/index.js";
import { readStateMarker } from "./migration.js";
import { rollbackDistribution, updateDistribution } from "./update/index.js";

useLifecycleHomes();

/** Each versioned file, a valid content, and that content cut short. */
const FILES: readonly { path: string; valid: string }[] = [
  {
    path: "state.json",
    valid: JSON.stringify({
      schema: "piship-state/v1",
      distribution: ID,
      version: "1.0.0",
      pi: "1.0.3",
      piship: "0.7.0",
    }),
  },
  {
    path: "config/preferences.json",
    valid: JSON.stringify({ schema: "piship-preferences/v1", values: {} }),
  },
  {
    path: "identity/session.json",
    valid: JSON.stringify({ schema: "piship-identity-metadata/v1" }),
  },
  {
    path: "credentials-metadata/inference.json",
    valid: JSON.stringify({ schema: "piship-credential-metadata/v1" }),
  },
  {
    path: "credentials-metadata/sandbox.json",
    valid: JSON.stringify({
      schema: "piship-sandbox-credential-metadata/v1",
    }),
  },
  {
    path: "credentials-metadata/pending-issuance.json",
    valid: JSON.stringify({ schema: "piship-credential-issuance/v1" }),
  },
  {
    path: "logs/audit.jsonl",
    valid: `${JSON.stringify({ schema: "piship-audit/v1", type: "launch" })}\n`,
  },
];

const CASES = FILES.flatMap(({ path, valid }) => [
  { path, damage: "empty", content: "" },
  {
    path,
    damage: "truncated",
    content: valid.slice(0, Math.floor(valid.length / 2)),
  },
]);

function absolute(path: string): string {
  return join(stateDir(), ...path.split("/"));
}
function digest(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

type Operation = "update" | "rollback";

/** 1.0.0 installed (and, for a rollback, updated to 1.1.0). */
async function ready(operation: Operation) {
  const { opts } = await installed();
  if (operation === "rollback") await updateDistribution(ID, opts);
  return opts;
}
function run(operation: Operation, opts: Awaited<ReturnType<typeof ready>>) {
  const secretStore = new MemorySecretStore();
  return operation === "update"
    ? updateDistribution(ID, { ...opts, secretStore })
    : rollbackDistribution(ID, { runCheck: fakeRun, secretStore });
}
const TARGET = { update: "1.1.0", rollback: "1.0.0" };
const ACTIVE = { update: "1.0.0", rollback: "1.1.0" };

describe.runIf(HOST_EVIDENCED)("a damaged versioned state file", () => {
  it.each(CASES.filter((item) => item.path === "state.json"))(
    "rebuilds an $damage state marker before the switch is even checked",
    async ({ content }) => {
      await installed();
      write(absolute("state.json"), content);
      // No retained release: rollback stops after repairing the marker.
      const error = await rejection(
        rollbackDistribution(ID, { runCheck: fakeRun }),
      );
      expect(error.message).toMatch(/has no retained release/);
      expect(readStateMarker(stateDir())).toMatchObject({
        schema: "piship-state/v1",
        distribution: ID,
        version: "1.0.0",
      });
    },
  );

  for (const operation of ["update", "rollback"] as const)
    describe(operation, () => {
      it.each(CASES.filter((item) => item.path !== "config/preferences.json"))(
        "goes ahead over an $damage $path",
        async ({ path, content }) => {
          const opts = await ready(operation);
          write(absolute(path), content);
          await run(operation, opts);
          expect(readInstallReceipt(ID).active).toBe(TARGET[operation]);
          expect(launch()).toBe(`payload ${TARGET[operation]}`);
          // The marker is rebuilt for the release now active.
          expect(readStateMarker(stateDir())).toMatchObject({
            schema: "piship-state/v1",
            version: TARGET[operation],
          });
          if (path.startsWith("logs/"))
            // An audit log is never rewritten or dropped.
            expect(readFileSync(absolute(path), "utf8")).toBe(content);
          else if (path !== "state.json")
            // Credential metadata is cleared and reacquired.
            expect(existsSync(absolute(path))).toBe(false);
        },
      );

      it.each(CASES.filter((item) => item.path === "config/preferences.json"))(
        "refuses an $damage $path naming it and the way out, then goes ahead once it is moved aside",
        async ({ path, content }) => {
          const opts = await ready(operation);
          const file = absolute(path);
          write(file, content);
          const error = await rejection(run(operation, opts));
          expect(error.code).toBe(
            operation === "update" ? "UPDATE_FAILED" : "ROLLBACK_FAILED",
          );
          expect(error.message).toContain(file);
          expect(error.message).toMatch(/move it aside/);
          expect(readInstallReceipt(ID).active).toBe(ACTIVE[operation]);
          // Never deleted or rewritten.
          expect(readFileSync(file, "utf8")).toBe(content);
          renameSync(file, `${file}.damaged`);
          const kept = digest(`${file}.damaged`);
          await run(operation, opts);
          expect(readInstallReceipt(ID).active).toBe(TARGET[operation]);
          expect(digest(`${file}.damaged`)).toBe(kept);
        },
      );
    });
});
