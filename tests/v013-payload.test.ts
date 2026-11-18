import { createHash } from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { verifyPayloadContents } from "@piship/core";

// piship.yaml and piship.lock of two examples exactly as tag v0.13.0
// (7f9e167d) has them: `git show v0.13.0:examples/<name>/<file>`. Do not
// edit or relock them; they are what an installed v0.13 payload carries.
const FIXTURES = join(import.meta.dirname, "fixtures", "v0.13.0");

const made: string[] = [];
afterEach(() => {
  for (const dir of made.splice(0))
    rmSync(dir, { recursive: true, force: true });
});

/**
 * A payload around the fixture's manifest and lock. Only the npm lock digest
 * is replaced, to match the stand-in package-lock.json; the manifest digest,
 * app, and versions are the ones v0.13 recorded.
 */
function payload(name: string, manifest?: (text: string) => string): string {
  const dir = mkdtempSync(join(tmpdir(), "piship-v013-"));
  made.push(dir);
  const source = readFileSync(join(FIXTURES, name, "piship.yaml"), "utf8");
  writeFileSync(join(dir, "piship.yaml"), manifest ? manifest(source) : source);
  const lock = JSON.parse(
    readFileSync(join(FIXTURES, name, "piship.lock"), "utf8"),
  );
  writeFileSync(join(dir, "package-lock.json"), "{}\n");
  lock.runtime.npmLockSha256 = createHash("sha256")
    .update("{}\n")
    .digest("hex");
  writeFileSync(join(dir, "piship.lock"), JSON.stringify(lock));
  mkdirSync(join(dir, "metadata"));
  writeFileSync(
    join(dir, "metadata", "target.json"),
    JSON.stringify({ platform: process.platform, arch: process.arch }),
  );
  return dir;
}
const verify = (dir: string) => () =>
  verifyPayloadContents(dir, { requireTarget: true, verifyContents: false });

describe("payloads PiShip v0.13.0 built", () => {
  it.each(["demo-company", "personal"])(
    "verify the %s example's manifest against its v0.13 lock",
    (name) => {
      expect(verify(payload(name))).not.toThrow();
    },
  );

  it("still refuse a one-byte change to the v0.13 managed manifest", () => {
    const dir = payload("demo-company", (text) =>
      text.replace('path: "/srv/src/**"', 'path: "/srv/sr*/**"'),
    );
    expect(verify(dir)).toThrow(/manifest and lock mismatch/);
    // Writing in the newer, looser default the lock never recorded.
    const trust = payload("demo-company", (text) =>
      text.replace(
        "  projectTrust:\n",
        "  projectTrust:\n    unknown:\n      instructions: allow\n",
      ),
    );
    expect(verify(trust)).toThrow(/manifest and lock mismatch/);
  });

  it("does not apply the 0.13 defaults when the lock names a later Pi", () => {
    const dir = payload("demo-company");
    const path = join(dir, "piship.lock");
    const lock = JSON.parse(readFileSync(path, "utf8"));
    lock.runtime.version = "1.5.0";
    writeFileSync(path, JSON.stringify(lock));
    expect(verify(dir)).toThrow(/manifest and lock mismatch/);
  });
});
