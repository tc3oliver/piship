import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";

// The reference realm (examples/enterprise-reference/keycloak) is test and
// exploration infrastructure, not a production identity provider, but it
// still must not invite password guessing: brute-force detection is on and
// passwords follow a policy. Keycloak refuses to import a user whose
// password breaks the realm's policy, so the passwords generate-env.mjs
// makes for the fixture users are checked against the policy here, without
// Docker, on every pull request. Nothing in the reference E2E signs in with
// a wrong password, so the lockout never trips it.

const reference = fileURLToPath(
  new URL("../examples/enterprise-reference/", import.meta.url),
);

type Realm = {
  bruteForceProtected?: boolean;
  permanentLockout?: boolean;
  failureFactor?: number;
  waitIncrementSeconds?: number;
  maxFailureWaitSeconds?: number;
  maxDeltaTimeSeconds?: number;
  quickLoginCheckMilliSeconds?: number;
  minimumQuickLoginWaitSeconds?: number;
  passwordPolicy?: string;
  users: { username: string; email?: string }[];
};

const realm = JSON.parse(
  readFileSync(
    join(reference, "keycloak", "piship-reference-realm.json"),
    "utf8",
  ),
) as Realm;

/** The policy's terms, e.g. `length(12)` as ["length", 12]. */
function terms(policy: string): [string, number | undefined][] {
  return policy.split(/\s+and\s+/).map((term) => {
    const match = /^([A-Za-z]+)(?:\((\d+)\))?$/.exec(term.trim());
    if (!match) throw new Error(`unreadable password policy term: ${term}`);
    return [match[1], match[2] === undefined ? undefined : Number(match[2])];
  });
}

/** Why `password` breaks `policy` for `user`, or undefined when it does not. */
function breaks(
  policy: string,
  password: string,
  user: { username: string; email?: string },
): string | undefined {
  const count = (pattern: RegExp) => (password.match(pattern) ?? []).length;
  for (const [name, value = 1] of terms(policy)) {
    const ok = {
      length: () => password.length >= value,
      maxLength: () => password.length <= value,
      notUsername: () => password.toLowerCase() !== user.username.toLowerCase(),
      notEmail: () =>
        !user.email || password.toLowerCase() !== user.email.toLowerCase(),
      digits: () => count(/\d/g) >= value,
      lowerCase: () => count(/[a-z]/g) >= value,
      upperCase: () => count(/[A-Z]/g) >= value,
      specialChars: () => count(/[^A-Za-z0-9]/g) >= value,
      // Applies to a change, not to the first password a user is given.
      passwordHistory: () => true,
    }[name];
    // A term this check cannot evaluate must be added here first.
    if (!ok) throw new Error(`password policy term not checked: ${name}`);
    if (!ok()) return name;
  }
  return undefined;
}

describe("the reference Keycloak realm", () => {
  const scratch = mkdtempSync(join(tmpdir(), "piship-realm-policy-"));
  afterAll(() => rmSync(scratch, { recursive: true, force: true }));

  it("detects brute force with a temporary lockout, never a permanent one", () => {
    expect(realm.bruteForceProtected).toBe(true);
    // Temporary: a permanent lockout would let anyone lock a user out by
    // guessing, and would need an administrator to undo.
    expect(realm.permanentLockout).toBe(false);
    expect(realm.failureFactor).toBeGreaterThanOrEqual(3);
    expect(realm.failureFactor).toBeLessThanOrEqual(10);
    expect(realm.waitIncrementSeconds).toBeGreaterThanOrEqual(30);
    expect(realm.maxFailureWaitSeconds).toBeGreaterThanOrEqual(
      realm.waitIncrementSeconds ?? 0,
    );
    expect(realm.maxDeltaTimeSeconds).toBeGreaterThan(0);
    expect(realm.quickLoginCheckMilliSeconds).toBeGreaterThan(0);
    expect(realm.minimumQuickLoginWaitSeconds).toBeGreaterThan(0);
  });

  it("has a password policy of at least 12 characters, never the username or email", () => {
    const policy = realm.passwordPolicy ?? "";
    const named = new Map(terms(policy));
    expect(named.get("length")).toBeGreaterThanOrEqual(12);
    expect(named.has("notUsername")).toBe(true);
    expect(named.has("notEmail")).toBe(true);
    // The policy's own check: a short password and the username break it.
    const alice = { username: "alice" };
    expect(breaks(policy, "short1", alice)).toBe("length");
    expect(breaks(policy, "alice", alice)).toBeDefined();
  });

  it("is satisfied by the passwords generate-env.mjs makes for every fixture user", () => {
    const policy = realm.passwordPolicy ?? "";
    for (let run = 0; run < 20; run++) {
      const out = join(scratch, `env-${run}`);
      const generated = spawnSync(
        process.execPath,
        [join(reference, "scripts", "generate-env.mjs"), "--out", out],
        { encoding: "utf8" },
      );
      expect(generated.status, generated.stderr).toBe(0);
      const env = Object.fromEntries(
        readFileSync(out, "utf8")
          .split("\n")
          .filter((line) => /^[A-Z_]+=/.test(line))
          .map((line) => [
            line.slice(0, line.indexOf("=")),
            line.slice(line.indexOf("=") + 1),
          ]),
      );
      expect(realm.users.length).toBeGreaterThan(0);
      for (const user of realm.users) {
        const password =
          env[`REFERENCE_${user.username.toUpperCase()}_PASSWORD`];
        expect(password, user.username).toBeTruthy();
        expect(breaks(policy, password, user), user.username).toBeUndefined();
      }
    }
  });
});
