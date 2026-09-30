import {
  chmodSync,
  existsSync,
  readdirSync,
  readFileSync,
  statSync,
} from "node:fs";
import { join, relative, sep } from "node:path";
import { STATE_DATA_CLASSES } from "@piship/core";
import { describe, expect, it } from "vitest";
import { branded } from "../helpers/distribution.js";
import {
  lifecycleScenario,
  scanDecoded as scan,
  windows,
} from "../helpers/lifecycle.js";

// Lifecycle scenario: every local credential class (identity tokens, the
// runtime credential, a discarded credential whose deletion failed, and the
// pending revocation record) across update, rollback, a second update and
// rollback (A -> B -> A -> B -> A), and a reinstall. A secret that was
// revoked or cleared never comes back: not in the state directory, not in
// a rollback snapshot, not in any retained release. Logout clears local
// secrets even without the runtime variables.

// The store is locked by taking away write access to the file fallback's
// directory and read access to its files; Windows ignores POSIX modes, and
// root ignores both.
const lockable = !windows && process.getuid?.() !== 0;

function files(root: string): string[] {
  const out: string[] = [];
  const visit = (dir: string) => {
    for (const name of readdirSync(dir)) {
      const path = join(dir, name);
      if (statSync(path).isDirectory()) visit(path);
      else out.push(relative(root, path).split(sep).join("/"));
    }
  };
  visit(root);
  return out.sort();
}

describe("production lifecycle: credential classes (local fixtures)", () => {
  it("never restores a revoked or cleared secret of any credential class across update, rollback and reinstall", async () => {
    const s = await lifecycleScenario("credentials");
    const { services } = s;
    const state = join(s.state, "acmecode");
    const path = (...parts: string[]) => join(state, ...parts);
    const seen = () => [
      ...services.state.credentials.keys(),
      ...services.state.accessTokens.keys(),
      ...services.state.refreshTokens.keys(),
    ];
    const ids = () =>
      [...services.state.credentials.values()].map(
        (entry: { id: string }) => entry.id,
      );
    const run = async (args: string[], status = 0) => {
      const done = await s.run(args);
      expect(done.status, `${args.join(" ")}: ${done.stderr}`).toBe(status);
      return done;
    };
    await s.installFirst();

    // 1.0.0: identity tokens and the first runtime credential.
    await run(["login"]);
    await run(["--smoke"]);
    const first = seen();
    const [firstCredential] = ids();

    // 1.1.0 keeps what it can read; the update snapshot holds no credential.
    s.publish(1);
    await run(["update"]);
    await run(["--smoke"]);

    // A sign-in whose broker revocation fails: the replaced credential is
    // deleted locally and recorded, without its secret, for follow-up.
    services.knobs.revokeStatus = 503;
    const relogin = await run(["login"]);
    services.knobs.revokeStatus = undefined;
    expect(relogin.stderr).toContain(
      "The previous credential was deleted locally but not revoked",
    );
    const retryPath = path("credentials-metadata", "revocation-retry.json");
    expect(JSON.parse(readFileSync(retryPath, "utf8")).entries).toEqual([
      expect.objectContaining({
        credential_id: firstCredential,
        reason: "replace",
      }),
    ]);
    // The replaced credential and identity tokens are gone from the state.
    expect(scan(state, first)).toEqual([]);
    expect(scan(path("credentials-metadata"), seen())).toEqual([]);

    if (lockable) {
      // Logout while the store is locked: nothing can be read or deleted, so
      // logout fails, says so, and keeps every secret tracked: the
      // credential and the identity session as discarded records, which
      // name only the references, and are never restored as a session.
      const secrets = path("secrets");
      for (const name of readdirSync(secrets))
        chmodSync(join(secrets, name), 0o644);
      chmodSync(secrets, 0o500);
      try {
        const locked = await run(["logout"], 1);
        expect(locked.stderr).toContain("SECRET_STORE_UNAVAILABLE");
        expect(locked.stderr).toContain(
          "the identity session and the runtime credential could not be deleted from the secret store",
        );
        // Nothing is used while the store stays locked.
        const blocked = await run(["--smoke"], 1);
        expect(blocked.stderr).toContain("SECRET_STORE_UNAVAILABLE");
      } finally {
        chmodSync(secrets, 0o700);
        for (const name of readdirSync(secrets))
          chmodSync(join(secrets, name), 0o600);
      }
      expect(
        JSON.parse(
          readFileSync(path("credentials-metadata", "inference.json"), "utf8"),
        ).schema,
      ).toBe("piship-credential-discarded/v1");
      const marker = JSON.parse(
        readFileSync(path("identity", "session.json"), "utf8"),
      );
      expect(marker.schema).toBe("piship-identity-discarded/v1");
      expect(marker).not.toHaveProperty("subject");
      expect(marker.orphans.length).toBeGreaterThan(0);
    } else await run(["logout"]);

    // Roll back to 1.0.0. A discarded record is a credential class no
    // release reads, so rollback deletes its secrets (and confirms it)
    // before switching; the pending revocation record stays.
    const rollback = await run(["rollback"]);
    expect(rollback.stdout).toContain("Rolled back AcmeCode 1.1.0 -> 1.0.0");
    if (lockable)
      expect(rollback.stderr).toContain(
        "runtime credential metadata was cleared because the target cannot read it",
      );
    expect(existsSync(retryPath)).toBe(true);
    const cleared = seen();
    expect(scan(state, cleared)).toEqual([]);
    expect(scan(s.install, cleared)).toEqual([]);

    // A -> B -> A again, then a reinstall over the kept state: nothing
    // brings a cleared secret back, and signing in is required again.
    s.publish(2);
    await run(["update"]);
    await run(["rollback"]);
    expect(scan(state, cleared)).toEqual([]);
    const uninstall = s.cli("uninstall", "acmecode");
    expect(uninstall.status, uninstall.stderr).toBe(0);
    const reinstall = s.cli(
      "install",
      s.releases.first,
      "--use-existing-state",
    );
    expect(reinstall.status, reinstall.stderr).toBe(0);
    expect(scan(state, cleared)).toEqual([]);
    expect(scan(s.install, cleared)).toEqual([]);
    const signedOut = await run(["--smoke"], 1);
    expect(signedOut.stderr).toMatch(/IDENTITY_REQUIRED|CREDENTIAL_REQUIRED/);

    // A new sign-in gets a new credential, never a cleared one.
    await run(["login"]);
    const after = await run(["--smoke"]);
    const current = JSON.parse(after.stdout).access.credential.credentialId;
    expect(ids().slice(0, -1)).not.toContain(current);

    // Logout without the runtime variables still clears every local secret;
    // the credential it could not revoke is recorded, never kept.
    const env = { ...s.env };
    for (const name of Object.keys(services.env())) delete env[name];
    const revokedBefore = [...services.state.revokedCredentials];
    const logout = await branded(s.command, ["logout"], { cwd: s.temp, env });
    expect(logout.status, logout.stderr).toBe(0);
    expect(logout.stderr).toContain(
      "signing out locally without contacting the identity provider or credential broker",
    );
    expect(logout.stdout).toContain(
      "Local runtime and identity credentials were cleared",
    );
    expect(services.state.revokedCredentials).toEqual(revokedBefore);
    expect(
      JSON.parse(readFileSync(retryPath, "utf8")).entries.map(
        (entry: { credential_id: string }) => entry.credential_id,
      ),
    ).toContain(current);
    expect(existsSync(path("identity", "session.json"))).toBe(false);
    expect(existsSync(path("credentials-metadata", "inference.json"))).toBe(
      false,
    );

    // No secret of any class is left anywhere, the non-secret records hold
    // none, and every file left is a documented state class.
    const everything = seen();
    expect(scan(s.state, everything)).toEqual([]);
    expect(scan(s.install, everything)).toEqual([]);
    const classes = STATE_DATA_CLASSES.map((entry) => entry.path);
    const undocumented = files(state).filter(
      (file) =>
        !classes.some(
          (prefix) => file === prefix || file.startsWith(`${prefix}/`),
        ),
    );
    expect(undocumented).toEqual([]);
  }, 900000);
});
