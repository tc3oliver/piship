import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { lifecycleScenario, scan } from "../helpers/lifecycle.js";
import {
  PLATFORM_STORE_KIND,
  partsOf,
  type Storage,
  storageSkipReason,
} from "../helpers/secret-store.js";

// Lifecycle scenario: where a managed distribution keeps its secrets, from
// the first sign-in to purge. The same flow runs with the restricted file
// fallback and with the platform store the example declares (macOS
// Keychain, Windows Credential Manager, Linux Secret Service), which is live
// only with PISHIP_LIVE_SECRET_STORE=1. After every step the secret store
// holds exactly the references the metadata names, and a distribution that
// declares the system store never writes the file fallback.
//
// The identity token bundle is larger than one platform item on every OS
// (Windows Credential Manager 2,048 characters, the Secret Service 8,000,
// Keychain 1,024), so it is stored, replaced, refreshed and deleted as a
// value split across parts.

// An ID token with a long `name` claim: the bundle encodes to about 22,000
// characters.
const LONG_NAME = `Store Tester ${"x".repeat(12_000)}`;
// Found in every ID token the fixture issues from then on: the base64url of
// the long run of "x" in its payload, whatever the run's alignment. The
// name itself is not a secret and appears in the identity metadata.
const ID_TOKEN_MARK = "eHh4".repeat(100);

/**
 * The scenario with one storage. Each storage has a test file of its own
 * (lifecycle-secret-store-file.test.ts and lifecycle-secret-store-system.test.ts),
 * so Portable E2E can run the two on different runners.
 */
export function secretStoreLifecycle(storage: Storage): void {
  const skip = storageSkipReason(storage);
  describe(`secret store lifecycle: ${storage} storage (local fixtures)${skip ? ` [skipped: ${skip}]` : ""}`, () => {
    it.skipIf(skip !== null)(
      "stores, loads, replaces, refreshes and deletes every secret across update, rollback, logout and purge",
      async () => {
        const s = await lifecycleScenario(`store-${storage}`, { storage });
        const { services } = s;
        const state = join(s.state, s.id);
        const identityFile = join(state, "identity", "session.json");
        const credentialFile = join(
          state,
          "credentials-metadata",
          "inference.json",
        );
        const read = (path: string) => JSON.parse(readFileSync(path, "utf8"));
        const refs = () => ({
          identity: read(identityFile).secretRef as string,
          credential: read(credentialFile).credential_ref as string,
        });
        const issued = () => [
          ID_TOKEN_MARK,
          ...services.state.credentials.keys(),
          ...services.state.accessTokens.keys(),
          ...services.state.refreshTokens.keys(),
        ];
        const run = async (args: string[], status = 0) => {
          const done = await s.run(args);
          expect(done.status, `${args.join(" ")}: ${done.stderr}`).toBe(status);
          return done;
        };
        const credentialId = async () =>
          JSON.parse((await run(["--smoke"])).stdout).access.credential
            .credentialId as string;

        /**
         * The store holds exactly `expected` and no token (runtime
         * credential, access, refresh or ID token) is in plain text anywhere
         * under the scenario: state, home, install home, and releases; in
         * the platform store the identity bundle is split into parts.
         */
        const expectStored = (expected: readonly string[]) => {
          expect(scan(s.temp, issued())).toEqual([]);
          const listed = s.expectSecretStore(expected);
          if (storage === "system")
            for (const ref of expected.filter((item) =>
              item.includes(":identity#"),
            ))
              expect(partsOf(listed, ref).length).toBeGreaterThan(1);
        };

        await s.installFirst();

        // Store: sign-in stores the oversized identity bundle and the
        // runtime credential it acquires, which is short-lived.
        services.knobs.displayName = LONG_NAME;
        services.knobs.credentialTtl = 120;
        await run(["login"]);
        services.knobs.credentialTtl = 3600;
        expect(refs()).toEqual({
          identity: `piship:${s.id}:identity#1`,
          credential: `piship:${s.id}:inference#1`,
        });
        expectStored(Object.values(refs()));

        // The distribution reports the store it declares and uses.
        const explained = await run(["config", "explain", "--json"]);
        const rows = JSON.parse(explained.stdout) as {
          key: string;
          value: unknown;
        }[];
        const value = (key: string) =>
          rows.find((item) => item.key === key)?.value;
        expect(value("credential.storage")).toBe(storage);
        expect(value("credential.state")).toMatchObject({
          store: expect.stringMatching(
            `^${storage === "system" ? PLATFORM_STORE_KIND : "file"} `,
          ),
        });

        // Credential refresh: it expires within refresh.beforeExpiry (5m),
        // so the next launch renews it into a new generation and deletes
        // the old one from the store.
        const first = [...services.state.credentials.values()].map(
          (entry: { id: string }) => entry.id,
        );
        const renewed = await credentialId();
        expect(first).not.toContain(renewed);
        expect(refs()).toEqual({
          identity: `piship:${s.id}:identity#1`,
          credential: `piship:${s.id}:inference#2`,
        });
        expectStored(Object.values(refs()));

        // Load: launches and a model request read both back unchanged.
        await run(["--smoke-model"]);
        expect(await credentialId()).toBe(renewed);
        const loaded = refs();
        expectStored(Object.values(loaded));

        // Replace: signing in again replaces the identity bundle, now with
        // a short-lived access token, and the runtime credential.
        services.knobs.accessTokenTtl = 30;
        await run(["login"]);
        services.knobs.accessTokenTtl = 3600;
        const replaced = refs();
        expect(replaced.identity).toBe(`piship:${s.id}:identity#2`);
        expectStored(Object.values(replaced));
        const current = await credentialId();
        expect(current).not.toBe(renewed);
        expect(services.state.revokedCredentials).toContain(renewed);

        // Identity refresh: the access token expires within a minute, so
        // that launch refreshed the session and replaced its bundle.
        const refreshed = refs();
        expect(refreshed).toEqual({
          ...replaced,
          identity: `piship:${s.id}:identity#3`,
        });
        expectStored(Object.values(refreshed));
        expect(await credentialId()).toBe(current);
        expect(refs()).toEqual(refreshed);

        // Update and rollback keep what the store holds, and both releases
        // load it.
        s.publish(1);
        await run(["update"]);
        expect(await credentialId()).toBe(current);
        await run(["--smoke-model"]);
        expect(refs()).toEqual(refreshed);
        expectStored(Object.values(refreshed));
        const rollback = await run(["rollback"]);
        expect(rollback.stdout).toContain(
          "Rolled back AcmeCode 1.1.0 -> 1.0.0",
        );
        expect(await credentialId()).toBe(current);
        await run(["--smoke-model"]);
        expect(refs()).toEqual(refreshed);
        expectStored(Object.values(refreshed));

        // Logout deletes every secret it stored.
        await run(["logout"]);
        expect(existsSync(identityFile)).toBe(false);
        expect(existsSync(credentialFile)).toBe(false);
        expectStored([]);
        const signedOut = await run(["--smoke"], 1);
        expect(signedOut.stderr).toContain("IDENTITY_REQUIRED");

        // A user who installed from the release, whose download is gone
        // (installFirst deletes it), removes everything with the manager
        // the install ships. Purge revokes nothing, so while signed in it
        // refuses, deleting nothing, until logout revoked the credential.
        await run(["login"]);
        const live = await credentialId();
        const signedIn = refs();
        expectStored(Object.values(signedIn));
        const receiptFile = join(s.install, "receipts", `${s.id}.json`);
        const { payload } = read(receiptFile) as { payload: string };
        const purge = () =>
          spawnSync(
            process.execPath,
            [
              join(payload, "piship.mjs"),
              "uninstall",
              s.id,
              "--purge",
              "--yes",
            ],
            { cwd: s.temp, env: s.env, encoding: "utf8" },
          );
        const refused = purge();
        expect(refused.status).toBe(1);
        expect(refused.stderr).toContain(
          `Run ${s.id} logout first, then purge again`,
        );
        expect(existsSync(s.command)).toBe(true);
        expect(refs()).toEqual(signedIn);
        expectStored(Object.values(signedIn));
        expect(services.state.revokedCredentials).not.toContain(live);
        await run(["logout"]);
        expect(services.state.revokedCredentials).toContain(live);
        const purged = purge();
        expect(purged.status, purged.stderr).toBe(0);
        expect(existsSync(s.command)).toBe(false);
        expect(existsSync(join(s.install, "apps", s.id))).toBe(false);
        expect(existsSync(receiptFile)).toBe(false);
        expect(existsSync(state)).toBe(false);
        if (storage === "system") expect(s.storeRefs()).toEqual([]);
        expect(scan(s.temp, issued())).toEqual([]);
      },
      900000,
    );
  });
}
