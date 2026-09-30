import { describe, expect, it } from "vitest";
import {
  lifecycleScenario,
  type Services,
  scanDecoded as scan,
} from "../helpers/lifecycle.js";
import { STORAGES } from "../helpers/secret-store.js";

// User switching on one installed distribution: Alice signs in, then Bob
// signs in over her without logging out, across an update and a rollback.
// Bob never gets Alice's runtime credential, entitlement, or model
// selection, and no secret of hers is left in the state directory, the file
// secret store (searched in decoded form: the file store keeps values
// base64url encoded), rollback snapshots, or the install home. It runs with
// the file fallback and, with PISHIP_LIVE_SECRET_STORE=1, the platform store.

const ALICE = {
  subject: "alice-0001",
  displayName: "Alice Example",
  models: ["acme/coder", "acme/general"],
};
const BOB = {
  subject: "bob-0002",
  displayName: "Bob Example",
  models: ["acme/coder"],
};

function as(services: Services, person: typeof ALICE): void {
  services.knobs.subject = person.subject;
  services.knobs.displayName = person.displayName;
  services.knobs.email = `${person.subject}@demo.example`;
  services.knobs.entitledModels = [...person.models];
}

function secretsOf(services: Services, subject: string): string[] {
  const { state } = services;
  const owned = (map: Map<string, { subject: string }>) =>
    [...map].filter(([, entry]) => entry.subject === subject);
  return [
    ...owned(state.credentials),
    ...owned(state.accessTokens),
    ...owned(state.refreshTokens),
  ].map(([secret]) => secret);
}

const credentialIds = (services: Services, subject: string): string[] =>
  [...services.state.credentials.values()]
    .filter((entry: { subject: string }) => entry.subject === subject)
    .map((entry: { id: string }) => entry.id);

for (const { storage, skip } of STORAGES)
  describe(`user switching: ${storage} storage (local fixtures)${skip ? ` [skipped: ${skip}]` : ""}`, () => {
    it.skipIf(skip !== null)(
      "gives Bob none of Alice's credential, entitlement, or model selection, and leaves none of her secrets, across update and rollback",
      async () => {
        const s = await lifecycleScenario(`user-switch-${storage}`, {
          storage,
        });
        await s.installFirst();
        const services = s.services;

        as(services, ALICE);
        const aliceLogin = await s.run(["login"]);
        expect(aliceLogin.status, aliceLogin.stderr).toBe(0);
        expect(aliceLogin.stdout).toContain(
          `Signed in as ${ALICE.displayName}`,
        );
        expect(
          (await s.run(["config", "set", "model", "acme/general"])).status,
        ).toBe(0);
        const aliceRun = await s.run(["--smoke"]);
        expect(aliceRun.status, aliceRun.stderr).toBe(0);
        const [aliceCredential] = credentialIds(services, ALICE.subject);
        expect(JSON.parse(aliceRun.stdout).access).toMatchObject({
          identity: { subject: ALICE.subject },
          credential: { credentialId: aliceCredential },
          selectedModel: `${s.id}/acme/general`,
          allowedModels: ALICE.models,
        });
        const aliceSessions = JSON.parse(aliceRun.stdout).sessionDir;
        expect(JSON.parse(aliceRun.stdout).resumed).toBe(false);
        // An update writes a rollback snapshot while Alice is signed in.
        s.publish(1);
        const updated = await s.run(["update"]);
        expect(updated.status, updated.stderr).toBe(0);
        const aliceSecrets = secretsOf(services, ALICE.subject);
        expect(aliceSecrets.length).toBeGreaterThan(2);

        // Bob signs in over Alice, without a logout.
        as(services, BOB);
        const bobLogin = await s.run(["login"]);
        expect(bobLogin.status, bobLogin.stderr).toBe(0);
        expect(bobLogin.stdout).toContain(`Signed in as ${BOB.displayName}`);
        expect(services.state.revokedCredentials).toEqual([aliceCredential]);
        const bobRun = await s.run(["--smoke"]);
        expect(bobRun.status, bobRun.stderr).toBe(0);
        const [bobCredential] = credentialIds(services, BOB.subject);
        expect(bobCredential).not.toBe(aliceCredential);
        expect(JSON.parse(bobRun.stdout).access).toMatchObject({
          identity: { subject: BOB.subject },
          credential: { credentialId: bobCredential },
          // Alice's model selection is gone, and Bob's entitlement applies.
          selectedModel: `${s.id}/acme/coder`,
          allowedModels: BOB.models,
        });
        // Bob does not resume Alice's session history: it is kept per principal.
        const bobSessions = JSON.parse(bobRun.stdout).sessionDir;
        expect(JSON.parse(bobRun.stdout).resumed).toBe(false);
        expect(bobSessions).not.toBe(aliceSessions);
        expect(scan(s.state, aliceSecrets)).toEqual([]);
        expect(scan(s.install, aliceSecrets)).toEqual([]);
        // The store holds Bob's identity and credential and nothing else.
        expect(s.metadataRefs()).toHaveLength(2);
        s.expectSecretStore();

        // Rolling back does not bring Alice's credential back.
        const rollback = await s.run(["rollback"]);
        expect(rollback.status, rollback.stderr).toBe(0);
        const afterRollback = await s.run(["--smoke"]);
        expect(afterRollback.status, afterRollback.stderr).toBe(0);
        expect(JSON.parse(afterRollback.stdout).access).toMatchObject({
          identity: { subject: BOB.subject },
          credential: { credentialId: bobCredential },
          allowedModels: BOB.models,
        });
        // The same user resumes across a rollback.
        expect(JSON.parse(afterRollback.stdout)).toMatchObject({
          resumed: true,
          sessionDir: bobSessions,
        });
        expect(scan(s.state, aliceSecrets)).toEqual([]);
        expect(scan(s.install, aliceSecrets)).toEqual([]);
        s.expectSecretStore();

        // Alice signing in again gets a new credential, never the revoked one.
        as(services, ALICE);
        expect((await s.run(["login"])).status).toBe(0);
        const again = await s.run(["--smoke"]);
        expect(again.status, again.stderr).toBe(0);
        // Alice gets her own history back, never Bob's.
        expect(JSON.parse(again.stdout)).toMatchObject({
          resumed: true,
          sessionDir: aliceSessions,
        });
        const credential = JSON.parse(again.stdout).access.credential
          .credentialId;
        expect([aliceCredential, bobCredential]).not.toContain(credential);
        const logout = await s.run(["logout"]);
        expect(logout.status, logout.stderr).toBe(0);
        const everything = [
          ...aliceSecrets,
          ...secretsOf(services, ALICE.subject),
          ...secretsOf(services, BOB.subject),
        ];
        expect(scan(s.state, everything)).toEqual([]);
        expect(scan(s.install, everything)).toEqual([]);
        s.expectSecretStore([]);
      },
      900000,
    );
  });
