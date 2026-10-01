import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  fileStoreValues,
  type Installed,
  installDistribution,
  leaks,
  type Smoke,
  scan,
  type StoredSecrets,
  storeMode,
} from "./support/distribution.js";
import {
  accessTokenStatus,
  gatewayChat,
  gatewayKey,
  gatewayModels,
  refreshTokenStatus,
} from "./support/services.js";
import { type Stack, startStack } from "./support/stack.js";

// User switching and entitlement on the reference stack. Alice (group
// `engineering`, both models) and Bob (group `support`, `acme/coder` only)
// sign in over each other on one installed AcmeCode without a logout. Bob
// gets none of Alice's credential, entitlement, or model selection, and Alice's
// key stops working at the gateway. A model outside a user's entitlement is
// refused by PiShip and, independently, by the gateway. A distribution whose
// model list is narrower than the entitlement stays narrower. Needs Docker;
// run with `npm run test:reference` after `npm run build`.

const mode = storeMode();
const ALICE_MODELS = ["acme/coder", "acme/general"];
const BOB_MODELS = ["acme/coder"];
const NOT_ENTITLED = "not included in the runtime credential entitlement";

describe.skipIf(process.platform === "win32")(
  "identity flows on the reference stack",
  () => {
    let stack: Stack;

    beforeAll(async () => {
      stack = await startStack();
    }, 600_000);

    afterAll(() => {
      stack?.stop();
    }, 120_000);

    describe("user switching without a logout", () => {
      let acme: Installed;
      let aliceSmoke: Smoke;
      let bobSmoke: Smoke;
      let alice: StoredSecrets;
      let bob: StoredSecrets;
      const aliceSecrets = new Set<string>();
      const bobSecrets = new Set<string>();

      const held = async (into: Set<string>): Promise<StoredSecrets> => {
        const secrets = await acme.secrets();
        if (!secrets) throw new Error("no credential is held");
        for (const value of secrets.values) into.add(value);
        return secrets;
      };
      const noTrace = (secrets: Iterable<string>) => {
        const values = [...secrets];
        expect(scan(acme.state, values)).toEqual([]);
        expect(scan(acme.install, values)).toEqual([]);
        expect(leaks(acme.output(), values)).toEqual([]);
      };

      beforeAll(async () => {
        acme = await installDistribution(stack, { name: "switching" });
      }, 300_000);
      afterAll(() => acme?.remove());

      it("gives Alice both models and keeps the one she picks", async () => {
        const login = await acme.login("alice");
        expect(login.status, login.stderr).toBe(0);
        expect(login.stdout).toContain("Signed in as Alice Engineer");
        const picked = await acme.run([
          "config",
          "set",
          "model",
          "acme/general",
        ]);
        expect(picked.status, picked.stderr).toBe(0);

        aliceSmoke = await acme.smoke();
        expect(aliceSmoke.resumed).toBe(false);
        expect(aliceSmoke.access).toMatchObject({
          identity: { issuer: stack.issuer },
          selectedModel: "acmecode-reference/acme/general",
          allowedModels: ALICE_MODELS,
        });
        alice = await held(aliceSecrets);
        expect(alice.credentialId).toBe(
          aliceSmoke.access.credential.credentialId,
        );
        expect((await gatewayModels(stack, alice.credential)).status).toBe(200);
      });

      it("signs Bob in over Alice, revokes Alice's key and tokens, and gives Bob none of hers", async () => {
        const login = await acme.login("bob");
        expect(login.status, login.stderr).toBe(0);
        expect(login.stdout).toContain("Signed in as Bob Support");

        // Alice's runtime credential is dead at the gateway, gone from it, and
        // her identity session is closed at Keycloak.
        expect((await gatewayModels(stack, alice.credential)).status).toBe(401);
        expect(await gatewayKey(stack, alice.credentialId)).toBeUndefined();
        expect(await refreshTokenStatus(stack, alice.refreshToken)).toEqual({
          status: 400,
          error: "invalid_grant",
        });

        bobSmoke = await acme.smoke();
        bob = await held(bobSecrets);
        expect(bobSmoke.access.identity.subject).not.toBe(
          aliceSmoke.access.identity.subject,
        );
        expect(bobSmoke.access.credential.credentialId).not.toBe(
          alice.credentialId,
        );
        expect(bob.credentialId).toBe(bobSmoke.access.credential.credentialId);
        expect(bob.credential).not.toBe(alice.credential);
        expect(bob.refreshToken).not.toBe(alice.refreshToken);
        // Alice's model selection is gone, and Bob's entitlement applies.
        expect(bobSmoke.access.selectedModel).toBe(
          "acmecode-reference/acme/coder",
        );
        expect(bobSmoke.access.allowedModels).toEqual(BOB_MODELS);
        expect(bobSmoke.access.models).toEqual([
          { id: "acme/coder", available: true },
          { id: "acme/general", available: false, reason: NOT_ENTITLED },
        ]);
        // Nor does Bob resume Alice's session history.
        expect(bobSmoke.resumed).toBe(false);
        expect(bobSmoke.sessionDir).not.toBe(aliceSmoke.sessionDir);

        // The gateway agrees with the entitlement PiShip shows.
        const record = await gatewayKey(stack, bob.credentialId);
        expect([...(record?.models ?? [])]).toEqual(BOB_MODELS);
        const listed = await gatewayModels(stack, bob.credential);
        expect(listed).toMatchObject({ status: 200, models: BOB_MODELS });

        noTrace(aliceSecrets);
        // None of Alice's secrets is left in the file store either. The check
        // finds what is there: the store holds Bob's credential and tokens.
        const stored = fileStoreValues(acme.stateRoot).join("\n");
        expect(leaks(stored, [...aliceSecrets])).toEqual([]);
        if (mode === "file") expect(leaks(stored, bob.values)).toHaveLength(4);
      });

      it("refuses a model Bob is not entitled to, at PiShip and at the gateway", async () => {
        const startup = await acme.run(["--model", "acme/general", "--smoke"]);
        expect(startup.status).toBe(1);
        expect(startup.stderr).toContain("MODEL_UNAVAILABLE");
        expect(startup.stderr).toContain(NOT_ENTITLED);
        expect(startup.stderr).toContain("Choose one of: acme/coder");
        const request = await acme.run([
          "--model",
          "acme/general",
          "--smoke-model",
        ]);
        expect(request.status).toBe(1);
        expect(request.stderr).toContain("MODEL_UNAVAILABLE");

        // The gateway refuses the same request on its own, and serves the model
        // Bob does have.
        expect(
          await gatewayChat(stack, bob.credential, "acme/general"),
        ).toEqual({
          status: 403,
          error: "key_model_access_denied",
        });
        expect(await gatewayChat(stack, bob.credential, "acme/coder")).toEqual({
          status: 200,
          reply: "Reference mock reply from gpt-4.1.",
        });
        const ok = await acme.run(["--smoke-model"]);
        expect(ok.status, ok.stderr).toBe(0);
        expect(JSON.parse(ok.stdout).modelRequest.text).toBe(
          "Reference mock reply from gpt-4.1.",
        );

        // A preference for a model the distribution allows but Bob is not
        // entitled to is accepted, and every launch then refuses it, naming
        // the recovery: PiShip never substitutes another model. The models
        // listing still works, since it uses no selection. Choosing an
        // entitled one recovers.
        expect(
          (await acme.run(["config", "set", "model", "acme/general"])).status,
        ).toBe(0);
        const unavailable = await acme.run(["--smoke"]);
        expect(unavailable.status).toBe(1);
        expect(unavailable.stderr).toContain("MODEL_UNAVAILABLE");
        expect(unavailable.stderr).toContain("config unset model");
        const listing = await acme.run(["models"]);
        expect(listing.status, listing.stderr).toBe(0);
        expect(listing.stdout).toContain("acme/coder");
        expect(
          (await acme.run(["config", "set", "model", "acme/coder"])).status,
        ).toBe(0);
        expect((await acme.smoke()).access.selectedModel).toBe(
          "acmecode-reference/acme/coder",
        );
      });

      it("gives Alice a new credential and her own history when she signs back in", async () => {
        const login = await acme.login("alice");
        expect(login.status, login.stderr).toBe(0);
        const again = await acme.smoke();
        const returned = await held(aliceSecrets);

        // Bob's key and session are dead at the gateway and the provider.
        expect((await gatewayModels(stack, bob.credential)).status).toBe(401);
        expect(await gatewayKey(stack, bob.credentialId)).toBeUndefined();
        expect(await refreshTokenStatus(stack, bob.refreshToken)).toEqual({
          status: 400,
          error: "invalid_grant",
        });

        // A new key, never one of the revoked ones, with Alice's entitlement.
        expect([alice.credentialId, bob.credentialId]).not.toContain(
          returned.credentialId,
        );
        expect([alice.credential, bob.credential]).not.toContain(
          returned.credential,
        );
        expect(again.access.allowedModels).toEqual(ALICE_MODELS);
        // Her earlier model selection was cleared when Bob signed in.
        expect(again.access.selectedModel).toBe(
          "acmecode-reference/acme/coder",
        );
        // Her session history is hers again, and Bob's is not resumed.
        expect(again).toMatchObject({
          resumed: true,
          sessionDir: aliceSmoke.sessionDir,
        });
        noTrace(bobSecrets);
      });

      it("leaves none of either user's secrets after logout", async () => {
        const last = await held(aliceSecrets);
        const logout = await acme.run(["logout"]);
        expect(logout.status, logout.stderr).toBe(0);
        expect((await gatewayModels(stack, last.credential)).status).toBe(401);
        expect(await accessTokenStatus(stack, last.accessToken)).toBe(401);
        expect(await acme.secrets()).toBeUndefined();
        const everything = [...aliceSecrets, ...bobSecrets];
        noTrace(everything);
        expect(fileStoreValues(acme.stateRoot)).toEqual([]);
      });
    });

    describe("the distribution's model list is the upper bound", () => {
      let acme: Installed;

      beforeAll(async () => {
        // A distribution that allows only acme/coder, for a user whose key and
        // gateway both cover acme/general as well.
        acme = await installDistribution(stack, {
          name: "ceiling",
          allowedModels: BOB_MODELS,
        });
      }, 300_000);
      afterAll(() => acme?.remove());

      it("does not widen to what the entitlement and the gateway offer", async () => {
        const login = await acme.login("alice");
        expect(login.status, login.stderr).toBe(0);
        const smoke = await acme.smoke();
        const secrets = await acme.secrets();
        if (!secrets) throw new Error("no credential is held");

        // Alice's key and the gateway's catalog reach acme/general...
        const record = await gatewayKey(stack, secrets.credentialId);
        expect([...(record?.models ?? [])].sort()).toEqual(ALICE_MODELS);
        const listed = await gatewayModels(stack, secrets.credential);
        expect([...listed.models].sort()).toEqual(ALICE_MODELS);
        // ...and the distribution still offers only its own list.
        expect(smoke.access.allowedModels).toEqual(BOB_MODELS);
        expect(smoke.access.models).toEqual([
          { id: "acme/coder", available: true },
        ]);
        const denied = await acme.run(["--model", "acme/general", "--smoke"]);
        expect(denied.status).toBe(1);
        expect(denied.stderr).toContain("MODEL_DENIED");
        const models = await acme.run(["models"]);
        expect(models.stdout).toMatch(
          /^\* acme\/coder\s+Acme Coder\s+available/m,
        );
        expect(models.stdout).not.toContain("acme/general");

        const logout = await acme.run(["logout"]);
        expect(logout.status, logout.stderr).toBe(0);
        expect(scan(acme.state, secrets.values)).toEqual([]);
      });
    });
  },
);
