import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  cliPath,
  fileStoreValues,
  type Installed,
  installDistribution,
  leaks,
  scan,
  storeDescription,
  storeMode,
} from "./support/distribution.js";
import {
  accessTokenStatus,
  gatewayDeleteKey,
  gatewayKey,
  gatewayModels,
  refreshTokenStatus,
  upstreamRequests,
} from "./support/services.js";
import { referenceDirectory, type Stack, startStack } from "./support/stack.js";

// The AcmeCode reference distribution against the live reference stack, for one
// user: build, install, sign in on the real Keycloak authorization page,
// exchange the identity for a scoped credential at the reference broker, keep
// it in the secret store, discover models, send a request through LiteLLM,
// renew a credential the gateway rejected, and sign out. Needs Docker; run with
// `npm run test:reference` after `npm run build`.
//
// The tests follow one user's session in order, so a failure early on makes
// the later ones fail too: fix the first failure first.

const mode = storeMode();
const backend = storeDescription(mode);
const ALICE_MODELS = ["acme/coder", "acme/general"];
const escaped = (text: string) =>
  text.replace(/[.*+?^${}()|[\]\\]/g, (character) => `\\${character}`);

describe.skipIf(process.platform === "win32")(
  "AcmeCode on the reference stack",
  () => {
    let stack: Stack;
    let acme: Installed;
    // Every secret PiShip held at any point, for the leak scans.
    const seen = new Set<string>();
    const remember = async () => {
      const held = await acme.secrets();
      for (const value of held?.values ?? []) seen.add(value);
      return held;
    };

    beforeAll(async () => {
      console.info(
        mode === "system"
          ? `secret store under test: ${backend} (PISHIP_LIVE_SECRET_STORE=1)`
          : `secret store under test: ${backend} (the platform store runs with PISHIP_LIVE_SECRET_STORE=1)`,
      );
      stack = await startStack();
      acme = await installDistribution(stack, { name: "flow" });
    }, 600_000);

    afterAll(() => {
      acme?.remove();
      stack?.stop();
    }, 120_000);

    it("builds from the committed lock, which keeps templates and no secret", () => {
      const lock = readFileSync(
        join(referenceDirectory, "piship.lock"),
        "utf8",
      );
      expect(lock).toContain(`\${ACMECODE_OIDC_ISSUER}`);
      expect(lock).toContain(`\${ACMECODE_LLM_GATEWAY_URL}`);
      expect(lock).not.toContain(stack.issuer);
      expect(lock).not.toContain(stack.gatewayUrl);
      expect(lock).not.toMatch(/sk-[0-9a-f]{16}/);
      // `piship build` refuses a lock that no longer matches the manifest and
      // its resources, so this builds exactly what is committed.
      const out = mkdtempSync(join(tmpdir(), "piship-reference-committed-"));
      try {
        const built = spawnSync(
          process.execPath,
          [cliPath, "build", join(referenceDirectory, "piship.yaml")],
          { cwd: out, env: acme.env, encoding: "utf8" },
        );
        expect(built.status, built.stderr).toBe(0);
        expect(built.stderr).not.toContain("stale");
        expect(existsSync(join(out, "dist", "acmecode", "piship.mjs"))).toBe(
          true,
        );
      } finally {
        rmSync(out, { recursive: true, force: true });
      }
    });

    it("is installed, and refuses to launch before sign-in", async () => {
      const version = await acme.run(["version"]);
      expect(version.stdout).toContain("AcmeCode 1.0.0");
      const before = await acme.run(["--smoke"]);
      expect(before.status).toBe(1);
      expect(before.stderr).toContain("IDENTITY_REQUIRED");
      expect(before.stderr).toContain("acmecode login");
    });

    it("signs Alice in on the Keycloak authorization page with PKCE and a loopback redirect", async () => {
      const login = await acme.login("alice");
      expect(login.status, login.stderr).toBe(0);
      expect(login.stdout).toContain(
        `Signed in as Alice Engineer (${stack.issuer})`,
      );
      expect(login.authorization).toMatchObject({
        clientId: "acmecode",
        responseType: "code",
        codeChallengeMethod: "S256",
        hasState: true,
        hasNonce: true,
      });
      expect(login.authorization.scope?.split(" ")).toContain("openid");
      // The manifest registers a port-less loopback URI; PiShip picks the port.
      expect(login.authorization.redirectUri).toMatch(
        /^http:\/\/127\.0\.0\.1:[1-9]\d{3,4}\/callback$/,
      );
      const principal = JSON.parse(
        readFileSync(
          join(acme.stateRoot, "identity", "principal.json"),
          "utf8",
        ),
      );
      expect(principal.issuer).toBe(stack.issuer);
      expect(principal.subject).toMatch(/^[0-9a-f-]{36}$/);
    });

    it(`exchanges the identity for a credential scoped to Alice's models and stores it in the secret store (${backend})`, async () => {
      const first = await acme.smoke();
      expect(first.resumed).toBe(false);
      expect(first.access).toMatchObject({
        identity: { issuer: stack.issuer },
        credential: { mode: "http-broker" },
        selectedModel: "acmecode/acme/coder",
        allowedModels: ALICE_MODELS,
      });
      const { credentialId, expiresAt } = first.access.credential;
      expect(credentialId).toMatch(/^pb-[0-9a-f]{24}$/);
      const lifetime = Date.parse(expiresAt ?? "") - Date.now();
      expect(lifetime).toBeGreaterThan(60 * 60 * 1000);
      expect(lifetime).toBeLessThanOrEqual(24 * 60 * 60 * 1000);
      expect(first.access.removedEnvironment).toEqual(
        expect.arrayContaining(["OPENAI_API_KEY", "ANTHROPIC_API_KEY"]),
      );

      // What the broker asked the gateway for, read from the gateway itself.
      const record = await gatewayKey(stack, credentialId);
      expect(record).toMatchObject({
        models: expect.arrayContaining(ALICE_MODELS),
        teamId: null,
        metadata: { issued_by: "piship-reference-broker" },
      });
      expect([...(record?.models ?? [])].sort()).toEqual(ALICE_MODELS);
      expect(record?.userId).toMatch(/^oidc-[0-9a-f]{40}$/);

      // The stored credential is the key the gateway knows, and only that.
      const held = await remember();
      expect(held?.credentialId).toBe(credentialId);
      const listed = await gatewayModels(stack, held?.credential ?? "");
      expect(listed.status).toBe(200);
      expect([...listed.models].sort()).toEqual(ALICE_MODELS);

      const doctor = await acme.run(["doctor"]);
      expect(doctor.stdout).toMatch(
        new RegExp(`Secret Store\\n {2}[✓!] backend\\s+${backend}`),
      );
      // The file store holds the identity bundle and the credential; the
      // platform store leaves no secret file in the state directory.
      const directory = join(acme.stateRoot, "secrets");
      const files = existsSync(directory) ? readdirSync(directory) : [];
      expect(files).toHaveLength(mode === "file" ? 2 : 0);
    });

    it("lists the models Alice is entitled to", async () => {
      const models = await acme.run(["models"]);
      expect(models.status, models.stderr).toBe(0);
      expect(models.stdout).toMatch(
        /^\* acme\/coder\s+Acme Coder\s+available/m,
      );
      expect(models.stdout).toMatch(
        /^ {2}acme\/general\s+Acme General\s+available/m,
      );
    });

    it("sends a model request through LiteLLM with the brokered credential", async () => {
      expect((await acme.smoke()).resumed).toBe(true);
      const request = await acme.run(["--smoke-model"]);
      expect(request.status, request.stderr).toBe(0);
      expect(JSON.parse(request.stdout).modelRequest).toMatchObject({
        model: "acmecode/acme/coder",
        text: "Reference mock reply from gpt-4.1.",
        stopReason: "stop",
      });
      // Alice may pick the other model she is entitled to.
      const general = await acme.run([
        "--model",
        "acme/general",
        "--smoke-model",
      ]);
      expect(general.status, general.stderr).toBe(0);
      expect(JSON.parse(general.stdout).modelRequest).toMatchObject({
        model: "acmecode/acme/general",
        text: "Reference mock reply from gpt-4.1-mini.",
      });
      // The upstream saw both requests, as streams, after LiteLLM mapped the
      // gateway model names to its own.
      const upstream = await upstreamRequests(stack);
      expect(upstream.slice(-2)).toMatchObject([
        { model: "gpt-4.1", stream: true, status: 200 },
        { model: "gpt-4.1-mini", stream: true, status: 200 },
      ]);
    });

    it("renews a credential the gateway rejected", async () => {
      const before = await remember();
      if (!before) throw new Error("no credential is held");
      await gatewayDeleteKey(stack, before.credentialId);
      expect((await gatewayModels(stack, before.credential)).status).toBe(401);

      const renewed = await acme.run(["--smoke-model"]);
      expect(renewed.status, renewed.stderr).toBe(0);
      const result = JSON.parse(renewed.stdout);
      expect(result.access.credential.credentialId).not.toBe(
        before.credentialId,
      );
      expect(result.access.notices).toContain(
        "The gateway rejected the stored credential; a new credential was acquired",
      );
      expect(result.modelRequest.text).toBe(
        "Reference mock reply from gpt-4.1.",
      );
      const after = await remember();
      expect(after?.credential).not.toBe(before.credential);
      expect((await gatewayModels(stack, after?.credential ?? "")).status).toBe(
        200,
      );
    });

    it("reports the identity, credential, gateway, and secret store in doctor", async () => {
      const doctor = await acme.run(["doctor"]);
      expect(doctor.status, doctor.stdout + doctor.stderr).toBe(0);
      expect(doctor.stdout).toMatch(
        new RegExp(
          `Identity\\n {2}✓ mode\\s+oidc\\n {2}✓ session\\s+signed in\\n {2}✓ issuer\\s+${escaped(stack.issuer)}`,
        ),
      );
      expect(doctor.stdout).toMatch(/Credential\n {2}✓ provider\s+http-broker/);
      expect(doctor.stdout).toMatch(/✓ valid\s+\d+m remaining/);
      expect(doctor.stdout).toMatch(
        /Gateway\n(?: {2}.*\n)*? {2}✓ gateway\s+reachable \(2 listed\)/,
      );
      expect(doctor.stdout).toMatch(
        new RegExp(`Secret Store\\n {2}[✓!] backend\\s+${backend}`),
      );
      expect(doctor.stdout).toMatch(
        /✓ outbound\s+private-only: declared hosts only \(127\.0\.0\.1\)/,
      );
    });

    it("keeps every secret out of the state directory, install home, artifact metadata, and output", async () => {
      const held = await remember();
      expect(seen.size).toBeGreaterThanOrEqual(5);
      expect(scan(acme.state, [...seen])).toEqual([]);
      expect(scan(acme.install, [...seen])).toEqual([]);
      expect(scan(join(acme.artifact, "metadata"), [...seen])).toEqual([]);
      expect(leaks(acme.output(), [...seen])).toEqual([]);
      expect(held?.credentialId).toBeTruthy();
      // The check finds what is there: the file store holds these secrets
      // (the credential and the three identity tokens).
      if (mode === "file")
        expect(
          leaks(fileStoreValues(acme.stateRoot).join("\n"), held?.values ?? []),
        ).toHaveLength(4);
    });

    it("signs out: revokes the credential and the identity tokens, and clears the secret store", async () => {
      const held = await remember();
      if (!held) throw new Error("no credential is held");
      const logout = await acme.run(["logout"]);
      expect(logout.status, logout.stderr).toBe(0);
      expect(logout.stdout).toContain("Signed out of AcmeCode.");

      // At the gateway, at the identity provider, and locally.
      expect((await gatewayModels(stack, held.credential)).status).toBe(401);
      expect(await gatewayKey(stack, held.credentialId)).toBeUndefined();
      expect(await accessTokenStatus(stack, held.accessToken)).toBe(401);
      expect(await refreshTokenStatus(stack, held.refreshToken)).toEqual({
        status: 400,
        error: "invalid_grant",
      });
      expect(await acme.secrets()).toBeUndefined();
      expect(fileStoreValues(acme.stateRoot)).toEqual([]);
      // Sessions are kept, and the next launch needs a new sign-in.
      expect(existsSync(join(acme.stateRoot, "sessions"))).toBe(true);
      expect((await acme.run(["--smoke"])).stderr).toContain(
        "IDENTITY_REQUIRED",
      );

      expect(scan(acme.state, [...seen])).toEqual([]);
      expect(scan(acme.install, [...seen])).toEqual([]);
      expect(leaks(acme.output(), [...seen])).toEqual([]);
    });
  },
);
