// PiShip's credential broker service kit (`testCredentialBroker` from
// packages/adapter-conformance, built in this repository: `npm run build` at
// the root first) against the reference broker, the way a company runs it
// against its own broker. PISHIP_REPO_ROOT may point at another checkout's
// root.
//
//   node --test test/
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { startHarness } from "./harness.mjs";

const root = resolve(
  process.env.PISHIP_REPO_ROOT ??
    join(dirname(fileURLToPath(import.meta.url)), "../../../.."),
);
const kitsDist = join(root, "packages/adapter-conformance/dist/index.js");
if (!existsSync(kitsDist))
  throw new Error(
    `PiShip packages are not built under ${root}: run "npm ci && npm run build" at the repository root`,
  );
const { testCredentialBroker } = await import(pathToFileURL(kitsDist).href);

describe("the credential broker service kit against the reference broker", () => {
  let h;
  before(async () => {
    h = await startHarness();
  });
  after(() => h.close());

  it("passes every behavior and leaves no key behind", async () => {
    const report = await testCredentialBroker({
      endpoint: `${h.url}/v1/credential`,
      revokeEndpoint: `${h.url}/v1/revoke`,
      distribution: "acmecode",
      identityToken: () => h.keycloak.mint(),
    });
    assert.deepEqual(
      report.results.filter((result) => result.status !== "passed"),
      [],
    );
    assert.equal(h.litellm.keys.size, 0);
  });
});
