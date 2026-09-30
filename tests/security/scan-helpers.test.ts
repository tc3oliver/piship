import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RestrictedFileSecretStore } from "@piship/credentials";
import { SecretValue } from "@piship/contracts";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  describeSightings,
  fileStoreSecrets,
  filesUnder,
  scanTree,
  sightings,
} from "../helpers/security.js";

// The security suite is only as good as its scan. These tests show the scan
// finds a secret in every form a real run leaves it in, and stays quiet
// otherwise, so a clean sweep means something.

const SECRET = "fake-secret-SENTINEL-scan-0001";
let temp: string;
beforeEach(() => {
  temp = mkdtempSync(join(tmpdir(), "piship-scan-helpers-"));
});
afterEach(() => {
  rmSync(temp, { recursive: true, force: true });
});

describe("sightings", () => {
  it("finds a secret in plain text", () => {
    const found = sightings("text", `token=${SECRET};`, [SECRET]);
    expect(found).toEqual([
      {
        where: "text",
        secret: "fake-sec…",
        form: "plain",
        // What carried it, with the secret itself masked.
        context: "token=<secret>;",
      },
    ]);
    expect(JSON.stringify(found)).not.toContain(SECRET);
  });

  it.each([
    ["base64url", Buffer.from(SECRET).toString("base64url")],
    ["base64", Buffer.from(SECRET).toString("base64")],
    [
      "base64url inside JSON",
      Buffer.from(JSON.stringify({ accessToken: SECRET })).toString(
        "base64url",
      ),
    ],
  ])("finds a secret inside %s", (_name, encoded) => {
    const found = sightings("text", `{"value":"${encoded}"}`, [SECRET]);
    expect(found.map((hit) => hit.form)).toContain("decoded");
  });

  it("finds nothing in unrelated text, and ignores an empty secret", () => {
    expect(
      sightings(
        "text",
        "nothing to see; QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=",
        [SECRET, ""],
      ),
    ).toEqual([]);
  });
});

describe("scanTree and fileStoreSecrets", () => {
  it("finds a secret the file store holds, which a plain search cannot", async () => {
    const secrets = join(temp, "state", "secrets");
    const store = new RestrictedFileSecretStore(secrets);
    await store.put("piship:demo:inference#1", new SecretValue(SECRET));
    await store.put(
      "piship:demo:identity#1",
      new SecretValue(
        JSON.stringify({
          accessToken: "fake-access-SENTINEL-0002",
          idToken: "fake-id-SENTINEL-0003",
          refreshToken: "fake-refresh-SENTINEL-0004",
        }),
      ),
    );
    const held = fileStoreSecrets(secrets);
    expect(held).toEqual(
      expect.arrayContaining([
        SECRET,
        "fake-access-SENTINEL-0002",
        "fake-id-SENTINEL-0003",
        "fake-refresh-SENTINEL-0004",
      ]),
    );
    // A plain search of the files does not see them: the store encodes every value.
    const raw = filesUnder(secrets)
      .map((path) => readFileSync(path, "utf8"))
      .join("\n");
    expect(held.filter((secret) => raw.includes(secret))).toEqual([]);
    const found = scanTree(join(temp, "state"), held, []);
    expect(describeSightings(found).length).toBeGreaterThanOrEqual(4);
    // The tree holds them; without the store's own directory it is clean.
    expect(scanTree(join(temp, "state"), held)).not.toEqual([]);
    expect(scanTree(join(temp, "state"), held, ["secrets"])).toEqual([]);
  });

  it("reports where a secret was found without printing it", () => {
    mkdirSync(join(temp, "logs"));
    writeFileSync(join(temp, "logs", "audit.jsonl"), `{"note":"${SECRET}"}\n`);
    const [line] = describeSightings(scanTree(temp, [SECRET]));
    expect(line).toContain("audit.jsonl");
    expect(line).not.toContain(SECRET);
  });

  it("treats a missing directory as empty", () => {
    expect(scanTree(join(temp, "absent"), [SECRET])).toEqual([]);
  });
});
