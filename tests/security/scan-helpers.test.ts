import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SecretValue } from "@piship/contracts";
import { RestrictedFileSecretStore } from "@piship/credentials";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  describeSightings,
  fileStoreSecrets,
  filesUnder,
  MAX_DECODED_BYTES,
  scanTree,
  scanTreeReport,
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

  it("masks a second secret the context window would cut in half", () => {
    const other = "fake-other-SENTINEL-scan-0002";
    const padding = "x".repeat(70);
    const [hit] = sightings("text", `${SECRET}${padding}${other}`, [
      SECRET,
      other,
    ]);
    expect(hit?.context).toBe(`<secret>${padding}<secret>`);
    expect(hit?.context).not.toContain("fake-other");
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

  it.each([0, 1, 2, 3])(
    "finds a secret whose encoding is glued to an identifier, %i characters off a base64 boundary",
    (glue) => {
      // `request_id` and the like run straight into the encoded value.
      const encoded = Buffer.from(SECRET).toString("base64url");
      const found = sightings("text", `${"i".repeat(glue)}${encoded}`, [
        SECRET,
      ]);
      expect(found.map((hit) => hit.form)).toContain("decoded");
    },
  );

  it("finds the shortest secret the ledger tracks, in its shortest encoded form", () => {
    const short = "s3cr3tK!";
    const found = sightings(
      "text",
      `{"v":"${Buffer.from(short).toString("base64url")}"}`,
      [short],
    );
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
    const found = scanTree(join(temp, "state"), held);
    expect(describeSightings(found).length).toBeGreaterThanOrEqual(4);
    // The tree holds them; without the store's own directory it is clean.
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

  it("skips a directory by its path, not by a name that any other directory may share", () => {
    mkdirSync(join(temp, "state", "secrets"), { recursive: true });
    mkdirSync(join(temp, "resources", "secrets"), { recursive: true });
    mkdirSync(join(temp, "node_modules", "pkg"), { recursive: true });
    for (const where of [
      join(temp, "state", "secrets", "a.txt"),
      join(temp, "resources", "secrets", "b.txt"),
      join(temp, "node_modules", "pkg", "c.txt"),
    ])
      writeFileSync(where, SECRET);
    const found = scanTree(temp, [SECRET], ["state/secrets"]).map((hit) =>
      hit.where.slice(temp.length + 1),
    );
    // Only the named path and node_modules are left out.
    expect(found).toEqual([join("resources", "secrets", "b.txt")]);
  });

  it("does not follow a symbolic link, so a directory loop ends", () => {
    mkdirSync(join(temp, "a"));
    writeFileSync(join(temp, "a", "file.txt"), SECRET);
    symlinkSync(temp, join(temp, "a", "loop"));
    symlinkSync(join(temp, "a", "file.txt"), join(temp, "a", "link.txt"));
    expect(filesUnder(temp)).toEqual([join(temp, "a", "file.txt")]);
    expect(scanTree(temp, [SECRET])).toHaveLength(1);
  });

  it("lists the files too large to decode, which it searched in plain form only", () => {
    const big = join(temp, "big.log");
    writeFileSync(
      big,
      `${"y".repeat(MAX_DECODED_BYTES)}${Buffer.from(SECRET).toString("base64url")}`,
    );
    const small = join(temp, "small.log");
    writeFileSync(small, Buffer.from(SECRET).toString("base64url"));
    const { found, plainOnly } = scanTreeReport(temp, [SECRET]);
    expect(plainOnly).toEqual([big]);
    // The small file's encoded secret is found; the big file's is not, and
    // the report says why.
    expect(found.map((hit) => hit.where)).toEqual([small]);
  });
});
