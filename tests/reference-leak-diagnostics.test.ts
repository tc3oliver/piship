import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { inspect } from "node:util";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  leaks,
  scan,
} from "../examples/enterprise-reference/tests/support/distribution.js";
import { scan as lifecycleScan } from "./helpers/lifecycle.js";
import { describeSightings, scanTree } from "./helpers/security.js";

// A leak assertion that fails prints its failure in a public CI log, so it
// must say where and what kind of leak it found and nothing derived from the
// secret. Each test plants fake secrets, makes a real assertion fail, and
// searches everything Vitest printed for the secrets.
//
// Every four consecutive characters of these fakes include a punctuation mark
// that no label, file name, or temporary path contains, so finding four of
// their characters in a failure means the failure printed part of a secret,
// never a coincidence.
const SECRETS = [
  "Zq!7Kp~2Xw!9Mv~4Hd!3Jt~8Rc!",
  "Lc~5Ny!8Rt~1Bg!6Fs~0Wa!7Qe~",
  "Xb!4Vk~9Pz!2Gm~6Td!1Hn~5Jy!",
];
const [ACCESS_TOKEN, ID_TOKEN, REFRESH_TOKEN] = SECRETS as [
  string,
  string,
  string,
];

/** Every substring of four characters of a secret: each longer substring holds one. */
const fragments = (secret: string) =>
  Array.from({ length: secret.length - 3 }, (_, at) =>
    secret.slice(at, at + 4),
  );

/** Everything Vitest shows of a failed assertion: message, diff, and the values it carries. */
function shown(assertion: () => void): string {
  try {
    assertion();
  } catch (error) {
    return `${(error as Error).message}\n${inspect(error, { depth: 6 })}`;
  }
  throw new Error("the assertion was expected to fail");
}

function expectNoSecretIn(output: string) {
  for (const secret of SECRETS) {
    expect(output.includes(secret), "a whole secret was printed").toBe(false);
    const printed = fragments(secret).filter((piece) => output.includes(piece));
    // Never print what was found: that would print it once more.
    expect(printed.length, "part of a secret was printed").toBe(0);
  }
}

let temp: string;
beforeEach(() => {
  temp = mkdtempSync(join(tmpdir(), "piship-leak-diagnostics-"));
});
afterEach(() => {
  rmSync(temp, { recursive: true, force: true });
});

/** A tree with a secret in a file, and the encoded form the file store keeps in another. */
function plant() {
  mkdirSync(join(temp, "state", "logs"), { recursive: true });
  writeFileSync(
    join(temp, "state", "logs", "audit.jsonl"),
    `{"note":"token=${ACCESS_TOKEN}"}\n`,
  );
  writeFileSync(join(temp, "state", "kept.txt"), `${REFRESH_TOKEN}\n`);
  writeFileSync(
    join(temp, "state", "encoded.json"),
    JSON.stringify({ value: Buffer.from(ID_TOKEN).toString("base64url") }),
  );
  return join(temp, "state");
}

describe("the reference leak assertions", () => {
  it("leaks() names which of the given secrets leaked, and prints nothing of them", () => {
    const text = `output ${ID_TOKEN} and ${ACCESS_TOKEN} again`;
    expect(leaks(text, SECRETS)).toEqual(["secret #1", "secret #2"]);
    const failure = shown(() => expect(leaks(text, SECRETS)).toEqual([]));
    // What is needed to debug: which of the secrets, in the order it was given.
    expect(failure).toContain("secret #1");
    expect(failure).toContain("secret #2");
    expect(failure).not.toContain("secret #3");
    expectNoSecretIn(failure);
  });

  it("leaks() ignores an empty secret and finds nothing in clean text", () => {
    expect(leaks("nothing here", ["", ...SECRETS])).toEqual([]);
  });

  it("scan() names the file and that it holds a protected secret, and prints nothing of it", () => {
    const state = plant();
    const found = scan(state, SECRETS);
    expect(found).toHaveLength(2);
    expect(found).toContain(
      `${join(state, "logs", "audit.jsonl")} contains protected secret #1`,
    );
    expect(found).toContain(
      `${join(state, "kept.txt")} contains protected secret #3`,
    );
    const failure = shown(() => expect(scan(state, SECRETS)).toEqual([]));
    expect(failure).toContain("audit.jsonl");
    expect(failure).toContain("protected secret");
    expectNoSecretIn(failure);
  });

  it("scan() skips the file store's own directory, as before", () => {
    mkdirSync(join(temp, "secrets"));
    writeFileSync(join(temp, "secrets", "a.secret"), ACCESS_TOKEN);
    expect(scan(temp, SECRETS)).toEqual([]);
  });
});

describe("the other leak assertions of the test suites", () => {
  it("describeSightings() names where a secret was found and in what form, and prints nothing of it", () => {
    const state = plant();
    const found = describeSightings(scanTree(state, SECRETS));
    expect(found).toHaveLength(3);
    const failure = shown(() => expect(found).toEqual([]));
    expect(failure).toContain("audit.jsonl");
    expect(failure).toContain("encoded.json");
    expect(failure).toContain("(plain)");
    expect(failure).toContain("(decoded)");
    expect(failure).toContain("secret #1");
    expectNoSecretIn(failure);
  });

  it("the lifecycle scan names the file, and prints nothing of the secret", () => {
    const state = plant();
    const found = lifecycleScan(state, SECRETS);
    expect(found.length).toBeGreaterThan(0);
    const failure = shown(() => expect(found).toEqual([]));
    expect(failure).toContain("audit.jsonl");
    expectNoSecretIn(failure);
  });
});
