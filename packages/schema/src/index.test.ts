import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { redact } from "@piship/contracts";
import { parseDocument } from "yaml";
import { describe, expect, it } from "vitest";
import {
  ManifestError,
  PISHIP_SCHEMA_V1,
  PISHIP_SCHEMA_V1ALPHA6,
  PISHIP_SCHEMA_VERSION,
  parseManifest,
  parseManifestHeader,
  readManifest,
} from "./index.js";
const valid = {
  schema: PISHIP_SCHEMA_VERSION,
  app: { id: "mypi", name: "My Pi", command: "mypi", version: "0.1.0" },
  runtime: { pi: "1.0.3" },
  deployment: { mode: "personal" },
};
const validV6 = {
  ...valid,
  schema: PISHIP_SCHEMA_V1ALPHA6,
  updates: { channel: "stable", channels: ["stable"] },
};
describe("alpha manifest", () => {
  it("accepts the minimal distribution", () => {
    expect(parseManifest(valid).resources.skills).toEqual([]);
    expect(parseManifestHeader(valid)).toEqual({
      schema: PISHIP_SCHEMA_VERSION,
    });
  });
  it("allows ordinary words that resemble credential names", () => {
    expect(
      parseManifest({ ...valid, app: { ...valid.app, name: "Secret Agent" } })
        .app.name,
    ).toBe("Secret Agent");
  });
  it.each(["1.0.0", "1.2.3-alpha.1", "1.2.3+build.5", "1.2.3-alpha.1+build.5"])(
    "accepts SemVer 2.0.0 version %s",
    (version) => {
      expect(
        parseManifest({ ...valid, app: { ...valid.app, version } }).app.version,
      ).toBe(version);
    },
  );
  it.each(["1.2.3-", "1.2.3-alpha..1", "1.2.3-01", "1.2.3+", "01.2.3"])(
    "rejects invalid SemVer version %s",
    (version) => {
      expect(() =>
        parseManifest({ ...valid, app: { ...valid.app, version } }),
      ).toThrow("app.version");
    },
  );
  it.each([
    [{ ...valid, schema: "piship/v2" }, "schema mismatch"],
    [
      { ...valid, app: { name: "My Pi", command: "mypi", version: "0.1.0" } },
      "app.id",
    ],
    [{ ...valid, app: { ...valid.app, command: "../pi" } }, "app.command"],
    [{ ...valid, runtime: { pi: "latest" } }, "runtime.pi"],
    [
      { ...valid, resources: { skills: ["./../outside"] } },
      "resources.skills[0]",
    ],
    [{ ...valid, app: { ...valid.app, apiKey: "secret" } }, "app.apiKey"],
    [{ ...valid, app: { ...valid.app, theme: "../unsafe" } }, "app.theme"],
    [
      { ...valid, resources: { themes: ["../unsafe.json"] } },
      "resources.themes[0]",
    ],
    [
      { ...valid, app: { ...valid.app, banner: "unsafe\noutput" } },
      "app.banner",
    ],
    [
      { ...valid, app: { ...valid.app, name: "$" + "{SECRET_NAME}" } },
      "app.name",
    ],
    [{ ...valid, deployment: { mode: "managed" } }, "deployment.mode"],
    [
      {
        ...validV6,
        runtime: { pi: "1.0.3", verifyAtLaunch: "yes" },
      },
      "runtime.verifyAtLaunch",
    ],
  ])("rejects invalid fields with location", (input, expected) => {
    expect(() => parseManifest(input)).toThrow(expected);
  });
});

describe("runtime.verifyAtLaunch", () => {
  it.each([
    [true, true],
    [false, false],
  ] as const)(
    "accepts verifyAtLaunch %s and preserves it",
    (input, expected) => {
      expect(
        parseManifest({
          ...validV6,
          runtime: { pi: "1.0.3", verifyAtLaunch: input },
        }).runtime.verifyAtLaunch,
      ).toBe(expected);
    },
  );
  it("leaves verifyAtLaunch undefined when the field is absent", () => {
    expect(parseManifest(validV6).runtime.verifyAtLaunch).toBeUndefined();
  });
  it("reports Expected true or false on a non-boolean value", () => {
    const message = messageOf(() =>
      parseManifest({
        ...validV6,
        runtime: { pi: "1.0.3", verifyAtLaunch: "yes" },
      }),
    );
    expect(message).toContain("runtime.verifyAtLaunch");
    expect(message).toContain("Expected true or false");
  });
});

// Built at runtime so no scanner flags the fixtures themselves.
const fakeSecrets = {
  openai: ["sk", "proj", "A1b2C3d4E5f6G7h8"].join("-"),
  github: ["ghp", "A1b2C3d4E5f6G7h8I9j0"].join("_"),
  jwt: ["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiJ4In0", "c2lnbmF0dXJl"].join("."),
  aws: `AKIA${"ABCDEFGHIJKLMNOP"}`,
  key: `-----BEGIN ${"PRIVATE"} KEY-----`,
  bearer: `Bearer ${"abc123def456ghi"}`,
};
function messageOf(action: () => unknown): string {
  try {
    action();
  } catch (error) {
    expect(error).toBeInstanceOf(ManifestError);
    return (error as Error).message;
  }
  throw new Error("expected a ManifestError");
}
const example = (name: string) =>
  fileURLToPath(
    new URL(`../../../examples/${name}/piship.yaml`, import.meta.url),
  );
describe("secret-looking values", () => {
  it.each(Object.entries(fakeSecrets))(
    "rejects a %s value in app.banner without echoing it",
    (_kind, secret) => {
      const message = messageOf(() =>
        parseManifest({ ...valid, app: { ...valid.app, banner: secret } }),
      );
      expect(message).toContain("app.banner");
      expect(message).toContain("looks like secret material");
      expect(message).not.toContain(secret);
    },
  );
  it("scans every string scalar, including nested lists and catalog entries", () => {
    const managed = parseDocument(
      readFileSync(example("demo-company"), "utf8"),
    ).toJS() as {
      models: { catalog: Record<string, { name: string }> };
    };
    const coder = managed.models.catalog["acme/coder"];
    if (!coder) throw new Error("demo catalog changed");
    coder.name = fakeSecrets.openai;
    const catalog = messageOf(() => parseManifest(managed));
    expect(catalog).toContain("models.catalog.acme/coder.name");
    expect(catalog).not.toContain(fakeSecrets.openai);
    const nested = {
      ...valid,
      resources: { skills: ["./resources/skills", fakeSecrets.github] },
    };
    const list = messageOf(() => parseManifest(nested));
    expect(list).toContain("resources.skills[1]");
    expect(list).not.toContain(fakeSecrets.github);
  });
  it("rejects a secret-looking mapping key without echoing it", () => {
    const message = messageOf(() =>
      parseManifest({
        ...valid,
        app: { ...valid.app, [fakeSecrets.github]: "x" },
      }),
    );
    expect(message).toContain("at app");
    expect(message).not.toContain(fakeSecrets.github);
  });
  it.each([
    "Basic Agent",
    "Bearer of good news",
    "Task-runner sketch",
    "risk-assessment helper",
  ])("accepts ordinary display text %s", (name) => {
    expect(
      parseManifest({ ...valid, app: { ...valid.app, name } }).app.name,
    ).toBe(name);
  });
  it.each(["sk-helper", "sk-learning-assistant", "desk-tools"])(
    "accepts the ordinary id %s",
    (id) => {
      expect(
        parseManifest({ ...valid, app: { ...valid.app, id, command: id } }).app
          .id,
      ).toBe(id);
    },
  );
  it("accepts both shipped examples", () => {
    expect(readManifest(example("personal")).app.id).toBe("mypi");
    expect(readManifest(example("demo-company")).schema).toBe(PISHIP_SCHEMA_V1);
  });
});
describe("secret-named unknown fields", () => {
  it.each([
    ["inference", "apiKey"],
    ["app", "password"],
    ["app", "clientSecret"],
    ["runtime", "token"],
  ])("reports %s.%s readably after redaction", (section, key) => {
    const input = {
      ...valid,
      schema: "piship/v1alpha2",
      identity: { mode: "none" },
      credential: { provider: "pi-native" },
      inference: { provider: "pi-native" },
    } as Record<string, unknown>;
    input[section] = {
      ...(input[section] as object),
      [key]: "plain-value-123",
    };
    const message = redact(messageOf(() => parseManifest(input)));
    expect(message).toContain(`${section}.${key}`);
    expect(message).toContain(
      "Unknown field; secrets are not allowed in piship.yaml",
    );
    expect(message).not.toContain("REDACTED");
    expect(message).not.toContain("plain-value-123");
  });
  it("keeps other secret-named field diagnostics readable after redaction", () => {
    const message = redact(
      messageOf(() =>
        parseManifest({
          ...valid,
          schema: "piship/v1alpha2",
          identity: { mode: "none" },
          credential: { provider: "pi-native", apiKey: "plain-value-123" },
          inference: { provider: "pi-native" },
        }),
      ),
    );
    expect(message).toContain("credential.apiKey");
    expect(message).toContain("Secrets are never declared");
    expect(message).not.toContain("REDACTED");
    expect(message).not.toContain("plain-value-123");
  });
});
