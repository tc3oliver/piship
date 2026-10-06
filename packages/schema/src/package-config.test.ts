// What a Pi package is given around its code (piship/v1alpha6, additive):
// `resources.packages[].environment` and `.agentFiles`, and a capability
// provider that is a declared package.
import { describe, expect, it } from "vitest";
import {
  type Manifest,
  ManifestError,
  PISHIP_SCHEMA_V1ALPHA5,
  PISHIP_SCHEMA_V1ALPHA6,
  parseManifest,
} from "./index.js";

type Json = Record<string, unknown>;

const INTEGRITY = `sha256-${"b".repeat(64)}`;
const CONFIG_FILE = "extensions/permissions/config.json";
// Any exact version: the manifest and the certified evidence only have to agree.
const PI = "1.0.0";

function base(extra: Json = {}): Json {
  return {
    schema: PISHIP_SCHEMA_V1ALPHA6,
    app: {
      id: "devcode",
      name: "DevCode",
      command: "devcode",
      version: "1.0.0",
    },
    runtime: { pi: PI },
    deployment: { mode: "personal" },
    updates: { channel: "stable", channels: ["stable"] },
    ...extra,
  };
}

function pkg(extra: Json = {}): Json {
  return {
    id: "tools",
    source: "npm",
    package: "pi-tools",
    version: "1.0.0",
    class: "user",
    ...extra,
  };
}

function withPackages(...packages: Json[]): Json {
  return base({ resources: { packages } });
}

function parsed(input: Json): Manifest {
  return parseManifest(input);
}

function rejects(input: Json, field: string, message?: string): void {
  let error: unknown;
  try {
    parseManifest(input);
  } catch (caught) {
    error = caught;
  }
  expect(error).toBeInstanceOf(ManifestError);
  expect((error as ManifestError).field).toBe(field);
  if (message) expect((error as ManifestError).message).toContain(message);
}

describe("package environment", () => {
  it("allows only the owning npm package to set its Pi-prefixed variables", () => {
    for (const [name, variable] of [
      ["pi-lens", "PI_LENS_HOME"],
      ["pi-background-tasks", "PI_BG_FEATURES"],
    ] as const) {
      expect(
        parsed(
          withPackages(
            pkg({ package: name, environment: { [variable]: "1" } }),
          ),
        ).governance,
      ).toBeDefined();
      rejects(
        withPackages(pkg({ environment: { [variable]: "1" } })),
        `resources.packages[0].environment.${variable}`,
      );
    }
  });
  it("parses literals and state paths, and is absent when not declared", () => {
    const manifest = parsed(
      withPackages(
        pkg({
          environment: {
            APP_BG_FEATURES: "process",
            APP_LENS_HOME: { statePath: "pi-lens/home" },
          },
        }),
        pkg({ id: "plain", package: "pi-plain" }),
      ),
    );
    const [first, second] = manifest.governance?.resources.packages ?? [];
    expect(first?.environment).toEqual({
      APP_BG_FEATURES: "process",
      APP_LENS_HOME: { statePath: "pi-lens/home" },
    });
    // An existing manifest keeps its parsed shape, so its digest.
    expect(second).not.toHaveProperty("environment");
    expect(second).not.toHaveProperty("agentFiles");
  });

  it.each([
    ["PATH", "PATH"],
    ["HOME", "HOME"],
    ["lowercase_name", "lowercase_name"],
    ["PISHIP_STATE_HOME", "PISHIP_STATE_HOME"],
    ["PI_CODING_AGENT_DIR", "PI_CODING_AGENT_DIR"],
    ["PI_OFFLINE", "PI_OFFLINE"],
    ...[
      "PI_PACKAGE_DIR",
      "PI_MANAGED_INSTALL_ROOT",
      "PI_INSTALLER_API_BASE",
      "PI_RADIUS_GATEWAY",
      "PI_SHARE_VIEWER_URL",
      "PI_EXPERIMENTAL",
      "PI_CODING_AGENT",
      "ELECTRON_RUN_AS_NODE",
      "BASH_ENV",
      "PROMPT_COMMAND",
      "XDG_CONFIG_HOME",
      "JDK_JAVA_OPTIONS",
    ].map((name) => [name, name]),
    ["NODE_OPTIONS", "NODE_OPTIONS"],
    ["NODE_EXTRA_CA_CERTS", "NODE_EXTRA_CA_CERTS"],
    ["LD_PRELOAD", "LD_PRELOAD"],
    ["DYLD_INSERT_LIBRARIES", "DYLD_INSERT_LIBRARIES"],
    ["HTTPS_PROXY", "HTTPS_PROXY"],
    ["ALL_PROXY", "ALL_PROXY"],
    ["SSL_CERT_FILE", "SSL_CERT_FILE"],
    ["GIT_CONFIG_GLOBAL", "GIT_CONFIG_GLOBAL"],
    ["NPM_CONFIG_REGISTRY", "NPM_CONFIG_REGISTRY"],
  ])("refuses the reserved or malformed name %s", (name) => {
    rejects(
      withPackages(pkg({ environment: { [name]: "1" } })),
      `resources.packages[0].environment.${name}`,
    );
  });

  it.each([
    "OPENAI_API_KEY",
    "GITHUB_TOKEN",
    "SERVICE_PASSWORD",
    "AWS_SECRET_THING",
  ])("refuses the credential-looking name %s", (name) => {
    rejects(
      withPackages(pkg({ environment: { [name]: "x" } })),
      `resources.packages[0].environment.${name}`,
      "secret",
    );
  });

  it("refuses values that are not plain, non-secret strings", () => {
    rejects(
      withPackages(pkg({ environment: { APP_A_FLAG: 1 } })),
      "resources.packages[0].environment.APP_A_FLAG",
      "quote",
    );
    rejects(
      withPackages(pkg({ environment: { APP_A_FLAG: true } })),
      "resources.packages[0].environment.APP_A_FLAG",
      "quote",
    );
    rejects(
      // biome-ignore lint/suspicious/noTemplateCurlyInString: the manifest's own variable syntax is what this rejects
      withPackages(pkg({ environment: { APP_A_FLAG: "${HOME}" } })),
      "resources.packages[0].environment.APP_A_FLAG",
    );
    rejects(
      withPackages(pkg({ environment: { APP_A_FLAG: "sk-abcdef123456" } })),
      "resources.packages[0].environment.APP_A_FLAG",
      "secret",
    );
    rejects(
      withPackages(pkg({ environment: {} })),
      "resources.packages[0].environment",
    );
  });

  it.each(["../escape", "/abs", "a/../b", "a//b", ".hidden", "a\\b"])(
    "refuses the state path %s",
    (statePath) => {
      rejects(
        withPackages(pkg({ environment: { APP_A_HOME: { statePath } } })),
        "resources.packages[0].environment.APP_A_HOME.statePath",
      );
    },
  );

  it("lets two packages share a variable only at the same value", () => {
    const first = pkg({ environment: { APP_SHARED_FLAG: "1" } });
    const second = (value: string) =>
      pkg({
        id: "other",
        package: "pi-other",
        environment: { APP_SHARED_FLAG: value },
      });
    expect(() => parsed(withPackages(first, second("1")))).not.toThrow();
    rejects(
      withPackages(first, second("2")),
      "resources.packages[1].environment.APP_SHARED_FLAG",
      "already set",
    );
  });

  it("is a v1alpha6 field only", () => {
    expect(() =>
      parseManifest({
        ...withPackages(pkg({ environment: { APP_A_FLAG: "1" } })),
        schema: PISHIP_SCHEMA_V1ALPHA5,
      }),
    ).toThrow(ManifestError);
  });
});

describe("package agent files", () => {
  const file = (extra: Json = {}): Json => ({
    path: CONFIG_FILE,
    json: { permission: { "*": "allow" } },
    ...extra,
  });

  it("parses files, defaulting the mode to seed and keeping key order", () => {
    const manifest = parsed(
      withPackages(
        pkg({
          agentFiles: [
            file({ json: { permission: { "*": "allow", "*.env": "deny" } } }),
            file({ path: "extensions/own.json", mode: "enforce", json: {} }),
          ],
        }),
      ),
    );
    const [item] = manifest.governance?.resources.packages ?? [];
    expect(item?.agentFiles?.map((entry) => [entry.path, entry.mode])).toEqual([
      [CONFIG_FILE, "seed"],
      ["extensions/own.json", "enforce"],
    ]);
    // Rules are read in order: the declared order survives parsing.
    const first = item?.agentFiles?.[0]?.json as { permission: Json };
    expect(Object.keys(first.permission)).toEqual(["*", "*.env"]);
  });

  it.each([
    "settings.json",
    "auth.json",
    "extensions/x.ts",
    "extensions/a/b/c.json",
    "extensions/../auth.json",
    "extensions/A.json/../x.json",
    "/extensions/x.json",
    "extensions/.hidden.json",
    "bin/rg.json",
  ])("refuses the path %s", (path) => {
    rejects(
      withPackages(pkg({ agentFiles: [file({ path })] })),
      "resources.packages[0].agentFiles[0].path",
    );
  });

  it("refuses a document that is not an object, an unknown mode, and an empty list", () => {
    rejects(
      withPackages(pkg({ agentFiles: [file({ json: [1] })] })),
      "resources.packages[0].agentFiles[0].json",
    );
    rejects(
      withPackages(pkg({ agentFiles: [file({ mode: "overwrite" })] })),
      "resources.packages[0].agentFiles[0].mode",
    );
    rejects(
      withPackages(pkg({ agentFiles: [] })),
      "resources.packages[0].agentFiles",
    );
  });

  it("refuses a file that is too large, too many files, and one path declared twice", () => {
    rejects(
      withPackages(
        pkg({ agentFiles: [file({ json: { text: "x".repeat(70_000) } })] }),
      ),
      "resources.packages[0].agentFiles[0].json",
    );
    rejects(
      withPackages(
        pkg({
          agentFiles: Array.from({ length: 9 }, (_, index) =>
            file({ path: `extensions/f${index}.json` }),
          ),
        }),
      ),
      "resources.packages[0].agentFiles",
    );
    rejects(
      withPackages(pkg({ agentFiles: [file(), file()] })),
      "resources.packages[0].agentFiles[1]",
    );
  });

  it("lets no two packages write the same file", () => {
    rejects(
      withPackages(
        pkg({ agentFiles: [file()] }),
        pkg({ id: "other", package: "pi-other", agentFiles: [file()] }),
      ),
      "resources.packages[1].agentFiles",
      "already written",
    );
  });

  it("refuses a secret in the document", () => {
    rejects(
      withPackages(
        pkg({
          agentFiles: [file({ json: { header: "Bearer abcdef0123456789" } })],
        }),
      ),
      "resources.packages[0].agentFiles[0].json.header",
    );
  });
});

describe("a capability provider that is a package", () => {
  const certified = {
    version: "1.0.0",
    source: "https://www.npmjs.com/package/pi-tools",
    integrity: INTEGRITY,
    license: "MIT",
    pi: [PI],
  };
  const provider = (extra: Json = {}): Json => ({
    id: "certified/tools",
    version: "1.0.0",
    implements: ["piship.capability/permissions/v1"],
    package: "tools",
    ...extra,
  });
  const manifest = (options: {
    provider?: Json;
    settings?: Json;
    packageClass?: string;
    agentFiles?: Json[];
  }): Json =>
    base({
      resources: {
        packages: [
          pkg({
            class: options.packageClass ?? "certified",
            ...((options.packageClass ?? "certified") === "certified"
              ? { certified }
              : {}),
            ...(options.agentFiles ? { agentFiles: options.agentFiles } : {}),
          }),
        ],
      },
      capabilities: {
        permissions: {
          enabled: true,
          provider: options.provider ?? provider(),
          ...(options.settings ? { settings: options.settings } : {}),
        },
      },
    });

  it("is locked as the package, with the package's class", () => {
    const result = parsed(manifest({}));
    const permissions = result.governance?.capabilities.find(
      (item) => item.name === "permissions",
    );
    expect(permissions?.provider).toEqual({
      id: "certified/tools",
      class: "certified",
      version: "1.0.0",
      implements: ["piship.capability/permissions/v1"],
      package: "tools",
    });
  });

  it("must name a declared package of the same class", () => {
    rejects(
      manifest({ provider: provider({ package: "missing" }) }),
      "capabilities.permissions.provider.package",
      "not declared",
    );
    rejects(
      manifest({ packageClass: "user" }),
      "capabilities.permissions.provider.package",
      "classes must match",
    );
  });

  it("is a path or a package, never both, and carries no evidence of its own", () => {
    rejects(
      manifest({ provider: provider({ path: "./providers/x" }) }),
      "capabilities.permissions.provider.package",
    );
    rejects(
      manifest({ provider: provider({ integrity: INTEGRITY }) }),
      "capabilities.permissions.provider.integrity",
      "package declaration",
    );
  });

  it("is a v1alpha6 field only", () => {
    expect(() =>
      parseManifest({
        ...manifest({}),
        schema: PISHIP_SCHEMA_V1ALPHA5,
      }),
    ).toThrow(ManifestError);
  });

  it("names its session auto-approval as a key of one of the package's files", () => {
    const files = [{ path: CONFIG_FILE, json: { yoloMode: false } }];
    const settings = {
      autoApproveFile: CONFIG_FILE,
      autoApproveKey: "yoloMode",
    };
    expect(() =>
      parsed(manifest({ agentFiles: files, settings })),
    ).not.toThrow();
    rejects(
      manifest({
        agentFiles: files,
        settings: { autoApproveFile: CONFIG_FILE },
      }),
      "capabilities.permissions.settings",
      "go together",
    );
    rejects(
      manifest({
        agentFiles: files,
        settings: { ...settings, autoApproveFile: "extensions/other.json" },
      }),
      "capabilities.permissions.settings.autoApproveFile",
      "agentFiles",
    );
    rejects(
      manifest({
        agentFiles: files,
        settings: { ...settings, autoApproveKey: "a.b" },
      }),
      "capabilities.permissions.settings.autoApproveKey",
    );
    rejects(
      base({
        capabilities: { permissions: { enabled: true, settings } },
      }),
      "capabilities.permissions.settings",
      "declared Pi package",
    );
  });
});
