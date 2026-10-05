import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLog, type AuditStatus } from "@piship/audit";
import {
  approvedNetworkEnvironment,
  formatError,
  NO_CONTENT_CAPTURE,
  PiShipError,
  principalKey,
  type SecretStore,
  SecretValue,
} from "@piship/contracts";
import { type ActivatedAccess, SandboxCredential } from "@piship/core";
import type { WorkspaceReport } from "@piship/sandbox";
import type { GovernanceManifest } from "@piship/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { renderDoctor } from "../commands/doctor.js";
import type { GovernanceInspection } from "../governance-session.js";
import type { LaunchContext } from "../launch/context.js";
import type { AccessData, DoctorData, GovernanceData } from "./data.js";
import { sandboxIsolation } from "./data.js";
import { DOCTOR_GROUPS, DoctorReport, sanitizeDoctorText } from "./report.js";
import { sandboxCredentialData } from "./sandbox.js";
import { workspaceData } from "./workspace.js";

let temp: string;
const saved = { ...process.env };
beforeEach(() => {
  temp = mkdtempSync(join(tmpdir(), "piship-doctor-"));
  // No installation is recorded here, so the lifecycle groups report a
  // build directory.
  process.env.PISHIP_INSTALL_HOME = join(temp, "install");
});
afterEach(() => {
  rmSync(temp, { recursive: true, force: true });
  for (const key of Object.keys(process.env))
    if (!(key in saved)) delete process.env[key];
  Object.assign(process.env, saved);
});

function context(mode: "managed" | "personal"): LaunchContext {
  return {
    metadata: {
      schema: "piship-lock/v1alpha4",
      app: {
        id: "doctor-test",
        name: "AcmeCode",
        version: "1.0.0",
        command: "acmecode",
      },
      runtime: { pishipVersion: "0.7.0" },
      manifest: { schema: "piship/v1alpha4" },
    },
    mode,
    distributionDir: temp,
    stateDir: join(temp, "state"),
    agentDir: join(temp, "agent"),
    out: () => undefined,
    err: () => undefined,
  } as unknown as LaunchContext;
}

const metrics = {
  schema: "piship-metrics/v1",
  updatedAt: "2026-09-29T00:00:00.000Z",
  policyDenials: {},
  mcpHealth: {},
  startupFailures: {},
} as unknown as DoctorData["metrics"];

function accessData(overrides: Partial<AccessData> = {}): AccessData {
  const policy = {
    inheritProxyEnvironment: true,
    additionalCA: [] as string[],
    privateOnly: true,
    allowHosts: ["gateway.acme.example"],
  };
  return {
    manifest: {
      identity: { mode: "oidc" },
      credential: { provider: "http-broker" },
      inference: { provider: "openai-compatible" },
      network: {
        proxy: { inheritEnvironment: true },
        tls: { additionalCA: [] },
      },
    } as unknown as AccessData["manifest"],
    signedIn: true,
    issuer: "https://idp.acme.example/realms/acme",
    store: { kind: "macos-keychain", description: "macOS Keychain" },
    credential: { state: "valid", remainingSeconds: 43 * 60 + 5 },
    activation: {
      runtime: "managed-endpoint",
      gatewayOrigin: "https://gateway.acme.example",
      allowedModels: 3,
      selectedModel: "acme-large",
    },
    gateway: { listed: 3 },
    network: {
      privateOnly: true,
      allowHosts: policy.allowHosts,
      undeclared: [],
      inheritProxy: true,
      caBundles: 0,
      approved: approvedNetworkEnvironment(policy, {}),
      childrenRestricted: true,
      notApproved: [],
    },
    removedEnvironment: [],
    ...overrides,
  };
}

function inspection(
  sandbox: Partial<GovernanceInspection["sandbox"]> = {},
): GovernanceInspection {
  const report = {
    level: "enforced",
    adapter: "macos-seatbelt",
    provider: "native",
    required: true,
    planes: ["filesystem-read-deny", "filesystem-write-allowlist"],
    network: "deny",
    verification: "live-probe",
    localProcesses: true,
    warnings: [],
    isolation: "local",
    workspace: {
      declared: "shared",
      effective: "shared",
      verification: "not-required",
      gitControlProtection: "verified",
      complete: true,
    },
    ...sandbox,
  };
  return {
    project: { origin: "company", root: "/work/acme" },
    candidates: [],
    sandbox: report,
    containment: "enforced by macos-seatbelt (required)",
    engine: { id: "acme-engineering@1", diagnostics: [] },
    capabilities: [],
    resources: [],
    userAuto: { allowed: false, state: "not-allowed", active: false },
  } as unknown as GovernanceInspection;
}

const okStatus: AuditStatus = {
  state: "ok",
  rejected: 0,
  sinks: [
    {
      id: "local",
      type: "file",
      required: true,
      state: "ok",
      delivered: 3,
      pending: 0,
      dropped: 0,
    },
  ],
};

/** Overrides of the defaults below; a field set to undefined is left out. */
function governanceData(
  overrides: {
    readonly [K in keyof GovernanceData]?: GovernanceData[K] | undefined;
  } = {},
): GovernanceData {
  const inspected = inspection();
  const defaults: GovernanceData = {
    manifest: {
      policy: { default: "deny", enforced: [], defaults: [], adapter: null },
      capabilities: [],
      mcp: { servers: [] },
      audit: { sinks: [{ id: "local", type: "file", required: true }] },
    } as unknown as GovernanceData["manifest"],
    inspection: inspected,
    isolation: sandboxIsolation(inspected.sandbox),
    workspace: {},
    mcp: [],
    audit: {
      status: okStatus,
      targets: [{ id: "local", target: "local file" }],
    },
  };
  const data = { ...defaults, ...overrides };
  for (const key of Object.keys(data) as (keyof GovernanceData)[])
    if (data[key] === undefined) delete data[key];
  return data as GovernanceData;
}

function doctorData(
  mode: "managed" | "personal",
  parts: Pick<DoctorData, "access" | "governance">,
): DoctorData {
  return {
    ctx: context(mode),
    piVersion: "1.0.2",
    metrics,
    ...parts,
  };
}

/** The lines of one group, without the heading. */
function group(output: string, name: string): string[] {
  const lines = output.split("\n");
  const start = lines.indexOf(name);
  if (start < 0) return [];
  const end = lines.indexOf("", start);
  return lines.slice(start + 1, end < 0 ? undefined : end);
}

describe("DoctorReport", () => {
  it("prints groups in the fixed order, whatever order they are written in, and skips empty ones", () => {
    const report = new DoctorReport("AcmeCode Doctor");
    report.section("Network").ok("outbound", "private-only");
    report.section("Distribution").ok("AcmeCode", "1.0.0");
    report.section("Audit");
    report.section("Identity").info("mode", "none");
    expect(report.render()).toBe(
      [
        "AcmeCode Doctor",
        "",
        "Distribution",
        `  ✓ ${"AcmeCode".padEnd(20)} 1.0.0`,
        "",
        "Identity",
        `  - ${"mode".padEnd(20)} none`,
        "",
        "Network",
        `  ✓ ${"outbound".padEnd(20)} private-only`,
      ].join("\n"),
    );
  });

  it("fails only on a failed line", () => {
    const report = new DoctorReport("AcmeCode Doctor");
    const out = report.section("Gateway");
    out.ok("a", "b");
    out.warn("c", "d");
    out.info("e", "f");
    expect(report.failed).toBe(false);
    out.bad("g", "h");
    expect(report.failed).toBe(true);
    expect(report.render()).toContain(`  ✗ ${"g".padEnd(20)} h`);
    expect(report.render()).toContain(`  ! ${"c".padEnd(20)} d`);
  });

  it("sanitizes URL credentials, queries, fragments, tokens, and control characters", () => {
    expect(
      sanitizeDoctorText(
        "proxy http://alice:s3cret@proxy.acme.example:3128/path?key=abc#frag",
      ),
    ).toBe("proxy http://proxy.acme.example:3128/path");
    expect(
      sanitizeDoctorText("Authorization: Bearer abcdefghijklmnop"),
    ).not.toContain("abcdefghijklmnop");
    expect(sanitizeDoctorText("a\u001b[31mred\u0007\nnext")).toBe(
      "a[31mred\nnext",
    );
  });

  it("names every enterprise diagnostics group", () => {
    for (const name of [
      "Distribution",
      "Identity",
      "Credential",
      "Inference",
      "Gateway",
      "Resources",
      "Policy",
      "Sandbox",
      "Workspace",
      "Secret Store",
      "Audit",
      "Network",
      "Release",
    ])
      expect(DOCTOR_GROUPS).toContain(name);
  });
});

describe("renderDoctor", () => {
  it("reports a managed, governed distribution in every group", () => {
    const report = renderDoctor(
      doctorData("managed", {
        access: accessData(),
        governance: governanceData(),
      }),
    );
    const output = report.render();
    expect(report.failed).toBe(false);
    const headings = output
      .split("\n")
      .filter((line) => line && !line.startsWith(" "))
      .slice(1);
    // No resources or capabilities are declared in this data.
    expect(headings).toEqual(
      DOCTOR_GROUPS.filter(
        (name) => name !== "Resources" && name !== "Capabilities",
      ),
    );
    expect(group(output, "Identity")).toEqual([
      `  ✓ ${"mode".padEnd(20)} oidc`,
      `  ✓ ${"session".padEnd(20)} signed in`,
      `  - ${"issuer".padEnd(20)} https://idp.acme.example/realms/acme`,
    ]);
    expect(group(output, "Credential")).toContain(
      `  ✓ ${"valid".padEnd(20)} 43m remaining`,
    );
    expect(group(output, "Gateway")).toEqual([
      `  ✓ ${"endpoint".padEnd(20)} https://gateway.acme.example`,
      `  ✓ ${"gateway".padEnd(20)} reachable (3 listed; model providers not contacted)`,
    ]);
    expect(group(output, "Secret Store")).toEqual([
      `  ✓ ${"backend".padEnd(20)} macOS Keychain`,
    ]);
    expect(group(output, "Sandbox")).toContain(
      `  ✓ ${"isolation".padEnd(20)} local (commands run on this host inside the sandbox)`,
    );
    expect(group(output, "Workspace")).toEqual([
      `  - ${"consistency".padEnd(20)} not reported by the sandbox backend`,
    ]);
    expect(group(output, "Audit")).toEqual([
      `  ✓ ${"state".padEnd(20)} healthy`,
      `  ✓ ${"sink local".padEnd(20)} file, required, local file: healthy; delivered 3, pending 0, dropped 0`,
      `  ✓ ${"local metrics".padEnd(20)} 0 policy denial(s)`,
    ]);
    expect(group(output, "Release")).toEqual([
      `  ✓ ${"release".padEnd(20)} none; running from a build directory`,
    ]);
  });

  it("never reports a rule on an unsupported action as enforced", () => {
    const withPolicy = (acknowledgeUnenforced?: string[]) =>
      governanceData({
        manifest: {
          ...governanceData().manifest,
          policy: {
            default: "deny",
            enforced: [
              {
                id: "acme.web.deny",
                action: "web.request",
                resource: "**",
                effect: "deny",
              },
            ],
            defaults: [],
            adapter: null,
            ...(acknowledgeUnenforced ? { acknowledgeUnenforced } : {}),
          },
        } as unknown as GovernanceData["manifest"],
      });
    const line = (output: string) =>
      group(output, "Policy").find((item) => item.includes("web.request"));
    const acknowledged = renderDoctor(
      doctorData("managed", {
        access: accessData(),
        governance: withPolicy(["web.request:**"]),
      }),
    );
    expect(acknowledged.failed).toBe(false);
    expect(line(acknowledged.render())).toBe(
      `  - ${"web.request".padEnd(20)} unsupported (acknowledged): rule acme.web.deny (deny **)`,
    );
    const unacknowledged = renderDoctor(
      doctorData("managed", { access: accessData(), governance: withPolicy() }),
    );
    expect(unacknowledged.failed).toBe(true);
    expect(line(unacknowledged.render())).toBe(
      `  ✗ ${"web.request".padEnd(20)} unsupported: rule acme.web.deny (deny **)`,
    );
    const personal = renderDoctor(
      doctorData("personal", { governance: withPolicy() }),
    ).render();
    expect(line(personal)).toBe(
      `  ! ${"web.request".padEnd(20)} unsupported: rule acme.web.deny (deny **)`,
    );
    for (const output of [acknowledged.render(), personal])
      expect(line(output)).not.toMatch(/\benforced\b/);
  });

  it("always reports session export, and counts data.export as a rule", () => {
    const exportLine = (output: string) =>
      group(output, "Policy").find((item) => item.includes("session export"));
    const plain = renderDoctor(
      doctorData("managed", {
        access: accessData(),
        governance: governanceData(),
      }),
    ).render();
    // Nothing declared: the gaps are still shown.
    expect(exportLine(plain)).toBe(
      `  - ${"session export".padEnd(20)} public unsupported, local unsupported, support enforced`,
    );
    const declared = (acknowledgeUnenforced?: string[]) => {
      const data = doctorData("managed", {
        access: accessData(),
        governance: governanceData({
          manifest: {
            ...governanceData().manifest,
            policy: {
              ...governanceData().manifest.policy,
              ...(acknowledgeUnenforced ? { acknowledgeUnenforced } : {}),
            },
          } as unknown as GovernanceData["manifest"],
        }),
      });
      return renderDoctor({
        ...data,
        ctx: {
          ...data.ctx,
          metadata: {
            ...data.ctx.metadata,
            data: {
              contract: "piship-data/v1",
              declared: {
                retention: {},
                purge: { onLogout: [], onUninstall: "none" },
                export: { public: "deny" },
              },
            },
          },
        },
      });
    };
    const unacknowledged = declared();
    expect(unacknowledged.failed).toBe(true);
    expect(
      group(unacknowledged.render(), "Policy").find((item) =>
        item.includes("data.export.public"),
      ),
    ).toBe(
      `  ✗ ${"session.export".padEnd(20)} unsupported: rule data.export.public (deny public)`,
    );
    const acknowledged = declared(["session.export:public"]);
    expect(acknowledged.failed).toBe(false);
    expect(exportLine(acknowledged.render())).toBe(
      `  - ${"session export".padEnd(20)} public unsupported (acknowledged), local unsupported, support enforced`,
    );
  });

  it("never shows identity claims", () => {
    const output = renderDoctor(
      doctorData("managed", { access: accessData() }),
    ).render();
    expect(output).not.toMatch(/subject|email|display/i);
  });

  it("fails when the user is not signed in", () => {
    const report = renderDoctor(
      doctorData("managed", {
        access: accessData({ signedIn: false }),
      }),
    );
    expect(report.failed).toBe(true);
    expect(group(report.render(), "Identity")).toContain(
      `  ✗ ${"session".padEnd(20)} not signed in; run acmecode login`,
    );
  });

  it("says what stale credential state remains and which command clears it (#196)", () => {
    const notice =
      "Secret references that a discarded credential or an interrupted sign-in left in the system secret store are still to be deleted; they are never used, and login or logout deletes them once that store works (or drops them when it is not installed)";
    const report = renderDoctor(
      doctorData("managed", {
        access: accessData({ credential: { state: "absent", notice } }),
      }),
    );
    expect(report.failed).toBe(true);
    expect(group(report.render(), "Credential")).toContain(
      `  ✗ ${"state".padEnd(20)} absent; ${notice}; run acmecode login`,
    );
  });

  it("reports a workload identity as obtained per run, whatever session is stored", () => {
    for (const signedIn of [false, true]) {
      const report = renderDoctor(
        doctorData("managed", {
          access: accessData({
            manifest: {
              ...accessData().manifest,
              identity: { mode: "adapter" },
            } as unknown as AccessData["manifest"],
            signedIn,
            workload: true,
          }),
        }),
      );
      expect(report.failed).toBe(false);
      expect(group(report.render(), "Identity")).toEqual([
        `  ✓ ${"mode".padEnd(20)} adapter`,
        `  ✓ ${"session".padEnd(20)} workload identity, obtained per run`,
        `  - ${"issuer".padEnd(20)} https://idp.acme.example/realms/acme`,
      ]);
    }
    const failed = renderDoctor(
      doctorData("managed", {
        access: accessData({
          workload: true,
          identityError:
            "IDENTITY_INVALID: The workload identity adapter could not obtain a session",
        }),
      }),
    );
    expect(failed.failed).toBe(true);
    expect(group(failed.render(), "Identity")).toContain(
      `  ✗ ${"session".padEnd(20)} IDENTITY_INVALID: The workload identity adapter could not obtain a session`,
    );
  });

  it("serializes the same checks for doctor --json", () => {
    const report = renderDoctor(
      doctorData("managed", { access: accessData({ signedIn: false }) }),
    );
    const json = JSON.parse(JSON.stringify(report));
    expect(json.failed).toBe(true);
    const identity = json.groups.find(
      (item: { group: string }) => item.group === "Identity",
    );
    expect(identity.checks).toContainEqual({
      status: "fail",
      label: "session",
      value: "not signed in; run acmecode login",
    });
    // The text report is rendered from the same checks.
    expect(report.render()).toContain(
      `  ✗ ${"session".padEnd(20)} not signed in; run acmecode login`,
    );
  });

  it("shows a stored session as working only when activation used it", () => {
    const identity = (overrides: Partial<AccessData>) => {
      const report = renderDoctor(
        doctorData("managed", { access: accessData(overrides) }),
      );
      return group(report.render(), "Identity").find((line) =>
        line.includes("session"),
      );
    };
    expect(
      identity({
        activationError: "IDENTITY_EXPIRED: The session expired",
        identityError: "IDENTITY_EXPIRED: The session expired",
      }),
    ).toBe(
      `  ✗ ${"session".padEnd(20)} stored, but activation could not use it; see the Inference activation line`,
    );
    expect(
      identity({
        activationError: "CREDENTIAL_ACQUIRE_FAILED: The broker refused",
      }),
    ).toBe(
      `  ! ${"session".padEnd(20)} stored; not verified, because activation failed before using it`,
    );
  });

  it("shows the issuer as answering only when doctor reached it", () => {
    const issuer = (overrides: Partial<AccessData>, path?: object) => {
      const base = accessData();
      return group(
        renderDoctor(
          doctorData("managed", {
            access: accessData({
              ...overrides,
              network: {
                ...base.network,
                ...(path
                  ? {
                      paths: [
                        {
                          label: "identity",
                          host: "idp.acme.example",
                          ...path,
                        },
                      ],
                    }
                  : {}),
              },
            }),
          }),
        ).render(),
        "Identity",
      ).find((line) => line.includes("issuer"));
    };
    const dead = {
      code: "GATEWAY_UNREACHABLE",
      error: "GATEWAY_UNREACHABLE: doctor request to idp.acme.example failed",
    };
    // A stored session hides a dead issuer from activation until refresh.
    expect(issuer({}, dead)).toBe(
      `  ! ${"issuer".padEnd(20)} https://idp.acme.example/realms/acme does not answer (${dead.error}); sign-in and session refresh fail until it does`,
    );
    expect(
      issuer({ activationError: "IDENTITY_INVALID: refresh failed" }, dead),
    ).toMatch(
      /^ {2}✗ issuer\s+https:\/\/idp\.acme\.example\/realms\/acme does not answer/,
    );
    expect(issuer({}, { status: 200 })).toBe(
      `  ✓ ${"issuer".padEnd(20)} https://idp.acme.example/realms/acme answers`,
    );
  });

  it("reports pending revocation retries by count and age, never by credential", () => {
    const lines = (pending: AccessData["pendingRevocations"]) =>
      group(
        renderDoctor(
          doctorData("managed", {
            access: accessData(pending ? { pendingRevocations: pending } : {}),
          }),
        ).render(),
        "Secret Store",
      );
    expect(
      lines({ readable: true, count: 0, dropped: 0, oldestAgeSeconds: null }),
    ).toEqual([
      `  ✓ ${"backend".padEnd(20)} macOS Keychain`,
      `  ✓ ${"revocation retries".padEnd(20)} none pending`,
    ]);
    expect(
      lines({
        readable: true,
        count: 2,
        dropped: 0,
        oldestAgeSeconds: 3 * 3600 + 5,
      }),
    ).toEqual([
      `  ✓ ${"backend".padEnd(20)} macOS Keychain`,
      `  ! ${"revocation retries".padEnd(20)} pending revocation retries: 2, oldest 3h`,
      `  ! ${"revocation".padEnd(20)} a replaced credential could not be revoked and may still be valid at the provider until it expires or an administrator revokes it`,
    ]);
    expect(
      lines({ readable: true, count: 20, dropped: 4, oldestAgeSeconds: 90 })[1],
    ).toBe(
      `  ! ${"revocation retries".padEnd(20)} pending revocation retries: 20, oldest 90s; 4 older not listed`,
    );
    expect(
      lines({ readable: false, count: 0, dropped: 0, oldestAgeSeconds: null }),
    ).toContain(
      `  ! ${"revocation retries".padEnd(20)} the pending revocation record is unreadable`,
    );
    // Warnings never fail the report.
    expect(
      renderDoctor(
        doctorData("managed", {
          access: accessData({
            pendingRevocations: {
              readable: true,
              count: 1,
              dropped: 0,
              oldestAgeSeconds: 60,
            },
          }),
        }),
      ).failed,
    ).toBe(false);
  });

  it("reports a pending credential request, and the user step once it is past retention", () => {
    const lines = (stale: boolean) =>
      group(
        renderDoctor(
          doctorData("managed", {
            access: accessData({
              pendingIssuance: { idempotencyKey: "key-0001", stale },
            }),
          }),
        ).render(),
        "Credential",
      );
    expect(lines(false)).toContain(
      `  ! ${"pending request".padEnd(20)} credential request key-0001 is unresolved; the next renewal repeats it`,
    );
    expect(lines(true)).toContain(
      `  ! ${"pending request".padEnd(20)} credential request key-0001 is older than broker retention; renewal fails until you run acmecode logout, then acmecode login`,
    );
  });

  it("warns about the plaintext file secret store and says when no store is used", () => {
    const file = renderDoctor(
      doctorData("managed", {
        access: accessData({
          store: {
            kind: "file",
            description: "restricted plaintext file (explicit opt-in fallback)",
          },
        }),
      }),
    ).render();
    expect(group(file, "Secret Store")).toEqual([
      `  ! ${"backend".padEnd(20)} restricted plaintext file (explicit opt-in fallback)`,
    ]);
    const { store: _store, ...withoutStore } = accessData();
    const none = renderDoctor(
      doctorData("personal", { access: withoutStore }),
    ).render();
    expect(group(none, "Secret Store")).toEqual([
      `  - ${"backend".padEnd(20)} not used; this distribution stores no PiShip secret`,
    ]);
  });

  it("reports a Pi-native distribution without access", () => {
    const output = renderDoctor(doctorData("personal", {})).render();
    expect(group(output, "Identity")).toEqual([
      `  ✓ ${"mode".padEnd(20)} personal Pi-native (no identity; Pi auth in isolated state)`,
    ]);
    expect(group(output, "Network")).toContain(
      `  - ${"agent commands".padEnd(20)} not restricted (personal mode; child processes keep the shell's proxy and CA variables)`,
    );
    expect(group(output, "Audit")[0]).toBe(
      `  - ${"state".padEnd(20)} not configured (the distribution declares no audit)`,
    );
    expect(output).not.toContain("Gateway");
    expect(output).not.toContain("Workspace");
  });
});

describe("Network group", () => {
  const policy = {
    inheritProxyEnvironment: true,
    additionalCA: ["/etc/acme/root.pem", "/etc/acme/issuing.pem"],
    privateOnly: true,
    allowHosts: ["gateway.acme.example"],
  };

  it("states the proxy, NO_PROXY, CA bundles, and the withheld child variables by name and reason", () => {
    const approved = approvedNetworkEnvironment(policy, {
      HTTPS_PROXY: "http://proxy.acme.example:3128",
      NO_PROXY: "localhost,.acme.internal",
    });
    const base = accessData();
    const output = renderDoctor(
      doctorData("managed", {
        access: accessData({
          network: {
            ...base.network,
            caBundles: 2,
            approved,
            notApproved: ["SSL_CERT_FILE"],
          },
        }),
      }),
    ).render();
    const lines = group(output, "Network");
    expect(lines).toEqual([
      `  ✓ ${"TLS verification".padEnd(20)} on`,
      `  ✓ ${"outbound".padEnd(20)} private-only: declared hosts only (gateway.acme.example); public fallback denied`,
      `  ✓ ${"proxy".padEnd(20)} active (https http://proxy.acme.example:3128)`,
      `  ✓ ${"NO_PROXY".padEnd(20)} set`,
      `  ✓ ${"enterprise CA".padEnd(20)} 2 additional bundle(s) declared`,
      `  ✓ ${"agent commands".padEnd(20)} approved network variables only: HTTPS_PROXY, https_proxy, NO_PROXY, no_proxy`,
      `  ! ${"withheld NODE_EXTRA_CA_CERTS".padEnd(20)} not passed to child processes: network.tls.additionalCA lists several bundles and a child accepts one file`,
      `  - ${"withheld SSL_CERT_FILE".padEnd(20)} not passed to child processes: not approved by the network policy`,
    ]);
    // NO_PROXY is reported as set, never by value.
    expect(output).not.toContain("acme.internal");
  });

  it("shows each endpoint that opted in to plain HTTP, by host, and whether it is unencrypted", () => {
    const data = doctorData("managed", { access: accessData() });
    const metadata = data.ctx.metadata as unknown as Record<string, unknown>;
    metadata.access = {
      variables: [],
      identity: {
        mode: "oidc",
        oidc: {
          issuer: "https://idp.acme.example/realms/acme",
          httpTransport: "http-allowed",
        },
      },
      credential: {
        provider: "http-broker",
        broker: {
          endpoint: "http://10.20.30.40:8080/token",
          httpTransport: "http-allowed",
        },
      },
      inference: {
        provider: "openai-compatible",
        baseUrl: "http://10.20.30.40:4000/v1",
        httpTransport: "http-allowed",
      },
    };
    metadata.governance = {
      manifest: {
        audit: {
          sinks: [
            {
              id: "collector",
              type: "http",
              url: "http://10.0.0.6/events",
              required: false,
              httpTransport: "http-allowed",
            },
          ],
        },
        sandbox: { httpTransport: "https" },
      },
    };
    const lines = group(renderDoctor(data).render(), "Network");
    expect(lines.slice(0, 4)).toEqual([
      `  - ${"identity.oidc.httpTransport".padEnd(20)} http-allowed; the issuer resolves to https`,
      `  ! ${"credential.broker.httpTransport".padEnd(20)} http-allowed: plain HTTP to 10.20.30.40:8080; the identity token and the issued gateway credential are unencrypted on the network path`,
      `  ! ${"inference.httpTransport".padEnd(20)} http-allowed: plain HTTP to 10.20.30.40:4000; the gateway credential and every prompt and response are unencrypted on the network path`,
      `  ! ${"audit sink collector httpTransport".padEnd(20)} http-allowed: plain HTTP to 10.0.0.6; audit events are unencrypted on the network path`,
    ]);
    expect(lines[4]).toContain("TLS verification");
    // Through a proxy that is not private, the request would be refused.
    // Clear before setting: on Windows process.env ignores case, so
    // deleting http_proxy after setting HTTP_PROXY would remove it again.
    for (const name of ["http_proxy", "HTTP_PROXY", "no_proxy", "NO_PROXY"])
      delete process.env[name];
    process.env.HTTP_PROXY = "http://proxy.acme.example:3128";
    process.env.NO_PROXY = "10.0.0.6";
    const proxied = group(renderDoctor(data).render(), "Network");
    expect(proxied).toContain(
      `  ✗ ${"credential.broker.httpTransport".padEnd(20)} plain HTTP to 10.20.30.40 would go through a proxy that is not a private host and is refused (NETWORK_DENIED); add 10.20.30.40 to NO_PROXY`,
    );
    // NO_PROXY names the audit collector, so it goes direct.
    expect(
      proxied.filter(
        (line) => line.includes("audit sink") && line.includes("NO_PROXY"),
      ),
    ).toEqual([]);
  });

  it("says when no proxy is set and when the proxy environment is ignored", () => {
    const base = accessData();
    const unset = group(
      renderDoctor(doctorData("managed", { access: base })).render(),
      "Network",
    );
    expect(unset).toContain(
      `  ✓ ${"proxy".padEnd(20)} none set in the environment`,
    );
    expect(unset).toContain(`  ✓ ${"NO_PROXY".padEnd(20)} not set`);
    const ignored = group(
      renderDoctor(
        doctorData("managed", {
          access: accessData({
            network: { ...base.network, inheritProxy: false },
          }),
        }),
      ).render(),
      "Network",
    );
    expect(ignored).toContain(
      `  ✓ ${"proxy".padEnd(20)} not used; network.proxy.inheritEnvironment is off`,
    );
    expect(ignored.join("\n")).not.toContain("NO_PROXY");
  });

  it("fails on a proxy that refuses connections and on an endpoint path that fails, naming the hop", () => {
    const approved = approvedNetworkEnvironment(policy, {
      HTTPS_PROXY: "http://proxyuser:proxy-pass-8812@proxy.acme.example:3128",
    });
    const base = accessData();
    const report = renderDoctor(
      doctorData("managed", {
        access: accessData({
          network: {
            ...base.network,
            approved,
            proxyChecks: [
              {
                proxy: "http://proxy.acme.example:3128",
                error: "ECONNREFUSED",
              },
            ],
            paths: [
              {
                label: "identity",
                host: "idp.acme.example",
                code: "GATEWAY_UNREACHABLE",
                error:
                  "GATEWAY_UNREACHABLE: doctor request to idp.acme.example failed at the proxy http://proxy.acme.example:3128: ECONNREFUSED",
              },
              { label: "gateway", host: "gateway.acme.example", status: 404 },
            ],
          },
        }),
      }),
    );
    expect(report.failed).toBe(true);
    const lines = group(report.render(), "Network");
    expect(lines).toContain(
      `  ✗ ${"proxy".padEnd(20)} active (https http://proxy.acme.example:3128); cannot connect to http://proxy.acme.example:3128 (ECONNREFUSED): check that the proxy is running and that HTTPS_PROXY and HTTP_PROXY name it`,
    );
    expect(lines).toContain(
      `  ✗ ${"path identity".padEnd(20)} idp.acme.example: GATEWAY_UNREACHABLE: doctor request to idp.acme.example failed at the proxy http://proxy.acme.example:3128: ECONNREFUSED`,
    );
    expect(lines).toContain(
      `  ✓ ${"path gateway".padEnd(20)} gateway.acme.example answered (HTTP 404)`,
    );
    expect(lines.join("\n")).not.toContain("proxy-pass-8812");
    expect(lines.join("\n")).not.toContain("proxyuser");
  });

  it("says the proxy accepts connections and how many CA certificates loaded", () => {
    const approved = approvedNetworkEnvironment(policy, {
      HTTPS_PROXY: "http://proxy.acme.example:3128",
    });
    const base = accessData();
    const lines = group(
      renderDoctor(
        doctorData("managed", {
          access: accessData({
            network: {
              ...base.network,
              approved,
              caBundles: 2,
              caCertificates: 3,
              proxyChecks: [{ proxy: "http://proxy.acme.example:3128" }],
            },
          }),
        }),
      ).render(),
      "Network",
    );
    expect(lines).toContain(
      `  ✓ ${"proxy".padEnd(20)} active (https http://proxy.acme.example:3128); accepts connections`,
    );
    expect(lines).toContain(
      `  ✓ ${"enterprise CA".padEnd(20)} 2 additional bundle(s) declared; 3 certificate(s) loaded`,
    );
  });

  it("fails on a CA bundle that does not load, and warns when none is declared but a chain is untrusted", () => {
    const base = accessData();
    const broken = group(
      renderDoctor(
        doctorData("managed", {
          access: accessData({
            network: {
              ...base.network,
              caBundles: 1,
              caError:
                "CONFIG_INVALID: Enterprise CA bundle contains no PEM certificate: /etc/acme/root.pem",
            },
          }),
        }),
      ).render(),
      "Network",
    );
    expect(broken).toContain(
      `  ✗ ${"enterprise CA".padEnd(20)} CONFIG_INVALID: Enterprise CA bundle contains no PEM certificate: /etc/acme/root.pem`,
    );
    const untrusted = group(
      renderDoctor(
        doctorData("managed", {
          access: accessData({
            network: {
              ...base.network,
              paths: [
                {
                  label: "gateway",
                  host: "gateway.acme.example",
                  code: "TLS_POLICY_VIOLATION",
                  error: "TLS_POLICY_VIOLATION: untrusted",
                },
              ],
            },
          }),
        }),
      ).render(),
      "Network",
    );
    expect(untrusted).toContain(
      `  ! ${"enterprise CA".padEnd(20)} none declared; default trust roots, and an endpoint failed TLS verification: if it uses an enterprise or private CA, declare that CA in network.tls.additionalCA`,
    );
  });

  it("says that a personal distribution does not restrict the agent commands' environment", () => {
    const base = accessData();
    const lines = group(
      renderDoctor(
        doctorData("personal", {
          access: accessData({
            network: {
              ...base.network,
              privateOnly: false,
              childrenRestricted: false,
            },
          }),
        }),
      ).render(),
      "Network",
    );
    expect(lines).toContain(
      `  - ${"outbound".padEnd(20)} any host (personal mode; network.privateOnly is off)`,
    );
    expect(lines.at(-1)).toBe(
      `  - ${"agent commands".padEnd(20)} not restricted (personal mode; child processes keep the shell's proxy and CA variables)`,
    );
    expect(lines.join("\n")).not.toContain("withheld");
  });

  it("fails on disabled TLS verification", () => {
    const report = renderDoctor(
      doctorData("managed", {
        access: accessData({
          tlsError: formatError(
            new PiShipError("TLS_POLICY_VIOLATION", "TLS disabled"),
          ),
        }),
      }),
    );
    expect(report.failed).toBe(true);
    expect(group(report.render(), "Network")[0]).toBe(
      `  ✗ ${"TLS verification".padEnd(20)} DISABLED in environment`,
    );
    expect(group(report.render(), "Inference")).toContain(
      `  ✗ ${"activation".padEnd(20)} TLS_POLICY_VIOLATION: TLS disabled`,
    );
  });
});

describe("Sandbox and Workspace groups", () => {
  const remote = (workspace: WorkspaceReport) =>
    inspection({
      adapter: "custom",
      provider: "custom",
      planes: ["host-filesystem-isolation", "environment-filter"],
      localProcesses: false,
      isolation: "remote",
      workspace,
    });
  const snapshot: WorkspaceReport = {
    declared: "snapshot",
    effective: "snapshot",
    verification: "not-required",
    gitControlProtection: "not-applicable",
    complete: false,
  };
  const workspaceLines = (inspected: GovernanceInspection) =>
    group(
      renderDoctor(
        doctorData("managed", {
          governance: governanceData({
            inspection: inspected,
            isolation: sandboxIsolation(inspected.sandbox),
            workspace: workspaceData(inspected),
          }),
        }),
      ).render(),
      "Workspace",
    );

  it("takes the isolation kind from the containment report", () => {
    expect(sandboxIsolation(inspection().sandbox)).toBe("local");
    expect(sandboxIsolation(remote(snapshot).sandbox)).toBe("remote");
    expect(
      sandboxIsolation(
        inspection({ level: "not-required", planes: [] }).sandbox,
      ),
    ).toBe("none");
  });

  it("shows the remote isolation and the containment summary", () => {
    const inspected = remote(snapshot);
    const output = renderDoctor(
      doctorData("managed", {
        governance: governanceData({
          inspection: inspected,
          isolation: sandboxIsolation(inspected.sandbox),
          workspace: workspaceData(inspected),
        }),
      }),
    ).render();
    const sandbox = group(output, "Sandbox");
    expect(sandbox[0]).toBe(`  ✓ ${"provider".padEnd(20)} custom`);
    expect(sandbox).toContain(
      `  ✓ ${"isolation".padEnd(20)} remote (commands run on another machine; host files unreachable)`,
    );
    expect(sandbox).toContain(
      `  - ${"summary".padEnd(20)} enforced by macos-seatbelt (required)`,
    );
  });

  it("shows how network denial is known", () => {
    const networkLine = (inspected: GovernanceInspection) =>
      group(
        renderDoctor(
          doctorData("managed", {
            governance: governanceData({
              inspection: inspected,
              isolation: sandboxIsolation(inspected.sandbox),
              workspace: workspaceData(inspected),
            }),
          }),
        ).render(),
        "Sandbox",
      ).find((line) => line.includes("network".padEnd(20)));
    expect(
      networkLine(
        inspection({ networkDenial: { evidence: "verified", probe: false } }),
      ),
    ).toBe(`  ✓ ${"network".padEnd(20)} deny (verified)`);
    expect(
      networkLine(
        inspection({
          verification: "backend-attested",
          isolation: "remote",
          networkDenial: {
            evidence: "attested",
            probe: false,
            reason: "the backend declares no network probe to check it with",
          },
        }),
      ),
    ).toBe(
      `  ✓ ${"network".padEnd(20)} deny (attested by the backend, not verified: the backend declares no network probe to check it with)`,
    );
    expect(networkLine(inspection({ network: "allow" }))).toBe(
      `  ✓ ${"network".padEnd(20)} allow`,
    );
  });

  it("says host files are reachable through a shared or synchronized remote workspace", () => {
    const pending = (declared: "shared" | "synchronized"): WorkspaceReport => ({
      declared,
      effective: "snapshot",
      verification: "pending",
      gitControlProtection: "pending",
      complete: false,
    });
    for (const declared of ["shared", "synchronized"] as const) {
      const inspected = inspection({
        adapter: "custom",
        provider: "custom",
        planes: [
          "workspace-confinement",
          "git-control-protection",
          "environment-filter",
        ],
        localProcesses: false,
        isolation: "remote",
        workspace: pending(declared),
      });
      const sandbox = group(
        renderDoctor(
          doctorData("managed", {
            governance: governanceData({
              inspection: inspected,
              isolation: sandboxIsolation(inspected.sandbox),
              workspace: workspaceData(inspected),
            }),
          }),
        ).render(),
        "Sandbox",
      );
      expect(sandbox).toContain(
        `  ✓ ${"isolation".padEnd(20)} remote (commands run on another machine; host files reachable only through the workspace)`,
      );
      expect(sandbox.join("\n")).not.toContain("host files unreachable");
    }
  });

  it("shows the last session's workspace check from local metrics while doctor's own is pending", () => {
    const inspected = remote({
      declared: "shared",
      effective: "snapshot",
      verification: "pending",
      gitControlProtection: "pending",
      complete: false,
    });
    const render = (workspace: unknown) =>
      group(
        renderDoctor({
          ...doctorData("managed", {
            governance: governanceData({
              inspection: inspected,
              isolation: sandboxIsolation(inspected.sandbox),
              workspace: workspaceData(inspected),
            }),
          }),
          metrics: { ...metrics, workspace } as DoctorData["metrics"],
        }).render(),
        "Workspace",
      );
    expect(
      render({
        declared: "shared",
        effective: "synchronized",
        verification: "verified",
        checkedAt: "2026-09-29T11:00:00Z",
      }),
    ).toContain(
      `  - ${"verification".padEnd(20)} pending: verified before the first sandboxed command; not run by doctor; last session check verified (synchronized) at 2026-09-29T11:00:00Z`,
    );
    // A result recorded under another declaration says nothing about this one.
    expect(
      render({
        declared: "synchronized",
        effective: "synchronized",
        verification: "verified",
        checkedAt: "2026-09-29T11:00:00Z",
      }),
    ).toContain(
      `  - ${"verification".padEnd(20)} pending: verified before the first sandboxed command; not run by doctor`,
    );
  });

  it("reports a local backend's workspace as shared by construction", () => {
    expect(workspaceLines(inspection())).toEqual([
      `  ✓ ${"consistency".padEnd(20)} shared (commands run on this host's files)`,
      `  - ${"verification".padEnd(20)} not required`,
      `  ✓ ${"complete".padEnd(20)} yes: a complete coding-agent workspace`,
      `  - ${"git control files".padEnd(20)} verified by the live probe`,
    ]);
    expect(
      workspaceLines(
        inspection({
          workspace: {
            declared: "shared",
            effective: "shared",
            verification: "not-required",
            gitControlProtection: "not-verified",
            complete: true,
          },
        }),
      ).at(-1),
    ).toBe(
      `  ! ${"git control files".padEnd(20)} not verified; sandboxed commands may be able to change them`,
    );
  });

  it("never reports a snapshot as a complete workspace", () => {
    expect(workspaceLines(remote(snapshot))).toEqual([
      `  - ${"consistency".padEnd(20)} snapshot`,
      `  - ${"declared".padEnd(20)} snapshot`,
      `  - ${"verification".padEnd(20)} not required`,
      `  - ${"complete".padEnd(20)} no: remote commands do not see the files the agent edits`,
      `  - ${"git control files".padEnd(20)} n/a (the sandbox cannot reach this host's files)`,
    ]);
  });

  it("shows a shared workspace as pending, because doctor never runs the check", () => {
    expect(
      workspaceLines(
        remote({
          declared: "shared",
          effective: "snapshot",
          verification: "pending",
          gitControlProtection: "pending",
          complete: false,
        }),
      ),
    ).toEqual([
      `  - ${"consistency".padEnd(20)} pending (shared declared)`,
      `  - ${"declared".padEnd(20)} shared`,
      `  - ${"verification".padEnd(20)} pending: verified before the first sandboxed command; not run by doctor`,
      `  - ${"complete".padEnd(20)} not until verified`,
      `  - ${"git control files".padEnd(20)} pending: checked before the first sandboxed command`,
    ]);
  });

  it("shows a verified workspace, and warns about a lower one", () => {
    expect(
      workspaceLines(
        remote({
          declared: "shared",
          effective: "shared",
          verification: "verified",
          verifiedAt: "2026-09-29T12:00:00Z",
          gitControlProtection: "attested-renames",
          complete: true,
        }),
      ).slice(0, 3),
    ).toEqual([
      `  ✓ ${"consistency".padEnd(20)} shared`,
      `  - ${"declared".padEnd(20)} shared`,
      `  - ${"verification".padEnd(20)} verified at 2026-09-29T12:00:00Z`,
    ]);
    expect(
      workspaceLines(
        remote({
          declared: "synchronized",
          effective: "snapshot",
          verification: "failed",
          reason: "the sandbox did not see host changes",
          gitControlProtection: "attested-renames",
          complete: false,
        }),
      )[0],
    ).toBe(
      `  ! ${"consistency".padEnd(20)} snapshot, lower than the declared synchronized: the sandbox did not see host changes`,
    );
  });

  it("says when no sandbox is enforced", () => {
    expect(
      workspaceLines(inspection({ level: "not-required", planes: [] })),
    ).toEqual([
      `  - ${"consistency".padEnd(20)} none: no sandbox is enforced; commands run on this host's files`,
    ]);
  });
});

describe("Sandbox credential lines", () => {
  // An obvious fake: never a real key.
  const SENTINEL = "sandbox-sentinel-secret-7741";
  const ENDPOINT =
    "https://sandbox.acme.example:8443/api/v1?tenant=origin-path-5512";
  const ALICE = { issuer: "https://idp.acme.example", subject: "alice" };
  const BOB = { issuer: "https://idp.acme.example", subject: "bob" };

  function memoryStore(): SecretStore & { values: Map<string, string> } {
    const values = new Map<string, string>();
    return {
      kind: "memory",
      description: "process memory (not persisted)",
      values,
      put: async (ref, value) => {
        values.set(ref, value.reveal());
      },
      get: async (ref) => {
        const value = values.get(ref);
        return value === undefined ? null : new SecretValue(value);
      },
      delete: async (ref) => {
        values.delete(ref);
      },
    };
  }

  function sandboxManifest(endpoint = ENDPOINT): GovernanceManifest["sandbox"] {
    return {
      required: true,
      provider: "e2b-compatible",
      endpoint,
      credential: "stored",
    } as unknown as GovernanceManifest["sandbox"];
  }

  async function store(
    ctx: LaunchContext,
    secretStore: SecretStore,
    principal: typeof ALICE | null,
  ): Promise<SandboxCredential> {
    const slot = new SandboxCredential({
      distributionId: ctx.metadata.app.id,
      command: ctx.metadata.app.command,
      stateDir: ctx.stateDir,
      provider: "e2b-compatible",
      secretStore,
      principal: principal ? principalKey(principal) : null,
      targets: [ENDPOINT],
    });
    await slot.save(async () => SENTINEL);
    return slot;
  }

  function lines(
    ctx: LaunchContext,
    options: {
      secretStore: SecretStore;
      identity?: typeof ALICE;
      endpoint?: string;
    },
  ): { output: string; sandbox: string[]; failed: boolean } {
    const data = {
      ...doctorData("managed", {
        governance: governanceData({
          sandboxCredential: sandboxCredentialData({
            ctx,
            sandbox: sandboxManifest(options.endpoint),
            secretStore: options.secretStore,
            ...(options.identity
              ? {
                  activated: {
                    identity: options.identity,
                  } as unknown as ActivatedAccess,
                }
              : {}),
          }),
        }),
      }),
      ctx,
    };
    const report = renderDoctor(data);
    const output = report.render();
    return { output, sandbox: group(output, "Sandbox"), failed: report.failed };
  }

  const line = (mark: string, label: string, value: string) =>
    `  ${mark} ${label.padEnd(20)} ${value}`;
  const STORE = "memory (process memory (not persisted))";

  it("is not reported unless the manifest declares a stored credential", () => {
    expect(
      sandboxCredentialData({
        ctx: context("managed"),
        sandbox: {
          ...sandboxManifest(),
          credential: "runtime",
        } as GovernanceManifest["sandbox"],
      }),
    ).toBeUndefined();
  });

  it("fails a required sandbox without a stored credential and says how to store one", () => {
    const { sandbox, failed } = lines(context("managed"), {
      secretStore: memoryStore(),
    });
    expect(sandbox).toContain(
      line(
        "✗",
        "sandbox credential",
        `absent (stored) in ${STORE}; run acmecode sandbox login`,
      ),
    );
    expect(sandbox.some((text) => text.includes("credential principal"))).toBe(
      false,
    );
    expect(failed).toBe(true);
  });

  it("shows a valid credential with its source, kind, store, and both bindings", async () => {
    const ctx = context("managed");
    const secretStore = memoryStore();
    await store(ctx, secretStore, ALICE);
    const { sandbox, failed } = lines(ctx, { secretStore, identity: ALICE });
    expect(sandbox.slice(-3)).toEqual([
      line("✓", "sandbox credential", `valid (stored, api_key) in ${STORE}`),
      line("✓", "credential principal", "bound to the current principal: yes"),
      line(
        "✓",
        "credential endpoint",
        "bound origin matches the configured endpoint: yes",
      ),
    ]);
    expect(failed).toBe(false);
  });

  it("says a credential of a distribution without identity is bound to no user", async () => {
    const ctx = context("managed");
    const secretStore = memoryStore();
    await store(ctx, secretStore, null);
    expect(lines(ctx, { secretStore }).sandbox).toContain(
      line(
        "✓",
        "credential principal",
        "bound to the current principal: yes (no identity configured)",
      ),
    );
  });

  it("warns about a credential the sandbox service rejected (C-T12)", async () => {
    const ctx = context("managed");
    const secretStore = memoryStore();
    const slot = await store(ctx, secretStore, ALICE);
    const access = await slot.access();
    await access.secret();
    // The backend got 401 for it.
    await access.rejected();
    const { sandbox, failed } = lines(ctx, { secretStore, identity: ALICE });
    expect(sandbox).toContain(
      line(
        "!",
        "sandbox credential",
        `rejected (stored, api_key) in ${STORE}: the sandbox service rejected it; run acmecode sandbox login to store a new one`,
      ),
    );
    expect(failed).toBe(false);
  });

  it("fails on another user's credential and on another endpoint, without deleting anything", async () => {
    const ctx = context("managed");
    const secretStore = memoryStore();
    await store(ctx, secretStore, ALICE);
    const other = lines(ctx, { secretStore, identity: BOB });
    expect(other.sandbox).toContain(
      line("✗", "credential principal", "bound to the current principal: no"),
    );
    expect(
      other.sandbox.find((text) => text.includes("sandbox credential")),
    ).toMatch(
      /^ {2}✗ sandbox credential +principal-mismatch \(stored, api_key\)/,
    );
    expect(other.failed).toBe(true);
    // Doctor deletes nothing: the next launch does.
    expect(secretStore.values.size).toBe(1);
    const moved = lines(ctx, {
      secretStore,
      identity: ALICE,
      endpoint: "https://elsewhere.acme.example",
    });
    expect(moved.sandbox).toContain(
      line(
        "✗",
        "credential endpoint",
        "bound origin matches the configured endpoint: no",
      ),
    );
    expect(moved.failed).toBe(true);
  });

  it("does not guess the state without a signed-in user", async () => {
    const ctx = context("managed");
    (ctx.metadata as { access?: unknown }).access = {
      credential: { storage: { provider: "system" } },
      variables: [],
    };
    const secretStore = memoryStore();
    await store(ctx, secretStore, ALICE);
    const { sandbox } = lines(ctx, { secretStore });
    expect(sandbox).toContain(
      line(
        "!",
        "sandbox credential",
        `stored (stored, api_key) in ${STORE}; state not checked`,
      ),
    );
    expect(sandbox).toContain(
      line(
        "!",
        "credential principal",
        "not checked: no signed-in user to check it against",
      ),
    );
  });

  it("never prints the secret, its reference or ID, or the bound origins (C-T12)", async () => {
    const ctx = context("managed");
    const secretStore = memoryStore();
    const slot = await store(ctx, secretStore, ALICE);
    const refs = [...secretStore.values.keys()];
    const metadata = JSON.parse(
      readFileSync(
        join(ctx.stateDir, "credentials-metadata", "sandbox.json"),
        "utf8",
      ),
    ) as { credential_id: string; credential_ref: string };
    expect(metadata.credential_id).toBeTruthy();
    const outputs = [lines(ctx, { secretStore, identity: ALICE }).output];
    const access = await slot.access();
    await access.secret();
    await access.rejected();
    outputs.push(lines(ctx, { secretStore, identity: ALICE }).output);
    outputs.push(lines(ctx, { secretStore, identity: BOB }).output);
    for (const output of outputs)
      for (const planted of [
        SENTINEL,
        ...refs,
        metadata.credential_ref,
        metadata.credential_id,
        "piship:",
        "sandbox.acme.example",
        "8443",
        "/api/v1",
        "origin-path-5512",
      ])
        expect(output, planted).not.toContain(planted);
  });
});

describe("Audit group", () => {
  it("reports each sink's counts and a failed required delivery at session end without losing the report", () => {
    const status: AuditStatus = {
      state: "failed",
      rejected: 1,
      sinks: [
        ...okStatus.sinks,
        {
          id: "siem",
          type: "http",
          required: true,
          state: "failed",
          delivered: 1,
          pending: 2,
          dropped: 4,
          lastError: "HTTP 503",
        },
      ],
    };
    const report = renderDoctor(
      doctorData("managed", {
        access: accessData(),
        governance: governanceData({
          audit: {
            status,
            closeError: formatError(
              new PiShipError(
                "AUDIT_UNAVAILABLE",
                "The session ended: 6 audit event(s) were not delivered to required audit sink siem (2 pending, 4 dropped)",
              ),
            ),
            targets: [
              { id: "local", target: "local file" },
              { id: "siem", target: "host audit.acme.example" },
            ],
          },
        }),
      }),
    );
    expect(report.failed).toBe(true);
    const output = report.render();
    const audit = group(output, "Audit");
    expect(audit[0]).toMatch(
      /^ {2}✗ state {16}failed; governed actions fail closed/,
    );
    expect(audit).toContain(
      `  ✗ ${"sink siem".padEnd(20)} http, required, host audit.acme.example: failed; delivered 1, pending 2, dropped 4; last error: HTTP 503`,
    );
    expect(audit).toContain(
      `  ! ${"rejected".padEnd(20)} 1 malformed event(s) rejected`,
    );
    expect(audit.join("\n")).toContain(
      `  ✗ ${"session end".padEnd(20)} AUDIT_UNAVAILABLE: The session ended`,
    );
    // Every other group is still reported.
    for (const name of ["Identity", "Gateway", "Sandbox", "Network", "Release"])
      expect(group(output, name).length).toBeGreaterThan(0);
  });

  it("reports a required sink that could not open, and an optional sink that dropped events", () => {
    const opened = renderDoctor(
      doctorData("managed", {
        governance: governanceData({
          mcp: undefined,
          audit: {
            openError:
              "AUDIT_UNAVAILABLE: Required audit sink siem (http) is unavailable",
            targets: [],
          },
        }),
      }),
    );
    expect(opened.failed).toBe(true);
    const output = opened.render();
    expect(group(output, "Audit")[0]).toBe(
      `  ✗ ${"state".padEnd(20)} AUDIT_UNAVAILABLE: Required audit sink siem (http) is unavailable`,
    );
    expect(group(output, "MCP")).toEqual([
      `  - ${"mcp".padEnd(20)} not started; the governed session did not open`,
    ]);
    const degraded = renderDoctor(
      doctorData("managed", {
        governance: governanceData({
          audit: {
            status: {
              state: "degraded",
              rejected: 0,
              sinks: [
                {
                  id: "siem",
                  type: "http",
                  required: false,
                  state: "degraded",
                  delivered: 0,
                  pending: 0,
                  dropped: 3,
                },
              ],
            },
            targets: [{ id: "siem", target: "host audit.acme.example" }],
          },
        }),
      }),
    );
    expect(degraded.failed).toBe(false);
    expect(group(degraded.render(), "Audit").slice(0, 2)).toEqual([
      `  ! ${"state".padEnd(20)} degraded`,
      `  ! ${"sink siem".padEnd(20)} http, optional, host audit.acme.example: degraded; delivered 0, pending 0, dropped 3`,
    ]);
  });
});

describe("doctor secret scan", () => {
  it("never prints a planted credential, token, proxy credential, or audit URL query", async () => {
    const opaque = "planted-opaque-credential-4417";
    // A value that went through SecretValue.reveal() is redacted wherever it
    // appears, even without a recognizable shape.
    new SecretValue(opaque).reveal();
    const jwt =
      "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJwbGFudGVkLXN1YmplY3QifQ.c2lnbmF0dXJl";
    const policy = {
      inheritProxyEnvironment: true,
      additionalCA: [],
      privateOnly: true,
      allowHosts: ["gateway.acme.example"],
    };
    const approved = approvedNetworkEnvironment(policy, {
      HTTPS_PROXY: "http://proxyuser:proxy-pass-8812@proxy.acme.example:3128",
      HTTP_PROXY: "http://proxy.acme.example:3128/?token=proxy-query-5521",
      NO_PROXY: "no-proxy-host-7731.internal",
    });
    // A real audit log with an HTTP sink whose URL carries a routing secret
    // and whose transport error echoes the URL and a bearer token.
    const sinkUrl =
      "https://audit.acme.example/ingest?routing=audit-query-6604";
    const log = await AuditLog.open({
      config: {
        enabled: true,
        sinks: [{ id: "siem", type: "http", url: sinkUrl, required: false }],
        buffer: { maxEvents: 10, flushIntervalMs: 0 },
        capture: NO_CONTENT_CAPTURE,
      },
      distribution: "doctor-test",
      stateDir: join(temp, "state"),
      fetch: async () => {
        throw new Error(
          `request to https://AUDIT.acme.example/ingest?routing=audit-query-6604 failed; Authorization: Bearer planted-bearer-9931abcdef`,
        );
      },
    });
    log.emit({ event: "session.start", user: null, session: "s1" });
    await log.flush();
    const status = await log.close();
    expect(status.sinks[0]?.lastError).toBeDefined();
    const base = accessData();
    const output = renderDoctor(
      doctorData("managed", {
        access: accessData({
          issuer:
            "https://idp-user:idp-pass-3390@idp.acme.example/realms/acme?x=idp-query-2280",
          gateway: {
            error: formatError(
              new PiShipError(
                "GATEWAY_UNREACHABLE",
                `request with sk-planted0credential0123 to https://gw-user:gw-pass-1174@gateway.acme.example/v1/models?key=gw-query-4459 failed`,
              ),
            ),
          },
          activationError: `refresh failed for ${jwt} (${opaque})`,
          network: { ...base.network, approved },
        }),
        governance: governanceData({
          mcp: [
            {
              id: "docs",
              state: "failed",
              transport: "streamable-http",
              tools: [],
              required: false,
              reason: `401 for token ${opaque}`,
            },
          ] as unknown as NonNullable<GovernanceData["mcp"]>,
          audit: {
            status,
            targets: [{ id: "siem", target: "host audit.acme.example" }],
          },
        }),
      }),
    ).render();
    for (const planted of [
      opaque,
      jwt,
      "proxyuser",
      "proxy-pass-8812",
      "proxy-query-5521",
      "no-proxy-host-7731",
      "audit-query-6604",
      "routing=",
      "planted-bearer-9931abcdef",
      "sk-planted0credential0123",
      "gw-user",
      "gw-pass-1174",
      "gw-query-4459",
      "idp-user",
      "idp-pass-3390",
      "idp-query-2280",
    ])
      expect(output, planted).not.toContain(planted);
    // What is safe to show still is.
    expect(output).toContain("http://proxy.acme.example:3128");
    expect(output).toContain("host audit.acme.example");
    expect(output).toContain("https://idp.acme.example/realms/acme");
  });
});

describe("MCP group", () => {
  it("shows plain HTTP and identity header names, never a value", () => {
    const output = renderDoctor(
      doctorData("managed", {
        governance: governanceData({
          manifest: {
            policy: {
              default: "deny",
              enforced: [],
              defaults: [],
              adapter: null,
            },
            capabilities: [],
            mcp: {
              servers: [
                {
                  id: "tickets",
                  transport: "streamable-http",
                  httpTransport: "http-allowed",
                  headers: {
                    "X-Company-User": { identityClaim: "preferred_username" },
                  },
                },
              ],
            },
            audit: { sinks: [] },
          } as unknown as GovernanceData["manifest"],
          mcp: [
            {
              id: "tickets",
              state: "healthy",
              transport: "streamable-http",
              plainHttp: true,
              tools: ["mcp__tickets__search"],
              required: true,
            },
          ] as unknown as NonNullable<GovernanceData["mcp"]>,
        }),
      }),
    ).render();
    expect(group(output, "MCP")).toEqual([
      `  ! ${"mcp tickets".padEnd(20)} healthy (streamable-http; plain HTTP, unencrypted; identity headers X-Company-User from preferred_username; 1 tool(s))`,
    ]);
  });
});

describe("Governance group", () => {
  const v6 = (
    data: DoctorData,
    metadata: Record<string, unknown> = {},
  ): DoctorData => ({
    ...data,
    ctx: {
      ...data.ctx,
      metadata: {
        ...data.ctx.metadata,
        schema: "piship-lock/v1alpha6",
        manifest: { schema: "piship/v1alpha6" },
        enforcement: { pi: "1.0.2", seams: {}, digest: "sha256-x" },
        ...metadata,
      } as unknown as LaunchContext["metadata"],
    },
  });

  it("lists every action no seam enforces, and never calls it enforced", () => {
    const output = renderDoctor(
      doctorData("managed", {
        access: accessData(),
        // A sandbox without the network plane: network.connect has no seam.
        governance: governanceData(),
      }),
    ).render();
    const lines = group(output, "Governance");
    expect(lines).toContain(`  ✓ ${"enforced actions".padEnd(20)} 13 of 19`);
    for (const action of [
      "agent.invoke",
      "network.connect",
      "memory.read",
      "memory.write",
      "web.request",
      "browser.execute",
    ])
      expect(lines).toContain(`  - ${action.padEnd(20)} unsupported`);
    for (const line of lines.filter((item) => item.includes("unsupported")))
      expect(line).not.toMatch(/\benforced\b/);
  });

  it("suggests migrate for an older manifest schema", () => {
    const output = renderDoctor(doctorData("personal", {})).render();
    expect(group(output, "Governance")).toEqual([
      `  - ${"manifest schema".padEnd(20)} piship/v1alpha4; the maintainer runs piship migrate <manifest> --check, then --write, to adopt piship/v1alpha6`,
    ]);
  });

  it("warns when the seam table was proven against another Pi", () => {
    const data = v6(doctorData("personal", {}), {
      enforcement: { pi: "0.87.1", seams: {}, digest: "sha256-x" },
    });
    expect(group(renderDoctor(data).render(), "Governance")).toEqual([
      `  ! ${"seam table".padEnd(20)} proven against Pi 0.87.1, running Pi 1.0.2; relock the distribution`,
      // A v1alpha6 lock without runtime.cacheWarming is off.
      `  ✓ ${"cache warming".padEnd(20)} off`,
    ]);
  });

  it("reports the tool exposure a launch resolves", () => {
    const data = v6(
      doctorData("managed", {
        access: accessData(),
        governance: governanceData({
          exposure: {
            codemode: "on",
            codemodeOn: true,
            toolSearchOn: false,
            tools: {
              bash: "codemode",
              docs_delete: "hidden",
              edit: "direct",
              read: "direct",
            },
          },
        }),
      }),
      {
        runtimeTools: { codemode: "on", toolSearch: "off", exposure: [] },
        declared: { extensions: ["./extensions/router.ts"] },
        virtualModels: [
          {
            id: "acme/auto",
            router: "./extensions/router.ts",
            routes: ["acme/coder"],
          },
          {
            id: "acme/platform",
            router: "package:platform",
            routes: ["acme/coder"],
          },
        ],
        packages: [
          {
            id: "pi-platform",
            source: "npm",
            class: "company",
            version: "1.0.0",
            files: 4,
          },
        ],
        cacheWarming: { mode: "streaming", userOverride: true },
      },
    );
    const lines = group(renderDoctor(data).render(), "Governance");
    expect(lines).toEqual(
      expect.arrayContaining([
        `  ✓ ${"Pi packages".padEnd(20)} 1 vendored, integrity verified at launch`,
        `  - ${"package pi-platform".padEnd(20)} npm 1.0.0 (company), 4 files`,
        `  ✓ ${"cache warming".padEnd(20)} streaming (user may override)`,
        `  ✓ ${"runtime mutation".padEnd(20)} enforced per turn; a change that cannot be restored blocks the session`,
      ]),
    );
    const blocked = renderDoctor(
      v6(
        doctorData("managed", {
          access: accessData(),
          governance: governanceData({
            runtimeError:
              "Enforced instructions or tools of this session were changed and could not be restored",
          }),
        }),
      ),
    );
    expect(blocked.failed).toBe(true);
    expect(group(blocked.render(), "Governance")).toContain(
      `  ✗ ${"runtime".padEnd(20)} Enforced instructions or tools of this session were changed and could not be restored`,
    );
    expect(lines).toEqual(
      expect.arrayContaining([
        `  ✓ ${"seam table".padEnd(20)} Pi 1.0.2`,
        `  ✓ ${"Codemode".padEnd(20)} enforced (on)`,
        `  ✓ ${"deferred tools".padEnd(20)} off`,
        `  ✓ ${"tool exposure".padEnd(20)} codemode: bash; hidden: docs_delete; direct: edit, read`,
        `  - ${"extension tools".padEnd(20)} exposure resolved and enforced at launch`,
        `  ✓ ${"virtual acme/auto".padEnd(20)} router ./extensions/router.ts, routes acme/coder`,
        // A router that names no built extension cannot register the model.
        `  ✗ ${"virtual acme/platform".padEnd(20)} router package:platform, routes acme/coder; the router is not a declared extension of this build, so the model cannot be registered`,
      ]),
    );
    expect(renderDoctor(data).failed).toBe(true);
    const failed = renderDoctor(
      doctorData("managed", {
        access: accessData(),
        governance: governanceData({
          exposureError:
            "Codemode is on, but the policy decides bash only by its built-in default",
        }),
      }),
    );
    expect(failed.failed).toBe(true);
    expect(group(failed.render(), "Governance")).toContain(
      `  ✗ ${"tool exposure".padEnd(20)} Codemode is on, but the policy decides bash only by its built-in default`,
    );
  });

  it("reports the data lifecycle, and a retained release that stops sweeping", () => {
    const home = join(temp, "install");
    const bin = join(temp, "bin");
    process.env.PISHIP_BIN_HOME = bin;
    const app = join(home, "apps", "doctor-test");
    const payload = (version: string, lock: Record<string, unknown>) => {
      const dir = join(app, version);
      mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, "piship.lock"), JSON.stringify(lock));
      return dir;
    };
    const older = payload("0.9.0", { schema: "piship-lock/v1alpha5" });
    const active = payload("1.0.0", {
      schema: "piship-lock/v1alpha6",
      data: { contract: "piship-data/v1" },
    });
    mkdirSync(join(home, "receipts"), { recursive: true });
    writeFileSync(
      join(home, "receipts", "doctor-test.json"),
      JSON.stringify({
        schema: "piship-install/v1",
        app: {
          id: "doctor-test",
          name: "AcmeCode",
          version: "1.0.0",
          command: "acmecode",
        },
        payload: active,
        commandPath: join(
          bin,
          process.platform === "win32" ? "acmecode.cmd" : "acmecode",
        ),
        launcher: join(app, "launch.mjs"),
        active: "1.0.0",
        previous: "0.9.0",
        releases: [
          { version: "0.9.0", payload: older, installedAt: "" },
          { version: "1.0.0", payload: active, installedAt: "" },
        ],
      }),
    );
    const base = doctorData("personal", {});
    const data = v6(
      { ...base, ctx: { ...base.ctx, distributionDir: active } },
      {
        data: {
          contract: "piship-data/v1",
          declared: {
            retention: {
              sessions: { retentionSeconds: 30 * 86_400 },
              audit: { retentionSeconds: 180 * 86_400 },
              temp: { retentionSeconds: 3_600 },
            },
            purge: { onLogout: ["cache", "temp"], onUninstall: "none" },
            export: {},
          },
        },
      },
    );
    expect(group(renderDoctor(data).render(), "Governance")).toEqual([
      `  ✓ ${"seam table".padEnd(20)} Pi 1.0.2`,
      `  ✓ ${"cache warming".padEnd(20)} off`,
      `  ✓ ${"data retention".padEnd(20)} sessions 30d max, audit 180d min, temp 1h max`,
      `  ✓ ${"data purge".padEnd(20)} logout: cache, temp; uninstall: none`,
      `  ! ${"data retention".padEnd(20)} installed release 0.9.0 predates the data contract: rolled back to, it stops the retention sweep`,
    ]);
    const undeclared = v6(base, { data: { contract: "piship-data/v1" } });
    expect(group(renderDoctor(undeclared).render(), "Governance")).toContain(
      `  - ${"data retention".padEnd(20)} not declared; nothing is swept`,
    );
  });
});
