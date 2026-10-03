import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AuditStatus } from "@piship/audit";
import { PiShipError } from "@piship/contracts";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { selfSignedLoopbackCertificate } from "../../../../tests/helpers/x509.js";
import type { LaunchContext } from "../launch/context.js";

// The governed session is replaced so each close() outcome can be forced.
const session = vi.hoisted(() => ({
  close: vi.fn<() => Promise<AuditStatus>>(),
  open: vi.fn(),
}));
vi.mock("../launch/governance.js", () => ({
  governanceOptions: () => ({}),
  openGovernance: session.open,
}));
vi.mock("../governance-session.js", () => ({
  inspectGovernance: async () => ({
    project: { origin: "company", root: "/work/acme" },
    candidates: [],
    sandbox: {
      level: "not-required",
      adapter: "linux-bubblewrap",
      provider: "native",
      required: false,
      planes: [],
      network: "allow",
      localProcesses: false,
      warnings: [],
    },
    containment: "not required",
    engine: { id: "acme-engineering@1", diagnostics: [] },
    capabilities: [],
    resources: [],
    userAuto: { allowed: false, state: "not-allowed", active: false },
  }),
}));

const { collectDoctorData, networkChecks } = await import("./data.js");
const { renderDoctor } = await import("../commands/doctor.js");

const lostStatus: AuditStatus = {
  state: "failed",
  rejected: 0,
  sinks: [
    {
      id: "siem",
      type: "http",
      required: true,
      state: "failed",
      delivered: 1,
      pending: 2,
      dropped: 0,
    },
  ],
};

let temp: string;
beforeEach(() => {
  temp = mkdtempSync(join(tmpdir(), "piship-doctor-collect-"));
  vi.stubEnv("PISHIP_INSTALL_HOME", join(temp, "install"));
  session.close.mockReset();
  session.open.mockReset();
  session.open.mockImplementation(async () => ({
    mcpReports: [],
    audit: { flush: async () => undefined, status: () => lostStatus },
    close: session.close,
  }));
});
afterEach(() => {
  vi.unstubAllEnvs();
  rmSync(temp, { recursive: true, force: true });
});

function context(): LaunchContext {
  return {
    metadata: {
      schema: "piship-lock/v1alpha4",
      app: {
        id: "doctor-collect",
        name: "AcmeCode",
        version: "1.0.0",
        command: "acmecode",
      },
      runtime: { pishipVersion: "0.7.0" },
      manifest: { schema: "piship/v1alpha4" },
      governance: {
        manifest: {
          policy: { default: "deny", enforced: [], defaults: [] },
          capabilities: [],
          mcp: { servers: [] },
          audit: {
            sinks: [
              {
                id: "siem",
                type: "http",
                url: "https://audit.acme.example/in?routing=q-5512",
                required: true,
              },
            ],
          },
        },
      },
    },
    mode: "personal",
    distributionDir: temp,
    stateDir: join(temp, "state"),
    agentDir: join(temp, "agent"),
    out: () => undefined,
    err: () => undefined,
  } as unknown as LaunchContext;
}

describe("collectDoctorData", () => {
  it("keeps the whole report when closing the session loses required audit events", async () => {
    session.close.mockRejectedValue(
      new PiShipError(
        "AUDIT_UNAVAILABLE",
        "The session ended: 2 audit event(s) were not delivered to required audit sink siem (2 pending, 0 dropped)",
      ),
    );
    const data = await collectDoctorData(context());
    expect(session.close).toHaveBeenCalledTimes(1);
    expect(data.governance?.audit.closeError).toContain("AUDIT_UNAVAILABLE");
    expect(data.governance?.shutdownError).toBeUndefined();
    const report = renderDoctor(data);
    expect(report.failed).toBe(true);
    const output = report.render();
    expect(output).toMatch(
      /Audit\n {2}✗ state {16}failed[^\n]*\n {2}✗ sink siem {12}http, required, host audit\.acme\.example: failed; delivered 1, pending 2, dropped 0\n {2}✗ session end {10}AUDIT_UNAVAILABLE: The session ended/,
    );
    expect(output).not.toContain("q-5512");
    for (const name of ["Distribution", "Policy", "Sandbox", "Network"])
      expect(output).toContain(`\n${name}\n`);
  });

  it("reports a cleanup failure at session end apart from audit", async () => {
    session.close.mockRejectedValue(new Error("sandbox dispose failed"));
    const data = await collectDoctorData(context());
    expect(data.governance?.audit.closeError).toBeUndefined();
    expect(data.governance?.shutdownError).toBe("sandbox dispose failed");
    expect(renderDoctor(data).render()).toContain(
      `  ✗ ${"shutdown".padEnd(20)} sandbox dispose failed`,
    );
  });

  it("reports a required sink that cannot open in the Audit group", async () => {
    session.open.mockRejectedValue(
      new PiShipError(
        "AUDIT_UNAVAILABLE",
        "Required audit sink siem (http) is unavailable: <sink> refused",
      ),
    );
    const data = await collectDoctorData(context());
    expect(session.close).not.toHaveBeenCalled();
    const output = renderDoctor(data).render();
    expect(output).toContain(
      `Audit\n  ✗ ${"state".padEnd(20)} AUDIT_UNAVAILABLE: Required audit sink siem (http) is unavailable`,
    );
    expect(output).toContain(
      `MCP\n  - ${"mcp".padEnd(20)} not started; the governed session did not open`,
    );
  });

  it("closes the session and reports the final audit status", async () => {
    session.close.mockResolvedValue({
      state: "ok",
      rejected: 0,
      sinks: [{ ...lostStatus.sinks[0], state: "ok", pending: 0 }],
    } as AuditStatus);
    const output = renderDoctor(await collectDoctorData(context())).render();
    expect(output).toContain(
      `  ✓ ${"sink siem".padEnd(20)} http, required, host audit.acme.example: healthy; delivered 1, pending 0, dropped 0`,
    );
  });
});

describe("networkChecks", () => {
  const servers: Server[] = [];
  afterEach(async () => {
    for (const server of servers.splice(0)) {
      server.closeAllConnections();
      await new Promise<void>((closed) => server.close(() => closed()));
    }
  });
  const listen = (server: Server) =>
    new Promise<number>((done) => {
      servers.push(server);
      server.listen(0, "127.0.0.1", () =>
        done((server.address() as AddressInfo).port),
      );
    });
  const policy = {
    inheritProxyEnvironment: true,
    additionalCA: [] as string[],
    privateOnly: false,
    allowHosts: [],
  };

  it("checks the proxy, the CA bundles, and each endpoint's path, with the proxy credential removed", async () => {
    const certificate = selfSignedLoopbackCertificate();
    const tlsPort = await listen(
      createHttpsServer(
        { cert: certificate.certificate, key: certificate.key },
        (_request, response) => response.writeHead(404).end(),
      ),
    );
    const plainPort = await listen(
      createServer((_request, response) => response.writeHead(405).end()),
    );
    const dead = createServer();
    const deadPort = await listen(dead);
    dead.close();
    // Lower-case names first: on Windows they are the same variables, so
    // clearing them after setting HTTPS_PROXY would clear it too.
    vi.stubEnv("https_proxy", undefined);
    vi.stubEnv("http_proxy", undefined);
    vi.stubEnv("no_proxy", undefined);
    vi.stubEnv("HTTP_PROXY", undefined);
    vi.stubEnv("NO_PROXY", undefined);
    vi.stubEnv(
      "HTTPS_PROXY",
      `http://proxyuser:proxy-pass-8812@127.0.0.1:${deadPort}`,
    );
    const checks = await networkChecks(policy, [
      { label: "gateway", url: `https://127.0.0.1:${tlsPort}/v1` },
      { label: "broker", url: `http://127.0.0.1:${plainPort}/broker` },
      { label: "issuer", url: undefined },
    ]);
    expect(checks.proxyChecks).toEqual([
      { proxy: `http://127.0.0.1:${deadPort}`, error: "ECONNREFUSED" },
    ]);
    expect(checks.paths).toEqual([
      {
        label: "gateway",
        host: `127.0.0.1:${tlsPort}`,
        code: "GATEWAY_UNREACHABLE",
        error: expect.stringContaining(
          `failed at the proxy http://127.0.0.1:${deadPort}: ECONNREFUSED`,
        ),
      },
      // Plain HTTP to a loopback host is not proxied by HTTPS_PROXY.
      { label: "broker", host: `127.0.0.1:${plainPort}`, status: 405 },
    ]);
    expect(JSON.stringify(checks)).not.toContain("proxy-pass-8812");

    vi.stubEnv("HTTPS_PROXY", undefined);
    const direct = await networkChecks(policy, [
      { label: "gateway", url: `https://127.0.0.1:${tlsPort}/v1` },
    ]);
    expect(direct.proxyChecks).toEqual([]);
    expect(direct.paths).toEqual([
      {
        label: "gateway",
        host: `127.0.0.1:${tlsPort}`,
        code: "TLS_POLICY_VIOLATION",
        error: expect.stringContaining("network.tls.additionalCA"),
      },
    ]);

    const bundle = join(temp, "ca.pem");
    writeFileSync(bundle, certificate.certificate);
    const trusted = await networkChecks({ ...policy, additionalCA: [bundle] }, [
      { label: "gateway", url: `https://127.0.0.1:${tlsPort}/v1` },
    ]);
    expect(trusted.caCertificates).toBe(1);
    expect(trusted.paths).toEqual([
      { label: "gateway", host: `127.0.0.1:${tlsPort}`, status: 404 },
    ]);

    writeFileSync(bundle, "not a certificate");
    const broken = await networkChecks({ ...policy, additionalCA: [bundle] }, [
      { label: "gateway", url: `https://127.0.0.1:${tlsPort}/v1` },
    ]);
    expect(broken.caError).toContain("CONFIG_INVALID");
    expect(broken.paths).toBeUndefined();
  });
});
