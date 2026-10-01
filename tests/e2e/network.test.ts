import { spawnSync } from "node:child_process";
import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import {
  createServer,
  request as httpRequest,
  type IncomingMessage,
  type Server,
} from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { type AddressInfo, connect as connectSocket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  afterAll,
  beforeAll,
  describe,
  expect,
  it,
  onTestFinished,
} from "vitest";
// @ts-expect-error The deterministic fixture is plain JavaScript.
import { startLocalServices } from "../../examples/demo-company/fixtures/local-services.mjs";
import { branded, launcher, type Result } from "../helpers/distribution.js";
import { selfSignedLoopbackCertificate } from "../helpers/x509.js";

// Enterprise networking through the real launcher (spec section 17): the
// proxy path, the NO_PROXY path, the custom CA path, the private endpoint
// path, publicFallback: deny, TLS that is never downgraded or disabled, and
// the network environment of child processes. Everything runs on loopback: a
// forwarding proxy, a TLS server in front of the deterministic fixtures, and
// an audit sink. No compose stack and no real company service.
const root = fileURLToPath(new URL("../../", import.meta.url));
const bin = join(root, "packages/cli/dist/bin.js");
const windows = process.platform === "win32";

type Services = Awaited<ReturnType<typeof startLocalServices>>;

// Every variable that picks a proxy, trust roots, or TLS verification. The
// tests start from none of them, so the machine running them cannot change
// what a launch sees.
const NETWORK_NAMES = [
  "HTTP_PROXY",
  "http_proxy",
  "HTTPS_PROXY",
  "https_proxy",
  "NO_PROXY",
  "no_proxy",
  "ALL_PROXY",
  "all_proxy",
  "NODE_EXTRA_CA_CERTS",
  "SSL_CERT_FILE",
  "SSL_CERT_DIR",
  "CURL_CA_BUNDLE",
  "REQUESTS_CA_BUNDLE",
  "GIT_SSL_CAINFO",
  "GIT_SSL_NO_VERIFY",
  "NODE_TLS_REJECT_UNAUTHORIZED",
];

interface Recorder {
  readonly url: string;
  /** `METHOD target` for each request and `CONNECT host:port` for each tunnel. */
  readonly seen: string[];
  readonly proxyAuthorization: string[];
}

function listen(server: Server): Promise<number> {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () =>
      resolve((server.address() as AddressInfo).port),
    );
    onTestFinished(
      () =>
        new Promise<void>((done) => {
          server.close(() => done());
          server.closeAllConnections();
        }),
    );
  });
}

/**
 * A loopback HTTP proxy. `forward` relays absolute-URI requests and CONNECT
 * tunnels to their target; `trap` answers 502 to everything. Both record
 * what they saw, so a test can prove which requests used the proxy.
 */
async function proxy(mode: "forward" | "trap"): Promise<Recorder> {
  const seen: string[] = [];
  const proxyAuthorization: string[] = [];
  const server = createServer((request, response) => {
    seen.push(`${request.method} ${request.url}`);
    const credential = request.headers["proxy-authorization"];
    if (typeof credential === "string") proxyAuthorization.push(credential);
    if (mode === "trap") {
      response.headersSent ? response.destroy() : response.writeHead(502).end();
      return;
    }
    const target = new URL(request.url ?? "");
    const headers = { ...request.headers };
    delete headers["proxy-authorization"];
    delete headers["proxy-connection"];
    const upstream = httpRequest(
      {
        hostname: target.hostname,
        port: target.port,
        path: `${target.pathname}${target.search}`,
        method: request.method,
        headers,
      },
      (reply) => {
        response.writeHead(reply.statusCode ?? 502, reply.headers);
        reply.pipe(response);
      },
    );
    upstream.on("error", () =>
      response.headersSent ? response.destroy() : response.writeHead(502).end(),
    );
    request.pipe(upstream);
  });
  server.on("connect", (request, socket, head) => {
    seen.push(`CONNECT ${request.url}`);
    const credential = request.headers["proxy-authorization"];
    if (typeof credential === "string") proxyAuthorization.push(credential);
    if (mode === "trap") {
      socket.end("HTTP/1.1 502 Bad Gateway\r\n\r\n");
      return;
    }
    const [host, port] = (request.url ?? "").split(":");
    const upstream = connectSocket(Number(port), host ?? "127.0.0.1", () => {
      socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      upstream.write(head);
      upstream.pipe(socket);
      socket.pipe(upstream);
    });
    upstream.on("error", () => socket.destroy());
    socket.on("error", () => upstream.destroy());
  });
  const port = await listen(server);
  return { url: `http://127.0.0.1:${port}`, seen, proxyAuthorization };
}

/** An HTTPS server, with a certificate of its own, in front of the fixtures. */
async function tlsFront(target: string) {
  const certificate = selfSignedLoopbackCertificate("gateway");
  const hits: string[] = [];
  const upstream = new URL(target);
  const server = createHttpsServer(
    { cert: certificate.certificate, key: certificate.key },
    (request: IncomingMessage, response) => {
      hits.push(`${request.method} ${request.url}`);
      const forwarded = httpRequest(
        {
          hostname: upstream.hostname,
          port: upstream.port,
          path: request.url,
          method: request.method,
          headers: request.headers,
        },
        (reply) => {
          response.writeHead(reply.statusCode ?? 502, reply.headers);
          reply.pipe(response);
        },
      );
      forwarded.on("error", () =>
        response.headersSent
          ? response.destroy()
          : response.writeHead(502).end(),
      );
      request.pipe(forwarded);
    },
  );
  const port = await listen(server);
  return {
    url: `https://127.0.0.1:${port}`,
    hits,
    certificate: certificate.certificate,
  };
}

/** A metadata audit sink that records the event names it receives. */
async function auditSink() {
  const events: string[] = [];
  const server = createServer((request, response) => {
    let body = "";
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      const parsed = JSON.parse(body || "{}") as {
        events?: { event?: string }[];
      };
      for (const event of parsed.events ?? [])
        if (event.event) events.push(event.event);
      response.writeHead(200, { "content-type": "application/json" });
      response.end("{}");
    });
  });
  const port = await listen(server);
  return { url: `http://127.0.0.1:${port}/audit`, events };
}

interface Built {
  readonly directory: string;
  readonly command: string;
}
const built = new Map<"sandboxed" | "unsandboxed", Built>();
const temporary: string[] = [];

/**
 * A copy of the demo distribution that reads its enterprise CA and its audit
 * sink from the launch environment, with the sandbox either allowing the
 * network (Windows has no native sandbox, so it runs uncontained there) or
 * off. Only the fixture's own policy is loosened: Build mode and shell
 * commands, which the scripted model turns need.
 */
function build(kind: "sandboxed" | "unsandboxed"): Built {
  const temp = realpathSync(mkdtempSync(join(tmpdir(), "piship-network-e2e-")));
  temporary.push(temp);
  const directory = join(temp, "distribution");
  cpSync(join(root, "examples", "demo-company"), directory, {
    recursive: true,
  });
  const manifest = join(directory, "piship.yaml");
  const replacements: [string, string][] = [
    ["provider: system", "provider: file\n    acknowledgePlaintext: true"],
    ["127.0.0.1:8765", "127.0.0.1"],
    ["defaultMode: plan", "defaultMode: build"],
    [
      '    - id: acme.shell\n      action: shell.execute\n      resource: "**"\n      effect: ask',
      '    - id: acme.shell\n      action: shell.execute\n      resource: "**"\n      effect: allow',
    ],
    [
      "  - ACMECODE_LLM_GATEWAY_URL\n",
      "  - ACMECODE_LLM_GATEWAY_URL\n  - ACMECODE_CA_BUNDLE\n  - ACMECODE_AUDIT_URL\n",
    ],
    [
      "  publicFallback: deny\n  privateOnly: true\n",
      `  publicFallback: deny\n  privateOnly: true\n  tls:\n    additionalCA:\n      - \${ACMECODE_CA_BUNDLE}\n`,
    ],
    [
      "    - id: local\n      type: file\n      required: false",
      `    - id: local\n      type: file\n      required: false\n    - id: company\n      type: http\n      url: \${ACMECODE_AUDIT_URL}\n      required: true`,
    ],
    [
      "  network:\n    mode: deny",
      kind === "sandboxed"
        ? "  network:\n    mode: allow"
        : "  network:\n    mode: deny",
    ],
  ];
  if (kind === "unsandboxed" || windows)
    replacements.push([
      "  required: true\n  filesystem:",
      "  required: false\n  filesystem:",
    ]);
  let source = readFileSync(manifest, "utf8");
  for (const [from, to] of replacements) {
    if (!source.includes(from)) throw new Error(`manifest patch: ${from}`);
    source = source.replace(from, to);
  }
  writeFileSync(manifest, source);
  const env = { ...process.env };
  delete env.PISHIP_BUILD_INPUT;
  delete env.PISHIP_SANDBOX_ADAPTER;
  for (const step of ["lock", "build"]) {
    const done = spawnSync(process.execPath, [bin, step, manifest], {
      cwd: temp,
      env,
      encoding: "utf8",
    });
    expect(done.status, done.stderr).toBe(0);
  }
  return {
    directory,
    command: launcher(join(temp, "dist", "acmecode"), "acmecode"),
  };
}

beforeAll(() => {
  // Windows has no native sandbox: only the uncontained distribution is used.
  if (!windows) built.set("sandboxed", build("sandboxed"));
  built.set("unsandboxed", build("unsandboxed"));
}, 600000);
afterAll(() => {
  for (const path of temporary.splice(0))
    rmSync(path, { recursive: true, force: true });
}, 60000);

/**
 * One launch environment: fresh fixtures, state, and home, a project that
 * holds the CA bundles, and every gateway endpoint on plain loopback until a
 * test moves the broker and gateway behind TLS.
 */
async function scenario(kind: "sandboxed" | "unsandboxed" = "unsandboxed") {
  const distribution = built.get(kind);
  if (!distribution) throw new Error("distribution not built");
  const services: Services = await startLocalServices();
  onTestFinished(() => services.close());
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "piship-network-run-")));
  onTestFinished(() => rmSync(dir, { recursive: true, force: true }));
  const project = join(dir, "project");
  const home = join(dir, "home");
  mkdirSync(project);
  mkdirSync(home);
  const sink = await auditSink();
  const front = await tlsFront(services.base);
  writeFileSync(join(project, "front-ca.pem"), front.certificate);
  writeFileSync(
    join(project, "wrong-ca.pem"),
    selfSignedLoopbackCertificate("unrelated").certificate,
  );
  const environment = (extra: Record<string, string | undefined>) => {
    const env: NodeJS.ProcessEnv = { ...process.env };
    for (const name of NETWORK_NAMES) delete env[name];
    delete env.PISHIP_BUILD_INPUT;
    delete env.PISHIP_SANDBOX_ADAPTER;
    Object.assign(env, services.env(), {
      PISHIP_STATE_HOME: join(dir, "state"),
      PISHIP_NO_BROWSER: "1",
      HOME: home,
      USERPROFILE: home,
      ACMECODE_CA_BUNDLE: join(project, "front-ca.pem"),
      ACMECODE_AUDIT_URL: sink.url,
    });
    for (const [name, value] of Object.entries(extra))
      if (value === undefined) delete env[name];
      else env[name] = value;
    return env;
  };
  const run = (
    args: string[],
    extra: Record<string, string | undefined> = {},
  ): Promise<Result> =>
    branded(distribution.command, args, {
      cwd: project,
      env: environment(extra),
      approve: (url) => services.approve(url),
    });
  return {
    services,
    sink,
    front,
    project,
    run,
    /** The broker and the gateway behind the TLS server. */
    tls: {
      ACMECODE_CREDENTIAL_BROKER_URL: `${front.url}/broker/v1/llm-credential`,
      ACMECODE_CREDENTIAL_REVOKE_URL: `${front.url}/broker/v1/revoke`,
      ACMECODE_LLM_GATEWAY_URL: `${front.url}/gateway/v1`,
    },
  };
}

const path = (recorder: readonly string[], fragment: string) =>
  recorder.some((line) => line.includes(fragment));

async function signedIn(
  s: Awaited<ReturnType<typeof scenario>>,
  extra: Record<string, string | undefined> = {},
) {
  const login = await s.run(["login"], extra);
  expect(login.status, login.stderr).toBe(0);
}

describe("enterprise networking through the launcher (loopback fixtures)", () => {
  it("proxy path: every managed request goes through the inherited proxy", async () => {
    const s = await scenario();
    const forward = await proxy("forward");
    const env = {
      HTTP_PROXY: forward.url,
      http_proxy: forward.url,
    };
    await signedIn(s, env);
    const smoke = await s.run(["--smoke"], env);
    expect(smoke.status, smoke.stderr).toBe(0);
    for (const fragment of [
      "/idp/.well-known/openid-configuration",
      "/idp/token",
      "/broker/v1/llm-credential",
      "/gateway/v1/models",
      "/audit",
    ])
      expect(path(forward.seen, fragment), fragment).toBe(true);
    // Everything the proxy relayed reached the fixtures.
    expect(
      path(
        s.services.state.requests.map((r: { path: string }) => r.path),
        "/gateway/v1/models",
      ),
    ).toBe(true);
  }, 300000);

  it("proxy path: a proxy that refuses the traffic stops the launch, so the proxy really is in the path", async () => {
    const s = await scenario();
    await signedIn(s);
    const trap = await proxy("trap");
    const smoke = await s.run(["--smoke"], {
      HTTP_PROXY: trap.url,
      http_proxy: trap.url,
    });
    expect(smoke.status).toBe(1);
    expect(trap.seen.length).toBeGreaterThan(0);
  }, 300000);

  it("NO_PROXY path: excluded hosts bypass the proxy and nothing reaches it", async () => {
    const s = await scenario();
    const trap = await proxy("trap");
    const env = {
      HTTP_PROXY: trap.url,
      http_proxy: trap.url,
      NO_PROXY: "127.0.0.1,localhost",
      no_proxy: "127.0.0.1,localhost",
    };
    await signedIn(s, env);
    const smoke = await s.run(["--smoke"], env);
    expect(smoke.status, smoke.stderr).toBe(0);
    expect(trap.seen).toEqual([]);
    expect(
      path(
        s.services.state.requests.map((r: { path: string }) => r.path),
        "/gateway/v1/models",
      ),
    ).toBe(true);
  }, 300000);

  it("custom CA path: the declared bundle is trusted, and a bundle without the server certificate is not", async () => {
    const s = await scenario();
    await signedIn(s, s.tls);
    const smoke = await s.run(["--smoke"], s.tls);
    expect(smoke.status, smoke.stderr).toBe(0);
    expect(path(s.front.hits, "/gateway/v1/models")).toBe(true);
    expect(path(s.front.hits, "/broker/v1/llm-credential")).toBe(true);

    const before = s.front.hits.length;
    const untrusted = await s.run(["--smoke"], {
      ...s.tls,
      ACMECODE_CA_BUNDLE: join(s.project, "wrong-ca.pem"),
    });
    expect(untrusted.status).toBe(1);
    expect(untrusted.stderr).toContain("TLS_POLICY_VIOLATION");
    expect(untrusted.stderr).toContain("network.tls.additionalCA");
    // No request completed a TLS handshake, and verification was never turned off.
    expect(s.front.hits.length).toBe(before);
    expect(untrusted.stderr).not.toContain("NODE_TLS_REJECT_UNAUTHORIZED");
  }, 300000);

  it("private endpoint path: private hosts on other ports work under private-only, with a proxy that would refuse anything else", async () => {
    const s = await scenario();
    const trap = await proxy("trap");
    const env = {
      ...s.tls,
      HTTP_PROXY: trap.url,
      HTTPS_PROXY: trap.url,
      NO_PROXY: "127.0.0.1",
    };
    await signedIn(s, env);
    const smoke = await s.run(["--smoke"], env);
    expect(smoke.status, smoke.stderr).toBe(0);
    // The IdP, the TLS gateway, and the audit sink share one hostname and
    // three ports. Private-only compares the hostname, so all are allowed.
    expect(s.sink.events).toContain("session.start");
    expect(path(s.front.hits, "/gateway/v1/models")).toBe(true);
    expect(trap.seen).toEqual([]);
    const doctor = await s.run(["doctor"], env);
    expect(doctor.status, doctor.stdout + doctor.stderr).toBe(0);
    expect(doctor.stdout).toMatch(
      /✓ outbound\s+private-only: declared hosts only/,
    );
  }, 300000);

  it("publicFallback: deny refuses an undeclared public host before any proxy or connection", async () => {
    const s = await scenario();
    await signedIn(s);
    const forward = await proxy("forward");
    const denied = await s.run(["--smoke"], {
      ACMECODE_AUDIT_URL: "https://audit.public.invalid/batch",
      HTTP_PROXY: forward.url,
      HTTPS_PROXY: forward.url,
    });
    expect(denied.status).toBe(1);
    expect(denied.stderr).toContain("AUDIT_UNAVAILABLE");
    expect(denied.stderr).toContain(
      "Private-only network policy denies undeclared host audit.public.invalid",
    );
    // Not even a CONNECT for the public host left the process.
    expect(forward.seen.some((line) => line.includes("public.invalid"))).toBe(
      false,
    );
  }, 300000);

  it("TLS is never disabled and an https endpoint is never reached over plain HTTP", async () => {
    const s = await scenario();
    await signedIn(s);
    const requests = () => s.services.state.requests.length;

    // A disabled-verification environment is refused before any request.
    const before = requests();
    const insecure = await s.run(["--smoke"], {
      NODE_TLS_REJECT_UNAUTHORIZED: "0",
    });
    expect(insecure.status).toBe(1);
    expect(insecure.stderr).toContain("TLS_POLICY_VIOLATION");
    expect(requests()).toBe(before);

    // An https URL on a port that only speaks plain HTTP fails at the
    // handshake; the plain server never sees the request.
    const plainPort = new URL(s.services.base).port;
    const downgraded = await s.run(["--smoke"], {
      ACMECODE_LLM_GATEWAY_URL: `https://127.0.0.1:${plainPort}/gateway/v1`,
    });
    expect(downgraded.status).toBe(1);
    expect(requests()).toBe(before);

    // Plain HTTP to a host that is not loopback is refused, not attempted.
    const forward = await proxy("forward");
    const plain = await s.run(["--smoke"], {
      ACMECODE_LLM_GATEWAY_URL: "http://gateway.internal.invalid/v1",
      HTTP_PROXY: forward.url,
    });
    expect(plain.status).toBe(1);
    expect(plain.stderr).toMatch(/CONFIG_INVALID|NETWORK_DENIED/);
    expect(forward.seen.some((line) => line.includes("internal.invalid"))).toBe(
      false,
    );
    expect(requests()).toBe(before);
  }, 300000);
});

// What a command run by the agent's bash tool receives. The fixture gateway
// scripts two tool calls: one prints the network variables, the other makes
// a TLS request that only succeeds when the child trusts the declared CA.
const CHILD_NAMES = [...NETWORK_NAMES, "PISHIP_E2E_PLAIN", "OPENAI_API_KEY"];
const node = JSON.stringify(process.execPath);
const dump = `${node} -e 'console.log(JSON.stringify(Object.fromEntries(${JSON.stringify(CHILD_NAMES)}.map((n)=>[n,process.env[n]??null]))))'`;

async function childEnvironment(
  s: Awaited<ReturnType<typeof scenario>>,
  extra: Record<string, string | undefined>,
) {
  await signedIn(s, extra);
  const probe = `${node} -e 'require("https").get(${JSON.stringify(`${s.front.url}/gateway/v1/models`)},(r)=>{console.log("TLS",r.statusCode);r.resume()}).on("error",(e)=>console.log("TLSERR",e.code))'`;
  s.services.knobs.gatewayMode = "script";
  s.services.knobs.toolScript = [
    { name: "bash", arguments: { command: dump } },
    { name: "bash", arguments: { command: probe } },
  ];
  s.services.state.toolResults = [];
  const result = await s.run(["--smoke-model"], extra);
  expect(result.status, result.stderr).toBe(0);
  const [printed, tls] = s.services.state.toolResults as string[];
  const match = /\{.*\}/s.exec(printed ?? "");
  expect(match, printed).not.toBeNull();
  return {
    env: JSON.parse(match?.[0] ?? "{}") as Record<string, string | null>,
    tls: tls ?? "",
  };
}

describe("child processes receive only the approved network environment", () => {
  // The launch environment carries approved settings and the ambient ones the
  // policy does not approve, including a proxy URL with credentials.
  const ambient = async () => {
    const forward = await proxy("forward");
    const credentialed = `http://svc-account:hunter2@127.0.0.1:${new URL(forward.url).port}`;
    return {
      forward,
      env: {
        HTTP_PROXY: forward.url,
        http_proxy: forward.url,
        HTTPS_PROXY: credentialed,
        https_proxy: credentialed,
        NO_PROXY: "internal.invalid",
        ALL_PROXY: "socks5://ambient.invalid:1080",
        SSL_CERT_FILE: "/etc/ambient-ca.pem",
        CURL_CA_BUNDLE: "/etc/ambient-ca.pem",
        REQUESTS_CA_BUNDLE: "/etc/ambient-ca.pem",
        GIT_SSL_CAINFO: "/etc/ambient-ca.pem",
        GIT_SSL_NO_VERIFY: "1",
        PISHIP_E2E_PLAIN: "kept",
        OPENAI_API_KEY: "sk-ambient-personal-key-e2e",
      },
    };
  };

  it.skipIf(windows)(
    "hands a sandboxed command the approved proxy and CA, and nothing else",
    async () => {
      const s = await scenario("sandboxed");
      const { forward, env } = await ambient();
      const { env: child, tls } = await childEnvironment(s, env);
      expect(child).toMatchObject({
        HTTP_PROXY: forward.url,
        http_proxy: forward.url,
        NO_PROXY: "internal.invalid",
        no_proxy: "internal.invalid",
        NODE_EXTRA_CA_CERTS: join(s.project, "front-ca.pem"),
      });
      // Not approved: the credentialed proxy, other proxies and CA settings,
      // a disabled verification, the ambient key, and anything not allowlisted.
      for (const name of [
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "SSL_CERT_FILE",
        "CURL_CA_BUNDLE",
        "REQUESTS_CA_BUNDLE",
        "GIT_SSL_CAINFO",
        "GIT_SSL_NO_VERIFY",
        "OPENAI_API_KEY",
        "PISHIP_E2E_PLAIN",
      ])
        expect(child[name], name).toBeNull();
      expect(JSON.stringify(child)).not.toContain("hunter2");
      // The child trusts the declared CA through NODE_EXTRA_CA_CERTS, so its
      // own TLS verification succeeds (the fixture answers 401 without a key).
      expect(tls).toContain("TLS 401");
    },
    300000,
  );

  it("hands an uncontained command the approved network environment and drops the unapproved", async () => {
    const s = await scenario("unsandboxed");
    const { forward, env } = await ambient();
    const { env: child, tls } = await childEnvironment(s, env);
    expect(child).toMatchObject({
      HTTP_PROXY: forward.url,
      http_proxy: forward.url,
      NO_PROXY: "internal.invalid",
      no_proxy: "internal.invalid",
      NODE_EXTRA_CA_CERTS: join(s.project, "front-ca.pem"),
      // Everything that is not network configuration and not a credential is
      // still inherited: only the network settings are narrowed.
      PISHIP_E2E_PLAIN: "kept",
    });
    for (const name of [
      "HTTPS_PROXY",
      "https_proxy",
      "ALL_PROXY",
      "SSL_CERT_FILE",
      "CURL_CA_BUNDLE",
      "REQUESTS_CA_BUNDLE",
      "GIT_SSL_CAINFO",
      "GIT_SSL_NO_VERIFY",
      "OPENAI_API_KEY",
    ])
      expect(child[name], name).toBeNull();
    expect(JSON.stringify(child)).not.toContain("hunter2");
    expect(tls).toContain("TLS 401");
  }, 300000);
});
