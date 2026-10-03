// updates.transport: http-allowed. Install, update, and rollback over a
// plain-HTTP channel on an internal host, reached through the configured
// forward proxy (no CA settings), with every signature, digest, and sequence
// check unchanged; public hosts, https sources, and redirects keep their
// rules.
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import { type AddressInfo, connect } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { PiShipError } from "@piship/contracts";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  HOST_EVIDENCED,
  ID,
  KEY,
  fakeRun,
  installed,
  launch,
  rejection,
  stateDir,
  useLifecycleHomes,
} from "../../../tests/helpers/lifecycle-faults.js";
import type { BrandedContext } from "./branded/context.js";
import { lifecycleDoctor } from "./branded/doctor.js";
import { runRollback, runUpdate } from "./branded/lifecycle.js";
import { resolveLock, signChannel, verifyPayload } from "./index.js";
import { readInstallReceipt } from "./install/index.js";
import { updateDistribution } from "./update/index.js";

const SOURCE = "http://updates.corp.internal/acmepi";
const DEMO = fileURLToPath(
  new URL("../../../examples/demo-company/piship.yaml", import.meta.url),
);
const PROXY_VARIABLES = [
  "HTTP_PROXY",
  "http_proxy",
  "HTTPS_PROXY",
  "https_proxy",
  "NO_PROXY",
  "no_proxy",
];

useLifecycleHomes();

let saved: Record<string, string | undefined>;
let server: Server;
/** `<host> <path>` of every request the channel host received. */
let requests: string[];
/** The directory served as the channel. */
let served: string;
/** Replace a served file's bytes, by file name. */
let tamper: (name: string, body: Buffer) => Buffer;
/** Redirect a file name to a Location. */
let redirects: Record<string, string>;
let scratch: string[];

/** Answer a channel request, whichever way the proxy delivered it. */
function answer(request: IncomingMessage, response: ServerResponse) {
  const url = new URL(request.url ?? "/", `http://${request.headers.host}`);
  requests.push(`${url.hostname} ${url.pathname}`);
  request.resume();
  const name = url.pathname.split("/").slice(2).join("/");
  const location = redirects[name];
  if (location) {
    response.writeHead(302, { location });
    response.end();
    return;
  }
  const file = join(served, ...name.split("/"));
  if (!name || !existsSync(file)) {
    response.statusCode = 404;
    response.end();
    return;
  }
  response.end(tamper(name, readFileSync(file)));
}

beforeEach(async () => {
  saved = Object.fromEntries(
    PROXY_VARIABLES.map((key) => [key, process.env[key]]),
  );
  for (const key of PROXY_VARIABLES) delete process.env[key];
  requests = [];
  redirects = {};
  scratch = [];
  tamper = (_name, body) => body;
  // A forward proxy that is also the channel host: an absolute-form request
  // is answered directly, and a CONNECT tunnel is opened back to itself.
  server = createServer(answer);
  server.on("connect", (request, socket, head) => {
    const port = (server.address() as AddressInfo).port;
    const upstream = connect(port, "127.0.0.1", () => {
      socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      upstream.write(head);
      upstream.pipe(socket);
      socket.pipe(upstream);
    });
    upstream.on("error", () => socket.destroy());
    socket.on("error", () => upstream.destroy());
    requests.push(`CONNECT ${request.url}`);
  });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  process.env.HTTP_PROXY = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterEach(async () => {
  server.closeAllConnections();
  await new Promise<void>((done) => server.close(() => done()));
  for (const [key, value] of Object.entries(saved))
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  for (const dir of scratch) rmSync(dir, { recursive: true, force: true });
});

function temp(): string {
  const dir = mkdtempSync(join(tmpdir(), "piship-http-channel-"));
  scratch.push(dir);
  return dir;
}

/** The branded command of the installed active release. */
function context(): BrandedContext {
  const receipt = readInstallReceipt(ID);
  return {
    metadata: verifyPayload(receipt.payload) as BrandedContext["metadata"],
    distributionDir: receipt.payload,
    stateDir: stateDir(),
    mode: "personal",
    out: () => {},
    err: () => {},
  };
}

async function update(
  args: readonly string[] = [],
  ctx = context(),
): Promise<string> {
  const lines: string[] = [];
  await runUpdate({ ...ctx, out: (line) => lines.push(line) }, args);
  return lines.join("\n");
}

async function refused(promise: Promise<unknown>): Promise<PiShipError> {
  const error = await rejection(promise);
  expect(error).toBeInstanceOf(PiShipError);
  return error as PiShipError;
}

const channelRequests = () =>
  requests.filter((line) => !line.startsWith("CONNECT"));

describe.runIf(HOST_EVIDENCED)("updates.transport: http-allowed", () => {
  it("installs, updates, and rolls back over a plain-HTTP internal channel through the proxy", async () => {
    const { channelDir } = await installed(false, "http-allowed");
    served = channelDir;
    process.env.ACMEPI_UPDATE_SOURCE = SOURCE;
    expect(await update(["--check"])).toContain("1.1.0 is available");
    expect(await update()).toContain("Updated AcmePi 1.0.0 -> 1.1.0");
    expect(launch()).toBe("payload 1.1.0");
    expect(channelRequests()).toEqual(
      expect.arrayContaining([
        "updates.corp.internal /acmepi/root/2.json",
        "updates.corp.internal /acmepi/stable.json",
        "updates.corp.internal /acmepi/stable.json.sig",
        expect.stringMatching(
          /^updates\.corp\.internal \/acmepi\/acmepi-1\.1\.0-.*\.tar\.gz$/,
        ),
      ]),
    );
    await runRollback(context());
    expect(launch()).toBe("payload 1.0.0");
  });

  it("reports the plain-HTTP source in doctor", async () => {
    await installed(false, "http-allowed");
    process.env.ACMEPI_UPDATE_SOURCE = SOURCE;
    const lines: string[] = [];
    lifecycleDoctor(
      context(),
      "Update",
      (label, value) => lines.push(`ok ${label} ${value}`),
      (label, value) => lines.push(`! ${label} ${value}`),
    );
    expect(lines).toContain(
      `! source http (integrity by signature only): \${ACMEPI_UPDATE_SOURCE}`,
    );
    expect(lines.join("\n")).toMatch(/ok transport http-allowed/);
  });

  it("audits an update check over plain HTTP with its transport", async () => {
    const { channelDir } = await installed(false, "http-allowed");
    served = channelDir;
    process.env.ACMEPI_UPDATE_SOURCE = SOURCE;
    const ctx = context();
    const governed = {
      ...ctx,
      metadata: { ...ctx.metadata, governance: resolveLock(DEMO).governance },
    } as BrandedContext;
    await update(["--check"], governed);
    const events = readFileSync(join(stateDir(), "logs", "audit.jsonl"), "utf8")
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    expect(events).toEqual([
      expect.objectContaining({
        event: "runtime.update",
        decision: "allowed",
        detail: expect.objectContaining({
          check: "available",
          to: "1.1.0",
          transport: "http",
        }),
      }),
    ]);
  });

  it("still refuses a tampered archive over HTTP", async () => {
    const { channelDir } = await installed(false, "http-allowed");
    served = channelDir;
    process.env.ACMEPI_UPDATE_SOURCE = SOURCE;
    tamper = (name, body) => {
      if (!name.endsWith(".tar.gz")) return body;
      const copy = Buffer.from(body);
      copy[copy.length - 1] = (copy[copy.length - 1] ?? 0) ^ 0xff;
      return copy;
    };
    const error = await refused(update());
    expect(error.code).toBe("INTEGRITY_FAILED");
    expect(launch()).toBe("payload 1.0.0");
  });

  it("still refuses altered channel metadata over HTTP", async () => {
    const { channelDir } = await installed(false, "http-allowed");
    served = channelDir;
    process.env.ACMEPI_UPDATE_SOURCE = SOURCE;
    tamper = (name, body) =>
      name === "stable.json"
        ? Buffer.from(body.toString("utf8").replace('"1.1.0"', '"1.1.1"'))
        : body;
    const error = await refused(update());
    expect(error.code).toBe("INTEGRITY_FAILED");
    expect(launch()).toBe("payload 1.0.0");
  });

  it("still refuses a replayed older channel over HTTP", async () => {
    const { b, channelDir } = await installed(false, "http-allowed");
    const old = temp();
    for (const name of ["stable.json", "stable.json.sig"])
      cpSync(join(channelDir, name), join(old, name));
    await signChannel({
      directory: channelDir,
      channel: "stable",
      archives: [b.archive],
      privateKeyPem: KEY.privateKeyPem,
      keyId: KEY.id,
    });
    served = channelDir;
    process.env.ACMEPI_UPDATE_SOURCE = SOURCE;
    await update();
    await runRollback(context());
    served = old;
    const error = await refused(update());
    expect(error.message).toMatch(/replayed channel/);
    expect(launch()).toBe("payload 1.0.0");
  });

  it("refuses a public host, from updates.source or --from, before any request", async () => {
    await installed(false, "http-allowed");
    for (const source of [
      "http://updates.acme.example/acmepi",
      "http://203.0.113.7/acmepi",
    ]) {
      process.env.ACMEPI_UPDATE_SOURCE = source;
      const error = await refused(update());
      expect(error.code).toBe("NETWORK_DENIED");
      expect(error.message).toMatch(/is public/);
    }
    process.env.ACMEPI_UPDATE_SOURCE = SOURCE;
    const error = await refused(
      update(["--from", "http://updates.acme.example/acmepi"]),
    );
    expect(error.code).toBe("NETWORK_DENIED");
    expect(requests).toEqual([]);
  });

  it("follows no redirect to another origin from a plain-HTTP source", async () => {
    const { channelDir } = await installed(false, "http-allowed");
    served = channelDir;
    process.env.ACMEPI_UPDATE_SOURCE = SOURCE;
    redirects["stable.json"] = "http://mirror.corp.internal/acmepi/stable.json";
    const error = await refused(update());
    expect(error.code).toBe("UPDATE_FAILED");
    expect(error.message).toMatch(/another origin/);
    expect(requests.some((line) => line.startsWith("mirror."))).toBe(false);
  });

  it("never follows an https source to plain HTTP", async () => {
    const { channelDir } = await installed(false, "http-allowed");
    const fetched: string[] = [];
    const fetcher = (async (input: URL | string) => {
      const url = new URL(String(input));
      fetched.push(url.href);
      if (url.protocol === "https:")
        return new Response(null, {
          status: 302,
          headers: { location: url.href.replace("https:", "http:") },
        });
      const file = join(channelDir, url.pathname.split("/").pop() as string);
      return existsSync(file)
        ? new Response(readFileSync(file))
        : new Response("", { status: 404 });
    }) as typeof fetch;
    const error = await refused(
      updateDistribution(ID, {
        runCheck: fakeRun,
        fetcher,
        env: { ACMEPI_UPDATE_SOURCE: "https://updates.corp.internal/acmepi" },
      }),
    );
    expect(error.message).toMatch(/never follows an https update source/);
    expect(fetched).toEqual([
      "https://updates.corp.internal/acmepi/root/2.json",
    ]);
  });
});

describe.runIf(HOST_EVIDENCED)("updates.transport: https (the default)", () => {
  for (const transport of [undefined, "https"] as const)
    it(`refuses a plain-HTTP internal source exactly as before (${transport ?? "absent"})`, async () => {
      await installed(false, transport);
      process.env.ACMEPI_UPDATE_SOURCE = SOURCE;
      const error = await refused(update());
      expect(error.code).toBe("NETWORK_DENIED");
      expect(error.message).toBe(
        "Update sources must use https (got http://updates.corp.internal)",
      );
      const from = await refused(update(["--from", SOURCE]));
      expect(from.code).toBe("NETWORK_DENIED");
      expect(requests).toEqual([]);
    });
});
