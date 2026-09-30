// The adapter against a stub of the service's fetch: what it sends and to
// whom, what it tells PiShip, and what it never repeats. The live test
// (tests/sandbox.test.ts) runs it against the real service and the
// conformance kit.
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { PiShipError } from "@piship/adapter-sdk";
import { capabilityMismatch, workspaceDeclaration } from "@piship/sandbox";
import createAdapter from "../acme-container-sandbox.mjs";

const ENDPOINT = "https://sandbox.acme.example";
const SECRET = "sbxk_stub-credential-value-0001";
const ID = "sbx_0123456789abcdef01234567";

const profile = () => ({
  workspace: "/work/project",
  network: "deny",
  homeDir: "/home/dev",
  readDeny: ["/home/dev/.ssh"],
  writeAllow: ["/work/project"],
  writeProtect: {
    files: ["/work/project/.git/config"],
    directories: ["/work/project/.git/hooks"],
  },
});

const json = (status, body, headers = {}) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });

/** A fetch that records each call and answers with `handle(call)`. */
function stub(handle) {
  const calls = [];
  const fetch = async (url, init = {}) => {
    const call = {
      url: String(url),
      method: init.method,
      headers: init.headers ?? {},
      body: init.body === undefined ? undefined : JSON.parse(init.body),
      signal: init.signal,
      redirect: init.redirect,
    };
    calls.push(call);
    return handle(call, calls.length);
  };
  return { fetch, calls };
}

async function backend(handle, context = {}) {
  const { fetch, calls } = stub(handle);
  const rejected = [];
  const instance = await createAdapter({
    distributionId: "distribution-id",
    fetch,
    endpoint: ENDPOINT,
    credential: async () => SECRET,
    credentialOrigins: [ENDPOINT],
    credentialRejected: async () => {
      rejected.push(true);
      return false;
    },
    ...context,
  });
  return { backend: instance, calls, rejected };
}

function ndjson(chunks) {
  const encoder = new TextEncoder();
  return new Response(
    new ReadableStream({
      start(controller) {
        for (const chunk of chunks) controller.enqueue(encoder.encode(chunk));
        controller.close();
      },
    }),
    { status: 200, headers: { "content-type": "application/x-ndjson" } },
  );
}

const line = (record) => `${JSON.stringify(record)}\n`;
const stdout = (text) => ({
  stream: "stdout",
  data: Buffer.from(text).toString("base64"),
});

describe("what it declares", () => {
  it("claims a shared workspace and only the guarantees the service gives", async () => {
    const { backend: adapter } = await backend(() => json(200, {}));
    const declared = adapter.capabilities();
    assert.deepEqual(declared, {
      isolation: "remote",
      planes: [
        "workspace-confinement",
        "git-control-protection",
        "network-deny",
        "environment-filter",
      ],
      network: ["deny", "allow"],
      localProcesses: false,
      workspace: { mode: "shared" },
    });
    assert.deepEqual(adapter.capabilities(), declared);
    assert.equal(adapter.provider, "custom");
    assert.equal(adapter.id, "acme-container");
    // PiShip accepts it for a required sandbox, in both network modes.
    for (const network of ["deny", "allow"])
      assert.equal(capabilityMismatch(declared, network), undefined);
    assert.deepEqual(workspaceDeclaration(declared), {
      declaration: { mode: "shared" },
    });
    // It never claims what it does not do.
    for (const plane of [
      "host-filesystem-isolation",
      "filesystem-read-deny",
      "filesystem-write-allowlist",
    ])
      assert.equal(declared.planes.includes(plane), false, plane);
  });
});

describe("availability", () => {
  it("is available when the service answers and its runtime is up", async () => {
    const { backend: adapter, calls } = await backend(() =>
      json(200, { runtime: "ok", sandboxes: 0, limit: 8 }),
    );
    assert.deepEqual(await adapter.available(), { available: true });
    assert.equal(calls[0].url, `${ENDPOINT}/v1/status`);
    assert.equal(calls[0].headers.authorization, `Bearer ${SECRET}`);
  });

  it("says why it is not, in words that never hold the credential or the service's answer", async () => {
    const down = await backend(() => json(200, { runtime: "unavailable" }));
    assert.match((await down.backend.available()).reason, /container runtime/);

    const refused = await backend(() =>
      json(401, { error: { code: "unauthorized", message: SECRET } }),
    );
    const answer = await refused.backend.available();
    assert.equal(answer.available, false);
    assert.match(answer.reason, /refused the sandbox credential/);
    assert.equal(JSON.stringify(answer).includes(SECRET), false);
    // PiShip is told, and marks a stored credential rejected.
    assert.equal(refused.rejected.length, 1);

    const forbidden = await backend(() => json(403, {}));
    assert.equal((await forbidden.backend.available()).available, false);
    assert.equal(forbidden.rejected.length, 1);

    const unreachable = await backend(() => {
      throw new TypeError(`Invalid value "Bearer ${SECRET}" for header`);
    });
    const outage = await unreachable.backend.available();
    assert.equal(outage.available, false);
    assert.equal(JSON.stringify(outage).includes(SECRET), false);
    assert.match(outage.reason, /unreachable/);

    const policy = await backend(() => {
      throw new PiShipError(
        "NETWORK_DENIED",
        "Private-only network policy denies undeclared host",
      );
    });
    assert.match((await policy.backend.available()).reason, /NETWORK_DENIED/);

    const none = await backend(() => json(200, {}), { endpoint: undefined });
    assert.match((await none.backend.available()).reason, /sandbox\.endpoint/);
  });
});

describe("the credential", () => {
  it("goes only to an origin it was issued for, and to no origin a response names", async () => {
    const elsewhere = await backend(() => json(200, { runtime: "ok" }), {
      endpoint: "https://elsewhere.example",
    });
    const answer = await elsewhere.backend.available();
    assert.equal(answer.available, false);
    assert.match(answer.reason, /not sent to an origin it was not issued for/);
    assert.equal(elsewhere.calls.length, 0, "a request was sent");
    await assert.rejects(
      elsewhere.backend.prepare({ profile: profile() }),
      /not sent to an origin/,
    );
    assert.equal(elsewhere.calls.length, 0);

    // Without recorded origins only the endpoint's own is allowed.
    const own = await backend(() => json(200, { runtime: "ok" }), {
      credentialOrigins: undefined,
    });
    assert.equal((await own.backend.available()).available, true);

    // A redirect is not followed, and the credential goes nowhere with it.
    const redirected = await backend(
      () =>
        new Response(null, {
          status: 302,
          headers: { location: "https://attacker.example/collect" },
        }),
    );
    await assert.rejects(
      redirected.backend.prepare({ profile: profile() }),
      (error) =>
        /HTTP 302/.test(error.message) && error.code === "SANDBOX_UNAVAILABLE",
    );
    assert.equal(redirected.calls.length, 1);
    assert.equal(redirected.calls[0].redirect, "manual");
    assert.equal(redirected.calls[0].url.startsWith(ENDPOINT), true);
  });

  it("is read for each request, and never placed in a URL, a body, or a command", async () => {
    let secret = SECRET;
    const { backend: adapter, calls } = await backend(
      (call) =>
        call.method === "POST" && call.url.endsWith("/v1/sandboxes")
          ? json(201, { id: ID })
          : call.url.endsWith("/exec")
            ? ndjson([line({ exit: 0, signal: null })])
            : json(204, {}),
      { credential: async () => secret },
    );
    const instance = await adapter.prepare({ profile: profile() });
    secret = "sbxk_rotated-credential-value-0002";
    await instance.exec(
      { command: "true", cwd: "/work/project", workspacePath: ".", env: {} },
      { signal: new AbortController().signal, onStdout() {}, onStderr() {} },
    );
    assert.equal(calls[0].headers.authorization, `Bearer ${SECRET}`);
    assert.equal(calls[1].headers.authorization, `Bearer ${secret}`);
    for (const call of calls)
      assert.equal(
        `${call.url}${JSON.stringify(call.body ?? {})}`.includes("sbxk_"),
        false,
      );
  });

  it("is not read at all when the service is called without one", async () => {
    const { backend: adapter, calls } = await backend(
      () => json(200, { runtime: "ok" }),
      {
        credential: undefined,
      },
    );
    assert.equal((await adapter.available()).available, true);
    assert.equal("authorization" in calls[0].headers, false);
  });
});

describe("creating a sandbox", () => {
  it("sends the workspace, the network, and the git control paths, and nothing else of the profile", async () => {
    const { backend: adapter, calls } = await backend(() =>
      json(201, { id: ID }),
    );
    await adapter.prepare({ profile: profile() });
    assert.equal(calls.length, 1);
    assert.equal(calls[0].method, "POST");
    assert.equal(calls[0].url, `${ENDPOINT}/v1/sandboxes`);
    assert.deepEqual(calls[0].body, {
      workspace: "/work/project",
      network: "deny",
      writeProtect: {
        files: ["/work/project/.git/config"],
        directories: ["/work/project/.git/hooks"],
      },
    });
    assert.equal(calls[0].headers["content-type"], "application/json");
  });

  it("is never repeated, whatever the service says", async () => {
    for (const status of [401, 429, 500, 502, 503]) {
      const { backend: adapter, calls } = await backend(() =>
        json(status, { error: { code: "runtime_error", message: SECRET } }),
      );
      await assert.rejects(adapter.prepare({ profile: profile() }), (error) => {
        assert.equal(error.code, "SANDBOX_UNAVAILABLE");
        assert.equal(error.message.includes(SECRET), false);
        assert.equal(JSON.stringify(error).includes(SECRET), false);
        return true;
      });
      assert.equal(calls.length, 1, `status ${status} was repeated`);
    }
  });

  it("names the service's error code, and nothing else it sent", async () => {
    const { backend: adapter } = await backend(() =>
      json(409, {
        error: { code: "workspace_unsupported", message: "PRIVATE-DETAIL" },
      }),
    );
    await assert.rejects(adapter.prepare({ profile: profile() }), (error) => {
      assert.match(error.message, /HTTP 409, workspace_unsupported/);
      assert.equal(error.message.includes("PRIVATE-DETAIL"), false);
      return true;
    });
    const odd = await backend(() =>
      json(409, { error: { code: "Not A Code!!", message: "x" } }),
    );
    await assert.rejects(
      odd.backend.prepare({ profile: profile() }),
      (error) => {
        assert.equal(error.message.includes("Not A Code"), false);
        return true;
      },
    );
    const empty = await backend(() => json(201, { id: "../../etc" }));
    await assert.rejects(
      empty.backend.prepare({ profile: profile() }),
      /without a sandbox/,
    );
  });

  it("reports a rejected credential to PiShip, which asks the user for a new one", async () => {
    const { backend: adapter, rejected } = await backend(() => json(401, {}));
    await assert.rejects(adapter.prepare({ profile: profile() }), (error) => {
      assert.match(error.userAction, /sandbox login/);
      return true;
    });
    assert.equal(rejected.length, 1);
  });
});

describe("running a command", () => {
  async function running(handleExec) {
    const made = await backend((call) =>
      call.url.endsWith("/v1/sandboxes")
        ? json(201, { id: ID })
        : call.method === "DELETE"
          ? json(204, {})
          : handleExec(call),
    );
    const instance = await made.backend.prepare({ profile: profile() });
    return { ...made, instance };
  }
  const io = () => {
    const out = [];
    const err = [];
    const controller = new AbortController();
    return {
      controller,
      out,
      err,
      io: {
        signal: controller.signal,
        onStdout: (chunk) => out.push(Buffer.from(chunk)),
        onStderr: (chunk) => err.push(Buffer.from(chunk)),
      },
    };
  };

  it("sends the command, the workspace path, and the environment, and forwards output as it arrives", async () => {
    const text = "héllo wörld";
    const whole = line(stdout(text));
    const cut = Math.floor(whole.length / 2);
    const { instance, calls } = await running(() =>
      ndjson([
        whole.slice(0, cut),
        whole.slice(cut),
        line({
          stream: "stderr",
          data: Buffer.from("warn").toString("base64"),
        }),
        line({ exit: 7, signal: null }),
      ]),
    );
    const sink = io();
    const result = await instance.exec(
      {
        command: "make test",
        cwd: "/work/project/src",
        workspacePath: "src",
        env: { CI: "1" },
      },
      sink.io,
    );
    assert.deepEqual(result, { exitCode: 7, signal: null });
    assert.equal(Buffer.concat(sink.out).toString(), text);
    assert.equal(Buffer.concat(sink.err).toString(), "warn");
    const exec = calls.at(-1);
    assert.equal(exec.url, `${ENDPOINT}/v1/sandboxes/${ID}/exec`);
    assert.deepEqual(exec.body, {
      command: "make test",
      cwd: "src",
      env: { CI: "1" },
    });
    // PiShip's own signal is what the request carries.
    assert.equal(exec.signal, sink.io.signal);
  });

  it("reports a command the service ended, and a stream that just stops", async () => {
    const killed = await running(() =>
      ndjson([line({ exit: null, signal: "SIGKILL" })]),
    );
    assert.deepEqual(
      await killed.instance.exec(
        { command: "x", cwd: "/w", workspacePath: ".", env: {} },
        io().io,
      ),
      { exitCode: null, signal: "SIGKILL" },
    );
    const cut = await running(() => ndjson([line(stdout("partial"))]));
    await assert.rejects(
      cut.instance.exec(
        { command: "x", cwd: "/w", workspacePath: ".", env: {} },
        io().io,
      ),
      /ended the connection before the command finished/,
    );
    const garbled = await running(() => ndjson(["not json\n"]));
    await assert.rejects(
      garbled.instance.exec(
        { command: "x", cwd: "/w", workspacePath: ".", env: {} },
        io().io,
      ),
      /unreadable answer/,
    );
  });

  it("refuses a command outside the workspace before asking the service", async () => {
    const { instance, calls } = await running(() => ndjson([]));
    const before = calls.length;
    await assert.rejects(
      instance.exec(
        { command: "x", cwd: "/elsewhere", workspacePath: undefined, env: {} },
        io().io,
      ),
      /outside the workspace/,
    );
    assert.equal(calls.length, before);
  });

  it("ends with PiShip's cancellation, whatever the connection does", async () => {
    let pending;
    const { instance } = await running(
      (call) =>
        new Promise((resolve, reject) => {
          pending = { resolve };
          call.signal.addEventListener("abort", () =>
            reject(new DOMException("aborted", "AbortError")),
          );
        }),
    );
    const sink = io();
    const run = instance.exec(
      { command: "sleep 30", cwd: "/w", workspacePath: ".", env: {} },
      sink.io,
    );
    await new Promise((resolve) => setTimeout(resolve, 20));
    sink.controller.abort(new Error("timeout"));
    await assert.rejects(run, (error) => error.message === "timeout");
    assert.ok(pending);
  });

  it("stops asking once it has been disposed, and disposing never throws or repeats", async () => {
    const { instance, calls } = await running(() =>
      ndjson([line({ exit: 0, signal: null })]),
    );
    await instance.dispose();
    await instance.dispose();
    assert.equal(calls.filter((call) => call.method === "DELETE").length, 1);
    const before = calls.length;
    await assert.rejects(
      instance.exec(
        { command: "x", cwd: "/w", workspacePath: ".", env: {} },
        io().io,
      ),
      /disposed/,
    );
    assert.equal(calls.length, before);

    const failing = await backend((call) => {
      if (call.method === "DELETE") throw new TypeError(`quotes ${SECRET}`);
      return json(201, { id: ID });
    });
    const held = await failing.backend.prepare({ profile: profile() });
    await held.dispose();
  });
});
