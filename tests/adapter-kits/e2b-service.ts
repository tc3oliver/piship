// A fake E2B-compatible service for the built-in e2b-compatible backend:
// the control plane (health, create, renew, delete) and envd's process
// service (Start as a Connect server stream, SendSignal), reached through
// the backend's fetch. Unlike the scripted mock in @piship/sandbox's own
// tests, every command runs for real, in an isolator that shows only the
// sandbox's own directory, so the sandbox kit can check the backend's
// claims. How SendSignal stops a command is a parameter: envd signals the
// process it started (`process`), and a service may signal its whole
// process group (`group`).
import { randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ManagedFetch } from "@piship/contracts";
import { connectEnvelope, EnvelopeReader } from "@piship/sandbox";
import { type Isolated, runIsolated } from "./isolator.js";

export const E2B_ENDPOINT = "https://api.e2b.conformance.invalid";
const ENVD = "https://envd.conformance.invalid";
/** The backend's default working directory inside the sandbox. */
const WORKDIR = "/home/user";

interface Sandbox {
  readonly root: string;
  readonly network: "deny" | "allow";
  readonly running: Map<string, Isolated>;
}

export class E2bService {
  readonly sandboxes = new Map<string, Sandbox>();

  constructor(readonly signalScope: "process" | "group") {}

  /** The backend's envdUrl seam: every sandbox's envd on one fake origin. */
  envdUrl = ({ sandboxId }: { sandboxId: string }) => `${ENVD}/${sandboxId}`;

  readonly fetch: ManagedFetch = async (url, init) => {
    const signal = init?.signal ?? undefined;
    signal?.throwIfAborted();
    const target = new URL(String(url));
    const method = (init?.method ?? "GET").toUpperCase();
    const headers = new Headers(init?.headers);
    if (target.origin === ENVD) return this.#envd(target, headers, init);
    if (method === "GET" && target.pathname === "/health")
      return new Response(null, { status: 204 });
    if (!headers.get("x-api-key")) return new Response(null, { status: 401 });
    if (method === "POST" && target.pathname === "/sandboxes") {
      const body = JSON.parse(String(init?.body ?? "{}")) as {
        allow_internet_access?: boolean;
      };
      const id = `sbx-${randomBytes(6).toString("hex")}`;
      const root = realpathSync(mkdtempSync(join(tmpdir(), "fake-e2b-")));
      this.sandboxes.set(id, {
        root,
        network: body.allow_internet_access ? "allow" : "deny",
        running: new Map(),
      });
      return Response.json(
        {
          sandboxID: id,
          templateID: "base",
          envdVersion: "0.4.0",
          envdAccessToken: `fake-envd-token-${id}`,
          domain: null,
        },
        { status: 201 },
      );
    }
    const match = /^\/sandboxes\/([\w-]+)(\/timeout)?$/.exec(target.pathname);
    const sandbox = match?.[1] ? this.sandboxes.get(match[1]) : undefined;
    if (!match || !sandbox) return new Response(null, { status: 404 });
    if (match[2] && method === "POST")
      return new Response(null, { status: 204 });
    if (!match[2] && method === "DELETE") {
      this.sandboxes.delete(match[1] as string);
      for (const run of sandbox.running.values()) run.killGroup();
      rmSync(sandbox.root, { recursive: true, force: true });
      return new Response(null, { status: 204 });
    }
    return new Response(null, { status: 405 });
  };

  #envd(target: URL, headers: Headers, init: RequestInit | undefined) {
    const [, id, method] = /^\/([\w-]+)\/(.+)$/.exec(target.pathname) ?? [];
    const sandbox = id ? this.sandboxes.get(id) : undefined;
    if (!sandbox || headers.get("x-access-token") !== `fake-envd-token-${id}`)
      return new Response(null, { status: 404 });
    if (method === "process.Process/SendSignal") {
      const body = JSON.parse(String(init?.body ?? "{}")) as {
        process?: { tag?: string };
      };
      const run = sandbox.running.get(body.process?.tag ?? "");
      if (this.signalScope === "group") run?.killGroup();
      else run?.killProcess();
      return Response.json({});
    }
    if (method === "process.Process/Start") return this.#start(sandbox, init);
    return new Response(null, { status: 404 });
  }

  #start(sandbox: Sandbox, init: RequestInit | undefined): Response {
    const [frame] = new EnvelopeReader().push(init?.body as Uint8Array);
    const start = frame?.message as {
      process: { args: string[]; envs: Record<string, string>; cwd: string };
      tag: string;
    };
    const cwd = start.process.cwd.startsWith(WORKDIR)
      ? join(sandbox.root, start.process.cwd.slice(WORKDIR.length))
      : sandbox.root;
    mkdirSync(cwd, { recursive: true });
    const signal = init?.signal ?? undefined;
    const stream = new ReadableStream<Uint8Array>({
      start: (controller) => {
        let open = true;
        const send = (message: unknown, flags = 0) => {
          if (open) controller.enqueue(connectEnvelope(message, flags));
        };
        const data = (key: "stdout" | "stderr") => (chunk: Buffer) =>
          send({ event: { data: { [key]: chunk.toString("base64") } } });
        const run = runIsolated(
          { root: sandbox.root, network: sandbox.network },
          cwd,
          // The command is `/bin/bash -l -c <command>`.
          start.process.args.at(-1) ?? "",
          start.process.envs,
          data("stdout"),
          data("stderr"),
        );
        sandbox.running.set(start.tag, run);
        // A closed stream is not a signal: the process runs on, as it does
        // in envd, until SendSignal or the sandbox's deletion stops it.
        signal?.addEventListener(
          "abort",
          () => {
            if (!open) return;
            open = false;
            controller.error(signal.reason);
          },
          { once: true },
        );
        void run.exited.then(({ code, signal: killed }) => {
          sandbox.running.delete(start.tag);
          send({
            event: {
              end: killed
                ? { exitCode: -1, status: `signal: ${killed}` }
                : { exitCode: code ?? 0, status: `exit status ${code}` },
            },
          });
          send({}, 0x02);
          if (open) {
            open = false;
            controller.close();
          }
        });
      },
    });
    return new Response(stream, {
      status: 200,
      headers: { "content-type": "application/connect+json" },
    });
  }

  close(): void {
    for (const sandbox of this.sandboxes.values()) {
      for (const run of sandbox.running.values()) run.killGroup();
      rmSync(sandbox.root, { recursive: true, force: true });
    }
    this.sandboxes.clear();
  }
}
