// A fake of the remote execution service the SDK's example sandbox adapter
// (packages/adapter-sdk/examples/sandbox.mjs) talks to, reached through the
// kit's context fetch. Every command runs for real, in an isolator that
// shows only the session's own directory, so the example's claims
// (host-filesystem-isolation, network-deny, environment-filter) hold the
// way a real remote service would make them hold. The session directory
// starts empty: the example declares no workspace, which is a snapshot.
import { randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ManagedFetch } from "@piship/adapter-sdk";
import { type Isolated, runIsolated } from "./isolator.js";

interface Session {
  readonly root: string;
  readonly network: "deny" | "allow";
  readonly running: Set<Isolated>;
}

export class ExecutionService {
  readonly sessions = new Map<string, Session>();

  readonly fetch: ManagedFetch = async (url, init) => {
    const signal = init?.signal ?? undefined;
    signal?.throwIfAborted();
    const target = new URL(String(url));
    const method = (init?.method ?? "GET").toUpperCase();
    const auth = new Headers(init?.headers).get("authorization") ?? "";
    if (!auth.startsWith("Bearer ")) return new Response(null, { status: 401 });
    const path = target.pathname.replace(/^\/sandbox\//, "");
    const body =
      typeof init?.body === "string"
        ? (JSON.parse(init.body) as Record<string, unknown>)
        : {};
    if (method === "GET" && path === "health")
      return Response.json({ ok: true });
    if (method === "POST" && path === "sessions") {
      const id = `session-${randomBytes(6).toString("hex")}`;
      const root = realpathSync(mkdtempSync(join(tmpdir(), "fake-exec-")));
      this.sessions.set(id, {
        root,
        network: body.network === "allow" ? "allow" : "deny",
        running: new Set(),
      });
      return Response.json({ id }, { status: 201 });
    }
    const match = /^sessions\/([\w-]+)(\/exec)?$/.exec(path);
    const session = match?.[1] ? this.sessions.get(match[1]) : undefined;
    if (!match || !session) return new Response(null, { status: 404 });
    if (method === "DELETE" && !match[2]) {
      this.sessions.delete(match[1] as string);
      for (const run of session.running) run.killGroup();
      rmSync(session.root, { recursive: true, force: true });
      return new Response(null, { status: 204 });
    }
    if (method !== "POST" || !match[2])
      return new Response(null, { status: 405 });
    return this.#exec(session, body, signal);
  };

  async #exec(
    session: Session,
    body: Record<string, unknown>,
    signal: AbortSignal | undefined,
  ): Promise<Response> {
    const relative = String(body.workspacePath ?? ".");
    if (relative.startsWith("/") || relative.split("/").includes(".."))
      return Response.json({ error: "outside the workspace" }, { status: 400 });
    const cwd = join(session.root, ...relative.split("/"));
    mkdirSync(cwd, { recursive: true });
    let stdout = "";
    let stderr = "";
    const run = runIsolated(
      { root: session.root, network: session.network },
      cwd,
      String(body.command),
      (body.env ?? {}) as Record<string, string>,
      (chunk) => {
        stdout += chunk.toString("utf8");
      },
      (chunk) => {
        stderr += chunk.toString("utf8");
      },
    );
    session.running.add(run);
    // The caller ending the request stops the command, as the service's
    // own cancellation does.
    const aborted = new Promise<never>((_, reject) => {
      signal?.addEventListener(
        "abort",
        () => {
          run.killGroup();
          reject(signal.reason);
        },
        { once: true },
      );
    });
    aborted.catch(() => undefined);
    try {
      const exit = await Promise.race([run.exited, aborted]);
      return Response.json({ exitCode: exit.code, stdout, stderr });
    } finally {
      session.running.delete(run);
    }
  }

  close(): void {
    for (const session of this.sessions.values()) {
      for (const run of session.running) run.killGroup();
      rmSync(session.root, { recursive: true, force: true });
    }
    this.sessions.clear();
  }
}
