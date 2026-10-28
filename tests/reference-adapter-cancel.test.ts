import type {
  ManagedFetch,
  SandboxAdapterFactory,
  SandboxProfile,
} from "@piship/adapter-sdk";
import { describe, expect, it } from "vitest";
// @ts-expect-error The reference adapter is a distribution-shipped JavaScript module.
import referenceAdapter from "../examples/enterprise-reference/sandbox/acme-container-sandbox.mjs";

const adapter = referenceAdapter as SandboxAdapterFactory;
const sandboxId = `sbx_${"a".repeat(24)}`;
const execId = "b".repeat(32);
const profile: SandboxProfile = {
  workspace: "/workspace",
  homeDir: "/home",
  tmpDir: "/tmp",
  readDeny: [],
  writeAllow: [],
  readOnly: [],
  writeProtect: { files: [], directories: [] },
  network: "deny",
  environmentAllow: [],
  warnings: [],
};

describe("reference sandbox cancellation", () => {
  it.each([204, 502])(
    "waits for cancellation (HTTP %i), retiring on failed confirmation",
    async (status) => {
      let acknowledge!: (response: Response) => void;
      let requested!: () => void;
      let ready!: () => void;
      const outputReady = new Promise<void>((resolve) => {
        ready = resolve;
      });
      const requestedCancel = new Promise<void>((resolve) => {
        requested = resolve;
      });
      const calls: string[] = [];
      const fetch: ManagedFetch = async (url, init) => {
        const path = new URL(String(url)).pathname;
        calls.push(`${init?.method ?? "GET"} ${path}`);
        if (path === "/v1/sandboxes")
          return new Response(JSON.stringify({ id: sandboxId }), { status: 201 });
        if (path.endsWith("/exec")) {
          const stream = new ReadableStream<Uint8Array>({
            start(controller) {
              controller.enqueue(
                new TextEncoder().encode(
                  '{"stream":"stdout","data":"cmVhZHk="}\n',
                ),
              );
              init?.signal?.addEventListener(
                "abort",
                () => controller.error(new Error("stream aborted")),
                { once: true },
              );
            },
          });
          return new Response(stream, {
            status: 200,
            headers: { "x-piship-exec-id": execId },
          });
        }
        if (path.endsWith("/cancel")) {
          requested();
          return new Promise<Response>((resolve) => {
            acknowledge = resolve;
          });
        }
        if (init?.method === "DELETE") return new Response(null, { status: 204 });
        throw new Error("unexpected sandbox request");
      };
      const backend = await adapter({
        distributionId: "reference-test",
        endpoint: "http://127.0.0.1:12345",
        fetch,
      });
      const instance = await backend.prepare({ profile });
      const controller = new AbortController();
      const execution = instance.exec(
        { command: "sleep 30", cwd: "/workspace", workspacePath: ".", env: {} },
        {
          signal: controller.signal,
          onStdout() {
            ready();
          },
          onStderr() {},
        },
      );
      await outputReady;
      controller.abort(new Error("stopped"));
      await requestedCancel;
      let settled = false;
      void execution
        .finally(() => {
          settled = true;
        })
        .catch(() => undefined);
      await new Promise<void>((resolve) => setImmediate(resolve));
      expect(settled).toBe(false);
      expect(calls.filter((call) => call.startsWith("DELETE"))).toEqual([]);
      acknowledge(new Response(null, { status }));
      await expect(execution).rejects.toThrow("stopped");
      expect(calls.filter((call) => call.endsWith("/cancel"))).toHaveLength(1);
      expect(calls.filter((call) => call.startsWith("DELETE"))).toHaveLength(
        status === 204 ? 0 : 1,
      );
      await instance.dispose();
      expect(calls.filter((call) => call.startsWith("DELETE"))).toHaveLength(1);
    },
  );
});
