import { redact } from "@piship/contracts";
import { describe, expect, it } from "vitest";
import { StdioTransport } from "./stdio.js";
import type { ProcessRuntime, SpawnRequest } from "./types.js";

async function transportWithStderr() {
  let emit: SpawnRequest["onStderr"];
  const runtime: ProcessRuntime = {
    spawn: (request) => {
      emit = request.onStderr;
      throw new Error("stop");
    },
    filterEnvironment: () => ({}),
    sanitizeStderr: (text) => text,
  };
  const transport = new StdioTransport({
    server: {
      id: "s",
      transport: "stdio",
      command: "node",
      args: [],
      env: { allow: [], set: {} },
    },
    runtime,
    workspace: process.cwd(),
    distributionDir: process.cwd(),
  } as never);
  await transport.start().catch(() => undefined);
  return { transport, emit: (text: string) => emit?.(text) };
}

describe("StdioTransport stderr", () => {
  it("leaves no secret fragment from the front of a full raw window", async () => {
    const { transport, emit } = await transportWithStderr();
    const line = `Bearer ${"k".repeat(200)}\n`;
    for (let i = 0; i < 400; i++) emit(line);
    const summary = transport.stderrSummary();
    expect(summary).toContain("[REDACTED]");
    expect(summary).not.toMatch(/k{8}/);
  });

  it("leaves no secret fragment from the front of one long line", async () => {
    const { transport, emit } = await transportWithStderr();
    for (let i = 0; i < 400; i++) emit(`Bearer ${"k".repeat(200)} `);
    const summary = transport.stderrSummary();
    expect(summary).toContain("[REDACTED]");
    expect(summary).not.toMatch(/k{8}/);
  });

  it("redacts a secret whose prefix falls on the tail cut", async () => {
    const secret = "Bearer abcdefghijklmnopqrstuvwxyz0123456789";
    expect(redact(secret)).not.toContain("abcdefghij");
    let emit: SpawnRequest["onStderr"];
    const runtime: ProcessRuntime = {
      spawn: (request) => {
        emit = request.onStderr;
        throw new Error("stop");
      },
      filterEnvironment: () => ({}),
      sanitizeStderr: (text) => text,
    };
    const transport = new StdioTransport({
      server: {
        id: "s",
        transport: "stdio",
        command: "node",
        args: [],
        env: { allow: [], set: {} },
      },
      runtime,
      workspace: process.cwd(),
      distributionDir: process.cwd(),
    } as never);
    await transport.start().catch(() => undefined);
    // Place the cut inside "Bearer ": exactly 8 KiB remain after the cut.
    emit?.(
      `${"a".repeat(100)} ${secret} ${"b".repeat(8192 - secret.length + 3 - 1)}`,
    );
    expect(transport.stderrSummary()).not.toContain("abcdefghij");
  });
});
