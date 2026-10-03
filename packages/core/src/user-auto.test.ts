// The user's auto mode switch outside a session: `<command> auto`, its
// audit, where it is stored, and how the release, the principal, config
// explain, inspect, diff, and purge treat it.
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type { AuditConfig } from "@piship/audit";
import { type AuditEvent, PiShipError } from "@piship/contracts";
import type { UserAutoSetting } from "@piship/schema";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { explainConfiguration } from "./access/index.js";
import { runAuto } from "./branded/auto.js";
import type { BrandedContext } from "./branded/context.js";
import {
  diffLocks,
  formatInspection,
  inspection,
  purgeDistributionState,
  resolveLock,
  runtimeStateDirectory,
} from "./index.js";
import {
  describeUserAuto,
  setUserAuto,
  USER_AUTO_SCHEMA,
  userAutoPath,
  userAutoStatus,
} from "./user-auto.js";

const DEMO = fileURLToPath(
  new URL("../../../examples/demo-company/piship.yaml", import.meta.url),
);

let temp: string;
beforeEach(() => {
  temp = mkdtempSync(join(tmpdir(), "piship-user-auto-"));
});
afterEach(() => {
  vi.unstubAllEnvs();
  rmSync(temp, { recursive: true, force: true });
});

/** The demo lock with `policy.userAuto` as a v1alpha5 manifest declares it. */
function demoLock(userAuto?: UserAutoSetting) {
  const lock = resolveLock(DEMO);
  const governance = lock.governance as NonNullable<typeof lock.governance>;
  const { userAuto: _absent, ...policy } = governance.manifest.policy;
  return {
    ...lock,
    governance: {
      ...governance,
      manifest: {
        ...governance.manifest,
        policy: { ...policy, ...(userAuto ? { userAuto } : {}) },
      },
    },
  };
}

function context(
  userAuto?: UserAutoSetting,
  mode: "managed" | "personal" = "managed",
) {
  const out: string[] = [];
  const ctx: BrandedContext = {
    metadata: demoLock(userAuto),
    distributionDir: temp,
    stateDir: join(temp, "state"),
    mode,
    out: (message) => out.push(message),
    err: () => {},
  };
  const events = () => {
    const file = join(temp, "state", "logs", "audit.jsonl");
    return existsSync(file)
      ? readFileSync(file, "utf8")
          .trim()
          .split("\n")
          .map((line) => JSON.parse(line) as AuditEvent)
      : [];
  };
  return { ctx, out, events };
}

function bind(stateDir: string, subject: string, at: string): void {
  mkdirSync(join(stateDir, "identity"), { recursive: true });
  writeFileSync(
    join(stateDir, "identity", "principal.json"),
    JSON.stringify({
      schema: "piship-principal-binding/v1",
      issuer: "https://id.acme.example",
      subject,
      bound_at: at,
    }),
  );
}

describe("<command> auto", () => {
  it("refuses auto on with a policy error while the release does not allow it", async () => {
    for (const userAuto of [undefined, "off"] as const) {
      const { ctx, events } = context(userAuto);
      const error = await runAuto(ctx, ["on"]).catch((caught) => caught);
      expect(error).toBeInstanceOf(PiShipError);
      expect(error).toMatchObject({
        code: "POLICY_DENIED",
        message:
          "This distribution does not allow auto mode (policy.userAuto is off)",
      });
      expect(existsSync(userAutoPath(ctx.stateDir))).toBe(false);
      expect(events()).toEqual([]);
    }
    const personal = context(undefined, "personal");
    await expect(runAuto(personal.ctx, ["on"])).rejects.toMatchObject({
      code: "POLICY_DENIED",
      message: expect.stringContaining("in personal mode you own the policy"),
    });
  });

  it("switches on and off when allowed, audited before it changes", async () => {
    const { ctx, out, events } = context("allowed");
    bind(ctx.stateDir, "alice", "2026-10-01T00:00:00.000Z");
    await runAuto(ctx, ["status"]);
    expect(out.at(-1)).toBe("Auto mode: off (the distribution allows it)");
    await runAuto(ctx, ["on"]);
    expect(out.at(-1)).toMatch(
      /^Auto mode is on: asks from the distribution defaults/,
    );
    expect(
      JSON.parse(readFileSync(userAutoPath(ctx.stateDir), "utf8")),
    ).toEqual({
      schema: USER_AUTO_SCHEMA,
      enabled: true,
      binding: {
        issuer: "https://id.acme.example",
        subject: "alice",
        bound_at: "2026-10-01T00:00:00.000Z",
      },
      changed_at: expect.any(String),
    });
    await runAuto(ctx, ["status"]);
    expect(out.at(-1)).toMatch(/^Auto mode: on: /);
    await runAuto(ctx, ["off"]);
    expect(existsSync(userAutoPath(ctx.stateDir))).toBe(false);
    expect(
      events().map((event) => [
        event.event,
        event.user,
        event.policy,
        event.detail,
      ]),
    ).toEqual([
      [
        "policy.auto_enabled",
        "https://id.acme.example#alice",
        "acme-engineering@1",
        { source: "command" },
      ],
      [
        "policy.auto_disabled",
        "https://id.acme.example#alice",
        "acme-engineering@1",
        { source: "command" },
      ],
    ]);
  });

  it("turns off even when a required audit sink is down, and stays off when on cannot be audited", async () => {
    const { ctx, out } = context("allowed");
    const err: string[] = [];
    // A local port nothing listens on.
    const server = createServer();
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    const { port } = server.address() as { port: number };
    await new Promise<void>((resolve) => server.close(() => resolve()));
    const governance = ctx.metadata.governance as NonNullable<
      typeof ctx.metadata.governance
    >;
    const down: BrandedContext = {
      ...ctx,
      err: (message) => err.push(message),
      auditCloseDeadlineMs: 300,
      metadata: {
        ...ctx.metadata,
        governance: {
          ...governance,
          manifest: {
            ...governance.manifest,
            audit: {
              ...governance.manifest.audit,
              enabled: true,
              sinks: [
                {
                  id: "company",
                  type: "http",
                  url: `http://127.0.0.1:${port}/ingest`,
                  required: true,
                },
              ] as AuditConfig["sinks"],
            },
          },
        },
      },
    };
    const error = await runAuto(down, ["on"]).catch((caught) => caught);
    expect(error).toMatchObject({ code: "AUDIT_UNAVAILABLE" });
    expect(error.message).toMatch(
      /^Auto mode was not switched on, because its audit was not recorded: /,
    );
    expect(existsSync(userAutoPath(ctx.stateDir))).toBe(false);
    setUserAuto(ctx.stateDir, true);
    await runAuto(down, ["off"]);
    expect(existsSync(userAutoPath(ctx.stateDir))).toBe(false);
    expect(out.at(-1)).toMatch(
      /^Auto mode is off from the next acmecode start/,
    );
    expect(err).toEqual([
      expect.stringMatching(/^Warning: AUDIT_UNAVAILABLE: /),
    ]);
  });

  it("rejects anything but on, off, or status", async () => {
    const { ctx } = context("allowed");
    for (const args of [[], ["yes"], ["on", "now"]])
      await expect(runAuto(ctx, args)).rejects.toMatchObject({
        code: "CONFIG_INVALID",
        message: "Usage: acmecode auto on | auto off | auto status",
      });
  });

  it("always turns off, without audit, where the release does not allow it", async () => {
    const { ctx, out, events } = context("off");
    setUserAuto(ctx.stateDir, true);
    await runAuto(ctx, ["status"]);
    expect(out.at(-1)).toMatch(
      /^Auto mode: off: the switch is on, but this release does not allow auto mode/,
    );
    await runAuto(ctx, ["off"]);
    expect(existsSync(userAutoPath(ctx.stateDir))).toBe(false);
    expect(events()).toEqual([]);
  });
});

describe("userAutoStatus", () => {
  const allowed = { userAuto: "allowed" } as const;

  it("applies only while the installed release allows it", () => {
    const state = join(temp, "state");
    setUserAuto(state, true);
    expect(userAutoStatus(state, allowed, "managed")).toEqual({
      allowed: true,
      state: "on",
      active: true,
    });
    // An update to a release with userAuto off makes the stored switch inert.
    for (const policy of [{ userAuto: "off" } as const, {}, undefined])
      expect(userAutoStatus(state, policy, "managed")).toEqual({
        allowed: false,
        state: "inert",
        active: false,
      });
    expect(userAutoStatus(state, allowed, "personal").active).toBe(false);
  });

  it("resets when another principal binds the state, even if the first returns", () => {
    const state = join(temp, "state");
    bind(state, "alice", "2026-10-01T00:00:00.000Z");
    setUserAuto(state, true);
    expect(userAutoStatus(state, allowed, "managed").state).toBe("on");
    bind(state, "bob", "2026-10-02T00:00:00.000Z");
    expect(userAutoStatus(state, allowed, "managed")).toMatchObject({
      state: "reset",
      active: false,
    });
    bind(state, "alice", "2026-10-03T00:00:00.000Z");
    expect(userAutoStatus(state, allowed, "managed").state).toBe("reset");
    // Switched on before the first sign-in: the sign-in resets it.
    rmSync(join(state, "identity"), { recursive: true });
    setUserAuto(state, true);
    expect(userAutoStatus(state, allowed, "managed").state).toBe("on");
    bind(state, "alice", "2026-10-04T00:00:00.000Z");
    expect(userAutoStatus(state, allowed, "managed").state).toBe("reset");
  });

  it("counts an unreadable switch or binding as off", () => {
    const state = join(temp, "state");
    mkdirSync(join(state, "config"), { recursive: true });
    writeFileSync(userAutoPath(state), "{not json");
    expect(userAutoStatus(state, allowed, "managed").state).toBe("off");
    writeFileSync(
      userAutoPath(state),
      JSON.stringify({ schema: USER_AUTO_SCHEMA, enabled: "yes" }),
    );
    expect(userAutoStatus(state, allowed, "managed").state).toBe("off");
    setUserAuto(state, true);
    mkdirSync(join(state, "identity"), { recursive: true });
    writeFileSync(join(state, "identity", "principal.json"), "{");
    expect(userAutoStatus(state, allowed, "managed").state).toBe("reset");
  });

  it("describes every state", () => {
    expect(
      (["on", "off", "reset", "inert", "not-allowed"] as const).map((state) =>
        describeUserAuto({ allowed: true, state, active: state === "on" }),
      ),
    ).toEqual([
      "on: asks from the distribution defaults are approved without a prompt and audited; deny and enforced rules still apply",
      "off (the distribution allows it)",
      "off: it was turned on under a previously signed-in identity, so it was reset; turn it on again to use it",
      "off: the switch is on, but this release does not allow auto mode (policy.userAuto), so it has no effect",
      "not allowed by this distribution",
    ]);
  });
});

describe("policy.userAuto in reports", () => {
  it("config explain shows the release setting and this user's switch (managed)", async () => {
    const { ctx } = context("allowed");
    setUserAuto(ctx.stateDir, true);
    const lock = ctx.metadata;
    const rows = await explainConfiguration({
      app: lock.app as never,
      mode: "managed",
      access: lock.access,
      stateDir: ctx.stateDir,
      distributionDir: temp,
      schema: lock.manifest.schema,
      governance: lock.governance?.manifest as never,
    });
    expect(rows.find((row) => row.key === "policy.userAuto")).toEqual({
      key: "policy.userAuto",
      value: "allowed",
      source: "distribution-enforced",
      overridable: false,
      note: expect.stringMatching(/^auto mode for this user: on: /),
    });
    const absent = await explainConfiguration({
      app: lock.app as never,
      mode: "managed",
      access: lock.access,
      stateDir: ctx.stateDir,
      distributionDir: temp,
      schema: lock.manifest.schema,
      governance: demoLock().governance.manifest as never,
    });
    expect(absent.find((row) => row.key === "policy.userAuto")).toMatchObject({
      value: "off",
      note: expect.stringMatching(/release does not allow auto mode/),
    });
  });

  it("inspect names it only when declared, and diff rates allowing it high", () => {
    const allowed = demoLock("allowed");
    const off = demoLock();
    const show = (lock: typeof off) =>
      formatInspection(inspection(lock as never, join(temp, "state")));
    expect(show(allowed)).toContain("(default ask, user auto allowed)");
    expect(show(off)).toContain("(default ask)");
    const widened = diffLocks(off as never, allowed as never).changes.find(
      (change) => change.item === "policy userAuto",
    );
    expect(widened).toMatchObject({
      before: "off",
      after: "allowed",
      risk: "high",
    });
    const narrowed = diffLocks(allowed as never, off as never).changes.find(
      (change) => change.item === "policy userAuto",
    );
    expect(narrowed).toMatchObject({ risk: "medium" });
    expect(
      diffLocks(off as never, demoLock("off") as never).changes.find(
        (change) => change.item === "policy userAuto",
      ),
    ).toBeUndefined();
  });

  it("is locked, and in the policy digest, only when declared", () => {
    const source = fileURLToPath(
      new URL("../../../examples/demo-company", import.meta.url),
    );
    const copy = join(temp, "demo");
    cpSync(source, copy, { recursive: true });
    const manifest = join(copy, "piship.yaml");
    const before = resolveLock(manifest);
    expect(before.governance?.manifest.policy).not.toHaveProperty("userAuto");
    expect(before).toEqual(resolveLock(DEMO));
    writeFileSync(
      manifest,
      readFileSync(manifest, "utf8").replace(
        "\n  default: ask\n",
        "\n  default: ask\n  userAuto: allowed\n",
      ),
    );
    const after = resolveLock(manifest);
    expect(after.governance?.manifest.policy.userAuto).toBe("allowed");
    expect(after.digests?.policy).not.toBe(before.digests?.policy);
    expect(after.digests?.sandbox).toBe(before.digests?.sandbox);
  });

  it("purge removes the switch with the rest of the state", async () => {
    vi.stubEnv("PISHIP_STATE_HOME", join(temp, "home"));
    vi.stubEnv("PISHIP_INSTALL_HOME", join(temp, "install"));
    vi.stubEnv("PISHIP_BIN_HOME", join(temp, "bin"));
    const state = runtimeStateDirectory({ value: "acmecode" });
    setUserAuto(state, true);
    expect(existsSync(userAutoPath(state))).toBe(true);
    await purgeDistributionState("acmecode");
    expect(existsSync(userAutoPath(state))).toBe(false);
    expect(existsSync(state)).toBe(false);
  });
});
