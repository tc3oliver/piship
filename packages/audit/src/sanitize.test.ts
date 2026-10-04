import {
  AUDIT_EVENT_TYPES,
  type AuditCapture,
  ENFORCEMENT_PLANES,
  ENFORCEMENT_STATUSES,
  NO_CONTENT_CAPTURE,
  PiShipError,
  SecretValue,
} from "@piship/contracts";
import { describe, expect, it } from "vitest";
import { AUDIT_LIMITS, sanitizeEvent } from "./index.js";

const ALL_CAPTURE: AuditCapture = {
  promptContent: true,
  responseContent: true,
  commandText: true,
  sourceContent: true,
};
const fixed = () => new Date("2026-09-28T10:00:00.000Z");

describe("tool execution detail (v0.9)", () => {
  it("keeps the source, parent, exposure, and pre-policy failure of a tool call", () => {
    const detail = {
      action: "tool.execute",
      source: "codemode",
      parent: "call_script_1",
      exposure: "deferred",
      error: "not-found",
    };
    for (const [event, rule] of [
      ["tool.request", undefined],
      ["tool.denied", "piship.pre-policy"],
      ["tool.denied", "piship.exposure.unresolved"],
    ] as const) {
      const sanitized = sanitizeEvent(
        {
          event,
          distribution: "acme",
          resource: "read",
          ...(rule ? { rule, decision: "denied" as const } : {}),
          detail,
        },
        NO_CONTENT_CAPTURE,
        fixed,
      );
      expect(sanitized.detail).toEqual(detail);
      if (rule) expect(sanitized.rule).toBe(rule);
    }
  });
});
const TOKENS = [
  "Bearer abc.def.ghi1234567",
  "sk-live0123456789abcdef",
  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N",
  "ghp_0123456789abcdefghijABCDEFGHIJ",
  "AKIAABCDEFGHIJKLMNOP",
  "Authorization: Basic dXNlcjpwYXNzd29yZA==",
];
const RAW_TOKEN_PARTS = [
  "abc.def.ghi1234567",
  "sk-live0123456789abcdef",
  "eyJhbGciOiJIUzI1NiJ9",
  "ghp_0123456789",
  "AKIAABCDEFGHIJKLMNOP",
  "dXNlcjpwYXNzd29yZA",
];

function expectNoTokens(value: unknown): void {
  const text = JSON.stringify(value);
  for (const part of RAW_TOKEN_PARTS) expect(text).not.toContain(part);
}

describe("sanitizeEvent", () => {
  it("builds a complete piship-audit/v1 event for every event type", () => {
    for (const type of AUDIT_EVENT_TYPES) {
      const event = sanitizeEvent(
        {
          event: type,
          distribution: "acmecode",
          user: "alice@example.com",
          session: "s-1",
          resource: "model:default",
          decision: "denied",
          policy: "acme@3",
          rule: "acme.secrets.read",
          enforcement: "control-plane",
        },
        NO_CONTENT_CAPTURE,
        fixed,
      );
      expect(event).toEqual({
        schema: "piship-audit/v1",
        event: type,
        time: "2026-09-28T10:00:00.000Z",
        user: "alice@example.com",
        session: "s-1",
        distribution: "acmecode",
        resource: "model:default",
        decision: "denied",
        policy: "acme@3",
        rule: "acme.secrets.read",
        enforcement: "control-plane",
      });
      expect(event.time).toMatch(
        /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/,
      );
    }
  });

  it("normalizes time to RFC 3339 UTC and defaults user and session to null", () => {
    const event = sanitizeEvent(
      {
        event: "session.start",
        distribution: "acmecode",
        time: "2026-09-28T12:00:00+02:00",
      },
      NO_CONTENT_CAPTURE,
      fixed,
    );
    expect(event.time).toBe("2026-09-28T10:00:00.000Z");
    expect(event.user).toBeNull();
    expect(event.session).toBeNull();
    const invalid = sanitizeEvent(
      { event: "session.end", distribution: "acmecode", time: "yesterday" },
      NO_CONTENT_CAPTURE,
      fixed,
    );
    expect(invalid.time).toBe("2026-09-28T10:00:00.000Z");
  });

  it("rejects unknown event types and missing distribution", () => {
    expect(() =>
      sanitizeEvent(
        { event: "tool.exploded", distribution: "acmecode" },
        NO_CONTENT_CAPTURE,
      ),
    ).toThrow(PiShipError);
    expect(() =>
      sanitizeEvent(
        { event: "session.start", distribution: "" },
        NO_CONTENT_CAPTURE,
      ),
    ).toThrow(/distribution/);
  });

  it("drops prompt, response, command, and source content by default", () => {
    const event = sanitizeEvent(
      {
        event: "model.request",
        distribution: "acmecode",
        content: {
          prompt: "summarize the payroll file",
          response: "here is the payroll",
          command: "cat /etc/shadow",
          source: "const salary = 1;",
        },
      },
      NO_CONTENT_CAPTURE,
    );
    expect(event.content).toBeUndefined();
    expect(JSON.stringify(event)).not.toMatch(/payroll|shadow|salary/);
  });

  it("keeps opted-in content classes only, redacted", () => {
    const event = sanitizeEvent(
      {
        event: "tool.request",
        distribution: "acmecode",
        content: {
          command: `curl -H "Authorization: Bearer abc.def.ghi1234567" https://x`,
          prompt: "not captured",
        },
      },
      { ...NO_CONTENT_CAPTURE, commandText: true },
    );
    expect(Object.keys(event.content ?? {})).toEqual(["command"]);
    expect(event.content?.command).toContain("curl");
    expect(event.content?.command).toContain("[REDACTED]");
    expectNoTokens(event);
  });

  it("caps content length", () => {
    const event = sanitizeEvent(
      {
        event: "model.request",
        distribution: "acmecode",
        content: { prompt: "x".repeat(50_000) },
      },
      ALL_CAPTURE,
    );
    expect(event.content?.prompt?.length).toBe(AUDIT_LIMITS.contentChars);
    expect(event.content?.prompt).toMatch(/\[truncated\]$/);
  });

  it("never emits tokens or SecretValue instances in any field", () => {
    const secret = new SecretValue("super-secret-runtime-value");
    for (const token of TOKENS) {
      const event = sanitizeEvent(
        {
          event: "credential.acquire",
          distribution: "acmecode",
          user: token,
          session: token,
          resource: token,
          policy: token,
          rule: token,
          detail: {
            note: `value ${token}`,
            secretObject: secret as unknown as string,
            token: "opaque-value",
            apiKey: "opaque-value",
          },
          content: {
            prompt: token,
            response: token,
            command: token,
            source: token,
          },
        },
        ALL_CAPTURE,
      );
      expectNoTokens(event);
      expect(JSON.stringify(event)).not.toContain("opaque-value");
      expect(JSON.stringify(event)).not.toContain("super-secret-runtime-value");
      expect(event.detail).not.toHaveProperty("secretObject");
    }
    const withSecretUser = sanitizeEvent(
      {
        event: "identity.login",
        distribution: "acmecode",
        user: secret as unknown as string,
      },
      NO_CONTENT_CAPTURE,
    );
    expect(withSecretUser.user).toBe("[REDACTED]");
  });

  it("keeps detail to capped primitives under valid keys", () => {
    const detail: Record<string, unknown> = {
      count: 3,
      ok: true,
      missing: null,
      bad: Number.NaN,
      nested: { a: 1 },
      list: [1, 2],
      fn: () => 1,
      "bad key!": "x",
      long: "y".repeat(1000),
    };
    for (let index = 0; index < 50; index += 1) detail[`k${index}`] = index;
    const event = sanitizeEvent(
      { event: "policy.violation", distribution: "acmecode", detail },
      NO_CONTENT_CAPTURE,
    );
    const output = event.detail ?? {};
    expect(output.count).toBe(3);
    expect(output.ok).toBe(true);
    expect(output.missing).toBeNull();
    expect(output.bad).toBeNull();
    expect(output).not.toHaveProperty("nested");
    expect(output).not.toHaveProperty("list");
    expect(output).not.toHaveProperty("fn");
    expect(output).not.toHaveProperty("bad key!");
    expect(String(output.long).length).toBe(AUDIT_LIMITS.detailValueChars);
    expect(Object.keys(output).length).toBeLessThanOrEqual(
      AUDIT_LIMITS.detailKeys,
    );
  });

  it("drops a detail key that holds a secret", () => {
    const secret = new SecretValue("piship-fake-detail-key-0123");
    const event = sanitizeEvent(
      {
        event: "policy.violation",
        distribution: "acmecode",
        detail: {
          [secret.reveal()]: true,
          "sk-live0123456789abcdef": 1,
          source: "project",
        },
      },
      NO_CONTENT_CAPTURE,
    );
    expect(event.detail).toEqual({ source: "project" });
    expect(JSON.stringify(event)).not.toContain(secret.reveal());
    expectNoTokens(event);
  });

  it("keeps every enforcement plane, gateway included, and never unsupported", () => {
    for (const enforcement of ENFORCEMENT_PLANES)
      expect(
        sanitizeEvent(
          { event: "model.dispatch", distribution: "acmecode", enforcement },
          NO_CONTENT_CAPTURE,
        ).enforcement,
      ).toBe(enforcement);
    // A status is not a plane: `unsupported` is never recorded.
    expect(ENFORCEMENT_STATUSES).toContain("unsupported");
    expect(
      sanitizeEvent(
        {
          event: "session.export",
          distribution: "acmecode",
          enforcement: "unsupported" as never,
        },
        NO_CONTENT_CAPTURE,
      ),
    ).not.toHaveProperty("enforcement");
  });

  it("accepts the v0.9 event types and keeps their governance detail", () => {
    for (const type of [
      "model.dispatch",
      "session.export",
      "runtime.mutation.reverted",
      "data.swept",
    ]) {
      expect(AUDIT_EVENT_TYPES).toContain(type);
      const event = sanitizeEvent(
        {
          event: type,
          distribution: "acmecode",
          detail: {
            source: "nested",
            error: "invalid-arguments",
            parent: "call-7",
            exposure: "codemode",
            selected: "company/auto",
            dispatched: "openai/gpt-y",
            router: "company-router",
            package: "company-platform@1.4.2",
          },
        },
        NO_CONTENT_CAPTURE,
      );
      expect(event.event).toBe(type);
      expect(event.detail).toEqual({
        source: "nested",
        error: "invalid-arguments",
        parent: "call-7",
        exposure: "codemode",
        selected: "company/auto",
        dispatched: "openai/gpt-y",
        router: "company-router",
        package: "company-platform@1.4.2",
      });
    }
  });

  it("drops invalid decision and enforcement values", () => {
    const event = sanitizeEvent(
      {
        event: "tool.denied",
        distribution: "acmecode",
        decision: "maybe" as never,
        enforcement: "kernel" as never,
      },
      NO_CONTENT_CAPTURE,
    );
    expect(event).not.toHaveProperty("decision");
    expect(event).not.toHaveProperty("enforcement");
  });
});

describe("sanitizeEvent control characters", () => {
  it("never rejoins a token that a control character hid from the scrubber", () => {
    const hidden = [
      "password\u0007=hunter2-audit-value",
      "Bearer\u0000abcdefgh0123456789",
      "client_secret\u001b:audit-client-value",
    ];
    for (const text of hidden) {
      const event = sanitizeEvent(
        {
          event: AUDIT_EVENT_TYPES[0],
          distribution: "acmecode",
          resource: text,
          detail: { note: text },
        },
        NO_CONTENT_CAPTURE,
        fixed,
      );
      const serialized = JSON.stringify(event);
      for (const value of [
        "hunter2-audit-value",
        "abcdefgh0123456789",
        "audit-client-value",
      ])
        expect(serialized, JSON.stringify(text)).not.toContain(value);
      expect(event.resource).toContain("[REDACTED]");
    }
  });
});
