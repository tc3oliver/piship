// The piship-audit-batch/v1 schema published in docs/enterprise-integration.md
// must describe exactly what the HTTP sink sends.
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  AUDIT_BATCH_SCHEMA,
  AUDIT_EVENT_TYPES,
  type AuditEvent,
  SecretValue,
} from "@piship/contracts";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  AUDIT_CONTENT_CLASSES,
  AUDIT_LIMITS,
  type AuditEmitInput,
  AuditLog,
} from "./index.js";

type Schema = Record<string, unknown>;

const DOC = new URL("../../../docs/enterprise-integration.md", import.meta.url);
const MARKER = "<!-- piship-audit-batch/v1 schema";

/** The JSON block that follows the schema marker in the integration doc. */
function documentedSchema(): Schema {
  const text = readFileSync(DOC, "utf8");
  const start = text.indexOf(MARKER);
  expect(start).toBeGreaterThan(0);
  const block = /```json\n([\s\S]*?)\n```/.exec(text.slice(start));
  if (!block?.[1]) throw new Error("no JSON block after the schema marker");
  return JSON.parse(block[1]) as Schema;
}

/**
 * A validator for the JSON Schema keywords the documented schema uses. It is
 * strict about the reverse direction too: an object property the schema
 * does not name (and no `additionalProperties` covers) is an error, so a
 * field the sink sends but the doc omits fails the test.
 */
function validate(root: Schema, value: unknown): string[] {
  const errors: string[] = [];
  const typeOf = (item: unknown) =>
    item === null
      ? "null"
      : Array.isArray(item)
        ? "array"
        : Number.isInteger(item)
          ? "integer"
          : typeof item;
  const visit = (schema: Schema, item: unknown, at: string): void => {
    if (typeof schema.$ref === "string") {
      const name = schema.$ref.replace("#/$defs/", "");
      visit((root.$defs as Record<string, Schema>)[name] as Schema, item, at);
      return;
    }
    const known = new Set([
      "$schema",
      "$id",
      "$defs",
      "$ref",
      "type",
      "const",
      "enum",
      "required",
      "properties",
      "additionalProperties",
      "propertyNames",
      "maxProperties",
      "items",
      "maxItems",
      "minLength",
      "maxLength",
      "pattern",
      "format",
    ]);
    for (const key of Object.keys(schema))
      if (!known.has(key)) errors.push(`${at}: unsupported keyword ${key}`);
    const actual = typeOf(item);
    if (schema.type !== undefined) {
      const types = ([] as unknown[]).concat(schema.type);
      const matches = types.some(
        (type) =>
          type === actual || (type === "number" && actual === "integer"),
      );
      if (!matches) errors.push(`${at}: ${actual} is not ${types.join("|")}`);
    }
    if ("const" in schema && item !== schema.const)
      errors.push(`${at}: ${JSON.stringify(item)} is not the const`);
    if (Array.isArray(schema.enum) && !schema.enum.includes(item))
      errors.push(`${at}: ${JSON.stringify(item)} is not in the enum`);
    if (typeof item === "string") {
      const length = [...item].length;
      if (typeof schema.minLength === "number" && length < schema.minLength)
        errors.push(`${at}: shorter than ${schema.minLength}`);
      if (typeof schema.maxLength === "number" && length > schema.maxLength)
        errors.push(`${at}: longer than ${schema.maxLength}`);
      if (
        typeof schema.pattern === "string" &&
        !new RegExp(schema.pattern, "u").test(item)
      )
        errors.push(`${at}: ${item} does not match ${schema.pattern}`);
    }
    if (Array.isArray(item)) {
      if (typeof schema.maxItems === "number" && item.length > schema.maxItems)
        errors.push(`${at}: more than ${schema.maxItems} items`);
      if (schema.items)
        for (const [index, entry] of item.entries())
          visit(schema.items as Schema, entry, `${at}[${index}]`);
    }
    if (actual === "object") {
      const object = item as Record<string, unknown>;
      const properties = (schema.properties ?? {}) as Record<string, Schema>;
      for (const key of (schema.required ?? []) as string[])
        if (!(key in object)) errors.push(`${at}: missing ${key}`);
      const keys = Object.keys(object);
      if (
        typeof schema.maxProperties === "number" &&
        keys.length > schema.maxProperties
      )
        errors.push(`${at}: more than ${schema.maxProperties} properties`);
      for (const key of keys) {
        if (schema.propertyNames)
          visit(schema.propertyNames as Schema, key, `${at} name ${key}`);
        if (properties[key])
          visit(properties[key], object[key], `${at}.${key}`);
        else if (
          schema.additionalProperties &&
          typeof schema.additionalProperties === "object"
        )
          visit(
            schema.additionalProperties as Schema,
            object[key],
            `${at}.${key}`,
          );
        else errors.push(`${at}: property ${key} is not in the schema`);
      }
    }
  };
  visit(root, value, "$");
  return errors;
}

let temp: string;
beforeEach(() => {
  temp = mkdtempSync(join(tmpdir(), "piship-audit-wire-"));
});
afterEach(() => rmSync(temp, { recursive: true, force: true }));

/** An HTTP sink whose fetch records every body it is asked to POST. */
async function capturingLog(capture: boolean) {
  const bodies: string[] = [];
  const log = await AuditLog.open({
    config: {
      enabled: true,
      sinks: [
        {
          id: "company",
          type: "http",
          url: "https://audit.example/ingest",
          required: true,
        },
      ],
      buffer: { maxEvents: 10_000, flushIntervalMs: 0 },
      capture: {
        promptContent: capture,
        responseContent: capture,
        commandText: capture,
        sourceContent: capture,
      },
    },
    distribution: "acmecode",
    stateDir: temp,
    fetch: async (_url, init) => {
      bodies.push(String(init?.body));
      return new Response(null, { status: 204 });
    },
  });
  return { log, bodies };
}

/** Every optional field at its limit, for every event type. */
function fullEvent(event: (typeof AUDIT_EVENT_TYPES)[number]): AuditEmitInput {
  const long = "x".repeat(4 * AUDIT_LIMITS.contentChars);
  const detail: Record<string, unknown> = {};
  for (let index = 0; index < AUDIT_LIMITS.detailKeys + 8; index += 1)
    detail[`key${index}`] =
      index % 4 === 0 ? long : index % 4 === 1 ? index : index % 4 === 2;
  detail.nothing = null;
  return {
    event,
    user: `alice-${long}`,
    session: long,
    resource: long,
    decision: "approved",
    policy: `acme@1-${long}`,
    rule: long,
    enforcement: "sandbox",
    detail,
    content: Object.fromEntries(
      Object.keys(AUDIT_CONTENT_CLASSES).map((name) => [name, long]),
    ),
  };
}

describe("piship-audit-batch/v1 wire schema", () => {
  it("is published in the integration doc and matches the event contract", () => {
    const schema = documentedSchema();
    expect(schema.properties).toMatchObject({
      schema: { const: AUDIT_BATCH_SCHEMA },
    });
    const event = (schema.$defs as Record<string, Schema>).event as Schema;
    const properties = event.properties as Record<string, Schema>;
    expect(properties.event?.enum).toEqual([...AUDIT_EVENT_TYPES]);
    expect(properties.decision?.enum).toEqual([
      "allowed",
      "denied",
      "asked",
      "approved",
    ]);
    expect(properties.enforcement?.enum).toEqual([
      "control-plane",
      "sandbox",
      "audit-only",
    ]);
    expect(Object.keys(properties.content?.properties as object)).toEqual(
      Object.keys(AUDIT_CONTENT_CLASSES),
    );
    expect(properties.detail?.maxProperties).toBe(AUDIT_LIMITS.detailKeys);
  });

  it("validates every batch the http sink sends, with every field at its limit", async () => {
    const schema = documentedSchema();
    const { log, bodies } = await capturingLog(true);
    for (const type of AUDIT_EVENT_TYPES) {
      log.emit(fullEvent(type));
      log.emit({ event: type, user: null, session: null });
    }
    // More than one request's worth, so the per-request bound is exercised.
    const perRequest = (schema.properties as Record<string, Schema>).events
      ?.maxItems as number;
    for (let index = 0; index < perRequest; index += 1)
      log.emit({ event: "tool.request", user: "alice", session: "s1" });
    await log.flush();
    await log.close();
    const batches = bodies.map((body) => JSON.parse(body));
    // The readiness probe is the empty batch.
    expect(batches[0]).toEqual({ schema: AUDIT_BATCH_SCHEMA, events: [] });
    expect(batches.map((batch) => batch.events.length)).toEqual([
      0,
      perRequest,
      2 * AUDIT_EVENT_TYPES.length,
    ]);
    for (const batch of batches) expect(validate(schema, batch)).toEqual([]);
    // Every property the schema names is one the sink actually sends.
    const sent = new Set(
      batches.flatMap((batch) =>
        batch.events.flatMap((item: object) => Object.keys(item)),
      ),
    );
    const event = (schema.$defs as Record<string, Schema>).event as Schema;
    expect([...sent].sort()).toEqual(
      Object.keys(event.properties as object).sort(),
    );
  });

  it("rejects batches that break the contract, so the check is not vacuous", async () => {
    const schema = documentedSchema();
    const { log, bodies } = await capturingLog(false);
    log.emit({ event: "session.start", user: "alice", session: "s1" });
    await log.close();
    const batch = JSON.parse(bodies[1] as string) as {
      events: Record<string, unknown>[];
    };
    const sent = batch.events[0];
    if (!sent) throw new Error("the batch carries no event");
    const variants: unknown[] = [
      { ...batch, schema: "piship-audit-batch/v2" },
      { ...batch, events: [{ ...sent, event: "made.up" }] },
      { ...batch, events: [{ ...sent, id: undefined }] },
      { ...batch, events: [{ ...sent, token: "t" }] },
      { ...batch, events: [{ ...sent, detail: { "9bad": 1 } }] },
      { ...batch, events: [{ ...sent, content: { secret: "x" } }] },
      { ...batch, events: [{ ...sent, time: "yesterday" }] },
    ];
    for (const variant of variants)
      expect(validate(schema, JSON.parse(JSON.stringify(variant)))).not.toEqual(
        [],
      );
  });

  it("gives every event a unique id", async () => {
    const { log, bodies } = await capturingLog(false);
    for (let index = 0; index < 50; index += 1)
      log.emit({ event: "tool.request", user: null, session: null });
    await log.close();
    const ids = bodies.flatMap((body) =>
      JSON.parse(body).events.map((item: AuditEvent) => item.id),
    );
    expect(ids).toHaveLength(50);
    expect(new Set(ids).size).toBe(50);
  });

  it("never sends prompt, response, source, command, credential, or token bodies by default", async () => {
    const { log, bodies } = await capturingLog(false);
    const jwt =
      "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZS1jYW5hcnkifQ.c2lnbmF0dXJlLWNhbmFyeQ";
    for (const type of AUDIT_EVENT_TYPES)
      log.emit({
        event: type,
        user: "alice",
        session: "s1",
        resource: `Bearer bearer-canary-${type}`,
        detail: {
          token: "token-canary",
          password: "password-canary",
          apiKey: "api-key-canary",
          credential: new SecretValue("credential-canary"),
          header: `Authorization: Bearer header-canary`,
          jwt,
          key: "sk-proj-openaikeycanary0123456789",
        },
        content: {
          prompt: "prompt-canary",
          response: "response-canary",
          source: "source-canary",
          command: "command-canary",
        },
      });
    await log.close();
    const sent = bodies.join("\n");
    expect(JSON.parse(bodies[1] as string).events).toHaveLength(
      AUDIT_EVENT_TYPES.length,
    );
    for (const canary of [
      "bearer-canary",
      "token-canary",
      "password-canary",
      "api-key-canary",
      "credential-canary",
      "header-canary",
      "c2lnbmF0dXJlLWNhbmFyeQ",
      "openaikeycanary",
      "prompt-canary",
      "response-canary",
      "source-canary",
      "command-canary",
    ])
      expect(sent).not.toContain(canary);
    expect(sent).not.toContain('"content"');
  });
});
