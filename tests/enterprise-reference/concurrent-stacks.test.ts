import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { startSandboxService } from "../../examples/enterprise-reference/tests/support/sandbox.js";
import { type ReferenceStack, request, startReferenceStack } from "./stack.js";

// Two copies of the reference stack, and two reference sandbox services, at
// once on one host: what two `npm run test:reference` runs on one machine
// start. Each stack has its own Compose project and the host ports Docker
// chose for it (examples/enterprise-reference/tests/support/ports.ts), and
// each sandbox service the port the system gave it, so nothing is fixed that
// two runs could both ask for.
//
// Shown: no host port is shared; each Keycloak names the issuer of the port it
// is asked on, which is the one its broker accepts; sign-in, the broker, and
// the gateway work on both; and neither accepts what the other issued. A
// broker started again comes back on a new port, which the stack reads.
//
// Needs Docker; run with `npm run test:reference` after `npm run build`.

let first: ReferenceStack | undefined;
let second: ReferenceStack | undefined;

const stacks = () => {
  if (!first || !second) throw new Error("the stacks did not start");
  return [first, second] as const;
};

beforeAll(() => {
  first = startReferenceStack({ name: "concurrent-a" });
  second = startReferenceStack({ name: "concurrent-b" });
  console.info(
    `reference stacks ${first.project} and ${second.project} up in ${first.startupSeconds} s and ${second.startupSeconds} s`,
  );
}, 900_000);

afterAll(() => {
  // Both, even when the first stop fails.
  const failures: unknown[] = [];
  for (const stack of [second, first])
    try {
      stack?.stop();
    } catch (error) {
      failures.push(error);
    }
  if (failures.length > 0) throw failures[0];
}, 120_000);

const issuerOf = (stack: ReferenceStack) =>
  `http://127.0.0.1:${stack.ports.KEYCLOAK_PORT}/realms/piship-reference`;

describe("two reference stacks on one host", () => {
  it("run under their own projects, with no host port in common", () => {
    const [a, b] = stacks();
    expect(a.project).not.toBe(b.project);
    const ports = [...Object.values(a.ports), ...Object.values(b.ports)];
    expect(new Set(ports).size).toBe(ports.length);
    for (const port of ports) expect(port).toBeGreaterThan(0);
  });

  it("each name the issuer of the port they are asked on", async () => {
    for (const stack of stacks()) {
      const issuer = issuerOf(stack);
      const discovery = await request(
        `${issuer}/.well-known/openid-configuration`,
      );
      expect(discovery.status).toBe(200);
      expect((discovery.body as { issuer?: unknown }).issuer).toBe(issuer);
      // The host part is pinned: asking through `localhost` still names
      // 127.0.0.1.
      const other = await request(
        `http://localhost:${stack.ports.KEYCLOAK_PORT}/realms/piship-reference/.well-known/openid-configuration`,
      );
      expect((other.body as { issuer?: unknown }).issuer).toBe(issuer);
    }
  });

  it("each sign a user in, issue a key at their broker, and serve it at their gateway", async () => {
    for (const stack of stacks()) {
      const credential = await stack.acquire("alice");
      const chat = await stack.chat(credential.key);
      expect(chat.status, chat.scrubbed).toBe(200);
    }
  });

  it("refuse what the other one issued", async () => {
    const [a, b] = stacks();
    // A token of the first Keycloak names the first issuer and is signed with
    // its key: the second broker refuses it.
    const refused = await request(`${b.broker}/v1/credential`, {
      bearer: a.accessToken("alice"),
      body: { distribution: "acmecode-reference", purpose: "inference" },
    });
    expect(refused.status).toBe(401);
    expect(refused.scrubbed).not.toMatch(/sk-|eyJ/);
    // A key of the first gateway is unknown to the second.
    const key = (await a.acquire("bob")).key;
    expect((await a.models(key)).status).toBe(200);
    expect((await b.models(key)).status).toBe(401);
  });

  it("find a broker started again on its new port", async () => {
    const [a, b] = stacks();
    const before = a.ports;
    a.service("stop", "broker");
    a.service("start", "broker");
    // Docker gives a container started again a new port, which the stack
    // reads; the other ports stay as they were.
    expect({ ...a.ports, BROKER_PORT: 0 }).toEqual({
      ...before,
      BROKER_PORT: 0,
    });
    const credential = await a.acquire("alice");
    expect((await a.models(credential.key)).status).toBe(200);
    // The other stack was not touched.
    expect((await b.acquire("alice")).models.length).toBeGreaterThan(0);
  });
});

describe("two reference sandbox services on one host", () => {
  it("listen on ports of their own and answer as themselves", async () => {
    const a = await startSandboxService();
    try {
      const b = await startSandboxService();
      try {
        expect(b.port).not.toBe(a.port);
        expect(b.instance).not.toBe(a.instance);
        for (const service of [a, b]) {
          const health = await service.request("/health");
          expect(health.status).toBe(200);
          expect((health.json() as { instance?: unknown }).instance).toBe(
            service.instance,
          );
          expect(await service.sandboxes("alice")).toBe(0);
        }
        // A key one service issued means nothing to the other.
        const foreign = await a.request("/v1/status", { key: b.key("alice") });
        expect(foreign.status).toBe(401);
      } finally {
        await b.stop();
      }
    } finally {
      await a.stop();
    }
  }, 120_000);
});
