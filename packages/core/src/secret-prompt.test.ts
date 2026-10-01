// The secret prompt with a real readline over a fake terminal: Ctrl-C,
// Ctrl-D, or the end of input rejects instead of leaving the await unsettled
// (which exits 13 with the credential lock still held).
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { fileURLToPath } from "node:url";
import type { AccessManifest } from "@piship/schema";
import { parseManifest, readManifestDocument } from "@piship/schema";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DistributionAccess } from "./access/index.js";
import { readSecretInput } from "./branded/login.js";

const examples = fileURLToPath(new URL("../../../examples/", import.meta.url));
const KEY = "sk-mypi-prompt-sentinel-0001";

let temp: string;
beforeEach(() => {
  temp = mkdtempSync(join(tmpdir(), "piship-secret-prompt-"));
  vi.spyOn(process.stderr, "write").mockImplementation(() => true);
});
afterEach(() => {
  vi.restoreAllMocks();
  rmSync(temp, { recursive: true, force: true });
});

/** A terminal on stdin that receives `keys` once the prompt is up. */
function terminal(keys: string | null): void {
  const stream = new PassThrough() as PassThrough & { isTTY?: boolean };
  stream.isTTY = true;
  vi.spyOn(process, "stdin", "get").mockReturnValue(
    stream as unknown as typeof process.stdin,
  );
  setImmediate(() => (keys === null ? stream.end() : stream.write(keys)));
}

/** MyPi Local with a `local-secret` credential on the personal file store. */
function open(): DistributionAccess {
  const document = readManifestDocument(
    join(examples, "personal", "local-model", "piship.yaml"),
  ) as Record<string, unknown>;
  document.credential = {
    provider: "local-secret",
    storage: { provider: "file" },
  };
  const manifest = parseManifest(document);
  return DistributionAccess.open({
    app: manifest.app,
    mode: "personal",
    access: manifest.access as AccessManifest,
    stateDir: join(temp, "state"),
    distributionDir: temp,
    env: { MYPI_MODEL_URL: "http://127.0.0.1:9/v1" },
    onEvent: () => {},
  });
}

const login = (access: DistributionAccess) =>
  access.login({
    openUrl: () => {
      throw new Error("a personal distribution never opens a sign-in URL");
    },
    readSecret: readSecretInput,
  });

const locks = () =>
  readdirSync(join(temp, "state"), { recursive: true }).filter((name) =>
    String(name).endsWith(".lock"),
  );

describe("secret prompt cancellation", () => {
  it.each([
    ["Ctrl-C", "\x03"],
    ["Ctrl-D", "\x04"],
    ["end of input", null],
  ] as const)("%s rejects with CREDENTIAL_REQUIRED", async (_name, keys) => {
    terminal(keys);
    await expect(readSecretInput("API key")).rejects.toMatchObject({
      code: "CREDENTIAL_REQUIRED",
    });
  });

  it("returns the line typed at the terminal", async () => {
    terminal(`${KEY}\r`);
    await expect(readSecretInput("API key")).resolves.toBe(KEY);
  });

  it.each([
    ["Ctrl-C", "\x03"],
    ["Ctrl-D", "\x04"],
  ] as const)(
    "%s at login leaves no credential lock behind",
    async (_name, keys) => {
      terminal(keys);
      await expect(login(open())).rejects.toMatchObject({
        code: "CREDENTIAL_REQUIRED",
      });
      expect(locks()).toEqual([]);
      // The next login is not kept waiting on a lock.
      terminal(`${KEY}\r`);
      await expect(login(open())).resolves.toMatchObject({
        credential: { state: "valid" },
      });
    },
  );
});
