import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { SecretValue } from "@piship/contracts";
import { PI_VERSION } from "@piship/core";
import { RestrictedFileSecretStore } from "@piship/credentials";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  describeSightings,
  fileStoreSecrets,
  filesUnder,
  scanTree,
  sightings,
} from "../helpers/security.js";

// A runtime credential never enters a migration artifact: not the output of
// `migrate`, `migrate --check`, or `migrate --write`, not the manifest they
// write, and not a backup file (there is none). The environment and the
// restricted file store hold sentinel credentials while each command runs.

const ENV_SECRET = "fake-env-SENTINEL-migrate-0001";
const STORED_SECRET = "fake-stored-SENTINEL-migrate-0002";
const SECRETS = [ENV_SECRET, STORED_SECRET];

const cli = fileURLToPath(
  new URL("../../packages/cli/dist/bin.js", import.meta.url),
);
let temp: string;
beforeEach(() => {
  temp = mkdtempSync(join(tmpdir(), "piship-migrate-credentials-"));
});
afterEach(() => {
  vi.unstubAllEnvs();
  rmSync(temp, { recursive: true, force: true });
});

function manifest(schema: string): string {
  const dir = join(temp, schema.replace("/", "-"));
  mkdirSync(dir);
  const path = join(dir, "piship.yaml");
  writeFileSync(
    path,
    [
      `schema: ${schema}`,
      "app: { id: mypi, name: MyPi, command: mypi, version: 1.0.0 }",
      `runtime: { pi: "${PI_VERSION}" }`,
      "deployment: { mode: personal }",
      "updates: { channel: stable, channels: [stable] }",
      "",
    ].join("\n"),
  );
  return path;
}

function run(args: string[]): { status: number | null; text: string } {
  const result = spawnSync(process.execPath, [cli, ...args], {
    env: process.env,
    encoding: "utf8",
  });
  return { status: result.status, text: `${result.stdout}\n${result.stderr}` };
}

describe("migrate with a credential in the environment and the state", () => {
  it("keeps every credential out of the output, the manifest, and the directory", async () => {
    vi.stubEnv("MYPI_API_KEY", ENV_SECRET);
    vi.stubEnv("PISHIP_INSTALL_HOME", join(temp, "install"));
    await new RestrictedFileSecretStore(join(temp, "state", "secrets")).put(
      "piship:mypi:inference#1",
      new SecretValue(STORED_SECRET),
    );
    // The scan below skips the store; make sure the credential is in it.
    expect(fileStoreSecrets(join(temp, "state", "secrets"))).toEqual([
      STORED_SECRET,
    ]);

    const outputs: Array<[string, string]> = [];
    for (const schema of ["piship/v1alpha5", "piship/v1alpha6"]) {
      const path = manifest(schema);
      for (const args of [
        [path, "--check"],
        [path],
        [path, "--write"],
        [path, "--check"],
      ]) {
        const { status, text } = run(["migrate", ...args]);
        // A refused or reviewed manifest is a status, never a leak.
        expect([0, 1]).toContain(status);
        outputs.push([`migrate ${schema} ${args.slice(1).join(" ")}`, text]);
      }
    }

    const found = [
      ...outputs.flatMap(([where, text]) => sightings(where, text, SECRETS)),
      ...scanTree(temp, SECRETS, ["state/secrets"]),
    ];
    expect(describeSightings(found)).toEqual([]);

    // Migrating rewrites the manifest in place: no backup or other artifact.
    for (const schema of ["piship-v1alpha5", "piship-v1alpha6"])
      expect(
        filesUnder(join(temp, schema)).map((file) => file.slice(temp.length)),
      ).toEqual([expect.stringMatching(/piship\.yaml$/)]);
  });
});
