import { describe, expect, it } from "vitest";
import {
  cliOptions,
  environmentLines,
  // @ts-expect-error The deterministic fixture is plain JavaScript.
} from "../../examples/demo-company/fixtures/local-services.mjs";

describe("environment lines printed for the user's shell", () => {
  const variables: [string, string][] = [["ACMECODE_URL", "http://x:1/v1"]];

  it("prints PowerShell and cmd forms on Windows, because PowerShell does not read `set`", () => {
    expect(environmentLines(variables, "win32")).toEqual([
      "# PowerShell:",
      '$env:ACMECODE_URL="http://x:1/v1"',
      "# cmd.exe:",
      "set ACMECODE_URL=http://x:1/v1",
    ]);
  });

  it("prints export lines elsewhere", () => {
    expect(environmentLines(variables, "darwin")).toEqual([
      "export ACMECODE_URL=http://x:1/v1",
    ]);
  });
});

describe("the fixture's command line", () => {
  it("keeps the demo's prefix and models by default", () => {
    expect(cliOptions([])).toEqual({ prefix: "ACMECODE", start: {} });
    expect(cliOptions(["--port", "9000"]).start).toEqual({ port: 9000 });
  });

  it("serves and entitles a template's models under its prefix", () => {
    const options = cliOptions([
      "--prefix",
      "ACME_AGENT",
      "--model",
      "example/coder",
    ]);
    expect(options.prefix).toBe("ACME_AGENT");
    expect(options.start.knobs.entitledModels).toContain("example/coder");
    expect(options.start.knobs.gatewayModels).toContain("example/coder");
  });

  it("refuses a prefix that is not a variable name", () => {
    expect(() => cliOptions(["--prefix", "acme-agent"])).toThrow(/--prefix/);
  });
});
