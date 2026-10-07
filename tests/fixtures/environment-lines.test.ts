import { describe, expect, it } from "vitest";
// @ts-expect-error The deterministic fixture is plain JavaScript.
import { environmentLines } from "../../examples/demo-company/fixtures/local-services.mjs";

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
