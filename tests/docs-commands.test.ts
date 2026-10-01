// The CLI is not published to npm. `npm exec -- piship` and `npx piship`
// resolve the bin from node_modules/.bin, which `npm ci` does not create on a
// clean clone (packages/cli/dist does not exist yet), and then fall through to
// the public registry. Documented commands use `node packages/cli/dist/bin.js`.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const root = fileURLToPath(new URL("..", import.meta.url));
const registryLookup = /\b(?:npm\s+exec|npx)(?:\s+-\S+)*\s+(?:--\s+)?piship\b/;

describe("documented CLI commands", () => {
  it("never resolve piship through npm exec or npx", () => {
    const files = execFileSync("git", ["ls-files", "-z", "*.md"], {
      cwd: root,
      encoding: "utf8",
    })
      .split("\0")
      .filter(Boolean);
    expect(files.length).toBeGreaterThan(0);
    const offenders = files.flatMap((file) =>
      readFileSync(join(root, file), "utf8")
        .split("\n")
        .flatMap((line, index) =>
          registryLookup.test(line)
            ? [`${file}:${index + 1}: ${line.trim()}`]
            : [],
        ),
    );
    expect(offenders).toEqual([]);
  });
});
