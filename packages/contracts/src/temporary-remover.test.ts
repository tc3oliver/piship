// Which `rm` a removal uses: absolute paths only, in a fixed order, and only
// one that proved itself on a throwaway tree. A candidate that is missing,
// fails, or proves nothing is skipped for the next.
import { describe, expect, it } from "vitest";
import {
  REMOVER_CANDIDATES,
  findRemover,
  usesSystemRemover,
  type Remover,
} from "./index.js";

const posix = process.platform !== "win32";

describe("the remover candidates", () => {
  it("are absolute paths, in order: /bin/rm, /usr/bin/rm, then NixOS's, GNU flags before BSD flags each", () => {
    expect(
      REMOVER_CANDIDATES.map((item) => [item.file, item.args.join(" ")]),
    ).toEqual([
      ["/bin/rm", "-rf --one-file-system --"],
      ["/bin/rm", "-rfx --"],
      ["/usr/bin/rm", "-rf --one-file-system --"],
      ["/usr/bin/rm", "-rfx --"],
      ["/run/current-system/sw/bin/rm", "-rf --one-file-system --"],
      ["/run/current-system/sw/bin/rm", "-rfx --"],
    ]);
    for (const item of REMOVER_CANDIDATES)
      expect(item.file.startsWith("/")).toBe(true);
  });
});

describe.runIf(posix)("probing a candidate", () => {
  const missing: Remover = {
    file: "/nonexistent/piship/rm",
    args: ["-rf", "--one-file-system", "--"],
  };
  // Exits 0 and removes nothing.
  const inert: Remover = { file: process.execPath, args: ["-e", ""] };
  // A real `rm` that does not know the flag.
  const rejects: Remover = {
    file: "/bin/rm",
    args: ["--not-a-flag-of-any-rm", "--"],
  };

  it("finds none among candidates that are missing, fail, or remove nothing", () => {
    expect(findRemover([missing, inert, rejects])).toBeNull();
    expect(findRemover([])).toBeNull();
  });

  it.runIf(usesSystemRemover())(
    "skips such candidates for the first one that passes, in order",
    () => {
      const working = findRemover(REMOVER_CANDIDATES) as Remover;
      expect(REMOVER_CANDIDATES).toContain(working);
      expect(findRemover([missing, inert, rejects, working])).toBe(working);
      // The first that passes is used, not a later one that would too.
      const later: Remover = { file: working.file, args: [...working.args] };
      expect(findRemover([missing, working, later])).toBe(working);
      // The default list reaches the same candidate past one that is missing.
      expect(findRemover([missing, ...REMOVER_CANDIDATES])).toBe(working);
    },
  );
});
