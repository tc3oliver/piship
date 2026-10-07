import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { checkSkills } from "./skills-check.js";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

/** A distribution directory holding the given files; skills are declared. */
function distribution(files: Record<string, string>, skills: string[]) {
  const dir = mkdtempSync(join(tmpdir(), "piship-skills-"));
  roots.push(dir);
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, path)), { recursive: true });
    writeFileSync(join(dir, path), text);
  }
  const resources = {
    instructions: [],
    skills,
    extensions: [],
    prompts: [],
    themes: [],
  };
  return (name = "piship.yaml") => checkSkills({ resources }, join(dir, name));
}
const skill = (name: string, description = "Reviews code") =>
  `---\nname: ${name}\ndescription: ${description}\n---\nBody\n`;

describe("declared skills", () => {
  it("accepts a skill whose name matches its directory", () => {
    expect(
      distribution({ "skills/review/SKILL.md": skill("review") }, [
        "./skills",
      ])(),
    ).toEqual([]);
    expect(
      distribution({ "skills/review/SKILL.md": skill("review") }, [
        "./skills/review",
      ])(),
    ).toEqual([]);
  });

  it("warns about a skills directory without any SKILL.md", () => {
    const warnings = distribution({ "skills/review/notes.txt": "x" }, [
      "./skills",
    ])();
    expect(warnings).toHaveLength(1);
    expect(warnings[0]?.path).toBe("resources.skills[0]");
    expect(warnings[0]?.message).toContain("./skills holds no skill");
    expect(warnings[0]?.message).toContain("SKILL.md");
  });

  it("warns about a SKILL.md without a description, which Pi skips", () => {
    const warnings = distribution(
      { "skills/review/SKILL.md": "---\nname: review\n---\nBody\n" },
      ["./skills"],
    )();
    expect(warnings.map((item) => item.message)).toEqual([
      expect.stringContaining(
        "skills/review/SKILL.md is skipped: its frontmatter has no description",
      ),
    ]);
  });

  it("warns about a SKILL.md with no frontmatter at all", () => {
    const warnings = distribution({ "skills/review/SKILL.md": "Body\n" }, [
      "./skills",
    ])();
    expect(warnings[0]?.message).toContain("is skipped");
  });

  it("warns about frontmatter that is not YAML", () => {
    const warnings = distribution(
      { "skills/review/SKILL.md": "---\nname: [oops\n---\nBody\n" },
      ["./skills"],
    )();
    expect(warnings[0]?.message).toContain("not valid YAML");
  });

  it("says Pi loads a skill whose name differs from its directory", () => {
    const warnings = distribution(
      { "skills/review/SKILL.md": skill("code-review") },
      ["./skills"],
    )();
    expect(warnings).toHaveLength(1);
    expect(warnings[0]?.message).toContain(
      "the skill name code-review differs from its directory review; Pi loads it as code-review",
    );
  });

  it("warns about a name that breaks the Agent Skills rules", () => {
    const warnings = distribution(
      { "skills/Review_It/SKILL.md": skill("Review_It") },
      ["./skills"],
    )();
    expect(warnings[0]?.message).toContain(
      "the skill name Review_It must be lowercase letters, digits and hyphens only",
    );
  });

  it("warns when two skills share a name", () => {
    const warnings = distribution(
      {
        "skills/one/SKILL.md": skill("one"),
        "other/one/SKILL.md": skill("one"),
      },
      ["./skills", "./other"],
    )();
    expect(warnings).toEqual([
      {
        path: "resources.skills[1]",
        message: expect.stringContaining("skill name one is used by"),
      },
    ]);
  });

  it("loads a described markdown file at the top of a skills directory", () => {
    expect(
      distribution({ "skills/quick.md": skill("quick") }, ["./skills"])(),
    ).toEqual([]);
  });

  it("warns about a declared file that is not markdown", () => {
    const warnings = distribution({ "skills/tool.js": "x" }, [
      "./skills/tool.js",
    ])();
    expect(warnings[0]?.message).toContain("not a markdown file");
  });
});
