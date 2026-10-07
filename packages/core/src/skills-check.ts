import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import { type Manifest, skillFrontmatter } from "@piship/schema";

/** A declared skill that Pi will not load as the author expects. */
export interface SkillWarning {
  /** The manifest field, such as `resources.skills[0]`. */
  readonly path: string;
  readonly message: string;
}

/** The skill name rules of the Agent Skills spec, as Pi applies them. */
function nameProblems(name: string): string[] {
  const problems: string[] = [];
  if (name.length > 64) problems.push(`is ${name.length} characters (max 64)`);
  if (!/^[a-z0-9-]+$/.test(name))
    problems.push("must be lowercase letters, digits and hyphens only");
  if (name.startsWith("-") || name.endsWith("-"))
    problems.push("must not start or end with a hyphen");
  if (name.includes("--"))
    problems.push("must not contain consecutive hyphens");
  return problems;
}

interface Found {
  readonly skills: { readonly file: string; readonly name: string }[];
  readonly warnings: string[];
}

/**
 * One skill file, judged as Pi's loader judges it: a file without a
 * description is skipped (a SKILL.md says so; another markdown file is not a
 * skill at all), and a name that breaks the spec loads with a warning.
 */
function checkSkillFile(file: string, found: Found, path: string): void {
  // Warnings name the file with forward slashes on every platform.
  const shown = sep === "/" ? path : path.split(sep).join("/");
  const isSkillFile = basename(file) === "SKILL.md";
  let text: string;
  try {
    text = readFileSync(file, "utf8");
  } catch (error) {
    found.warnings.push(
      `${shown} cannot be read: ${error instanceof Error ? error.message : "read failed"}`,
    );
    return;
  }
  const { frontmatter, error } = skillFrontmatter(text);
  if (error !== undefined) {
    if (isSkillFile)
      found.warnings.push(
        `${shown} is skipped: its frontmatter is not valid YAML (${error})`,
      );
    return;
  }
  const description = frontmatter.description;
  if (typeof description !== "string" || description.trim() === "") {
    if (isSkillFile)
      found.warnings.push(
        `${shown} is skipped: its frontmatter has no description. Start the file with a --- block that sets name and description`,
      );
    return;
  }
  const directory = basename(dirname(file));
  const name =
    typeof frontmatter.name === "string" && frontmatter.name
      ? frontmatter.name
      : directory;
  for (const problem of nameProblems(name))
    found.warnings.push(`${shown}: the skill name ${name} ${problem}`);
  if (isSkillFile && name !== directory)
    found.warnings.push(
      `${shown}: the skill name ${name} differs from its directory ${directory}; Pi loads it as ${name}, but the Agent Skills spec expects them to match`,
    );
  found.skills.push({ file, name });
}

/** Pi's discovery in one directory: a SKILL.md ends the descent. */
function discover(
  directory: string,
  base: string,
  found: Found,
  includeRootFiles: boolean,
): void {
  const entries = readdirSync(directory, { withFileTypes: true });
  const own = entries.find(
    (entry) => entry.name === "SKILL.md" && entry.isFile(),
  );
  if (own) {
    const file = join(directory, own.name);
    checkSkillFile(file, found, relative(base, file));
    return;
  }
  for (const entry of entries) {
    if (entry.name.startsWith(".") || entry.name === "node_modules") continue;
    const full = join(directory, entry.name);
    if (entry.isDirectory()) discover(full, base, found, false);
    else if (entry.isFile() && includeRootFiles && entry.name.endsWith(".md"))
      checkSkillFile(full, found, relative(base, full));
  }
}

/**
 * Declared skills that Pi loads differently from what the author wrote, or
 * not at all: a skills directory with no SKILL.md in it, a SKILL.md without
 * a description or with broken frontmatter, a name that breaks the spec or
 * differs from its directory, and two skills of one name. Pi drops these
 * without failing, so nothing else in the build says so.
 */
export function checkSkills(
  manifest: Pick<Manifest, "resources">,
  manifestPath: string,
): SkillWarning[] {
  const base = dirname(resolve(manifestPath));
  const warnings: SkillWarning[] = [];
  const names = new Map<string, string>();
  manifest.resources.skills.forEach((declared, index) => {
    const path = `resources.skills[${index}]`;
    const root = resolve(base, declared);
    if (!existsSync(root)) return;
    const found: Found = { skills: [], warnings: [] };
    if (statSync(root).isDirectory()) discover(root, base, found, true);
    else if (root.endsWith(".md")) checkSkillFile(root, found, declared);
    else
      found.warnings.push(
        `${declared} is not a markdown file or a skills directory, so Pi skips it`,
      );
    if (!found.skills.length && !found.warnings.length)
      found.warnings.push(
        `${declared} holds no skill: Pi loads a directory that has a SKILL.md (in it or in a subdirectory, with name and description frontmatter) or markdown files with a description at its top level`,
      );
    for (const skill of found.skills) {
      const first = names.get(skill.name);
      if (first)
        found.warnings.push(
          `skill name ${skill.name} is used by ${relative(base, skill.file)} and ${first}; Pi keeps the first and drops the other`,
        );
      else names.set(skill.name, relative(base, skill.file));
    }
    for (const message of found.warnings) warnings.push({ path, message });
  });
  return warnings;
}
