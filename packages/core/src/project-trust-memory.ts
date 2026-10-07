// What a person told a distribution about a project's own configuration, kept
// in the distribution state so the question is not asked at every launch:
// `<state>/config/project-trust.json`, owner-only, keyed by the project's
// canonical root. An answer holds a digest of the files it covered, so a
// changed file is a new question. A remembered answer only ever replaces the
// prompt of a policy `ask`; it never decides for a `deny`, a rule, or a
// managed distribution. The same file remembers which "left out" notice was
// already shown, so a launch that leaves the same files out says so once.
import {
  existsSync,
  lstatSync,
  openSync,
  readdirSync,
  readFileSync,
  readlinkSync,
  readSync,
  realpathSync,
  closeSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join, resolve } from "node:path";
import { writeJsonAtomic } from "./access/state.js";

export const PROJECT_TRUST_SCHEMA = "piship-project-trust/v1";

export type ProjectTrustAnswer = "allow" | "deny";

export interface RememberedProject {
  /** Canonical project root. */
  readonly root: string;
  readonly answer: ProjectTrustAnswer;
  /** Digest of the covered files when the answer was given. */
  readonly digest: string;
  /** The project paths the answer covered, as the prompt showed them. */
  readonly items: readonly string[];
  readonly answeredAt: string;
}

interface Stored {
  readonly schema: typeof PROJECT_TRUST_SCHEMA;
  readonly projects: Record<string, StoredProject>;
}

interface StoredProject {
  answer?: {
    value: ProjectTrustAnswer;
    digest: string;
    items: string[];
    at: string;
  };
  /** Digest of the last "left out" notice shown for this project. */
  noticed?: string;
}

/** `<state>/config/project-trust.json`. Tools never read or write the state. */
export function projectTrustPath(stateDir: string): string {
  return join(stateDir, "config", "project-trust.json");
}

/** A project root as the state keys it: symlinks resolved. */
export function projectTrustKey(root: string): string {
  try {
    return realpathSync(root);
  } catch {
    return resolve(root);
  }
}

function readStored(stateDir: string): Stored {
  const empty: Stored = { schema: PROJECT_TRUST_SCHEMA, projects: {} };
  const path = projectTrustPath(stateDir);
  if (!existsSync(path)) return empty;
  try {
    const value = JSON.parse(readFileSync(path, "utf8")) as Partial<Stored>;
    if (
      value?.schema !== PROJECT_TRUST_SCHEMA ||
      typeof value.projects !== "object" ||
      value.projects === null
    )
      return empty;
    const projects: Record<string, StoredProject> = {};
    for (const [root, raw] of Object.entries(value.projects)) {
      const item = raw as Partial<StoredProject> | null;
      const entry: StoredProject = {};
      const answer = item?.answer;
      if (
        answer &&
        (answer.value === "allow" || answer.value === "deny") &&
        typeof answer.digest === "string" &&
        Array.isArray(answer.items) &&
        typeof answer.at === "string"
      )
        entry.answer = {
          value: answer.value,
          digest: answer.digest,
          items: answer.items.filter(
            (path): path is string => typeof path === "string",
          ),
          at: answer.at,
        };
      if (typeof item?.noticed === "string") entry.noticed = item.noticed;
      if (entry.answer || entry.noticed) projects[root] = entry;
    }
    return { schema: PROJECT_TRUST_SCHEMA, projects };
  } catch {
    // An unreadable file is a question asked again, never an answer.
    return empty;
  }
}

function write(stateDir: string, stored: Stored): void {
  writeJsonAtomic(projectTrustPath(stateDir), stored);
}

/** The remembered answer for the project, only while its files are unchanged. */
export function recallProjectTrust(
  stateDir: string,
  root: string,
  digest: string,
): ProjectTrustAnswer | undefined {
  const answer = readStored(stateDir).projects[projectTrustKey(root)]?.answer;
  return answer && answer.digest === digest ? answer.value : undefined;
}

/** Remember an answer for the project's current files. */
export function rememberProjectTrust(
  stateDir: string,
  root: string,
  answer: ProjectTrustAnswer,
  digest: string,
  items: readonly string[],
  now: Date = new Date(),
): void {
  const stored = readStored(stateDir);
  const key = projectTrustKey(root);
  const entry = stored.projects[key] ?? {};
  entry.answer = {
    value: answer,
    digest,
    items: [...items],
    at: now.toISOString(),
  };
  write(stateDir, {
    ...stored,
    projects: { ...stored.projects, [key]: entry },
  });
}

/** Whether this "left out" notice was already shown for the project. */
export function projectNoticeSeen(
  stateDir: string,
  root: string,
  digest: string,
): boolean {
  return (
    readStored(stateDir).projects[projectTrustKey(root)]?.noticed === digest
  );
}

/** Record that the "left out" notice was shown. */
export function markProjectNotice(
  stateDir: string,
  root: string,
  digest: string,
): void {
  const stored = readStored(stateDir);
  const key = projectTrustKey(root);
  write(stateDir, {
    ...stored,
    projects: {
      ...stored.projects,
      [key]: { ...stored.projects[key], noticed: digest },
    },
  });
}

/** Every project with a remembered answer. */
export function listRememberedProjects(
  stateDir: string,
): readonly RememberedProject[] {
  return Object.entries(readStored(stateDir).projects)
    .flatMap(([root, entry]) =>
      entry.answer
        ? [
            {
              root,
              answer: entry.answer.value,
              digest: entry.answer.digest,
              items: entry.answer.items,
              answeredAt: entry.answer.at,
            },
          ]
        : [],
    )
    .sort((a, b) => a.root.localeCompare(b.root));
}

/**
 * Forget what is remembered for a project (answer and notice), or for all of
 * them. A path inside a remembered project names that project. Returns how
 * many projects were forgotten.
 */
export function forgetProjectTrust(
  stateDir: string,
  root: string | "all",
): number {
  const stored = readStored(stateDir);
  const projects = { ...stored.projects };
  let count = 0;
  if (root === "all") {
    count = Object.keys(projects).length;
    for (const key of Object.keys(projects)) delete projects[key];
  } else {
    let key = projectTrustKey(root);
    while (!(key in projects) && dirname(key) !== key) key = dirname(key);
    if (key in projects) {
      delete projects[key];
      count = 1;
    }
  }
  if (count) write(stateDir, { ...stored, projects });
  return count;
}

const MAX_ENTRIES = 5000;
const MAX_BYTES = 64 * 1024 * 1024;

/**
 * A digest of what the paths hold now: names, kinds, and file contents,
 * symlinks as their target text and never followed. `undefined` when the
 * content is too large to digest, which makes an answer unrememberable
 * (the person is asked again) rather than weakly bound.
 */
export function digestProjectFiles(
  items: readonly { readonly path: string; readonly resolvedPath: string }[],
): string | undefined {
  const hash = createHash("sha256");
  const budget = { entries: 0, bytes: 0 };
  const buffer = Buffer.allocUnsafe(64 * 1024);
  const visit = (path: string, label: string): boolean => {
    if (++budget.entries > MAX_ENTRIES) return false;
    let stat: ReturnType<typeof lstatSync>;
    try {
      stat = lstatSync(path);
    } catch {
      hash.update(`missing\0${label}\0`);
      return true;
    }
    if (stat.isSymbolicLink()) {
      let target = "";
      try {
        target = readlinkSync(path);
      } catch {
        // Unreadable: digested as an empty target.
      }
      hash.update(`link\0${label}\0${target}\0`);
      return true;
    }
    if (stat.isDirectory()) {
      hash.update(`dir\0${label}\0`);
      let names: string[];
      try {
        names = readdirSync(path).sort();
      } catch {
        return false;
      }
      return names.every((name) => visit(join(path, name), `${label}/${name}`));
    }
    if (!stat.isFile()) {
      hash.update(`other\0${label}\0`);
      return true;
    }
    budget.bytes += stat.size;
    if (budget.bytes > MAX_BYTES) return false;
    hash.update(`file\0${label}\0${stat.size}\0`);
    let fd: number;
    try {
      fd = openSync(path, "r");
    } catch {
      return false;
    }
    try {
      for (;;) {
        const read = readSync(fd, buffer, 0, buffer.length, null);
        if (read === 0) break;
        hash.update(buffer.subarray(0, read));
      }
    } catch {
      return false;
    } finally {
      closeSync(fd);
    }
    hash.update("\0");
    return true;
  };
  for (const item of [...items].sort((a, b) => a.path.localeCompare(b.path)))
    if (!visit(item.resolvedPath, item.path)) return undefined;
  return hash.digest("hex");
}
