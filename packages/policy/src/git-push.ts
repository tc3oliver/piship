import { simpleCommands } from "./shell-words.js";

/** More resources than this collapse to one unnamed target. */
const MAX_RESOURCES = 64;
/** More git options than this before the subcommand count as a push to `*`. */
const MAX_GIT_OPTIONS = 64;

// Git options before the subcommand that take the next word as a value.
const GIT_VALUE_OPTIONS = new Set([
  "-C",
  "-c",
  "--git-dir",
  "--work-tree",
  "--namespace",
  "--config-env",
  "--super-prefix",
  "--attr-source",
]);
// `git push` options that take the next word as a value.
const PUSH_VALUE_OPTIONS = new Set([
  "-o",
  "--push-option",
  "--receive-pack",
  "--exec",
]);

/** The branch a refspec pushes to, or `*` when the text does not name it. */
function refspecTarget(refspec: string): string {
  const spec = refspec.replace(/^\+/, "");
  const colon = spec.indexOf(":");
  const target = (colon === -1 ? spec : spec.slice(colon + 1)).replace(
    /^refs\/heads\//,
    "",
  );
  return !target || target === "HEAD" || target === "@" || target.includes("*")
    ? "*"
    : target;
}

/**
 * The `<remote>/<branch>` resources of the `git ... push ...` starting at
 * `words[start]`, or undefined when that is no git push.
 */
function pushTargets(
  words: readonly string[],
  start: number,
): string[] | undefined {
  const program = (words[start] ?? "").split(/[\\/]/).pop()?.toLowerCase();
  if (program !== "git" && program !== "git.exe") return undefined;
  let index = start + 1;
  for (let options = 0; (words[index] ?? "").startsWith("-"); options++) {
    // Too many to be an ordinary command: do not scan on, assume a push.
    if (options === MAX_GIT_OPTIONS) return ["*"];
    if (GIT_VALUE_OPTIONS.has(words[index] as string)) index++;
    index++;
  }
  // A subcommand the shell expands (`{push,x}`, `pu?h`) may be push.
  if (/[{*?[]/.test(words[index] ?? "")) return ["*"];
  if (words[index] !== "push") return undefined;
  let remote: string | undefined;
  let repo: string | undefined;
  const refspecs: string[] = [];
  let options = true;
  for (index++; index < words.length; index++) {
    const word = words[index] as string;
    if (options && word === "--") options = false;
    else if (options && PUSH_VALUE_OPTIONS.has(word)) index++;
    else if (options && word === "--repo") repo = words[++index];
    else if (options && word.startsWith("--repo=")) repo = word.slice(7);
    else if (options && word.startsWith("-")) continue;
    else if (remote === undefined) remote = word;
    else refspecs.push(word);
  }
  // As in git, a positional repository wins over `--repo`.
  remote ??= repo;
  if (remote === undefined) return ["*"];
  return refspecs.length
    ? refspecs.map((refspec) => `${remote}/${refspecTarget(refspec)}`)
    : [`${remote}/*`];
}

/**
 * The `git.push` resources a command's text names, one per refspec, as
 * `<remote>/<branch>`; `*` stands for a remote or branch the text does not
 * name. Empty when no `git push` is spelled out. git counts at any word of a
 * simple command (`sudo git push`, `if git push`, `xargs git push`), so an
 * unquoted `echo git push` counts too: git.push only adds a deny or ask. At
 * most MAX_RESOURCES distinct resources; more, or nesting too deep to read,
 * is the single unnamed target `*`.
 */
export function gitPushResources(command: string): string[] {
  const { commands, overflow, unterminated } = simpleCommands(command);
  if (overflow) return ["*"];
  const resources = new Set<string>();
  // Text left unread by an unended quote or heredoc that names git, then
  // push, counts as a push to an unnamed target.
  const git = unterminated.search(/\bgit\b/);
  if (git !== -1 && /\bpush\b/.test(unterminated.slice(git)))
    resources.add("*");
  for (const words of commands)
    for (let index = 0; index < words.length; index++) {
      const targets = pushTargets(words, index);
      if (!targets) continue;
      for (const target of targets) resources.add(target);
      if (resources.size > MAX_RESOURCES) return ["*"];
      // The rest of the word list is the push's arguments, not commands.
      break;
    }
  return [...resources];
}
