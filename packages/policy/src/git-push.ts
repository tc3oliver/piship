// Best-effort recognition of `git push` in a shell command's text, for the
// `git.push` action. This reads the words the command spells out; it does not
// run a shell, so a push from a script, an alias, `sh -c`, or a variable is
// not seen. Those stay decided by `shell.execute` alone. Every shell command
// passes through here, so the scan is one linear pass with bounded output.

/** Characters that end one simple command outside quotes. */
const SEPARATORS = new Set([";", "&", "|", "\n", "(", ")"]);

/** Substitutions nested deeper than this make the push target unnamed. */
const MAX_NESTING = 8;
/** More resources than this collapse to one unnamed target. */
const MAX_RESOURCES = 64;
/** More git options than this before the subcommand count as a push to `*`. */
const MAX_GIT_OPTIONS = 64;

/** A substitution being read: `$(`, or a backtick. */
interface Frame {
  readonly kind: "paren" | "backtick";
  /** Unclosed `(` inside it. */
  depth: number;
  /** Whether it opened inside double quotes, and the word it interrupted. */
  readonly quoted: boolean;
  readonly word: string | undefined;
  readonly command: string[];
  /** Whether it opened as a redirection's target. */
  readonly redirect: boolean;
  /** Pending heredocs when it opened: one opened inside ends with it. */
  readonly heredocs: number;
}

interface Scan {
  readonly commands: string[][];
  /** Nesting passed MAX_NESTING: what is inside was not read. */
  readonly overflow: boolean;
  /** Text read as data only because a quote or heredoc never ended. */
  readonly unterminated: string;
}

/**
 * Simple commands as word lists: quotes removed, separators split, a
 * backslash-newline joined, redirections and heredoc bodies dropped. A
 * `$(...)` or backtick substitution, also inside double quotes, is read as
 * commands of its own.
 */
function simpleCommands(text: string): Scan {
  const commands: string[][] = [];
  let command: string[] = [];
  let word: string | undefined;
  let quoted = false;
  let quoteStart = 0;
  let redirect = false;
  // Open `((` or `$((`: inside arithmetic `<<` is a shift, not a heredoc.
  let arithmetic = 0;
  let unterminated = "";
  const frames: Frame[] = [];
  const overflow = (): Scan => ({ commands, overflow: true, unterminated });
  const heredocs: { delimiter: string; tabs: boolean }[] = [];
  const end = () => {
    if (word !== undefined && !redirect) command.push(word);
    if (word !== undefined) redirect = false;
    word = undefined;
  };
  const split = () => {
    end();
    redirect = false;
    if (command.length) commands.push(command);
    command = [];
  };
  const open = (kind: Frame["kind"]): boolean => {
    if (frames.length >= MAX_NESTING) return false;
    frames.push({
      kind,
      depth: 0,
      quoted,
      word: quoted ? word : undefined,
      command,
      redirect,
      heredocs: heredocs.length,
    });
    if (quoted) word = undefined;
    else end();
    command = [];
    quoted = false;
    redirect = false;
    return true;
  };
  const close = () => {
    split();
    const frame = frames.pop() as Frame;
    heredocs.length = frame.heredocs;
    command = frame.command;
    quoted = frame.quoted;
    if (quoted) word = frame.word;
    // An unquoted substitution was the whole redirection target.
    redirect = quoted && frame.redirect;
  };
  for (let index = 0; index < text.length; index++) {
    const char = text[index] as string;
    const next = text[index + 1];
    if (char === "\\" && next === "\n") {
      index++;
    } else if (quoted) {
      if (char === '"') quoted = false;
      else if (char === "\\" && next !== undefined && '$`"\\'.includes(next))
        word = (word ?? "") + text[++index];
      // `$((...))` in quotes is arithmetic, read as text.
      else if (char === "$" && next === "(" && text[index + 2] !== "(") {
        if (!open("paren")) return overflow();
        index++;
      } else if (char === "`") {
        if (!open("backtick")) return overflow();
      } else word = (word ?? "") + char;
    } else if (char === "#" && word === undefined) {
      // A comment, to the end of the line.
      const lineEnd = text.indexOf("\n", index);
      index = (lineEnd === -1 ? text.length : lineEnd) - 1;
    } else if (char === "'" || (char === "$" && next === "'")) {
      // `$'...'` keeps its backslash escapes as written.
      const start = char === "$" ? index + 2 : index + 1;
      const stop = text.indexOf("'", start);
      if (stop === -1) unterminated = text.slice(start);
      word = (word ?? "") + text.slice(start, stop === -1 ? text.length : stop);
      index = stop === -1 ? text.length : stop;
    } else if (char === '"') {
      word ??= "";
      quoted = true;
      quoteStart = index + 1;
    } else if (char === "\\" && next !== undefined) {
      word = (word ?? "") + text[++index];
    } else if (
      (char === "$" && next === "(" && text[index + 2] === "(") ||
      (char === "(" && next === "(" && word === undefined)
    ) {
      arithmetic++;
      index += char === "$" ? 2 : 1;
    } else if (char === ")" && next === ")" && arithmetic > 0) {
      arithmetic--;
      index++;
    } else if (char === "$" && next === "(") {
      if (!open("paren")) return overflow();
      index++;
    } else if (char === "`") {
      const frame = frames.at(-1);
      if (frame?.kind === "backtick") close();
      else if (!open("backtick")) return overflow();
    } else if (arithmetic > 0 && (char === "<" || char === ">")) {
      word = (word ?? "") + char;
    } else if (char === "<" && next === "<" && text[index + 2] !== "<") {
      // A heredoc: its body, from the next line to the delimiter, is data.
      end();
      index += 2;
      const tabs = text[index] === "-";
      if (tabs) index++;
      while (text[index] === " " || text[index] === "\t") index++;
      // The delimiter is one word: quotes are part of it and removed.
      let delimiter = "";
      for (; index < text.length; index++) {
        const at = text[index] as string;
        if (at === "'" || at === '"') {
          const stop = text.indexOf(at, index + 1);
          const until = stop === -1 ? text.length : stop;
          delimiter += text.slice(index + 1, until);
          index = until;
        } else if (at === "\\" && index + 1 < text.length)
          delimiter += text[++index];
        else if (/[\s;&|()<>`]/.test(at)) break;
        else delimiter += at;
      }
      index--;
      if (delimiter) heredocs.push({ delimiter, tabs });
    } else if (char === "<" || char === ">") {
      // A redirection: its target (and a file descriptor before it) is no argument.
      if (word !== undefined && /^\d+$/.test(word)) word = undefined;
      end();
      redirect = true;
      while (
        text[index + 1] === ">" ||
        text[index + 1] === "&" ||
        text[index + 1] === "<"
      )
        index++;
    } else if (char === ")" && frames.at(-1)?.kind === "paren") {
      const frame = frames.at(-1) as Frame;
      if (frame.depth === 0) close();
      else {
        frame.depth--;
        split();
      }
    } else if (SEPARATORS.has(char)) {
      if (char === "(" && frames.at(-1)?.kind === "paren")
        (frames.at(-1) as Frame).depth++;
      split();
      if (char === "\n")
        for (const heredoc of heredocs.splice(0)) {
          // Skip lines until one is the delimiter.
          for (;;) {
            const lineEnd = text.indexOf("\n", index + 1);
            const stop = lineEnd === -1 ? text.length : lineEnd;
            let line = text.slice(index + 1, stop);
            if (heredoc.tabs) line = line.replace(/^\t+/, "");
            if (line === heredoc.delimiter) {
              index = stop;
              break;
            }
            if (stop === text.length) {
              unterminated = text.slice(index + 1);
              index = stop;
              break;
            }
            index = stop;
          }
        }
    } else if (/\s/.test(char)) {
      end();
    } else {
      word = (word ?? "") + char;
    }
  }
  if (quoted && !frames.length) unterminated = text.slice(quoteStart);
  split();
  while (frames.length) close();
  if (command.length) commands.push(command);
  return { commands, overflow: false, unterminated };
}

// Git options before the subcommand that take the next word as a value.
const GIT_VALUE_OPTIONS = new Set([
  "-C",
  "-c",
  "--git-dir",
  "--work-tree",
  "--namespace",
  "--config-env",
  "--super-prefix",
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
