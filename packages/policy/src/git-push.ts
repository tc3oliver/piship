// Best-effort recognition of `git push` in a shell command's text, for the
// `git.push` action. This reads the words the command spells out; it does not
// run a shell, so a push from a script, an alias, `sh -c`, or a variable is
// not seen. Those stay decided by `shell.execute` alone.

/** Characters that end one simple command outside quotes. */
const SEPARATORS = new Set([";", "&", "|", "\n", "(", ")", "`"]);

/** The index of the `)` closing the `$(` whose `(` is at `open`. */
function closingParen(text: string, open: number): number {
  let depth = 0;
  for (let index = open; index < text.length; index++) {
    if (text[index] === "(") depth++;
    else if (text[index] === ")" && --depth === 0) return index;
  }
  return text.length;
}

/**
 * Simple commands as word lists: quotes removed, separators split, a
 * backslash-newline joined. A `$(...)` or backtick substitution inside double
 * quotes runs too, so it is read as commands of its own.
 */
function simpleCommands(command: string): string[][] {
  const commands: string[][] = [[]];
  const nested: string[] = [];
  let word: string | undefined;
  const end = () => {
    if (word !== undefined) commands[commands.length - 1]?.push(word);
    word = undefined;
  };
  for (let index = 0; index < command.length; index++) {
    const char = command[index] as string;
    if (char === "'") {
      const close = command.indexOf(char, index + 1);
      const stop = close === -1 ? command.length : close;
      word = (word ?? "") + command.slice(index + 1, stop);
      index = stop;
    } else if (char === '"') {
      word ??= "";
      for (index++; index < command.length && command[index] !== '"'; index++) {
        const inner = command[index] as string;
        if (inner === "\\" && command[index + 1] === "\n") index++;
        // Inside double quotes a backslash escapes only these.
        else if (inner === "\\" && /^[$`"\\]$/.test(command[index + 1] ?? ""))
          word += command[++index];
        else if (inner === "$" && command[index + 1] === "(") {
          const close = closingParen(command, index + 1);
          nested.push(command.slice(index + 2, close));
          index = close;
        } else if (inner === "`") {
          const close = command.indexOf("`", index + 1);
          const stop = close === -1 ? command.length : close;
          nested.push(command.slice(index + 1, stop));
          index = stop;
        } else word += inner;
      }
    } else if (char === "\\" && command[index + 1] === "\n") {
      index++;
    } else if (char === "\\" && index + 1 < command.length) {
      word = (word ?? "") + command[++index];
    } else if (SEPARATORS.has(char)) {
      end();
      commands.push([]);
    } else if (/\s/.test(char)) {
      end();
    } else {
      word = (word ?? "") + char;
    }
  }
  end();
  return [
    ...commands.filter((words) => words.length > 0),
    ...nested.flatMap(simpleCommands),
  ];
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
 * `words[start]`, when that word is git.
 */
function pushTargets(words: readonly string[], start: number): string[] {
  const program = (words[start] ?? "").split(/[\\/]/).pop()?.toLowerCase();
  if (program !== "git" && program !== "git.exe") return [];
  let index = start + 1;
  while ((words[index] ?? "").startsWith("-")) {
    if (GIT_VALUE_OPTIONS.has(words[index] as string)) index++;
    index++;
  }
  if (words[index] !== "push") return [];
  let remote: string | undefined;
  const refspecs: string[] = [];
  let options = true;
  for (index++; index < words.length; index++) {
    const word = words[index] as string;
    if (options && word === "--") options = false;
    else if (options && PUSH_VALUE_OPTIONS.has(word)) index++;
    else if (options && word === "--repo") remote = words[++index];
    else if (options && word.startsWith("--repo=")) remote = word.slice(7);
    else if (options && word.startsWith("-")) continue;
    else if (remote === undefined) remote = word;
    else refspecs.push(word);
  }
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
 * unquoted `echo git push` counts too: git.push only adds a deny or ask.
 */
export function gitPushResources(command: string): string[] {
  return simpleCommands(command).flatMap((words) =>
    words.flatMap((_word, index) => pushTargets(words, index)),
  );
}
