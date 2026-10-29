// Shared quote-aware shell scanner. Git push detection remains best-effort;
// grant matching applies an additional fail-closed syntax check.

/** Characters that end one simple command outside quotes. */
const SEPARATORS = new Set([";", "&", "|", "\n", "(", ")"]);

/** Substitutions nested deeper than this make the push target unnamed. */
const MAX_NESTING = 8;
/**
 * A substitution being read: `$(`, a backtick, or arithmetic (`((` or
 * `$((`), whose words are read as commands too and where `<<` is a shift.
 */
interface Frame {
  readonly kind: "paren" | "backtick" | "arithmetic";
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
export function simpleCommands(text: string): Scan {
  const commands: string[][] = [];
  let command: string[] = [];
  let word: string | undefined;
  let quoted = false;
  let quoteStart = 0;
  let redirect = false;
  let unterminated = "";
  // Only the first text left unread counts; a later one may be empty.
  const unread = (from: number) => {
    if (!unterminated) unterminated = text.slice(from);
  };
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
      else if (char === "$" && next === "(") {
        const arithmetic = text[index + 2] === "(";
        if (!open(arithmetic ? "arithmetic" : "paren")) return overflow();
        index += arithmetic ? 2 : 1;
      } else if (char === "`") {
        if (!open("backtick")) return overflow();
      } else word = (word ?? "") + char;
    } else if (
      char === "#" &&
      word === undefined &&
      (index === 0 || /[\s;&|(]/.test(text[index - 1] as string))
    ) {
      // A comment, to the end of the line.
      const lineEnd = text.indexOf("\n", index);
      index = (lineEnd === -1 ? text.length : lineEnd) - 1;
    } else if (char === "'" || (char === "$" && next === "'")) {
      // `$'...'` keeps its backslash escapes as written.
      const start = char === "$" ? index + 2 : index + 1;
      const stop = text.indexOf("'", start);
      if (stop === -1) unread(start);
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
      if (!open("arithmetic")) return overflow();
      index += char === "$" ? 2 : 1;
    } else if (char === ")" && frames.at(-1)?.kind === "arithmetic") {
      const frame = frames.at(-1) as Frame;
      if (frame.depth > 0) {
        frame.depth--;
        split();
      } else {
        // `))` ends it; a lone `)` does too, so it never stays open.
        if (next === ")") index++;
        close();
      }
    } else if (char === "$" && next === "{") {
      // A parameter expansion is data unless it holds a substitution.
      const stop = text.indexOf("}", index);
      const body = text.slice(index, stop === -1 ? text.length : stop + 1);
      if (/\$\(|`/.test(body)) word = (word ?? "") + char;
      else {
        word = (word ?? "") + body;
        index += body.length - 1;
      }
    } else if (char === "$" && next === "(") {
      if (!open("paren")) return overflow();
      index++;
    } else if (char === "`") {
      const frame = frames.at(-1);
      if (frame?.kind === "backtick") close();
      else if (!open("backtick")) return overflow();
    } else if (
      frames.at(-1)?.kind === "arithmetic" &&
      (char === "<" || char === ">")
    ) {
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
      const frame = frames.at(-1);
      if (
        char === "(" &&
        (frame?.kind === "paren" || frame?.kind === "arithmetic")
      )
        frame.depth++;
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
              unread(index + 1);
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
  if (quoted && !frames.length) unread(quoteStart);
  split();
  while (frames.length) close();
  if (command.length) commands.push(command);
  return { commands, overflow: false, unterminated };
}

/**
 * A single literal shell command for task-grant matching. Shell constructs
 * whose execution differs from these parsed words are deliberately refused.
 * Git push detection uses the same tokenizer without this strict filter.
 */
export function grantCommandWords(
  text: string,
  platform: "posix" | "win32",
): string[] | undefined {
  if (text.length > 4096) return undefined;
  let quote: "'" | '"' | undefined;
  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    if (platform === "win32" && /[%^!]/.test(char)) return undefined;
    if (quote === "'") {
      if (char === "'") {
        quote = undefined;
      } else if (
        platform === "win32" &&
        /[;&|$\x60<>()\\\r\n]/.test(char)
      ) {
        // cmd.exe does not treat single quotes as quoting.
        return undefined;
      }
      continue;
    }
    if (quote === '"') {
      if (char === '"') {
        quote = undefined;
        continue;
      }
      if (char === "\\") {
        // Only escaped quotes/backslashes are unambiguous in this subset.
        if (text[i + 1] !== '"' && text[i + 1] !== "\\")
          return undefined;
        i++;
        continue;
      }
      if (char === "$" || char === "\x60") return undefined;
      continue;
    }
    if (char === "'" || char === '"') {
      quote = char;
      continue;
    }
    // No chaining, redirects, substitutions, grouping or escapes.
    if (/[;&|$\x60<>()\\\r\n]/.test(char)) return undefined;
    // Bash splits only on ASCII spaces/tabs here. The git-push scanner's
    // broader Unicode whitespace parsing must not grant a different program.
    if (/\s/.test(char) && char !== " " && char !== "\t")
      return undefined;
    if (char !== "\t" && /[\u0000-\u001f\u007f]/.test(char))
      return undefined;
  }
  if (quote !== undefined) return undefined;
  const parsed = simpleCommands(text);
  if (parsed.overflow || parsed.unterminated || parsed.commands.length !== 1)
    return undefined;
  return parsed.commands[0];
}
