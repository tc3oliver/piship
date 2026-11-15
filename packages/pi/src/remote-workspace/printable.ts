/**
 * Text that came from the sandbox, or names a file there, made safe to show or
 * put in a prompt: control characters (OSC 52 clipboard writes, screen
 * clears, DCS) and bidi controls become `?`; newline and tab stay.
 */
export function printable(text: string): string {
  return text.replace(
    // biome-ignore lint/suspicious/noControlCharactersInRegex: matching them is the point
    /[\u0000-\u0008\u000b-\u001f\u007f-\u009f‎‏‪-‮⁦-⁩]/g,
    "?",
  );
}
