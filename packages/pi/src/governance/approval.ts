import { createInterface } from "node:readline";
import { type ApprovalChannel, redact } from "@piship/contracts";

/** Longest subject shown in an approval prompt. */
const APPROVAL_SUBJECT_MAX = 2000;

/** The redacted subject of an approval prompt, shortened for a dialog. */
export function approvalSubject(subject: string): string {
  const shown = redact(subject);
  return shown.length > APPROVAL_SUBJECT_MAX
    ? `${shown.slice(0, APPROVAL_SUBJECT_MAX)}…`
    : shown;
}

/** A y/N prompt on the terminal before the TUI starts; headless has none. */
export function terminalApproval(): ApprovalChannel | undefined {
  if (!process.stdin.isTTY || !process.stderr.isTTY) return undefined;
  return async (_decision, detail) => {
    const rl = createInterface({
      input: process.stdin,
      output: process.stderr,
      terminal: true,
    });
    try {
      // Ctrl-C or Ctrl-D cancels: closing the interface never calls the
      // question callback, so without these the launch would never settle
      // and its teardown would not run.
      const answer = await new Promise<string | null>((done) => {
        rl.once("close", () => done(null));
        rl.once("SIGINT", () => done(null));
        rl.question(
          `${detail.title}\n${detail.message}\n${
            detail.offerRemember
              ? "Allow? [y] this time, [a] always for this project until its files change, [N] no, [never] no, and do not ask again: "
              : "Allow? [y/N] "
          }`,
          done,
        );
      });
      if (answer === null) return "cancelled";
      const reply = answer.trim().toLowerCase();
      if (detail.offerRemember && /^a(lways)?$/.test(reply))
        return "approved-always";
      if (detail.offerRemember && reply === "never") return "denied-always";
      return /^y(es)?$/.test(reply) ? "approved" : "denied";
    } finally {
      rl.close();
    }
  };
}
