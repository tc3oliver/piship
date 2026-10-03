// Reading a signing key passphrase without putting it on a command line.
import { PiShipError } from "@piship/contracts";
import { readSecretInput } from "./branded/login.js";

/** Where a signing key passphrase comes from; never a command-line value. */
export interface PassphraseInput {
  /** The name of an environment variable that holds it, not the value. */
  readonly env?: string;
  /** The first line of standard input. */
  readonly stdin?: boolean;
  /** Ask twice at a terminal prompt and require the answers to match. */
  readonly confirm?: boolean;
}

const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;

function required(message: string): PiShipError {
  return new PiShipError("CREDENTIAL_REQUIRED", message, {
    component: "signing",
    userAction:
      "Run the command at a terminal to be prompted, name an environment variable that holds the passphrase with --passphrase-env <NAME>, or pipe it with --passphrase-stdin",
  });
}

/**
 * The passphrase from `input.env`, standard input, or a hidden terminal
 * prompt, in that order. Without a terminal and without either channel it
 * fails closed. Messages never quote the passphrase or the variable's value;
 * the variable name is not echoed either, in case a value was passed as one.
 */
export async function readSigningPassphrase(
  label: string,
  input: PassphraseInput = {},
  options: {
    readonly env?: NodeJS.ProcessEnv;
    readonly isTTY?: boolean;
    readonly read?: (prompt: string) => Promise<string>;
  } = {},
): Promise<string> {
  const read = options.read ?? readSecretInput;
  if (input.env !== undefined && input.stdin)
    throw new PiShipError(
      "CONFIG_INVALID",
      "Choose one passphrase source: --passphrase-env or --passphrase-stdin",
      { component: "signing" },
    );
  let passphrase: string;
  if (input.env !== undefined) {
    if (!ENV_NAME.test(input.env))
      throw new PiShipError(
        "CONFIG_INVALID",
        "--passphrase-env takes the name of an environment variable (letters, digits, underscores), not the passphrase",
        { component: "signing" },
      );
    passphrase = (options.env ?? process.env)[input.env] ?? "";
    if (!passphrase)
      throw required(
        "The environment variable named by --passphrase-env is not set or is empty",
      );
    return passphrase;
  }
  if (input.stdin) passphrase = await read(label);
  else if (options.isTTY ?? process.stdin.isTTY) {
    passphrase = await read(label);
    if (
      passphrase &&
      input.confirm &&
      (await read(`${label} again`)) !== passphrase
    )
      throw new PiShipError("CONFIG_INVALID", "The passphrases do not match", {
        component: "signing",
      });
  } else throw required(`${label} is needed, but no terminal is attached`);
  if (!passphrase) throw required("No passphrase was entered");
  return passphrase;
}
