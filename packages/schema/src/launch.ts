// Cross-field checks for settings that validate field by field but cannot
// work on the machine that launches the distribution. A setting that is
// certain to fail at launch is rejected by the parser; one that fails or is
// ignored only in some environments is reported as a warning by `validate`.
import { posix, win32 } from "node:path";
import type { Manifest, ValidationDiagnostic } from "./index.js";

/**
 * Warnings for settings that parse but fail at launch in some environments
 * or have no effect. They never change how the manifest is parsed.
 */
export function launchWarnings(manifest: Manifest): ValidationDiagnostic[] {
  const warnings: ValidationDiagnostic[] = [];
  const access = manifest.access;
  if (access)
    // A path that starts with a variable is absolute or not only once the
    // variable is resolved; any other path is checked as written.
    for (const [index, path] of access.network.tls.additionalCA.entries())
      if (
        !path.startsWith("${") &&
        !posix.isAbsolute(path) &&
        !win32.isAbsolute(path)
      )
        warnings.push({
          path: `network.tls.additionalCA[${index}]`,
          message:
            "A relative CA bundle path is read from the directory the command is launched in, and is not packaged or locked; use an absolute path that device management installs on every machine",
        });
  return warnings;
}
