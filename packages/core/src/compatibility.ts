export const PI_PACKAGE = "@earendil-works/pi-coding-agent";
export const PI_VERSION = "1.0.2";
export const PISHIP_VERSION = "0.9.1";
/** OS/CPU targets with installed lifecycle evidence; others are never advertised. */
export const EVIDENCED_TARGETS = ["linux-x64", "darwin-arm64", "win32-x64"];
/**
 * Pi versions this PiShip build knows, per surface; mirrors
 * compatibility/pi.json (a test keeps them equal).
 */
export const PI_COMPATIBILITY: Readonly<
  Record<
    string,
    Readonly<
      Record<"personal" | "managed" | "governance" | "lifecycle", string>
    >
  >
> = {
  "0.87.1": {
    personal: "supported",
    managed: "candidate",
    governance: "candidate",
    lifecycle: "candidate",
  },
  "1.0.0": {
    personal: "supported",
    managed: "candidate",
    governance: "candidate",
    lifecycle: "candidate",
  },
  "1.0.2": {
    personal: "supported",
    managed: "candidate",
    governance: "candidate",
    lifecycle: "candidate",
  },
};
/**
 * Production packages whose npm lifecycle scripts were reviewed for the
 * pinned Pi closure (`path@version`). Any other install script stops a
 * release build.
 */
export const REVIEWED_INSTALL_SCRIPTS: readonly string[] = [
  // Pi 1.0.1+ ships no shrinkwrap, so these are hoisted to the top level.
  // preinstall is an echo; prepare does not run for registry installs.
  "node_modules/@google/genai@2.21.0",
  // Validates the platform binary from its optional @esbuild/* package.
  "node_modules/esbuild@0.28.2",
  // Prints a version compatibility notice for protobufjs CLI users.
  "node_modules/protobufjs@7.6.6",
];
/** `<platform>-<arch>` of this machine. */
export function currentTarget(): string {
  return `${process.platform}-${process.arch}`;
}
