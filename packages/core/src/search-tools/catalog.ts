// The upstream release archives of the search tools a distribution can
// bundle: the official sharkdp/fd and BurntSushi/ripgrep GitHub releases, by
// exact version and release target. Asset names follow the ones Pi's own
// tools manager downloads (musl builds on Linux).
import type { SearchTool } from "@piship/schema";

export interface SearchToolSpec {
  /** The upstream repository URL, which the lock records as `source`. */
  readonly source: string;
  /** The executable's name without the Windows `.exe`. */
  readonly binary: string;
  /** PiShip's default version when the manifest pins none. */
  readonly defaultVersion: string;
  /** The release tag of a version. */
  readonly tag: (version: string) => string;
  /** The archive name of a version for a Rust target triple. */
  readonly asset: (version: string, triple: string, ext: string) => string;
}

export const SEARCH_TOOL_SPECS: Readonly<Record<SearchTool, SearchToolSpec>> = {
  fd: {
    source: "https://github.com/sharkdp/fd",
    binary: "fd",
    defaultVersion: "10.5.0",
    tag: (version) => `v${version}`,
    asset: (version, triple, ext) => `fd-v${version}-${triple}.${ext}`,
  },
  rg: {
    source: "https://github.com/BurntSushi/ripgrep",
    binary: "rg",
    defaultVersion: "15.2.0",
    tag: (version) => version,
    asset: (version, triple, ext) => `ripgrep-${version}-${triple}.${ext}`,
  },
};

/** The Rust target triple and archive format of each release target. */
const TARGET_TRIPLES: Readonly<
  Record<string, { readonly triple: string; readonly ext: "tar.gz" | "zip" }>
> = {
  "linux-x64": { triple: "x86_64-unknown-linux-musl", ext: "tar.gz" },
  "linux-arm64": { triple: "aarch64-unknown-linux-musl", ext: "tar.gz" },
  "darwin-arm64": { triple: "aarch64-apple-darwin", ext: "tar.gz" },
  "darwin-x64": { triple: "x86_64-apple-darwin", ext: "tar.gz" },
  "win32-x64": { triple: "x86_64-pc-windows-msvc", ext: "zip" },
};

export interface SearchToolAsset {
  readonly name: string;
  readonly url: string;
  readonly format: "tar.gz" | "zip";
}

/** The upstream archive of `tool` at `version` for a release target. */
export function searchToolAsset(
  tool: SearchTool,
  version: string,
  target: string,
): SearchToolAsset {
  const spec = SEARCH_TOOL_SPECS[tool];
  const platform = TARGET_TRIPLES[target];
  if (!platform)
    throw new Error(
      `runtime.searchTools: PiShip has no ${tool} archive mapping for ${target}`,
    );
  const name = spec.asset(version, platform.triple, platform.ext);
  return {
    name,
    url: `${spec.source}/releases/download/${spec.tag(version)}/${name}`,
    format: platform.ext,
  };
}

/** The executable's file name on a release target (`fd`, or `fd.exe`). */
export function searchToolFileName(tool: SearchTool, target: string): string {
  const binary = SEARCH_TOOL_SPECS[tool].binary;
  return target.startsWith("win32-") ? `${binary}.exe` : binary;
}
