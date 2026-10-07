// Bundled search tools (`runtime.searchTools`, piship/v1alpha6): `fd` and
// `rg` from their official upstream release archives, pinned per release
// target by `piship lock`, verified and placed in the payload by `piship
// build`, and found by Pi at launch without the network or the user's PATH.
//
// Only downloading is asynchronous. `piship lock` and `piship build` first
// fill the PiShip download cache (`downloadSearchToolArchives`,
// `downloadLockedSearchTools`); the lock and the build then read it offline,
// and the stale-lock check never reads it at all.
import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import {
  createManagedFetch,
  DEFAULT_NETWORK_POLICY,
  type NetworkPolicy,
  PiShipError,
} from "@piship/contracts";
import {
  type AccessManifest,
  type Manifest,
  readManifest,
  SEARCH_TOOLS,
  type SearchTool,
} from "@piship/schema";
import { resolveAdditionalCA } from "../access/network.js";
import { currentTarget } from "../compatibility.js";
import type {
  DistributionLock,
  LockedSearchTool,
  LockedSearchToolTarget,
  LockedSearchTools,
} from "../lock-schema.js";
import { gate } from "../release/shared.js";
import {
  SEARCH_TOOL_SPECS,
  type SearchToolAsset,
  searchToolAsset,
  searchToolFileName,
} from "./catalog.js";
import { readSearchToolArchive } from "./extract.js";

export {
  SEARCH_TOOL_SPECS,
  searchToolAsset,
  searchToolFileName,
} from "./catalog.js";
export { readSearchToolArchive } from "./extract.js";

/** Where the payload holds the executables: `tools/fd`, `tools/rg.exe`. */
export const SEARCH_TOOL_PAYLOAD_DIRECTORY = "tools";

/** Hosts a release download may redirect to: GitHub's release asset storage. */
const ASSET_HOSTS = new Set([
  "github.com",
  "objects.githubusercontent.com",
  "release-assets.githubusercontent.com",
]);
const MAX_ARCHIVE_BYTES = 64 * 1024 * 1024;
const DOWNLOAD_TIMEOUT_MS = 5 * 60_000;
const MAX_REDIRECTS = 5;

const sha256 = (content: Buffer) =>
  `sha256-${createHash("sha256").update(content).digest("hex")}`;

/**
 * PiShip's download cache for search tool archives: `PISHIP_CACHE_HOME`, or
 * `piship` under `XDG_CACHE_HOME`, `%LOCALAPPDATA%`, or `~/.cache`. Archives
 * are named as upstream publishes them; every reader checks their digest.
 */
export function searchToolCacheDirectory(
  env: NodeJS.ProcessEnv = process.env,
): string {
  const base =
    env.PISHIP_CACHE_HOME ??
    join(
      env.XDG_CACHE_HOME ??
        (process.platform === "win32" && env.LOCALAPPDATA
          ? env.LOCALAPPDATA
          : join(homedir(), ".cache")),
      "piship",
    );
  return join(resolve(base), "search-tools");
}

export interface SearchToolRequest {
  readonly tool: SearchTool;
  readonly version: string;
  readonly targets: readonly string[];
}

/** The tools, versions, and targets a manifest asks to bundle. */
function requests(manifest: Manifest): SearchToolRequest[] {
  const declared = manifest.runtime.searchTools;
  if (!declared) return [];
  const targets = manifest.lifecycle?.release.targets ?? [currentTarget()];
  return SEARCH_TOOLS.map((tool) => ({
    tool,
    version: declared[tool] ?? SEARCH_TOOL_SPECS[tool].defaultVersion,
    targets,
  }));
}

/**
 * The source gate for search tools: each archive is the official upstream
 * release asset for its tool, version, and target, and its origin is in
 * `release.sources`.
 */
function checkSource(
  tool: SearchTool,
  version: string,
  target: string,
  url: string,
  sources: readonly string[] | undefined,
  stage: "Release" | "Build",
): void {
  if (searchToolAsset(tool, version, target).url !== url)
    throw gate(
      "LOCK_INVALID",
      "source",
      `${tool} ${version} for ${target} is not the official upstream release archive`,
      "Run piship lock",
      stage,
    );
  if (!sources) return;
  const origin = new URL(url).origin;
  if (!sources.includes(origin))
    throw gate(
      "POLICY_DENIED",
      "source",
      `${tool} ${version} comes from ${origin}, which is not in release.sources (${sources.join(", ")})`,
      `Review the upstream project, add ${origin} to release.sources, and lock again`,
      stage,
    );
}

/** `piship build` and `piship release`: the source gate over a lock. */
export function checkSearchToolSources(
  lock: Pick<DistributionLock, "searchTools" | "release">,
  stage: "Release" | "Build" = "Release",
): void {
  for (const tool of SEARCH_TOOLS) {
    const locked = lock.searchTools?.[tool];
    if (!locked) continue;
    for (const [target, entry] of Object.entries(locked.targets))
      checkSource(
        tool,
        locked.version,
        target,
        entry.url,
        lock.release?.sources,
        stage,
      );
  }
}

/** The lock-time network policy: the owner's proxy and CA, no private-only. */
function lockNetworkPolicy(access: AccessManifest | undefined): NetworkPolicy {
  if (!access) return DEFAULT_NETWORK_POLICY;
  let additionalCA: string[] = [];
  try {
    additionalCA = resolveAdditionalCA(access);
  } catch {
    // A `${NAME}` bundle unset on this machine: the default roots apply.
  }
  return {
    ...DEFAULT_NETWORK_POLICY,
    inheritProxyEnvironment: access.network.proxy.inheritEnvironment,
    additionalCA,
  };
}

export interface SearchToolDownloadOptions {
  /** Replaces the managed fetch (tests). */
  readonly fetch?: (url: URL, init: RequestInit) => Promise<Response>;
  /** Receives a short line before each download. */
  readonly progress?: (step: string) => void;
  readonly env?: NodeJS.ProcessEnv;
}

/**
 * GET an upstream archive. Redirects are followed only over https to
 * GitHub's release asset hosts; the body is size-limited.
 */
async function download(
  url: string,
  policy: NetworkPolicy,
  options: SearchToolDownloadOptions,
): Promise<Buffer> {
  const fetcher =
    options.fetch ??
    (createManagedFetch(policy, "lock") as (
      url: URL,
      init: RequestInit,
    ) => Promise<Response>);
  const signal = AbortSignal.timeout(DOWNLOAD_TIMEOUT_MS);
  let target = new URL(url);
  for (let hop = 0; ; hop++) {
    if (target.protocol !== "https:" || !ASSET_HOSTS.has(target.hostname))
      throw new PiShipError(
        "NETWORK_DENIED",
        `Search tool download refused ${target.protocol}//${target.host}: only https to the upstream release host and its asset storage is followed`,
        { component: "lock" },
      );
    const response = await fetcher(target, { redirect: "manual", signal });
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      await response.body?.cancel().catch(() => {});
      const location = response.headers.get("location");
      if (!location || hop + 1 > MAX_REDIRECTS)
        throw new Error(
          `Search tool download of ${basename(url)} was redirected without a usable location`,
        );
      target = new URL(location, target);
      continue;
    }
    if (!response.ok)
      throw new Error(
        `Search tool download of ${basename(url)} failed with HTTP ${response.status}${response.status === 404 ? "; check that the pinned version publishes an archive for every release target" : ""}`,
      );
    const length = Number(response.headers.get("content-length") ?? 0);
    if (length > MAX_ARCHIVE_BYTES)
      throw new PiShipError(
        "INTEGRITY_FAILED",
        `${basename(url)} is larger than ${MAX_ARCHIVE_BYTES} bytes`,
        { component: "lock" },
      );
    const body = Buffer.from(await response.arrayBuffer());
    if (body.length > MAX_ARCHIVE_BYTES)
      throw new PiShipError(
        "INTEGRITY_FAILED",
        `${basename(url)} is larger than ${MAX_ARCHIVE_BYTES} bytes`,
        { component: "lock" },
      );
    return body;
  }
}

/** Write a cache entry atomically, so a killed download leaves no archive. */
function store(path: string, content: Buffer): void {
  mkdirSync(dirname(path), { recursive: true });
  const temporary = `${path}.${process.pid}.${Date.now()}.partial`;
  try {
    writeFileSync(temporary, content, { flag: "wx", mode: 0o644 });
    renameSync(temporary, path);
  } finally {
    rmSync(temporary, { force: true });
  }
}

function cachePath(asset: SearchToolAsset, env?: NodeJS.ProcessEnv): string {
  return join(searchToolCacheDirectory(env), asset.name);
}

/** The search tools the lock beside a manifest records, if it can be read. */
function recordedSearchTools(base: string): LockedSearchTools | undefined {
  try {
    return (
      JSON.parse(
        readFileSync(join(base, "piship.lock"), "utf8"),
      ) as Partial<DistributionLock>
    ).searchTools;
  } catch {
    return undefined;
  }
}

/**
 * The official asset for a locked entry. A lock whose URL is not the official
 * upstream archive for its tool, version, and target (a hand-edited lock) is
 * refused before anything is downloaded or read from the cache, so it cannot
 * fill the cache under an official archive name.
 */
function lockedAsset(
  tool: SearchTool,
  version: string,
  target: string,
  entry: LockedSearchToolTarget,
): SearchToolAsset {
  const asset = searchToolAsset(tool, version, target);
  if (entry.url !== asset.url)
    throw new PiShipError(
      "LOCK_INVALID",
      `piship.lock records ${entry.url} for ${tool} ${version} on ${target}, which is not the official upstream release archive (${asset.url})`,
      {
        component: "build",
        userAction:
          "Do not build with it; restore piship.lock or run piship lock",
      },
    );
  return asset;
}

/**
 * `piship lock`, before the lock is computed: download every archive the
 * manifest's search tools need for its release targets into the cache. A
 * cached archive is reused only when the lock beside the manifest already
 * pins it (the same official URL and digest); any other cached file is
 * downloaded again, so a file planted in the cache is never pinned.
 */
export async function downloadSearchToolArchives(
  manifestPath: string,
  options: SearchToolDownloadOptions = {},
): Promise<void> {
  const manifest = readManifest(manifestPath);
  const policy = lockNetworkPolicy(manifest.access);
  const recorded = recordedSearchTools(dirname(resolve(manifestPath)));
  for (const request of checkSearchTools(manifest))
    for (const target of request.targets) {
      const asset = searchToolAsset(request.tool, request.version, target);
      const path = cachePath(asset, options.env);
      const pinned =
        recorded?.[request.tool]?.version === request.version
          ? recorded[request.tool]?.targets?.[target]
          : undefined;
      if (
        pinned?.url === asset.url &&
        existsSync(path) &&
        sha256(readFileSync(path)) === pinned.archive
      )
        continue;
      options.progress?.(`Downloading ${asset.name}`);
      store(path, await download(asset.url, policy, options));
    }
}

/**
 * `piship build` and `piship release`, before the payload is assembled: make
 * sure the cache holds each archive the lock pins for `target`, downloading
 * it again when it is missing or differs from the lock.
 */
export async function downloadLockedSearchTools(
  lock: Pick<DistributionLock, "searchTools" | "access">,
  target: string = currentTarget(),
  options: SearchToolDownloadOptions = {},
): Promise<void> {
  const policy = lockNetworkPolicy(lock.access);
  // Every locked URL is checked before anything is fetched or read.
  const wanted = SEARCH_TOOLS.flatMap((tool) => {
    const locked = lock.searchTools?.[tool];
    const entry = locked?.targets[target];
    if (!locked || !entry) return [];
    return [
      {
        entry,
        asset: lockedAsset(tool, locked.version, target, entry),
      },
    ];
  });
  for (const { entry, asset } of wanted) {
    const path = cachePath(asset, options.env);
    if (existsSync(path) && sha256(readFileSync(path)) === entry.archive)
      continue;
    options.progress?.(`Downloading ${asset.name}`);
    const content = await download(asset.url, policy, options);
    if (sha256(content) !== entry.archive)
      throw new PiShipError(
        "INTEGRITY_FAILED",
        `${asset.name} does not match the digest piship.lock records`,
        {
          component: "build",
          userAction:
            "Do not build with it; check the upstream release, then lock again only after review",
        },
      );
    store(path, content);
  }
}

/** One target's lock entry from a cached archive. */
function lockTarget(
  tool: SearchTool,
  version: string,
  target: string,
  env?: NodeJS.ProcessEnv,
): LockedSearchToolTarget {
  const asset = searchToolAsset(tool, version, target);
  const path = cachePath(asset, env);
  if (!existsSync(path))
    throw new PiShipError(
      "LOCK_INVALID",
      `runtime.searchTools: ${asset.name} is not in the PiShip download cache (${dirname(path)})`,
      { userAction: "Run piship lock, which downloads it" },
    );
  const archive = readFileSync(path);
  const files = readSearchToolArchive(
    archive,
    asset.format,
    searchToolFileName(tool, target),
  );
  return {
    url: asset.url,
    archive: sha256(archive),
    entry: files.entry,
    binary: sha256(files.binary),
    size: files.binary.length,
  };
}

/**
 * `piship validate` and `piship lock`: the tools, versions, and targets a
 * manifest bundles, after the source gate for each archive. Empty when it
 * bundles none.
 */
export function checkSearchTools(
  manifest: Manifest,
): readonly SearchToolRequest[] {
  const wanted = requests(manifest);
  for (const { tool, version, targets } of wanted)
    for (const target of targets)
      checkSource(
        tool,
        version,
        target,
        searchToolAsset(tool, version, target).url,
        manifest.lifecycle?.release.sources,
        "Release",
      );
  return wanted;
}

/**
 * `piship lock`: the lock entries of the manifest's search tools, from the
 * archives `downloadSearchToolArchives` cached. Undefined when the manifest
 * bundles none.
 */
export function lockSearchTools(
  manifest: Manifest,
  env?: NodeJS.ProcessEnv,
): LockedSearchTools | undefined {
  const wanted = checkSearchTools(manifest);
  if (!wanted.length) return undefined;
  const output: Partial<Record<SearchTool, LockedSearchTool>> = {};
  for (const { tool, version, targets } of wanted) {
    output[tool] = {
      version,
      source: SEARCH_TOOL_SPECS[tool].source,
      targets: Object.fromEntries(
        targets.map((target) => [
          target,
          lockTarget(tool, version, target, env),
        ]),
      ),
    };
  }
  return output;
}

/**
 * The stale-lock check, offline: the recorded entry of each tool whose
 * version, source, and targets still match the manifest, with each archive
 * URL the official one. A tool that no longer matches is left out, so the
 * lock reads as stale.
 */
export function currentSearchTools(
  manifest: Manifest,
  base: string,
): LockedSearchTools | undefined {
  const wanted = requests(manifest);
  if (!wanted.length) return undefined;
  const recorded = recordedSearchTools(base);
  const output: Partial<Record<SearchTool, LockedSearchTool>> = {};
  for (const { tool, version, targets } of wanted) {
    const entry = recorded?.[tool];
    if (
      !entry ||
      entry.version !== version ||
      entry.source !== SEARCH_TOOL_SPECS[tool].source ||
      Object.keys(entry.targets ?? {}).length !== targets.length ||
      targets.some(
        (target) =>
          entry.targets[target]?.url !==
          searchToolAsset(tool, version, target).url,
      )
    )
      continue;
    output[tool] = {
      version,
      source: entry.source,
      targets: Object.fromEntries(
        targets.map((target) => [
          target,
          entry.targets[target] as LockedSearchToolTarget,
        ]),
      ),
    };
  }
  return output;
}

/**
 * `piship build`: place each locked executable for `target` in the payload's
 * `tools/` directory, with its license files under `tools/licenses/<tool>/`.
 * The cached archive and the executable must both match the lock. A tool the
 * lock pins for other targets only is not placed (the launch runs without it,
 * as for a distribution that bundles none), and is returned so the build can
 * say so.
 */
export function stageSearchTools(
  lock: Pick<DistributionLock, "searchTools">,
  payload: string,
  target: string = currentTarget(),
  env?: NodeJS.ProcessEnv,
): SearchTool[] {
  const skipped: SearchTool[] = [];
  for (const tool of SEARCH_TOOLS) {
    const locked = lock.searchTools?.[tool];
    if (!locked) continue;
    const entry = locked.targets[target];
    if (!entry) {
      skipped.push(tool);
      continue;
    }
    const asset = lockedAsset(tool, locked.version, target, entry);
    const path = cachePath(asset, env);
    const archive = existsSync(path) ? readFileSync(path) : undefined;
    if (!archive || sha256(archive) !== entry.archive)
      throw new PiShipError(
        "INTEGRITY_FAILED",
        `${asset.name} is ${archive ? "not the archive piship.lock records" : "missing from the PiShip download cache"}`,
        {
          component: "build",
          userAction:
            "Run piship build again, which downloads the pinned archive",
        },
      );
    const files = readSearchToolArchive(
      archive,
      asset.format,
      searchToolFileName(tool, target),
    );
    if (
      files.entry !== entry.entry ||
      sha256(files.binary) !== entry.binary ||
      files.binary.length !== entry.size
    )
      throw new PiShipError(
        "INTEGRITY_FAILED",
        `${tool} ${locked.version} for ${target} does not match the executable piship.lock records`,
        { component: "build" },
      );
    const directory = join(payload, SEARCH_TOOL_PAYLOAD_DIRECTORY);
    mkdirSync(join(directory, "licenses", tool), { recursive: true });
    const executable = join(directory, searchToolFileName(tool, target));
    writeFileSync(executable, files.binary, { flag: "wx", mode: 0o755 });
    if (process.platform !== "win32") chmodSync(executable, 0o755);
    for (const [name, content] of files.licenses)
      writeFileSync(join(directory, "licenses", tool, name), content, {
        flag: "wx",
      });
  }
  return skipped;
}
