// Verbatim from packages/core/src/release/channel.ts at the v0.13.0 tag (git show
// v0.13.0:packages/core/src/release/channel.ts): the channel validator a
// v0.13.0 client applies to signed metadata. tests exercise it against a channel
// that carries packs[]. Do not edit it; a change to the validator belongs in
// channel.ts, and this file stays as the old client.
const CHANNEL_SCHEMA = "piship-channel/v1";
type ChannelMetadata = unknown;
const SHA256 = /^[a-f0-9]{64}$/;
const VERSION =
  /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const TARGET = /^(?:linux|darwin|win32)-(?:x64|arm64)$/;
const ARCHIVE = /^[A-Za-z0-9][A-Za-z0-9._-]*\.tar\.gz$/;

export function validChannel(value: unknown): value is ChannelMetadata {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const doc = value as Record<string, unknown>;
  if (
    doc.schema !== CHANNEL_SCHEMA ||
    typeof doc.distribution !== "string" ||
    typeof doc.channel !== "string" ||
    typeof doc.expires !== "string" ||
    !Number.isSafeInteger(doc.sequence) ||
    (doc.sequence as number) < 1 ||
    !Array.isArray(doc.releases)
  )
    return false;
  return doc.releases.every((entry: unknown) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry))
      return false;
    const release = entry as Record<string, unknown>;
    return (
      typeof release.version === "string" &&
      VERSION.test(release.version) &&
      typeof release.target === "string" &&
      TARGET.test(release.target) &&
      typeof release.archive === "string" &&
      ARCHIVE.test(release.archive) &&
      typeof release.sha256 === "string" &&
      SHA256.test(release.sha256) &&
      Number.isSafeInteger(release.bytes) &&
      (release.bytes as number) > 0 &&
      typeof release.pi === "string" &&
      VERSION.test(release.pi) &&
      typeof release.piship === "string" &&
      VERSION.test(release.piship) &&
      typeof release.lockSha256 === "string" &&
      SHA256.test(release.lockSha256)
    );
  });
}
