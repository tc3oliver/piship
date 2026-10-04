// Production release builds, consumer verification, signed channels, update
// sources, and reproducibility.
export { DEFAULT_RELEASE_TARGETS } from "@piship/schema";
export {
  buildRelease,
  runPayloadCommand,
} from "./build.js";
export {
  readChannel,
  signChannel,
  type ChannelMetadata,
  type ChannelRelease,
  type SignChannelOptions,
} from "./channel.js";
export { checkLockedPackageSources } from "./sources.js";
export {
  checkPackageSources,
  checkReleaseInputs,
  piCompatibility,
  piCompatibilitySurfaces,
  releaseName,
  virtualRouteProblems,
} from "./gates.js";
export {
  CHANNEL_SCHEMA,
  RELEASE_FILES,
  RELEASE_SCHEMA,
  REPRODUCIBILITY_SCHEMA,
  VULNERABILITY_REPORT_SCHEMA,
  type BuiltRelease,
  type CommandResult,
  type ReleaseMetadata,
  type ReleaseOptions,
  type ReleaseTestResult,
  type ReleaseTestRunner,
  type SignatureAuditor,
  type SignatureReport,
  type VulnerabilityFinding,
  type VulnerabilityReport,
  type VulnerabilityScanner,
} from "./metadata.js";
export {
  compareReleases,
  listArchives,
  type ReproducibilityReport,
} from "./reproducibility.js";
export {
  evaluateSignatures,
  evaluateVulnerabilities,
  npmAuditScanner,
  npmSignatureAuditor,
} from "./scans.js";
export {
  MAX_ROOT_BYTES,
  MAX_ROOT_SIGNATURE_BYTES,
  MAX_ROOT_TRANSITIONS,
  ROOT_SCHEMA,
  hostedRootText,
  parseHostedRoot,
  refreshRoot,
  rootDigest,
  rootExpired,
  rootFileName,
  verifyRootTransition,
} from "./root.js";
export {
  bootstrapYaml,
  describeTrustRoot,
  initTrustRoot,
  nextTrustRoot,
  type TrustRootDescription,
  type TrustRootNextOptions,
  type TrustRootNextResult,
} from "./trust-root.js";
export {
  checkSourceUrl,
  checkUpdateSource,
  downloadArchive,
  readSourceFile,
} from "./source.js";
export {
  payloadStateSchemas,
  verifyRelease,
  type VerifiedRelease,
} from "./verify.js";
