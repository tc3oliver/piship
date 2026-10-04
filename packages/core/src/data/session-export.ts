// Session export governance (spec v0.9 §14). The status of each
// `session.export` resource comes from the runtime seam table in
// @piship/policy (`enforcementStatus`); `data.export.<r>` is sugar for a
// distribution-enforced rule, so the seam table's POLICY_UNENFORCEABLE check
// covers it once the sugar is expanded (`withSessionExportRules`).
//
// What this module adds is the Radius closure the `public` resource relies on
// for its Radius path. Pi's `/share` uploads to Radius only when
// `modelRuntime.getAuth("radius")` yields a token. Pi always registers the
// built-in radius provider, so the closure rests on the token: the governed
// runtime (packages/pi governance.ts) answers `getAuth` with nothing for a
// provider it does not allow. A gateway (openai-compatible) distribution
// allows only its own provider and reads no auth.json (an in-memory store, no
// models.json), so Radius is closed unless that provider's id, the
// distribution id (`app.id`), is `radius`: validation refuses that
// (RADIUS_PROVIDER_RESERVED). Pi-native allows Radius whenever the model
// allowlist is empty or lists a `radius/` model; the gist fallback of `/share`
// is unsupported either way, so `public` stays unsupported.
import {
  type EnforcementStatus,
  PiShipError,
  SESSION_EXPORT_RESOURCES,
  type SessionExportResource,
} from "@piship/contracts";
import { enforcementStatus, type PolicyContainment } from "@piship/policy";
import type {
  AccessManifest,
  DataManifest,
  PolicyConfig,
  PolicyRule,
} from "@piship/schema";

export const SESSION_EXPORT_ACTION = "session.export";

/** Pi's built-in provider id `/share` uploads through. */
export const RADIUS_PROVIDER_ID = "radius";

/** The model governance of a launch, as packages/pi `ModelGovernance` has it. */
export type ExportModelGovernance =
  | { readonly kind: "managed-endpoint"; readonly providerId: string }
  | {
      readonly kind: "pi-native";
      readonly allowedModelKeys: readonly string[];
      readonly restricted: boolean;
    };

/** The model governance a launch of this manifest or lock applies. */
export function exportModelGovernance(
  appId: string,
  access: AccessManifest | undefined,
): ExportModelGovernance {
  return access?.inference.provider === "openai-compatible"
    ? { kind: "managed-endpoint", providerId: appId }
    : {
        kind: "pi-native",
        allowedModelKeys: access?.models.allowed ?? [],
        restricted: false,
      };
}

/**
 * Whether the governed runtime would hand `/share` a Radius token, mirroring
 * packages/pi `governModelRuntime`'s `providerHasAllowed` (getAuth answers
 * nothing for a provider it does not allow).
 */
export function radiusShareReachable(
  governance: ExportModelGovernance,
): boolean {
  if (governance.kind === "managed-endpoint")
    return governance.providerId === RADIUS_PROVIDER_ID;
  const unrestricted =
    !governance.restricted && governance.allowedModelKeys.length === 0;
  return (
    unrestricted ||
    governance.allowedModelKeys.some((key) =>
      key.startsWith(`${RADIUS_PROVIDER_ID}/`),
    )
  );
}

/**
 * Refuse a gateway distribution whose provider id is `radius`: Pi's `/share`
 * would upload the session to Radius with the distribution's credential.
 */
export function assertRadiusClosed(
  appId: string,
  access: AccessManifest | undefined,
): void {
  const governance = exportModelGovernance(appId, access);
  if (
    governance.kind === "managed-endpoint" &&
    radiusShareReachable(governance)
  )
    throw new PiShipError(
      "RADIUS_PROVIDER_RESERVED",
      `A gateway distribution may not have the id ${RADIUS_PROVIDER_ID}: its model provider takes the distribution id, so Pi's /share would upload the session to Radius with the distribution's credential`,
      { component: "policy", userAction: "Choose another app.id" },
    );
}

/** The status of each `session.export` resource, from the seam table. */
export function sessionExportStatus(
  containment: PolicyContainment,
): Readonly<Record<SessionExportResource, EnforcementStatus>> {
  const result = {} as Record<SessionExportResource, EnforcementStatus>;
  for (const resource of SESSION_EXPORT_RESOURCES)
    result[resource] = enforcementStatus(
      SESSION_EXPORT_ACTION,
      containment,
      resource,
    );
  return result;
}

/**
 * `data.export.<r>` as the distribution-enforced rules it is sugar for, with
 * ids that name where they came from.
 */
export function sessionExportRules(
  exports: DataManifest["export"] | undefined,
): PolicyRule[] {
  if (!exports) return [];
  return SESSION_EXPORT_RESOURCES.flatMap((resource) => {
    const effect = exports[resource];
    return effect
      ? [
          {
            id: `data.export.${resource}`,
            action: SESSION_EXPORT_ACTION,
            resource,
            effect,
            reason: `data.export.${resource}`,
          },
        ]
      : [];
  });
}

/** The policy with `data.export` expanded into its enforced rules. */
export function withSessionExportRules<
  P extends Pick<PolicyConfig, "enforced">,
>(policy: P, data: DataManifest | undefined): P {
  const rules = sessionExportRules(data?.export);
  return rules.length
    ? { ...policy, enforced: [...policy.enforced, ...rules] }
    : policy;
}
