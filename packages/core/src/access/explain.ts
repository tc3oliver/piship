import { redact } from "@piship/contracts";
import { resolveTemplate } from "@piship/schema";
import { readPreferences, resolveEffectiveConfig } from "../config.js";
import { DistributionAccess } from "./distribution-access.js";
import { effectivePrivateOnly } from "./network.js";
import { accessStatePaths } from "./state.js";
import type { AccessOptions } from "./types.js";

export interface ExplainRow {
  readonly key: string;
  readonly value: unknown;
  readonly source: string;
  readonly overridable: boolean;
  readonly note?: string;
}

/**
 * Explain every effective value and its source without secrets. Runtime
 * references show the template and whether it currently resolves; credential
 * state shows only references, identifiers, and expiry.
 */
export async function explainConfiguration(
  options: AccessOptions,
): Promise<ExplainRow[]> {
  const access = options.access;
  const env = options.env ?? process.env;
  const rows: ExplainRow[] = [
    {
      key: "schema",
      value: access ? "piship/v1alpha2" : "piship/v1alpha1",
      source: "manifest",
      overridable: false,
    },
    {
      key: "deployment.mode",
      value: options.mode,
      source: "distribution-enforced",
      overridable: false,
    },
  ];
  const reference = (key: string, template: string | undefined) => {
    if (template === undefined) return;
    let note: string;
    let value: unknown = template;
    try {
      const resolved = resolveTemplate(
        key,
        template,
        access?.variables ?? [],
        env,
      );
      note =
        resolved === template ? "static" : `resolves at runtime to ${resolved}`;
    } catch (error) {
      note = `unresolved: ${(error as Error).message}`;
      value = template;
    }
    rows.push({
      key,
      value,
      source: "distribution-enforced",
      overridable: false,
      note,
    });
  };
  if (!access) {
    rows.push(
      {
        key: "identity.mode",
        value: "none",
        source: "builtin-default",
        overridable: false,
      },
      {
        key: "credential.provider",
        value: "pi-native",
        source: "builtin-default",
        overridable: false,
        note: "Pi auth in isolated state",
      },
      {
        key: "inference.provider",
        value: "pi-native",
        source: "builtin-default",
        overridable: false,
      },
    );
  } else {
    rows.push({
      key: "identity.mode",
      value: access.identity.mode,
      source: "distribution-enforced",
      overridable: false,
    });
    if (access.identity.mode === "oidc") {
      reference("identity.oidc.issuer", access.identity.oidc.issuer);
      reference("identity.oidc.clientId", access.identity.oidc.clientId);
      reference("identity.oidc.audience", access.identity.oidc.audience);
      rows.push(
        {
          key: "identity.oidc.flow",
          value: "authorization_code_pkce (S256)",
          source: "distribution-enforced",
          overridable: false,
        },
        {
          key: "identity.oidc.redirectUri",
          value: access.identity.oidc.redirectUri,
          source: "distribution-enforced",
          overridable: false,
        },
        {
          key: "identity.oidc.scopes",
          value: access.identity.oidc.scopes,
          source: "distribution-enforced",
          overridable: false,
        },
      );
    }
    if (access.identity.mode === "adapter")
      rows.push({
        key: "identity.adapter",
        value: access.identity.adapter,
        source: "distribution-enforced",
        overridable: false,
      });
    rows.push({
      key: "credential.provider",
      value: access.credential.provider,
      source: "distribution-enforced",
      overridable: false,
    });
    reference("credential.broker.endpoint", access.credential.broker?.endpoint);
    reference(
      "credential.broker.revokeEndpoint",
      access.credential.broker?.revokeEndpoint,
    );
    if (!["pi-native", "none"].includes(access.credential.provider))
      rows.push(
        {
          key: "credential.storage",
          value: access.credential.storage.provider,
          source: "distribution-enforced",
          overridable: false,
          ...(access.credential.storage.provider === "file"
            ? {
                note: "plaintext fallback, explicitly opted in; not equivalent to platform secure storage",
              }
            : {}),
        },
        {
          key: "credential.refresh.beforeExpiry",
          value: `${access.credential.refresh.beforeExpirySeconds}s`,
          source: "distribution-enforced",
          overridable: false,
        },
      );
    rows.push({
      key: "inference.provider",
      value: access.inference.provider,
      source: "distribution-enforced",
      overridable: false,
    });
    reference("inference.baseUrl", access.inference.baseUrl);
    if (access.models.catalog.length)
      rows.push({
        key: "models.catalog",
        value: access.models.catalog.map(
          (model) =>
            `${model.id} (${model.name}; ctx ${model.contextWindow}; tags ${model.policyTags.join("|") || "-"})`,
        ),
        source: "distribution-enforced",
        overridable: false,
      });
    rows.push(
      {
        key: "network.publicFallback",
        value: access.network.publicFallback,
        source: "distribution-enforced",
        overridable: false,
      },
      {
        key: "network.privateOnly",
        value: effectivePrivateOnly(access, options.mode),
        source: "distribution-enforced",
        overridable: false,
      },
      {
        key: "network.proxy.inheritEnvironment",
        value: access.network.proxy.inheritEnvironment,
        source: "distribution-enforced",
        overridable: false,
      },
      {
        key: "network.tls.verification",
        value: "always on",
        source: "builtin-default",
        overridable: false,
      },
    );
    for (const [index, path] of access.network.tls.additionalCA.entries())
      reference(`network.tls.additionalCA[${index}]`, path);
  }
  const paths = accessStatePaths(options.stateDir);
  let preferences: ReturnType<typeof readPreferences> = {
    schema: "piship-preferences/v1",
    values: {},
  };
  let credentialModels: readonly string[] | undefined;
  try {
    const status = await DistributionAccess.open(options).status();
    credentialModels = status.credential.metadata?.models;
    rows.push({
      key: "identity.session",
      value: status.identity
        ? {
            subject: status.identity.subject,
            issuer: status.identity.issuer,
            expiresAt: status.identity.expiresAt ?? null,
          }
        : null,
      source: "runtime-state",
      overridable: false,
    });
    rows.push({
      key: "credential.state",
      value: {
        state: status.credential.state,
        ref: status.refs?.ref ?? null,
        credentialId: status.refs?.credentialId ?? null,
        expiresAt: status.credential.metadata?.expires_at ?? null,
        store: status.store,
      },
      source: "runtime-state",
      overridable: false,
      ...(status.credential.notice ? { note: status.credential.notice } : {}),
    });
  } catch (error) {
    rows.push({
      key: "credential.state",
      value: null,
      source: "runtime-state",
      overridable: false,
      note: redact((error as Error).message),
    });
  }
  try {
    preferences = readPreferences(paths.preferences);
  } catch (error) {
    rows.push({
      key: "preferences",
      value: null,
      source: "user-preference",
      overridable: false,
      note: redact((error as Error).message),
    });
  }
  const effective = resolveEffectiveConfig(
    access,
    options.app.theme,
    preferences,
    credentialModels,
  );
  for (const entry of effective.entries) rows.push(entry);
  for (const notice of effective.notices)
    rows.push({
      key: "notice",
      value: notice,
      source: "user-preference",
      overridable: false,
    });
  return rows;
}

/** Render explanation rows for a terminal, redacted. */
export function formatExplanation(
  appName: string,
  rows: readonly ExplainRow[],
): string {
  return [
    `${appName} configuration (Distribution Enforced > Distribution Defaults > User Preferences; enforced values cannot be overridden, permitted user preferences replace defaults)`,
    ...rows.map((row) =>
      redact(
        `${row.key.padEnd(34)} ${JSON.stringify(row.value)}  [${row.source}${row.overridable ? ", user-overridable" : ""}]${row.note ? ` — ${row.note}` : ""}`,
      ),
    ),
  ].join("\n");
}
