import type { AccessManifest } from "@piship/schema";
import { byKey, type Collector, compare, keys, safeUrl } from "../collector.js";
import type { AnyLock, Verdict } from "../types.js";

export function access(out: Collector, b: AnyLock, a: AnyLock): void {
  const x: AccessManifest | undefined = b.access;
  const y: AccessManifest | undefined = a.access;
  if (!x && !y) return;
  if (!x || !y) {
    out.push(
      "access",
      y ? "added" : "removed",
      "access",
      y
        ? [
            "high",
            "Adds managed identity, credential, and inference providers.",
          ]
        : [
            "high",
            "Removes managed identity, credential, and inference settings.",
          ],
    );
    return;
  }
  const provider: Verdict = [
    "high",
    "Provider mode changed; authentication and credential flow differ.",
  ];
  const endpoint: Verdict = ["medium", "Endpoint template changed."];
  out.scalar(
    "access",
    "identity mode",
    x.identity?.mode,
    y.identity?.mode,
    provider,
  );
  const xo = x.identity?.mode === "oidc" ? x.identity.oidc : undefined;
  const yo = y.identity?.mode === "oidc" ? y.identity.oidc : undefined;
  if (xo && yo) {
    out.scalar("access", "identity issuer", xo.issuer, yo.issuer, endpoint);
    out.scalar(
      "access",
      "identity clientId",
      xo.clientId,
      yo.clientId,
      endpoint,
    );
    out.scalar(
      "access",
      "identity audience",
      xo.audience,
      yo.audience,
      endpoint,
    );
    out.scalar(
      "access",
      "identity redirectUri",
      safeUrl(xo.redirectUri),
      safeUrl(yo.redirectUri),
      endpoint,
    );
    out.set(
      "access",
      "identity scope",
      xo.scopes,
      yo.scopes,
      ["medium", "Requests an additional identity scope."],
      ["low", "Requests fewer identity scopes."],
    );
  }
  // An absent httpTransport and http-allowed are the same default; only
  // https is stricter.
  const plainHttp =
    (exposed: string) =>
    (_: string, v: string): Verdict =>
      v === "http-allowed"
        ? [
            "high",
            `May be reached over plain HTTP to a private or internal host; ${exposed} unencrypted on the network path.`,
          ]
        : ["low", "Reached over https only."];
  out.transport(
    "access",
    "identity httpTransport",
    xo && { transport: xo.httpTransport, url: xo.issuer },
    yo && { transport: yo.httpTransport, url: yo.issuer },
    plainHttp("sign-in tokens, including the refresh token, are then"),
  );
  const xa = x.identity?.mode === "adapter" ? x.identity.adapter : undefined;
  const ya = y.identity?.mode === "adapter" ? y.identity.adapter : undefined;
  if (xa && ya)
    out.scalar("access", "identity adapter", xa, ya, [
      "high",
      "Identity adapter changed (executable code).",
    ]);
  out.scalar(
    "access",
    "credential provider",
    x.credential?.provider,
    y.credential?.provider,
    provider,
  );
  out.scalar(
    "access",
    "credential broker endpoint",
    safeUrl(x.credential?.broker?.endpoint),
    safeUrl(y.credential?.broker?.endpoint),
    endpoint,
  );
  out.scalar(
    "access",
    "credential revoke endpoint",
    safeUrl(x.credential?.broker?.revokeEndpoint),
    safeUrl(y.credential?.broker?.revokeEndpoint),
    endpoint,
  );
  out.transport(
    "access",
    "credential broker httpTransport",
    x.credential?.broker && {
      transport: x.credential.broker.httpTransport,
      url: x.credential.broker.endpoint,
    },
    y.credential?.broker && {
      transport: y.credential.broker.httpTransport,
      url: y.credential.broker.endpoint,
    },
    plainHttp("the identity token and the issued gateway credential are then"),
  );
  out.scalar(
    "access",
    "credential adapter",
    x.credential?.adapter,
    y.credential?.adapter,
    ["high", "Credential adapter changed (executable code)."],
  );
  out.scalar(
    "access",
    "credential storage",
    x.credential?.storage?.provider,
    y.credential?.storage?.provider,
    (_, s) =>
      s === "file"
        ? [
            "high",
            "Credentials are stored in a file instead of the system store.",
          ]
        : ["medium", "Credential storage moves to the system store."],
  );
  out.scalar(
    "access",
    "credential acknowledgePlaintext",
    x.credential?.storage?.acknowledgePlaintext,
    y.credential?.storage?.acknowledgePlaintext,
    (_, v) =>
      v === "true"
        ? ["high", "Accepts plaintext credential storage."]
        : ["medium", "No longer accepts plaintext credential storage."],
  );
  out.scalar(
    "access",
    "credential refresh",
    x.credential?.refresh?.beforeExpirySeconds,
    y.credential?.refresh?.beforeExpirySeconds,
    ["low", "Credential refresh timing changed."],
  );
  out.scalar(
    "access",
    "inference provider",
    x.inference?.provider,
    y.inference?.provider,
    provider,
  );
  out.scalar(
    "access",
    "inference baseUrl",
    safeUrl(x.inference?.baseUrl),
    safeUrl(y.inference?.baseUrl),
    endpoint,
  );
  out.transport(
    "access",
    "inference httpTransport",
    x.inference?.baseUrl === undefined
      ? undefined
      : {
          transport: x.inference.httpTransport,
          url: x.inference.baseUrl,
        },
    y.inference?.baseUrl === undefined
      ? undefined
      : {
          transport: y.inference.httpTransport,
          url: y.inference.baseUrl,
        },
    plainHttp("the gateway credential and every prompt and response are then"),
  );
  out.scalar("access", "inference api", x.inference?.api, y.inference?.api, [
    "medium",
    "Inference API dialect changed.",
  ]);
  out.scalar(
    "access",
    "inference liveCatalog",
    x.inference?.liveCatalog,
    y.inference?.liveCatalog,
    ["low", "Live model catalog setting changed."],
  );
  for (const layer of ["enforced", "defaults"] as const) {
    const bl: Record<string, string | undefined> = x.config?.[layer] ?? {};
    const al: Record<string, string | undefined> = y.config?.[layer] ?? {};
    for (const key of [
      ...new Set([...Object.keys(bl), ...Object.keys(al)]),
    ].sort(compare))
      out.scalar(
        "access",
        `config ${layer}.${key}`,
        bl[key],
        al[key],
        layer === "enforced" && al[key] === undefined
          ? ["medium", "Setting is no longer enforced."]
          : ["low", "Configuration value changed."],
      );
  }
  out.set(
    "access",
    "config userOverridable",
    x.config?.userOverridable,
    y.config?.userOverridable,
    ["medium", "Users may override an additional setting."],
    ["low", "Users may override fewer settings."],
  );
  out.set(
    "access",
    "variable",
    x.variables,
    y.variables,
    ["low", "Declares an additional runtime variable."],
    ["low", "Removes a runtime variable."],
  );

  out.set(
    "models",
    "model",
    x.models?.allowed,
    y.models?.allowed,
    ["medium", "Allows an additional model."],
    ["low", "Removes a model from the allow list."],
  );
  out.scalar("models", "default model", x.models?.default, y.models?.default, [
    "low",
    "Default model changed.",
  ]);
  const catalog = (models: AccessManifest["models"] | undefined) =>
    byKey(models?.catalog, (item) => item.id);
  const bc = catalog(x.models);
  const ac = catalog(y.models);
  for (const id of keys(bc, ac)) {
    const bm = bc.get(id);
    const am = ac.get(id);
    if (!bm || !am)
      out.push("models", bm ? "removed" : "added", `catalog ${id}`, [
        "low",
        "Model catalog entry changed.",
      ]);
    else if (JSON.stringify(bm) !== JSON.stringify(am))
      out.push("models", "changed", `catalog ${id}`, [
        "low",
        "Model catalog metadata changed.",
      ]);
  }

  out.scalar(
    "network",
    "network publicFallback",
    x.network?.publicFallback,
    y.network?.publicFallback,
    (_, v) =>
      v === "allow"
        ? ["high", "Falls back to public endpoints."]
        : ["medium", "No longer falls back to public endpoints."],
  );
  out.scalar(
    "network",
    "network privateOnly",
    x.network?.privateOnly,
    y.network?.privateOnly,
    (_, v) =>
      v === "false"
        ? ["high", "Endpoints are no longer restricted to private networks."]
        : ["medium", "Endpoints become restricted to private networks."],
  );
  out.set(
    "network",
    "network allowHost",
    x.network?.allowHosts,
    y.network?.allowHosts,
    ["high", "Allows an additional host."],
    ["medium", "Allows fewer hosts."],
  );
  out.set(
    "network",
    "network additionalCA",
    x.network?.tls?.additionalCA,
    y.network?.tls?.additionalCA,
    ["high", "Trusts an additional certificate authority."],
    ["medium", "Trusts fewer certificate authorities."],
  );
  out.scalar(
    "network",
    "network proxy.inheritEnvironment",
    x.network?.proxy?.inheritEnvironment,
    y.network?.proxy?.inheritEnvironment,
    ["medium", "Proxy selection changed."],
  );
}
