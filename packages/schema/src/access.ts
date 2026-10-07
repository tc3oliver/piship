import { unknownFieldMessage } from "./suggest.js";
import {
  HTTP_TRANSPORTS,
  type HttpTransport,
  plainHttpPermitted,
  plainHttpProblem,
} from "./http-transport.js";
import {
  checkTemplate,
  checkVariableName,
  hasRuntimeReference,
} from "./variables.js";

export type DeploymentMode = "personal" | "managed";

export type IdentityConfig =
  | { readonly mode: "none" }
  | {
      readonly mode: "oidc";
      readonly oidc: {
        readonly issuer: string;
        readonly clientId: string;
        readonly flow: "authorization_code_pkce";
        readonly scopes: readonly string[];
        readonly audience?: string;
        readonly redirectUri: string;
        /**
         * piship/v1alpha6: `https` forces HTTPS-only for the issuer and every
         * endpoint its discovery document names; absent or `http-allowed`
         * also permits plain HTTP to a private or internal host.
         */
        readonly httpTransport?: HttpTransport;
      };
    }
  | { readonly mode: "adapter"; readonly adapter: string };

export type CredentialProviderName =
  | "http-broker"
  | "local-secret"
  | "pi-native"
  | "none"
  | "adapter";

export interface CredentialConfig {
  readonly provider: CredentialProviderName;
  readonly broker?: {
    readonly endpoint: string;
    readonly revokeEndpoint?: string;
    /**
     * piship/v1alpha6: `https` forces HTTPS-only for `endpoint` and
     * `revokeEndpoint`; absent or `http-allowed` also permits plain HTTP to
     * a private or internal host.
     */
    readonly httpTransport?: HttpTransport;
  };
  readonly adapter?: string;
  readonly storage: {
    readonly provider: "system" | "file";
    readonly acknowledgePlaintext: boolean;
  };
  readonly refresh: { readonly beforeExpirySeconds: number };
}

export interface InferenceConfig {
  readonly provider: "openai-compatible" | "pi-native";
  readonly baseUrl?: string;
  readonly api?: "openai-completions" | "openai-responses";
  readonly liveCatalog: boolean;
  /**
   * piship/v1alpha6: `https` forces HTTPS-only for `baseUrl`; absent or
   * `http-allowed` also permits plain HTTP to a private or internal host.
   */
  readonly httpTransport?: HttpTransport;
}

/** Pi model types; Pi has no `embedding` type. */
export const MODEL_TYPES = ["chat", "classifier", "image"] as const;
export type ModelType = (typeof MODEL_TYPES)[number];

/**
 * A virtual model: an extension routes each request to one of a closed set
 * of physical models.
 */
export interface VirtualModelConfig {
  /**
   * The declared extension that registers the virtual model: its `./` path,
   * the `id` of a certified extension, or `package:<id>` for a Pi package.
   * The lock resolves it to a built path.
   */
  readonly router: string;
  /**
   * The physical catalog entries it may route to: bare ids in managed
   * (`openai-compatible`) mode, `provider/id` with pi-native inference.
   */
  readonly routes: readonly string[];
}

/** Model output modalities (image models). */
export const MODEL_OUTPUTS = ["text", "image"] as const;
export type ModelOutput = (typeof MODEL_OUTPUTS)[number];

export interface CatalogModel {
  readonly id: string;
  readonly name: string;
  readonly contextWindow: number;
  readonly maxOutputTokens: number;
  readonly input: readonly ("text" | "image")[];
  readonly reasoning: boolean;
  readonly tools: boolean;
  readonly streaming: boolean;
  /** Present only when declared; absent means unknown. */
  readonly structuredOutput?: boolean;
  readonly policyTags: readonly string[];
  /** piship/v1alpha6: the Pi model type (default `chat`). */
  readonly type?: ModelType;
  /**
   * piship/v1alpha6: the Pi API for this model; required for `classifier`
   * and `image` models, whose API differs from the provider's chat API.
   */
  readonly api?: string;
  /** piship/v1alpha6: output modalities; required for `image` models. */
  readonly output?: readonly ModelOutput[];
  /** piship/v1alpha6: present for a virtual model. */
  readonly virtual?: VirtualModelConfig;
}

export interface ModelsConfig {
  readonly default?: string;
  readonly allowed: readonly string[];
  readonly catalog: readonly CatalogModel[];
}

export const CONFIG_KEYS = ["model", "theme", "thinkingLevel"] as const;
export type ConfigKey = (typeof CONFIG_KEYS)[number];
export const THINKING_LEVELS = [
  "off",
  "minimal",
  "low",
  "medium",
  "high",
  "xhigh",
] as const;

/** Fields a user preference can never set, in any mode. */
export const SECURITY_SENSITIVE_KEYS = [
  "identity",
  "credential",
  "inference",
  "network",
  "models.allowed",
  "models.catalog",
  "variables",
] as const;

export interface ConfigLayers {
  readonly enforced: Readonly<Partial<Record<ConfigKey, string>>>;
  readonly defaults: Readonly<Partial<Record<ConfigKey, string>>>;
  readonly userOverridable: readonly ConfigKey[];
}

export interface NetworkConfig {
  readonly proxy: { readonly inheritEnvironment: boolean };
  readonly tls: { readonly additionalCA: readonly string[] };
  readonly publicFallback: "deny" | "allow";
  readonly privateOnly: boolean;
  readonly allowHosts: readonly string[];
}

export interface AccessManifest {
  readonly identity: IdentityConfig;
  readonly credential: CredentialConfig;
  readonly inference: InferenceConfig;
  readonly models: ModelsConfig;
  readonly config: ConfigLayers;
  readonly network: NetworkConfig;
  readonly variables: readonly string[];
}

export class AccessFieldError extends Error {
  /** Further problems found beside this one in the same pass. */
  more: readonly AccessFieldError[] = [];
  constructor(
    readonly kind: "invalid field" | "unsafe path/name" | "conflict",
    readonly field: string,
    message: string,
  ) {
    super(message);
    this.name = "AccessFieldError";
  }
}
/**
 * Fail on the unknown keys of a record, all of them in one error: the first
 * is the error, the rest ride in `more`. Each carries a suggestion.
 */
export function failUnknown(
  path: string,
  unknown: readonly string[],
  allowed: readonly string[],
  secrets?: RegExp,
): never {
  const errors = unknown.map(
    (key) =>
      new AccessFieldError(
        "invalid field",
        `${path}.${key}`,
        secrets?.test(key)
          ? "Secrets are never declared in piship.yaml"
          : unknownFieldMessage(key, allowed),
      ),
  );
  const [first] = errors;
  if (!first) throw new Error("failUnknown needs an unknown key");
  first.more = errors.slice(1);
  throw first;
}

type Json = Record<string, unknown>;
function fail(field: string, message: string): never {
  throw new AccessFieldError("invalid field", field, message);
}
function conflict(field: string, message: string): never {
  throw new AccessFieldError("conflict", field, message);
}
function isRecord(value: unknown): value is Json {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function record(
  value: unknown,
  path: string,
  allowed: readonly string[],
): Json {
  if (!isRecord(value)) fail(path, "Expected an object");
  const unknown = Object.keys(value).filter((key) => !allowed.includes(key));
  if (unknown.length) failUnknown(path, unknown, allowed);
  return value;
}
function plainString(value: unknown, path: string): string {
  if (typeof value !== "string" || value.trim() === "")
    fail(path, "Expected a non-empty string");
  if (hasRuntimeReference(value))
    fail(path, "Runtime references are not allowed in this field");
  if (
    [...value].some((character) => {
      const code = character.charCodeAt(0);
      return code < 32 || code === 127;
    })
  )
    fail(path, "Control characters are not allowed");
  return value;
}
function referenceString(
  value: unknown,
  path: string,
  variables: readonly string[],
  kind: "url" | "id" | "path",
  /** Whether the endpoint permits plain HTTP to a private host; see checkUrl. */
  plainHttp = false,
): string {
  if (typeof value !== "string" || value.trim() === "")
    fail(path, "Expected a non-empty string");
  if (hasRuntimeReference(value) || value.includes("$")) {
    const problem = checkTemplate(value, variables);
    if (problem) fail(path, problem.message);
    return value;
  }
  const text = plainString(value, path);
  if (kind === "url") checkUrl(text, path, plainHttp);
  return text;
}
/** Endpoint URL fields that have an `httpTransport` beside them. */
const PLAIN_HTTP_ENDPOINT =
  /^(?:identity\.oidc\.issuer|credential\.broker\.(?:endpoint|revokeEndpoint)|inference\.baseUrl|audit\.sinks\[\d+\]\.url|sandbox\.(?:endpoint|router)|mcp\.servers\.[^.]+\.url)$/;
/**
 * An endpoint URL: https, or plain HTTP to loopback. With `plainHttp` (an
 * endpoint whose `httpTransport` is not `https`) plain HTTP to a private or
 * internal host is accepted too, and to a public host refused. Only the URL
 * text is judged, never DNS.
 */
export function checkUrl(value: string, path: string, plainHttp = false): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    fail(path, "Expected an absolute URL");
  }
  if (url.username || url.password)
    fail(path, "URLs must not embed credentials");
  if (url.search || url.hash)
    fail(path, "URLs must not contain query strings or fragments");
  if (plainHttp && url.protocol === "http:") {
    const problem = plainHttpProblem(url);
    if (problem) fail(path, problem);
    return url;
  }
  const loopback = /^(localhost|127(?:\.\d{1,3}){3}|\[::1\])$/.test(
    url.hostname,
  );
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
    // An endpoint that would take plain HTTP to this host but is https-only.
    const strict =
      url.protocol === "http:" &&
      PLAIN_HTTP_ENDPOINT.test(path) &&
      !plainHttpProblem(url)
        ? `; this endpoint is https-only (${path.replace(/\.[^.]+$/, ".httpTransport")}: https, or a runtime credential)`
        : "";
    fail(
      path,
      `Use https; plain http is accepted only for loopback fixtures${strict}`,
    );
  }
  return url;
}
function bool(value: unknown, path: string, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  if (typeof value !== "boolean") fail(path, "Expected true or false");
  return value;
}
function stringList(
  value: unknown,
  path: string,
  item: (entry: unknown, path: string) => string,
): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) fail(path, "Expected a list");
  const output = value.map((entry, index) => item(entry, `${path}[${index}]`));
  if (new Set(output).size !== output.length)
    fail(path, "Duplicate entries are not allowed");
  return output;
}
const MODEL_ID = /^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$/;
function modelId(value: unknown, path: string): string {
  const id = plainString(value, path);
  if (!MODEL_ID.test(id) || id.includes(".."))
    fail(path, "Model IDs use letters, digits, and . _ : / @ - separators");
  return id;
}
function tag(value: unknown, path: string): string {
  const text = plainString(value, path);
  if (!/^[a-z][a-z0-9-]{0,31}$/.test(text))
    fail(path, "Policy tags use lowercase letters, digits, and hyphens");
  return text;
}
function adapterPath(value: unknown, path: string): string {
  const item = plainString(value, path);
  const segments = item.slice(2).split("/");
  if (
    !item.startsWith("./") ||
    item.includes("\\") ||
    segments.some((segment) => !segment || segment === "." || segment === "..")
  )
    throw new AccessFieldError(
      "unsafe path/name",
      path,
      "Use a ./ relative path without traversal",
    );
  if (!/\.(?:mjs|js)$/.test(item))
    fail(path, "Adapters must be ECMAScript modules ending in .mjs or .js");
  return item;
}
/**
 * `<endpoint>.httpTransport`; absent stays absent (plain HTTP to a private
 * host is admitted) so a manifest that does not set it parses as before.
 */
function httpTransport(
  value: unknown,
  path: string,
): HttpTransport | undefined {
  if (value === undefined) return undefined;
  if (
    typeof value !== "string" ||
    !(HTTP_TRANSPORTS as readonly string[]).includes(value)
  )
    fail(path, `Expected ${HTTP_TRANSPORTS.join(", ")}`);
  return value as HttpTransport;
}
function positiveInteger(value: unknown, path: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value <= 0)
    fail(path, "Expected a positive integer");
  return value;
}
export function parseDuration(value: unknown, path: string): number {
  if (typeof value === "number" && Number.isInteger(value) && value >= 0)
    return value;
  if (typeof value !== "string") fail(path, "Expected a duration like 5m");
  const match = /^(\d{1,6})(s|m|h)$/.exec(value);
  if (!match) fail(path, "Expected a duration like 30s, 5m, or 1h");
  const amount = Number(match[1]);
  return amount * (match[2] === "h" ? 3600 : match[2] === "m" ? 60 : 1);
}

/** Parse the declared runtime variable names (`variables`). */
export function parseVariables(value: unknown): string[] {
  return stringList(value, "variables", (entry, path) => {
    const name = plainString(entry, path);
    const problem = checkVariableName(name);
    if (problem) fail(path, problem.message);
    return name;
  });
}

function parseIdentity(
  value: unknown,
  mode: DeploymentMode,
  variables: readonly string[],
  v6 = false,
): IdentityConfig {
  if (value === undefined) {
    if (mode === "managed")
      fail("identity", "Managed mode requires identity.mode oidc or adapter");
    return { mode: "none" };
  }
  const identity = record(value, "identity", ["mode", "oidc", "adapter"]);
  const kind = identity.mode;
  if (kind === "none") {
    if (identity.oidc !== undefined || identity.adapter !== undefined)
      conflict("identity", "identity.mode none cannot declare oidc or adapter");
    if (mode === "managed")
      fail("identity.mode", "Managed mode requires oidc or adapter identity");
    return { mode: "none" };
  }
  if (kind === "adapter") {
    if (identity.oidc !== undefined)
      conflict("identity", "identity.mode adapter cannot declare oidc");
    return {
      mode: "adapter",
      adapter: adapterPath(identity.adapter, "identity.adapter"),
    };
  }
  if (kind !== "oidc") fail("identity.mode", "Expected none, oidc, or adapter");
  if (identity.adapter !== undefined)
    conflict("identity", "identity.mode oidc cannot declare an adapter");
  const oidc = record(identity.oidc, "identity.oidc", [
    "issuer",
    "clientId",
    "flow",
    "scopes",
    "audience",
    "redirectUri",
    "clientSecret",
    ...(v6 ? ["httpTransport"] : []),
  ]);
  const transport = httpTransport(
    oidc.httpTransport,
    "identity.oidc.httpTransport",
  );
  if (oidc.clientSecret !== undefined)
    fail(
      "identity.oidc.clientSecret",
      "Native clients are public; an embedded client secret is not confidential and is not accepted",
    );
  const flow = oidc.flow ?? "authorization_code_pkce";
  if (flow !== "authorization_code_pkce")
    fail(
      "identity.oidc.flow",
      "Only authorization_code_pkce is supported for native managed login",
    );
  const scopes = stringList(
    oidc.scopes ?? ["openid", "profile", "email"],
    "identity.oidc.scopes",
    (entry, path) => {
      const scope = plainString(entry, path);
      if (!/^[\x21\x23-\x5b\x5d-\x7e]+$/.test(scope))
        fail(path, "Invalid OAuth scope");
      return scope;
    },
  );
  if (!scopes.includes("openid"))
    fail("identity.oidc.scopes", "OIDC login requires the openid scope");
  const redirect = plainString(oidc.redirectUri, "identity.oidc.redirectUri");
  const url = checkUrl(redirect, "identity.oidc.redirectUri");
  if (
    url.protocol !== "http:" ||
    !/^(127\.0\.0\.1|\[::1\])$/.test(url.hostname)
  )
    fail(
      "identity.oidc.redirectUri",
      "Use a registered loopback redirect such as http://127.0.0.1:8765/callback (RFC 8252)",
    );
  return {
    mode: "oidc",
    oidc: {
      issuer: referenceString(
        oidc.issuer,
        "identity.oidc.issuer",
        variables,
        "url",
        plainHttpPermitted(transport),
      ),
      clientId: referenceString(
        oidc.clientId,
        "identity.oidc.clientId",
        variables,
        "id",
      ),
      flow: "authorization_code_pkce",
      scopes,
      ...(oidc.audience === undefined
        ? {}
        : {
            audience: referenceString(
              oidc.audience,
              "identity.oidc.audience",
              variables,
              "id",
            ),
          }),
      redirectUri: redirect,
      ...(transport === undefined ? {} : { httpTransport: transport }),
    },
  };
}

function parseCredential(
  value: unknown,
  mode: DeploymentMode,
  inferenceProvider: InferenceConfig["provider"],
  identity: IdentityConfig,
  variables: readonly string[],
  v6 = false,
): CredentialConfig {
  const credential = record(
    value ?? {
      provider: inferenceProvider === "pi-native" ? "pi-native" : undefined,
    },
    "credential",
    [
      "provider",
      "broker",
      "adapter",
      "storage",
      "refresh",
      "apiKey",
      "secret",
      "token",
    ],
  );
  for (const secret of ["apiKey", "secret", "token"])
    if (credential[secret] !== undefined)
      fail(`credential.${secret}`, "Secrets are never declared in piship.yaml");
  const provider = credential.provider;
  if (
    provider !== "http-broker" &&
    provider !== "local-secret" &&
    provider !== "pi-native" &&
    provider !== "none" &&
    provider !== "adapter"
  )
    fail(
      "credential.provider",
      "Expected http-broker, local-secret, pi-native, none, or adapter",
    );
  if (
    mode === "managed" &&
    provider !== "http-broker" &&
    provider !== "adapter"
  )
    fail(
      "credential.provider",
      "Managed mode requires an organization-issued credential: http-broker or adapter",
    );
  if (provider === "http-broker" && identity.mode === "none")
    conflict(
      "credential.provider",
      "http-broker needs an identity session; configure identity or choose local-secret, pi-native, or none",
    );
  if ((provider === "pi-native") !== (inferenceProvider === "pi-native"))
    conflict(
      "credential.provider",
      "pi-native credentials and pi-native inference must be selected together",
    );
  let broker: CredentialConfig["broker"];
  if (provider === "http-broker") {
    const section = record(credential.broker, "credential.broker", [
      "endpoint",
      "revokeEndpoint",
      ...(v6 ? ["httpTransport"] : []),
    ]);
    const transport = httpTransport(
      section.httpTransport,
      "credential.broker.httpTransport",
    );
    const plainHttp = plainHttpPermitted(transport);
    broker = {
      endpoint: referenceString(
        section.endpoint,
        "credential.broker.endpoint",
        variables,
        "url",
        plainHttp,
      ),
      ...(section.revokeEndpoint === undefined
        ? {}
        : {
            revokeEndpoint: referenceString(
              section.revokeEndpoint,
              "credential.broker.revokeEndpoint",
              variables,
              "url",
              plainHttp,
            ),
          }),
      ...(transport === undefined ? {} : { httpTransport: transport }),
    };
  } else if (credential.broker !== undefined)
    conflict(
      "credential.broker",
      "broker is only valid with credential.provider http-broker",
    );
  if (provider === "adapter" && credential.adapter === undefined)
    fail(
      "credential.adapter",
      "credential.provider adapter needs an adapter path",
    );
  if (provider !== "adapter" && credential.adapter !== undefined)
    conflict(
      "credential.adapter",
      "adapter is only valid with credential.provider adapter",
    );
  const storage = record(credential.storage ?? {}, "credential.storage", [
    "provider",
    "acknowledgePlaintext",
  ]);
  const storageProvider = storage.provider ?? "system";
  if (storageProvider !== "system" && storageProvider !== "file")
    fail("credential.storage.provider", "Expected system or file");
  const acknowledgePlaintext = bool(
    storage.acknowledgePlaintext,
    "credential.storage.acknowledgePlaintext",
    false,
  );
  if (storageProvider === "file" && mode === "managed" && !acknowledgePlaintext)
    fail(
      "credential.storage.acknowledgePlaintext",
      "Managed file storage is a plaintext fallback; set acknowledgePlaintext: true to opt in explicitly",
    );
  if (
    (provider === "pi-native" || provider === "none") &&
    credential.storage !== undefined
  )
    conflict(
      "credential.storage",
      `${provider} credentials are not stored by PiShip`,
    );
  const refresh = record(credential.refresh ?? {}, "credential.refresh", [
    "beforeExpiry",
  ]);
  const beforeExpirySeconds = parseDuration(
    refresh.beforeExpiry ?? "5m",
    "credential.refresh.beforeExpiry",
  );
  return {
    provider,
    ...(broker ? { broker } : {}),
    ...(provider === "adapter"
      ? { adapter: adapterPath(credential.adapter, "credential.adapter") }
      : {}),
    storage: { provider: storageProvider, acknowledgePlaintext },
    refresh: { beforeExpirySeconds },
  };
}

function parseInference(
  value: unknown,
  mode: DeploymentMode,
  variables: readonly string[],
  v6 = false,
): InferenceConfig {
  const inference = record(value ?? { provider: "pi-native" }, "inference", [
    "provider",
    "baseUrl",
    "api",
    "liveCatalog",
    ...(v6 ? ["httpTransport"] : []),
  ]);
  const provider = inference.provider;
  if (provider !== "openai-compatible" && provider !== "pi-native")
    fail("inference.provider", "Expected openai-compatible or pi-native");
  if (mode === "managed" && provider !== "openai-compatible")
    fail(
      "inference.provider",
      "Managed mode requires an explicit openai-compatible gateway; pi-native would inherit ambient provider access",
    );
  if (provider === "pi-native") {
    for (const key of ["baseUrl", "api", "liveCatalog", "httpTransport"])
      if (inference[key] !== undefined)
        conflict(
          `inference.${key}`,
          "pi-native inference uses Pi's own provider configuration",
        );
    return { provider, liveCatalog: false };
  }
  const api = inference.api ?? "openai-completions";
  if (api !== "openai-completions" && api !== "openai-responses")
    fail("inference.api", "Expected openai-completions or openai-responses");
  const transport = httpTransport(
    inference.httpTransport,
    "inference.httpTransport",
  );
  return {
    provider,
    baseUrl: referenceString(
      inference.baseUrl,
      "inference.baseUrl",
      variables,
      "url",
      plainHttpPermitted(transport),
    ),
    api,
    liveCatalog: bool(inference.liveCatalog, "inference.liveCatalog", false),
    ...(transport === undefined ? {} : { httpTransport: transport }),
  };
}

function parseVirtualModel(value: unknown, path: string): VirtualModelConfig {
  const item = record(value, path, ["router", "routes"]);
  const routes = stringList(item.routes, `${path}.routes`, modelId);
  if (!routes.length)
    fail(
      `${path}.routes`,
      "A virtual model lists the physical models it may route to",
    );
  for (const [index, route] of routes.entries())
    if (routes.indexOf(route) !== index)
      fail(`${path}.routes[${index}]`, `Duplicate route ${route}`);
  return { router: virtualRouter(item.router, `${path}.router`), routes };
}

const ROUTER_ID = /^[a-z0-9][a-z0-9._-]{0,127}$/;
const ROUTER_PACKAGE = /^package:[a-z][a-z0-9-]{0,63}$/;

/**
 * A router reference: a `./` extension path without traversal, a certified
 * extension id, or `package:<id>`. Whether it names a declared extension is
 * checked where the extensions are resolved.
 */
function virtualRouter(value: unknown, path: string): string {
  const router = plainString(value, path);
  if (router.startsWith("./")) {
    const segments = router.slice(2).split("/");
    if (
      router.includes("\\") ||
      segments.some(
        (segment) => !segment || segment === "." || segment === "..",
      )
    )
      fail(path, "Use a ./ relative extension path without traversal");
    return router;
  }
  if (ROUTER_PACKAGE.test(router) || ROUTER_ID.test(router)) return router;
  fail(
    path,
    "Expected a declared extension: its ./ path, a certified extension id, or package:<id>",
  );
}

/** `type`, `api`, and `output` of a piship/v1alpha6 catalog entry. */
function v6TypeFields(
  item: Json,
  path: string,
): Pick<CatalogModel, "type" | "api" | "output"> {
  const type = modelType(item.type, `${path}.type`);
  if (type !== "chat" && item.api === undefined)
    fail(
      `${path}.api`,
      `A ${type} model names its Pi API; the provider's chat API does not serve it`,
    );
  if (type !== "image" && item.output !== undefined)
    fail(`${path}.output`, "output applies to image models");
  if (type === "image" && item.output === undefined)
    fail(`${path}.output`, "An image model lists its output (text, image)");
  return {
    type,
    ...(item.api === undefined
      ? {}
      : { api: plainString(item.api, `${path}.api`) }),
    ...(item.output === undefined
      ? {}
      : {
          output: stringList(item.output, `${path}.output`, (entry, at) => {
            if (entry !== "text" && entry !== "image")
              fail(at, "Expected text or image");
            return entry;
          }) as ModelOutput[],
        }),
  };
}

function modelType(value: unknown, path: string): ModelType {
  if (value === undefined) return "chat";
  if (
    typeof value !== "string" ||
    !(MODEL_TYPES as readonly string[]).includes(value)
  )
    fail(path, `Expected ${MODEL_TYPES.join(", ")}`);
  return value as ModelType;
}

/**
 * A virtual model's routes are a closed set of physical chat models it may
 * be dispatched to: each is allowed, and none is itself virtual (Pi routes
 * only to a physical model) or a classifier or image model. With an
 * openai-compatible endpoint each is a catalog entry, the only models the
 * gateway credential serves; with pi-native inference Pi's own catalog
 * serves them.
 */
function assertVirtualRoutes(
  catalog: readonly CatalogModel[],
  allowed: readonly string[],
  inference: InferenceConfig,
): void {
  const managed = inference.provider === "openai-compatible";
  for (const item of catalog) {
    if (!item.virtual) continue;
    const path = `models.catalog.${item.id}`;
    if (item.type !== "chat")
      conflict(`${path}.type`, "A virtual model is a chat model");
    if (allowed.length && !allowed.includes(item.id))
      conflict(path, `${item.id} is not in models.allowed`);
    for (const [index, route] of item.virtual.routes.entries()) {
      const at = `${path}.virtual.routes[${index}]`;
      const entry = catalog.find((candidate) => candidate.id === route);
      if (entry?.virtual)
        conflict(
          at,
          `${route} is a virtual model; a route is a physical model`,
        );
      if (entry && entry.type !== "chat")
        conflict(
          at,
          `${route} is a ${entry.type} model; a route is a chat model`,
        );
      if (managed && !entry)
        conflict(at, `${route} has no models.catalog metadata`);
      if (!managed && !/^[^/]+\/.+$/.test(route))
        fail(at, "pi-native routes use provider/model");
      if (allowed.length && !allowed.includes(route))
        conflict(at, `${route} is not in models.allowed`);
    }
  }
}

function parseModels(
  value: unknown,
  mode: DeploymentMode,
  inference: InferenceConfig,
  /** piship/v1alpha6 and later: catalog `type` and `virtual`. */
  v6 = false,
): ModelsConfig {
  const models = record(value ?? {}, "models", [
    "default",
    "allowed",
    "catalog",
  ]);
  const allowed = stringList(models.allowed, "models.allowed", modelId);
  const defaultModel =
    models.default === undefined
      ? undefined
      : modelId(models.default, "models.default");
  const catalogSource =
    models.catalog === undefined
      ? {}
      : record(
          models.catalog,
          "models.catalog",
          Object.keys(models.catalog ?? {}),
        );
  const catalog: CatalogModel[] = Object.entries(catalogSource).map(
    ([id, entry]) => {
      const path = `models.catalog.${id}`;
      modelId(id, path);
      const item = record(entry, path, [
        "name",
        "contextWindow",
        "maxOutputTokens",
        "input",
        "reasoning",
        "tools",
        "streaming",
        "structuredOutput",
        "policyTags",
        ...(v6 ? ["type", "api", "output", "virtual"] : []),
      ]);
      const input = stringList(
        item.input ?? ["text"],
        `${path}.input`,
        (entry, inputPath) => {
          if (entry !== "text" && entry !== "image")
            fail(inputPath, "Expected text or image");
          return entry;
        },
      ) as ("text" | "image")[];
      return {
        id,
        name: plainString(item.name, `${path}.name`),
        contextWindow: positiveInteger(
          item.contextWindow,
          `${path}.contextWindow`,
        ),
        maxOutputTokens: positiveInteger(
          item.maxOutputTokens,
          `${path}.maxOutputTokens`,
        ),
        input,
        reasoning: bool(item.reasoning, `${path}.reasoning`, false),
        tools: bool(item.tools, `${path}.tools`, false),
        streaming: bool(item.streaming, `${path}.streaming`, true),
        ...(item.structuredOutput === undefined
          ? {}
          : {
              structuredOutput: bool(
                item.structuredOutput,
                `${path}.structuredOutput`,
                false,
              ),
            }),
        policyTags: stringList(item.policyTags, `${path}.policyTags`, tag),
        ...(v6
          ? {
              ...v6TypeFields(item, path),
              ...(item.virtual === undefined
                ? {}
                : {
                    virtual: parseVirtualModel(item.virtual, `${path}.virtual`),
                  }),
            }
          : {}),
      };
    },
  );
  catalog.sort((a, b) => a.id.localeCompare(b.id));
  if (inference.provider === "openai-compatible") {
    if (!allowed.length)
      fail(
        "models.allowed",
        "An openai-compatible endpoint needs an explicit model allowlist",
      );
    for (const [index, id] of allowed.entries())
      if (!catalog.some((item) => item.id === id))
        fail(
          `models.allowed[${index}]`,
          `${id} has no models.catalog metadata`,
        );
    for (const item of catalog)
      if (!allowed.includes(item.id))
        conflict(
          `models.catalog.${item.id}`,
          "Catalog entries must also be allowed",
        );
    if (mode === "managed" && defaultModel === undefined)
      fail("models.default", "Managed mode requires a default model");
  } else {
    // Pi's own catalog serves physical chat models. From piship/v1alpha6 the
    // manifest may still declare virtual and non-chat (classifier, image)
    // entries, keyed `provider/id`.
    for (const item of catalog) {
      if (!v6 || (!item.virtual && item.type === "chat"))
        conflict(
          v6 ? `models.catalog.${item.id}` : "models.catalog",
          v6
            ? "pi-native inference uses Pi's model catalog for chat models; only virtual and classifier or image entries are declared"
            : "pi-native inference uses Pi's model catalog",
        );
      if (!/^[^/]+\/.+$/.test(item.id))
        fail(
          `models.catalog.${item.id}`,
          "pi-native catalog entries use provider/model",
        );
    }
    for (const [index, id] of allowed.entries())
      if (!/^[^/]+\/.+$/.test(id))
        fail(
          `models.allowed[${index}]`,
          "pi-native allowlist entries use provider/model",
        );
  }
  if (
    defaultModel !== undefined &&
    allowed.length &&
    !allowed.includes(defaultModel)
  )
    conflict("models.default", `${defaultModel} is not in models.allowed`);
  assertVirtualRoutes(catalog, allowed, inference);
  return {
    ...(defaultModel === undefined ? {} : { default: defaultModel }),
    allowed,
    catalog,
  };
}

function configValue(
  key: ConfigKey,
  value: unknown,
  path: string,
  models: ModelsConfig,
): string {
  const text = plainString(value, path);
  if (
    key === "thinkingLevel" &&
    !(THINKING_LEVELS as readonly string[]).includes(text)
  )
    fail(path, `Expected one of ${THINKING_LEVELS.join(", ")}`);
  if (key === "theme" && !/^[a-z][a-z0-9-]*$/.test(text))
    fail(path, "Theme names use lowercase letters, digits, and hyphens");
  if (key === "model") {
    modelId(text, path);
    if (models.allowed.length && !models.allowed.includes(text))
      conflict(path, `${text} is not in models.allowed`);
  }
  return text;
}

function parseConfig(value: unknown, models: ModelsConfig): ConfigLayers {
  const config = record(value ?? {}, "config", [
    "enforced",
    "defaults",
    "userOverridable",
  ]);
  const layer = (name: "enforced" | "defaults") => {
    const section = record(config[name] ?? {}, `config.${name}`, CONFIG_KEYS);
    const output: Partial<Record<ConfigKey, string>> = {};
    for (const key of CONFIG_KEYS)
      if (section[key] !== undefined)
        output[key] = configValue(
          key,
          section[key],
          `config.${name}.${key}`,
          models,
        );
    return output;
  };
  const enforced = layer("enforced");
  const defaults = layer("defaults");
  if (defaults.model !== undefined)
    conflict(
      "config.defaults.model",
      "Use models.default for the default model",
    );
  const userOverridable = stringList(
    config.userOverridable ??
      CONFIG_KEYS.filter((key) => enforced[key] === undefined),
    "config.userOverridable",
    (entry, path) => {
      const key = plainString(entry, path);
      if (!(CONFIG_KEYS as readonly string[]).includes(key)) {
        if (
          (SECURITY_SENSITIVE_KEYS as readonly string[]).some(
            (item) => key === item || key.startsWith(`${item}.`),
          )
        )
          fail(
            path,
            `${key} is security-sensitive and can never be user-overridable`,
          );
        fail(path, `Expected one of ${CONFIG_KEYS.join(", ")}`);
      }
      return key;
    },
  ) as ConfigKey[];
  for (const key of userOverridable)
    if (enforced[key] !== undefined)
      conflict(
        `config.userOverridable`,
        `${key} is enforced and cannot also be user-overridable`,
      );
  if (
    enforced.model !== undefined &&
    models.default !== undefined &&
    enforced.model !== models.default
  )
    conflict(
      "config.enforced.model",
      "The enforced model must equal models.default",
    );
  return { enforced, defaults, userOverridable };
}

function parseNetwork(
  value: unknown,
  mode: DeploymentMode,
  variables: readonly string[],
): NetworkConfig {
  const network = record(value ?? {}, "network", [
    "proxy",
    "tls",
    "publicFallback",
    "privateOnly",
    "allowHosts",
  ]);
  const proxy = record(network.proxy ?? {}, "network.proxy", [
    "inheritEnvironment",
  ]);
  const tls = record(network.tls ?? {}, "network.tls", [
    "additionalCA",
    "rejectUnauthorized",
    "insecure",
  ]);
  if (tls.rejectUnauthorized !== undefined || tls.insecure !== undefined)
    fail(
      "network.tls",
      "TLS verification cannot be disabled; declare network.tls.additionalCA instead",
    );
  const publicFallback =
    network.publicFallback ?? (mode === "managed" ? "deny" : "allow");
  if (publicFallback !== "deny" && publicFallback !== "allow")
    fail("network.publicFallback", "Expected deny or allow");
  if (mode === "managed" && publicFallback !== "deny")
    fail(
      "network.publicFallback",
      "Managed mode never falls back to public providers",
    );
  return {
    proxy: {
      inheritEnvironment: bool(
        proxy.inheritEnvironment,
        "network.proxy.inheritEnvironment",
        true,
      ),
    },
    tls: {
      additionalCA: stringList(
        tls.additionalCA,
        "network.tls.additionalCA",
        (entry, path) => referenceString(entry, path, variables, "path"),
      ),
    },
    publicFallback,
    privateOnly: bool(network.privateOnly, "network.privateOnly", false),
    allowHosts: stringList(
      network.allowHosts,
      "network.allowHosts",
      (entry, path) => {
        const host = plainString(entry, path).toLowerCase();
        if (
          !/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$|^\[::1\]$/.test(
            host,
          )
        )
          fail(path, "Expected a hostname");
        return host;
      },
    ),
  };
}

const ACCESS_KEYS = [
  "identity",
  "credential",
  "inference",
  "models",
  "config",
  "network",
  "variables",
] as const;

/**
 * Parse the v1alpha2 access sections of a manifest root. A declared variable
 * that nothing references is not an error: `launchWarnings` reports it.
 */
export function parseAccess(
  root: Json,
  mode: DeploymentMode,
  /**
   * piship/v1alpha6 and later: model catalog `type` and `virtual`, and the
   * endpoints' `httpTransport`.
   */
  options: { readonly v6?: boolean } = {},
): AccessManifest {
  const variables = parseVariables(root.variables);
  const identity = parseIdentity(root.identity, mode, variables, options.v6);
  const inference = parseInference(root.inference, mode, variables, options.v6);
  const credential = parseCredential(
    root.credential,
    mode,
    inference.provider,
    identity,
    variables,
    options.v6,
  );
  const models = parseModels(root.models, mode, inference, options.v6);
  const config = parseConfig(root.config, models);
  const network = parseNetwork(root.network, mode, variables);
  return {
    identity,
    credential,
    inference,
    models,
    config,
    network,
    variables,
  };
}

export { ACCESS_KEYS };
