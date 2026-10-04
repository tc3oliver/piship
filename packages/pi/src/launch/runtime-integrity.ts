// Runtime mutation governance. Pi has no veto on a change to the prompt or
// the active tool set, and emits no event for one, so PiShip re-asserts what
// it enforces from the last mutation hooks to run and refuses every later
// model request when a repair fails. v0.9 knows two classes: what is listed
// here is enforced, everything else stays mutable by any extension.
import type {
  BuildSystemPromptOptions,
  ContextWithSystemEvent,
  ExtensionAPI,
  ExtensionContext,
  InlineExtension,
  SettingsManager,
} from "@earendil-works/pi-coding-agent";
import { formatError } from "@piship/contracts";
import type {
  CacheWarmingMode,
  MutabilityClass,
  ToolExposure,
} from "@piship/schema";
import { workflowSection } from "../builtins.js";
import { widenedTools } from "../governance/exposure.js";
import type { GovernanceSession } from "../governance-session.js";

export const RUNTIME_MUTATION_REVERTED = "runtime.mutation.reverted";

export const INTEGRITY_EXTENSION = "piship-runtime-integrity";

export interface CacheWarmingSetting {
  readonly mode: CacheWarmingMode;
  /** The user's `/settings` cannot change the mode. */
  readonly enforced: boolean;
}

export interface EnforcedRuntime {
  /** Instruction files Pi renders as `project_context`, in load order. */
  readonly instructions: readonly {
    readonly id: string;
    readonly path: string;
    readonly content: string;
    /** Position among every loaded instruction file. */
    readonly index: number;
  }[];
  /** PiShip-owned prompt sections; read per run, as the workflow mode changes. */
  readonly sections: () => Readonly<Record<string, string>>;
  /** PiShip tools that stay active. */
  readonly mandatoryTools: readonly string[];
  /**
   * Tools re-registered with an exposure wider than the one resolved at
   * launch, which the session refuses to run with (managed only).
   */
  readonly widenedTools?: (
    live: readonly { name: string; exposure: ToolExposure }[],
  ) => readonly string[];
  readonly cacheWarming: CacheWarmingSetting;
}

type IntegrityGovernance = Pick<
  GovernanceSession,
  "emit" | "blockRuntime" | "notice"
>;

/**
 * The cache warming mode of a session: the locked `runtime.cacheWarming`,
 * `off` when none is declared (Pi's own default is `streaming`). A declared
 * mode is enforced unless `userOverride` allows the user's `/settings`; an
 * undeclared one is enforced for a managed distribution only.
 */
export function cacheWarmingSetting(
  gov: Pick<GovernanceSession, "options"> | null,
): CacheWarmingSetting {
  if (!gov) return { mode: "off", enforced: false };
  const declared = gov.options.lock.cacheWarming;
  return declared
    ? { mode: declared.mode, enforced: !declared.userOverride }
    : {
        mode: "off",
        enforced: gov.options.lock.deployment.mode === "managed",
      };
}

/**
 * The mutability of a loaded instruction file: distribution-owned
 * (certified or company) and every managed one are enforced. A record that
 * does not line up with the loader is enforced: fail closed.
 */
function instructionMutability(
  managed: boolean,
  resourceClass: string | undefined,
): MutabilityClass {
  return managed ||
    resourceClass === undefined ||
    resourceClass === "certified" ||
    resourceClass === "company"
    ? "enforced"
    : "mutable";
}

/**
 * What a governed session enforces: distribution-owned instructions, the
 * workflow section, `ask_user`, and the Codemode and tool search tools the
 * exposure table activates.
 */
export function enforcedRuntime(
  gov: GovernanceSession,
  workflow: Readonly<Record<string, string>> | undefined,
): EnforcedRuntime {
  const managed = gov.options.lock.deployment.mode === "managed";
  // resolveResources adds a loaded instruction to the loader in the order of
  // its record.
  const records = gov.resources.filter(
    (item) => item.kind === "instructions" && item.loaded,
  );
  const instructions = gov.loader.instructions.flatMap((item, index) => {
    const record = records[index];
    return instructionMutability(managed, record?.class) === "enforced"
      ? [
          {
            id: `instructions:${record?.path ?? item.path}`,
            path: item.path,
            content: item.content,
            index,
          },
        ]
      : [];
  });
  return {
    instructions,
    sections: () =>
      workflow ? { piship_workflow: workflowSection(gov, workflow) } : {},
    // Read per check: the exposure table is built once extensions loaded.
    get mandatoryTools() {
      const table = gov.exposure;
      // Only a tool the model calls directly is active; a Codemode or
      // deferred ask_user is reached through Codemode or tool search.
      const askUser = table?.get("ask_user") ?? "direct";
      return [
        ...(gov.loader.builtin.has("piship-ask-user") &&
        (askUser === "direct" || askUser === "model-only")
          ? ["ask_user"]
          : []),
        ...(table?.mandatoryActive() ?? []),
      ];
    },
    widenedTools: (live) =>
      managed && gov.exposure ? widenedTools(gov.exposure, live) : [],
    cacheWarming: cacheWarmingSetting(gov),
  };
}

/**
 * Turns `forceSystemPrompt` into a plain data property holding its current
 * value, so an accessor an extension installed cannot answer PiShip's check
 * with one value and Pi's request projection with another. It stays
 * writable, as Pi's own handlers assign it; it is not configurable, so no
 * accessor can be installed again.
 */
function pinForced(options: BuildSystemPromptOptions): void {
  const descriptor = Object.getOwnPropertyDescriptor(
    options,
    "forceSystemPrompt",
  );
  if (descriptor && "value" in descriptor && !descriptor.configurable) return;
  Object.defineProperty(options, "forceSystemPrompt", {
    value: options.forceSystemPrompt,
    writable: true,
    enumerable: true,
    configurable: false,
  });
}

/** Enforced text a request lost, framed as one prompt section. */
function enforcedBlock(missing: readonly string[]): string {
  return `<piship_enforced>\n${missing.join("\n\n")}\n</piship_enforced>`;
}

interface SystemLike {
  readonly role: string;
  readonly content?: string | readonly { type: string; text?: string }[];
  readonly sections?: Readonly<Record<string, string | null>>;
  readonly toolsAdded?: readonly { name: string }[];
  readonly toolsRemoved?: readonly { name: string }[];
}

/**
 * The prompt text and declared tool names after replaying every system
 * message, as pi-ai's getCurrentSystemPrompt and getCurrentTools do: later
 * content is appended, sections are patched by name (`null` removes one),
 * and tools are removed then added per message. Kept local so pi-ai is not
 * a direct dependency; the compatibility suite pins the semantics.
 */
export function replaySystem(messages: readonly unknown[]): {
  prompt: string;
  tools: Set<string>;
} {
  const content: string[] = [];
  const sections = new Map<string, string>();
  const tools = new Set<string>();
  for (const message of messages as readonly SystemLike[]) {
    if (message.role !== "system") continue;
    const text =
      typeof message.content === "string"
        ? message.content
        : (message.content ?? [])
            .filter((part) => part.type === "text")
            .map((part) => part.text ?? "")
            .join("\n");
    if (text) content.push(text);
    for (const [name, value] of Object.entries(message.sections ?? {}))
      if (value === null) sections.delete(name);
      else sections.set(name, value);
    for (const tool of message.toolsRemoved ?? []) tools.delete(tool.name);
    for (const tool of message.toolsAdded ?? []) tools.add(tool.name);
  }
  const prompt = [content.join("\n\n"), ...sections.values()]
    .filter((part) => part.length > 0)
    .join("\n\n");
  return { prompt, tools };
}

/**
 * Re-asserts the enforced prompt and tools. Must be the last extension but
 * provider-error redaction, so its result is final for each hook.
 */
export function runtimeIntegrityExtension(
  gov: IntegrityGovernance,
  enforced: EnforcedRuntime,
): InlineExtension {
  const reverted = (
    resource: string,
    repair: "restored" | "appended",
    phase: string,
  ) =>
    gov.emit(RUNTIME_MUTATION_REVERTED, {
      resource,
      detail: { repair, phase },
    });
  // Pi catches a handler's throw and only reports it, which would skip the
  // enforcement silently: a failure blocks the session instead.
  const guarded =
    <E, R>(
      phase: string,
      handler: (event: E, ctx: ExtensionContext) => R | undefined,
    ) =>
    (event: E, ctx: ExtensionContext): R | undefined => {
      try {
        return handler(event, ctx);
      } catch (error) {
        gov.blockRuntime(`runtime:${phase}`, formatError(error));
        return undefined;
      }
    };
  const texts = () => [
    ...enforced.instructions.map((item) => item.content),
    ...Object.values(enforced.sections()),
  ];
  // A forced prompt replaces every system message of the request after the
  // context transforms, so the request-time repair does not apply to it.
  // Pi reads it from the run's prompt options when it projects each request,
  // and an extension can keep that object from before_agent_start and set it
  // later: it is re-read, as Pi will, at every request.
  let runOptions: BuildSystemPromptOptions | undefined;
  // The enforced text the run's prompt carries once before_agent_start
  // restored it. Pi copies the run's options into a new object for every
  // later turn, which PiShip never sees, so what the prompt Pi renders lost
  // after the first turn cannot be repaired, only refused.
  let runRequired: readonly string[] | undefined;
  return {
    name: INTEGRITY_EXTENSION,
    factory: (pi: ExtensionAPI) => {
      /** Re-activates a mandatory tool the live set lost. */
      const restoreLive = (phase: string, also: readonly string[] = []) => {
        const live = pi.getActiveTools();
        const missing = enforced.mandatoryTools.filter(
          (name) => !live.includes(name) || also.includes(name),
        );
        if (!missing.length) return;
        pi.setActiveTools([...new Set([...live, ...missing])]);
        const after = pi.getActiveTools();
        for (const name of missing)
          if (after.includes(name)) reverted(`tool:${name}`, "restored", phase);
          else
            gov.blockRuntime(
              `tool:${name}`,
              `${phase}: the tool could not be re-activated`,
            );
      };

      /** Blocks the session when a tool was re-registered more widely. */
      const checkExposure = (phase: string) => {
        for (const name of enforced.widenedTools?.(pi.getAllTools()) ?? [])
          gov.blockRuntime(
            `tool:${name}`,
            `${phase}: the tool was re-registered with a wider exposure`,
          );
      };

      pi.on(
        "before_agent_start",
        guarded("before_agent_start", (event) => {
          const phase = "before_agent_start";
          const options = event.systemPromptOptions;
          // An accessor would answer this check and the request differently.
          pinForced(options);
          runOptions = options;
          for (const item of enforced.instructions) {
            const at = options.contextFiles.findIndex(
              (file) => file.path === item.path,
            );
            if (at >= 0 && options.contextFiles[at]?.content === item.content)
              continue;
            const file = { path: item.path, content: item.content };
            if (at >= 0) options.contextFiles[at] = file;
            else
              options.contextFiles.splice(
                Math.min(item.index, options.contextFiles.length),
                0,
                file,
              );
            reverted(item.id, "restored", phase);
          }
          // A custom section named like Pi's own replaces it when rendered.
          if (
            enforced.instructions.length &&
            options.sections.project_context !== undefined
          ) {
            delete options.sections.project_context;
            reverted("section:project_context", "restored", phase);
          }
          const sections = enforced.sections();
          for (const [name, value] of Object.entries(sections)) {
            if (options.sections[name] === value) continue;
            options.sections[name] = value;
            reverted(`section:${name}`, "restored", phase);
          }
          const required = texts();
          if (options.forceSystemPrompt !== undefined) {
            const prompt = options.forceSystemPrompt;
            const missing = required.filter((text) => !prompt.includes(text));
            if (missing.length) {
              options.forceSystemPrompt = `${prompt}\n\n${enforcedBlock(missing)}`;
              reverted("prompt:forced", "appended", phase);
            }
          }
          // An edited selectedTools wins over the live set; when nobody
          // edited it, the live set does.
          const missing = enforced.mandatoryTools.filter(
            (name) => !options.selectedTools.includes(name),
          );
          if (missing.length) {
            options.selectedTools.push(...missing);
            for (const name of missing)
              reverted(`tool:${name}`, "restored", phase);
          } else restoreLive(phase);
          const final = options.forceSystemPrompt;
          const lost =
            final === undefined
              ? enforced.instructions.some(
                  (item) =>
                    !options.contextFiles.some(
                      (file) =>
                        file.path === item.path &&
                        file.content === item.content,
                    ),
                ) ||
                Object.entries(sections).some(
                  ([name, value]) => options.sections[name] !== value,
                )
              : required.some((text) => !final.includes(text));
          if (lost)
            gov.blockRuntime("prompt", `${phase}: the prompt was not restored`);
          runRequired = required;
          if (
            enforced.mandatoryTools.some(
              (name) => !options.selectedTools.includes(name),
            )
          )
            gov.blockRuntime("tools", `${phase}: the tools were not restored`);
          checkExposure(phase);
          return undefined;
        }),
      );

      // A tool removed in the middle of a run never passes through
      // before_agent_start again: Pi re-reads the live set every turn.
      pi.on(
        "turn_end",
        guarded("turn_end", () => {
          restoreLive("turn_end");
          checkExposure("turn_end");
          return undefined;
        }),
      );

      pi.on(
        "context_with_system",
        guarded(
          "context_with_system",
          (event: ContextWithSystemEvent, ctx: ExtensionContext) => {
            const phase = "context_with_system";
            if (runOptions) pinForced(runOptions);
            const forcedPrompt = runOptions?.forceSystemPrompt;
            if (forcedPrompt !== undefined && runOptions) {
              // Pi replaces every system message with the forced text after
              // this handler. The first turn's options are the object
              // before_agent_start handed out, so it can still be repaired.
              const missing = texts().filter(
                (text) => !forcedPrompt.includes(text),
              );
              if (missing.length) {
                runOptions.forceSystemPrompt = `${forcedPrompt}\n\n${enforcedBlock(missing)}`;
                reverted("prompt:forced", "appended", phase);
              }
            }
            // ctx.getSystemPrompt() renders the live run options, the forced
            // text when the prompt is forced: what Pi sends if it is, and the
            // prompt the request's system messages were built from if not.
            if (runRequired) {
              const sent = ctx.getSystemPrompt();
              if (runRequired.some((text) => !sent.includes(text)))
                gov.blockRuntime(
                  forcedPrompt === undefined ? "prompt:live" : "prompt:forced",
                  `${phase}: the prompt Pi renders for this turn lost enforced text`,
                );
            }
            if (forcedPrompt !== undefined) return undefined;
            const messages = event.messages;
            // The first system message is not always at index 0: a session
            // that began with entries appended outside a prompt gets its
            // prompt later in the transcript.
            const at = messages.findIndex(
              (message) => (message as SystemLike).role === "system",
            );
            const head = messages[at] as SystemLike | undefined;
            if (!head) {
              gov.blockRuntime(
                "prompt:system",
                `${phase}: the request has no system message`,
              );
              return undefined;
            }
            const required = texts();
            const current = replaySystem(messages);
            let result: { messages: typeof messages } | undefined;
            const missing = required.filter(
              (text) => !current.prompt.includes(text),
            );
            if (missing.length) {
              const repaired = messages.slice();
              repaired[at] = {
                ...head,
                sections: {
                  ...head.sections,
                  piship_enforced: enforcedBlock(missing),
                },
              } as unknown as (typeof messages)[number];
              const prompt = replaySystem(repaired).prompt;
              if (required.some((text) => !prompt.includes(text)))
                gov.blockRuntime(
                  "prompt:system",
                  `${phase}: the prompt was not restored`,
                );
              else {
                reverted("prompt:system", "appended", phase);
                result = { messages: repaired };
              }
            }
            // A declaration without an executable tool fails the call, so the
            // tool is restored for the next turn, not declared here.
            const undeclared = enforced.mandatoryTools.filter(
              (name) => !current.tools.has(name),
            );
            if (undeclared.length) restoreLive(phase, undeclared);
            return result;
          },
        ),
      );

      // Pi drops the run's prompt options when the run settles, and its
      // projection forces only a run's prompt.
      pi.on("agent_settled", () => {
        runOptions = undefined;
        runRequired = undefined;
      });

      pi.on(
        "cache_warming_decision",
        guarded("cache_warming_decision", () =>
          enforced.cacheWarming.enforced && enforced.cacheWarming.mode === "off"
            ? { action: "stop" as const }
            : undefined,
        ),
      );
    },
  };
}

/**
 * Makes an enforced cache warming mode authoritative. Pi reads the getter on
 * every decision and `reload()` re-reads the store, so the getter is
 * replaced; the setter refuses without throwing, as the TUI's `/settings`
 * callback does not catch.
 */
export function governCacheWarming(
  settings: Pick<
    SettingsManager,
    "getCacheWarmingMode" | "setCacheWarmingMode"
  >,
  setting: CacheWarmingSetting,
  gov: IntegrityGovernance | null,
): void {
  if (!setting.enforced) return;
  settings.getCacheWarmingMode = () => setting.mode;
  settings.setCacheWarmingMode = (requested) => {
    if (requested === setting.mode) return;
    gov?.emit(RUNTIME_MUTATION_REVERTED, {
      resource: "settings.cacheWarming",
      detail: { repair: "refused", requested },
    });
    gov?.notice(`Cache warming is set by the distribution (${setting.mode}).`);
  };
}

/**
 * PiShip's inline extensions in load order. Integrity runs after every
 * other inline handler; provider-error redaction stays last, so the message
 * Pi persists is the redacted one.
 */
export function inlineExtensionOrder(
  extensions: readonly InlineExtension[],
  integrity: InlineExtension | null,
  redaction: InlineExtension,
): InlineExtension[] {
  return [...extensions, ...(integrity ? [integrity] : []), redaction];
}
