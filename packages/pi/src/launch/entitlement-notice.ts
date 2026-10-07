// What to tell the user after the gateway refused a model with 403 and the
// credential's entitlement was re-read. The new list applies from the next
// launch: Pi's model registry of this session was narrowed from the list the
// launch started with.

function names(models: readonly string[]): string {
  return models.join(", ");
}

/**
 * The one line for a refused model: the change in the user's models when the
 * re-read found one (restart to pick it up), or else that the model is not
 * among them (choose another). `before` and `after` are the entitlement the
 * session started with and the one just read; either is undefined when the
 * credential carries none, which says nothing about a change.
 */
export function entitlementNotice(options: {
  readonly before: readonly string[] | undefined;
  readonly after: readonly string[] | undefined;
  readonly refused: string | undefined;
  readonly command: string;
}): string {
  const { before, after, refused, command } = options;
  if (before && after) {
    const added = after.filter((model) => !before.includes(model));
    const removed = before.filter((model) => !after.includes(model));
    if (added.length || removed.length)
      return `Your models changed (${[
        added.length ? `added: ${names(added)}` : "",
        removed.length ? `removed: ${names(removed)}` : "",
      ]
        .filter(Boolean)
        .join("; ")}). Restart ${command} to pick them up.`;
  }
  return `The gateway refused ${refused ?? "that model"}, and your model access has not changed. Choose another model with /model.`;
}
