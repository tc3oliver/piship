// Preloaded with NODE_OPTIONS=--require: copies READ_ON_EXIT_FROM to
// READ_ON_EXIT_TO when the process exits. Registered before the program's own
// exit handlers, so it sees the file as it is while the program still runs.
const { copyFileSync } = require("node:fs");

process.on("exit", () => {
  const from = process.env.READ_ON_EXIT_FROM;
  const to = process.env.READ_ON_EXIT_TO;
  if (!from || !to) return;
  try {
    copyFileSync(from, to);
  } catch {
    // The test reports the missing copy.
  }
});
