import { chmodSync } from "node:fs";

chmodSync(new URL("../packages/cli/dist/bin.js", import.meta.url), 0o755);
