import { tmpdir } from "node:os";
import { join } from "node:path";

/**
 * Where the shared file store of one test run lives, so that no test reaches
 * the user's own store. Named by the process that loads the Vitest config,
 * which is also the one that runs the global setup that removes it.
 */
export const testStoreHome = join(tmpdir(), `piship-store-${process.pid}`);
