#!/usr/bin/env node
// Reference sandbox service for the PiShip enterprise reference stack: an
// organization-style service that runs each caller's commands in a container
// with the caller's project bind-mounted. Configuration comes from the
// environment only; see ../README.md. No dependencies beyond Node 22 and the
// docker CLI.
import { createServer } from "node:http";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createApp } from "./src/app.mjs";
import { loadRegistry } from "./src/auth.mjs";
import { loadConfig } from "./src/config.mjs";
import { createDocker } from "./src/docker.mjs";
import { createLogger } from "./src/log.mjs";
import { Sandboxes } from "./src/sandboxes.mjs";

export { loadConfig };

/** Build the server and its dependencies from a config; `start()` listens. */
export function createSandboxServer(
  config,
  { write, env = process.env, owner } = {},
) {
  const log = createLogger(write ? { write } : {});
  const keys = loadRegistry(config.registry);
  const docker = createDocker({ command: config.docker, env });
  const sandboxes = new Sandboxes({
    config,
    docker,
    log,
    ...(owner ? { owner } : {}),
  });
  const server = createServer(createApp({ config, keys, sandboxes, log }));
  server.headersTimeout = 10_000;
  server.requestTimeout = 30_000;
  server.keepAliveTimeout = 5000;
  return {
    server,
    sandboxes,
    log,
    /**
     * Listen, then remove the previous run's sandboxes. It listens first: a
     * service that cannot have the port (another one holds it) must not have
     * removed that one's sandboxes. Resolves with the port.
     */
    async start() {
      await new Promise((resolveListen, rejectListen) => {
        server.once("error", rejectListen);
        server.listen(config.listenPort, config.listenHost, () => {
          server.off("error", rejectListen);
          resolveListen(undefined);
        });
      });
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      log("service.listening", { listen: `${config.listenHost}:${port}` });
      await sandboxes.start();
      return port;
    },
    /**
     * Stop accepting connections, remove every sandbox this instance holds
     * (a running command ends with its exit line, on a connection that is
     * still open), then close what is left.
     */
    async stop() {
      const closed = new Promise((done) => server.close(done));
      server.closeIdleConnections();
      await sandboxes.close();
      const force = setTimeout(() => server.closeAllConnections(), 1000);
      await closed;
      clearTimeout(force);
    },
  };
}

if (
  process.argv[1] &&
  fileURLToPath(import.meta.url) === resolve(process.argv[1])
) {
  let service;
  try {
    service = createSandboxServer(loadConfig(process.env));
  } catch (error) {
    process.stderr.write(`sandbox: ${error.message}\n`);
    process.exit(2);
  }
  let stopping = false;
  const stop = (code) => {
    if (stopping) return;
    stopping = true;
    service.stop().finally(() => process.exit(code));
  };
  process.on("SIGTERM", () => stop(0));
  process.on("SIGINT", () => stop(0));
  process.on("uncaughtException", (error) => {
    service.log("service.crashed", { reason: error?.code ?? "error" });
    stop(1);
  });
  // A supervisor that starts the service with SANDBOX_EXIT_ON_STDIN_END=1 and
  // a pipe for its standard input owns it: when the supervisor is gone, even
  // killed outright, the pipe closes and the service removes its sandboxes and
  // exits, instead of holding its port and its containers.
  if (process.env.SANDBOX_EXIT_ON_STDIN_END === "1") {
    process.stdin.on("end", () => stop(0));
    process.stdin.on("error", () => stop(0));
    process.stdin.resume();
  }
  service.start().catch((error) => {
    process.stderr.write(`sandbox: cannot start (${error?.code ?? "error"})\n`);
    stop(1);
  });
}
