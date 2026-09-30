#!/usr/bin/env node
// A stand-in for the docker CLI, for the service's contract test, which needs
// no Docker. It keeps its state under DOCKER_FAKE_DIR: one file per container
// (the arguments `docker run` received), and a log of every invocation with
// the environment a `docker exec` was given, read when the command started. A
// command "in a container" runs on this host with /bin/sh, in
// DOCKER_FAKE_CWD, so its output, exit, and environment are real; a cancel
// (the service's second `docker exec`) kills the process group of the command
// it names, and, in sweep mode, of every command of that container.
//
// Knobs, as files a test creates and removes under DOCKER_FAKE_DIR: DOWN fails
// every command, RUN_FAIL fails `run`, NO_MAIN makes the sandbox's main
// process unfindable, and CANCEL_DELAY (milliseconds as its content) makes a
// cancel take that long.
import { spawn } from "node:child_process";
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const dir = process.env.DOCKER_FAKE_DIR;
if (!dir) {
  process.stderr.write("DOCKER_FAKE_DIR is required\n");
  process.exit(125);
}
for (const sub of ["containers", "execs"])
  mkdirSync(join(dir, sub), { recursive: true });
const args = process.argv.slice(2);
if (args[0] === "--") args.shift();
const command = args[0];

function log(entry) {
  appendFileSync(
    join(dir, "calls.jsonl"),
    `${JSON.stringify({ t: Date.now(), ...entry })}\n`,
  );
}

function fail(message, code = 1) {
  process.stderr.write(`${message}\n`);
  process.exit(code);
}

if (existsSync(join(dir, "DOWN"))) {
  log({ command, args, down: true });
  fail("Cannot connect to the Docker daemon", 1);
}

function containerFile(name) {
  return join(dir, "containers", `${name}.json`);
}

// Every command started in a container is a process group on this host; a
// removed container takes them with it, as it would in Docker.
function killGroups(matches) {
  for (const file of readdirSync(join(dir, "execs"))) {
    if (!file.endsWith(".json")) continue;
    let record;
    try {
      record = JSON.parse(readFileSync(join(dir, "execs", file), "utf8"));
    } catch {
      // not a record (yet): never let a half-written one crash a removal
      continue;
    }
    if (!matches(record)) continue;
    try {
      process.kill(-record.pid, "SIGKILL");
    } catch {
      // already gone
    }
  }
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

if (command === "version") {
  log({ command, args });
  process.stdout.write("29.0.0-fake\n");
} else if (command === "run") {
  log({ command, args });
  if (existsSync(join(dir, "RUN_FAIL"))) fail("cannot start", 125);
  const name = args[args.indexOf("--name") + 1];
  const labels = args.flatMap((value, index) =>
    args[index - 1] === "--label" ? [value] : [],
  );
  writeFileSync(containerFile(name), JSON.stringify({ name, labels, args }));
  process.stdout.write(`${"f".repeat(64)}\n`);
} else if (command === "ps") {
  log({ command, args });
  // Every --filter label=... must hold, as Docker's filters are ANDed.
  const wanted = args.flatMap((value, index) =>
    args[index - 1] === "--filter" ? [value.replace(/^label=/, "")] : [],
  );
  for (const file of readdirSync(join(dir, "containers"))) {
    const container = JSON.parse(
      readFileSync(join(dir, "containers", file), "utf8"),
    );
    if (wanted.every((label) => container.labels.includes(label)))
      process.stdout.write(`${container.name}\n`);
  }
} else if (command === "rm") {
  log({ command, args });
  let missing = false;
  for (const name of args.slice(1).filter((value) => !value.startsWith("--"))) {
    if (existsSync(containerFile(name))) {
      killGroups((record) => record.container === name);
      rmSync(containerFile(name), { force: true });
    } else {
      missing = true;
      process.stderr.write(
        `Error response from daemon: No such container: ${name}\n`,
      );
    }
  }
  process.exit(missing ? 1 : 0);
} else if (command === "exec") {
  const flagValue = (flag) => args[args.indexOf(flag) + 1];
  const main = args.indexOf("piship-main");
  if (main > 0) {
    // The service's question at creation: which process is the sandbox's own.
    log({ command: "main" });
    if (existsSync(join(dir, "NO_MAIN"))) process.exit(1);
    process.stdout.write("4242\n");
    process.exit(0);
  }
  const marker = args.indexOf("piship-cancel");
  if (marker > 0) {
    // The service's cancel: kill the process group of the named command.
    const [id, mode, pid] = args.slice(marker + 1);
    const container = args[1];
    log({ command: "cancel", phase: "start", id, mode, main: pid });
    const delay = existsSync(join(dir, "CANCEL_DELAY"))
      ? Number(readFileSync(join(dir, "CANCEL_DELAY"), "utf8"))
      : 0;
    if (delay > 0) await sleep(delay);
    killGroups((record) =>
      mode === "sweep" ? record.container === container : record.id === id,
    );
    log({ command: "cancel", phase: "done", id, mode, main: pid });
    process.exit(0);
  }
  // The environment is on the standard input, which only `--interactive`
  // forwards to the command, as Docker does; it is read here as well, for the
  // log and the record, and given to the command whole.
  let input = "";
  for await (const chunk of process.stdin) input += chunk;
  const interactive = args.includes("--interactive");
  const environment = {};
  for (const line of input.split("\n"))
    if (line.includes("="))
      environment[line.slice(0, line.indexOf("="))] = line.slice(
        line.indexOf("=") + 1,
      );
  log({
    command,
    args,
    workdir: flagValue("--workdir"),
    environment: { interactive, variables: environment },
  });
  const separator = args.indexOf("piship-exec");
  const shell = args[separator - 3];
  const child = spawn(shell, ["-c", ...args.slice(separator - 1)], {
    cwd: process.env.DOCKER_FAKE_CWD ?? tmpdir(),
    env: { PATH: process.env.PATH },
    stdio: [interactive ? "pipe" : "ignore", "pipe", "pipe"],
    detached: true,
  });
  if (interactive) {
    child.stdin.on("error", () => undefined);
    child.stdin.end(input);
  }
  // Written whole and renamed into place: a removal or a cancel that reads the
  // records at the same moment sees this one complete, or not at all.
  const record = join(dir, "execs", `${environment.PISHIP_EXEC_ID}.json`);
  writeFileSync(
    `${record}.tmp`,
    JSON.stringify({
      id: environment.PISHIP_EXEC_ID,
      pid: child.pid,
      container: args[separator - 4],
    }),
  );
  renameSync(`${record}.tmp`, record);
  child.stdout.pipe(process.stdout);
  child.stderr.pipe(process.stderr);
  child.on("close", (code) => process.exit(code ?? 137));
} else {
  fail(`fake docker: unsupported command ${command}`, 125);
}
