#!/usr/bin/env node
// A stand-in for the docker CLI, for the service's contract test, which needs
// no Docker. It keeps its state under DOCKER_FAKE_DIR: one file per container
// (the arguments `docker run` received), and a log of every invocation with
// the env file a `docker exec` was given, read when the command started. A
// command "in a container" runs on this host with /bin/sh, in
// DOCKER_FAKE_CWD, so its output, exit, and environment are real; a cancel
// (the service's second `docker exec`) kills the process group of the command
// it names.
//
// Knobs, as files a test creates and removes under DOCKER_FAKE_DIR: DOWN fails
// every command, RUN_FAIL fails `run`.
import { spawn } from "node:child_process";
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
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
const command = args[0];

function log(entry) {
  appendFileSync(join(dir, "calls.jsonl"), `${JSON.stringify(entry)}\n`);
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
    const record = JSON.parse(readFileSync(join(dir, "execs", file), "utf8"));
    if (!matches(record)) continue;
    try {
      process.kill(-record.pid, "SIGKILL");
    } catch {
      // already gone
    }
  }
}

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
  const wanted = args[args.indexOf("--filter") + 1]?.replace(/^label=/, "");
  for (const file of readdirSync(join(dir, "containers"))) {
    const container = JSON.parse(
      readFileSync(join(dir, "containers", file), "utf8"),
    );
    if (container.labels.includes(wanted))
      process.stdout.write(`${container.name}\n`);
  }
} else if (command === "rm") {
  log({ command, args });
  let missing = false;
  for (const name of args.slice(1).filter((value) => !value.startsWith("--"))) {
    if (existsSync(containerFile(name))) {
      killGroups((record) => record.container === name);
      rmSync(containerFile(name));
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
  const marker = args.indexOf("piship-cancel");
  if (marker > 0) {
    // The service's cancel: kill the process group of the named command.
    const id = args[marker + 1];
    log({ command: "cancel", id });
    killGroups((record) => record.id === id);
    process.exit(0);
  }
  const envFile = flagValue("--env-file");
  const environment = {};
  for (const line of readFileSync(envFile, "utf8").split("\n"))
    if (line.includes("="))
      environment[line.slice(0, line.indexOf("="))] = line.slice(
        line.indexOf("=") + 1,
      );
  log({
    command,
    args,
    workdir: flagValue("--workdir"),
    envFile: {
      mode: (statSync(envFile).mode & 0o777).toString(8),
      variables: environment,
    },
  });
  const separator = args.indexOf("piship-exec");
  const wrapper = args[separator - 1];
  const shell = args[separator - 3];
  const child = spawn(
    shell,
    ["-c", wrapper, "piship-exec", args[separator + 1]],
    {
      cwd: process.env.DOCKER_FAKE_CWD ?? tmpdir(),
      env: { PATH: process.env.PATH, ...environment },
      stdio: ["ignore", "pipe", "pipe"],
      detached: true,
    },
  );
  writeFileSync(
    join(dir, "execs", `${environment.PISHIP_EXEC_ID}.json`),
    JSON.stringify({
      id: environment.PISHIP_EXEC_ID,
      pid: child.pid,
      container: args[separator - 4],
    }),
  );
  child.stdout.pipe(process.stdout);
  child.stderr.pipe(process.stderr);
  child.on("close", (code) => process.exit(code ?? 137));
} else {
  fail(`fake docker: unsupported command ${command}`, 125);
}
