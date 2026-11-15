// The remote-workspace rows of the Sandbox group: what a session's first tool
// call would otherwise find out as an error the model sees. The in-sandbox
// checks run on the sandbox doctor's own governed session already created, and
// change nothing in it.
import type { ActiveSandbox } from "@piship/sandbox";
import { ARCHIVE, MARKER } from "../remote-workspace/seed.js";
import type { DoctorSection } from "./report.js";

export interface RemoteWorkspaceProbe {
  /** The file API answered a `stat` of the project directory. */
  readonly files: boolean;
  readonly tar: boolean;
  readonly git: boolean;
  /** `marker`: only what an unfinished PiShip seed leaves. */
  readonly directory: "empty" | "marker" | "not-empty" | "unknown";
  /** Why a check could not run. */
  readonly error?: string;
}

export interface RemoteWorkspaceData {
  /** Absent when no governed session opened, so no sandbox was reachable. */
  readonly probe?: RemoteWorkspaceProbe;
  /** The network mode the sandbox was created with. */
  readonly network?: string;
  /** Unapplied sandbox changes for this project, or undefined when the project is unknown. */
  readonly waiting?: { files: number; patches: number; latest: string };
  readonly command: string;
}

const escapeDots = (name: string) => name.replaceAll(".", "\\.");
const SCRIPT = [
  "for t in tar git; do if command -v $t >/dev/null 2>&1; then echo piship-have:$t; else echo piship-missing:$t; fi; done",
  `other=$(ls -A | grep -v -e '^${escapeDots(ARCHIVE)}$' -e '^${escapeDots(MARKER)}$')`,
  `if [ -n "$other" ]; then echo piship-dir:not-empty; elif [ -e ${MARKER} ] || [ -e ${ARCHIVE} ]; then echo piship-dir:marker; else echo piship-dir:empty; fi`,
].join("\n");

/** Look at a freshly activated remote-workspace sandbox without changing it. */
export async function probeRemoteWorkspace(
  sandbox: Pick<ActiveSandbox, "exec" | "files">,
  root: string,
): Promise<RemoteWorkspaceProbe> {
  const unknown = {
    files: false,
    tar: false,
    git: false,
    directory: "unknown",
  } as const;
  if (!sandbox.files) return { ...unknown, error: "no file API" };
  try {
    await sandbox.files.stat(root, { signal: AbortSignal.timeout(30_000) });
  } catch (error) {
    return { ...unknown, error: `the file API failed: ${String(error)}` };
  }
  let output = "";
  try {
    const result = await sandbox.exec(SCRIPT, root, {
      onData: (chunk) => {
        output += chunk.toString("utf8");
      },
      timeout: 30,
    });
    if (result.exitCode !== 0)
      return {
        ...unknown,
        files: true,
        error: `a command in the sandbox failed (exit ${result.exitCode})`,
      };
  } catch (error) {
    return {
      ...unknown,
      files: true,
      error: `a command in the sandbox failed: ${String(error)}`,
    };
  }
  const dir = /piship-dir:(empty|marker|not-empty)/.exec(output)?.[1];
  return {
    files: true,
    tar: output.includes("piship-have:tar"),
    git: output.includes("piship-have:git"),
    directory:
      (dir as RemoteWorkspaceProbe["directory"] | undefined) ?? "unknown",
  };
}

export function remoteWorkspaceLines(
  data: RemoteWorkspaceData,
  out: DoctorSection,
): void {
  const { probe } = data;
  if (!probe)
    out.warn(
      "remote workspace",
      "not checked: no sandbox session could be opened (see the errors above)",
    );
  else if (probe.error && !probe.files)
    out.bad(
      "remote file API",
      `${probe.error}; use a sandbox backend that exposes read, write and stat`,
    );
  else {
    out.ok("remote file API", "the backend exposes read, write and stat");
    if (probe.error) out.warn("remote tools", `not checked: ${probe.error}`);
    else {
      for (const tool of ["tar", "git"] as const)
        if (probe[tool])
          out.ok(`remote ${tool}`, `${tool} found in the sandbox`);
        else
          out.bad(
            `remote ${tool}`,
            `${tool} is not in the sandbox; use a template that includes it`,
          );
      if (probe.directory === "empty")
        out.ok("remote directory", "the project directory is empty");
      else if (probe.directory === "marker")
        out.info(
          "remote directory",
          "holds only an unfinished PiShip seed; the next session cleans it",
        );
      else if (probe.directory === "not-empty")
        out.bad(
          "remote directory",
          "the project directory is not empty (the template fills it), so the seed would refuse it; leave sandbox.workdir unset or point it at a new directory",
        );
      else out.warn("remote directory", "could not be checked");
    }
  }
  if (data.network)
    out.info(
      "remote network",
      data.network === "allow"
        ? "outbound allowed: dependencies can be installed at run time"
        : "outbound denied: dependencies must already be in the template, outside the project directory; an install in the sandbox fails",
    );
  const { waiting } = data;
  if (!waiting)
    out.info("waiting patch", "not checked: the project is not known");
  else if (waiting.patches === 0) out.ok("waiting patch", "none");
  else
    out.warn(
      "waiting patch",
      `${waiting.files} ${waiting.files === 1 ? "file" : "files"} in ${waiting.patches} unapplied sandbox ${waiting.patches === 1 ? "patch" : "patches"} (latest saved ${waiting.latest.slice(0, 16).replace("T", " ")} UTC); run ${data.command} sandbox pull`,
    );
}
