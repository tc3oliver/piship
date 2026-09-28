import { afterEach, describe, expect, it, vi } from "vitest";
import { activateSandbox, describeContainment } from "./activate.js";
import type { SandboxAdapter } from "./adapter.js";
import { bubblewrapArgs } from "./bubblewrap.js";
import type { SandboxPolicy, SandboxProfile } from "./profile.js";
import { realpathNearest } from "./profile.js";
import { sbplString, seatbeltProfile } from "./seatbelt.js";
import { ADAPTER_OVERRIDE_VARIABLE, selectAdapter } from "./select.js";

const posix = process.platform !== "win32";
const tmpRoot = posix ? realpathNearest("/tmp") : "/tmp";
const sessionTmp = `${tmpRoot}/piship-sandbox-x`;

const profile = (overrides: Partial<SandboxProfile> = {}): SandboxProfile => ({
  workspace: "/work/ws",
  homeDir: "/home/u",
  tmpDir: sessionTmp,
  readDeny: [
    "/home/u/.ssh",
    "/home/u/.netrc",
    "/work/ws/.secrets",
    "/home/u/.ssh/id_rsa",
    "/missing",
  ],
  writeAllow: ["/work/ws", sessionTmp],
  readOnly: ["/opt/tools/node"],
  network: "deny",
  environmentAllow: ["PATH"],
  warnings: [],
  ...overrides,
});
const command = {
  file: "/bin/sh",
  args: ["-c", "echo hi"],
  cwd: "/work/ws",
  env: { PATH: "/usr/bin", LANG: "C" },
};
const seams = {
  exists: (path: string) => path !== "/missing",
  isDir: (path: string) => !/(\.netrc|id_rsa|docker\.sock)$/.test(path),
  escapePaths: [],
};

describe.skipIf(!posix)("bubblewrap arguments", () => {
  it("builds the full isolation plan in mount order", () => {
    const args = bubblewrapArgs(profile(), command, seams);
    expect(args).toEqual([
      "--die-with-parent",
      "--new-session",
      "--unshare-all",
      "--unshare-user",
      "--disable-userns",
      "--cap-drop",
      "ALL",
      "--ro-bind",
      "/",
      "/",
      "--dev",
      "/dev",
      "--proc",
      "/proc",
      "--tmpfs",
      tmpRoot,
      "--bind",
      "/work/ws",
      "/work/ws",
      "--bind",
      sessionTmp,
      sessionTmp,
      "--ro-bind",
      "/opt/tools/node",
      "/opt/tools/node",
      "--perms",
      "0000",
      "--tmpfs",
      "/home/u/.ssh",
      "--remount-ro",
      "/home/u/.ssh",
      "--ro-bind",
      "/dev/null",
      "/home/u/.netrc",
      "--perms",
      "0000",
      "--tmpfs",
      "/work/ws/.secrets",
      "--remount-ro",
      "/work/ws/.secrets",
      "--clearenv",
      "--setenv",
      "LANG",
      "C",
      "--setenv",
      "PATH",
      "/usr/bin",
      "--chdir",
      "/work/ws",
      "--",
      "/bin/sh",
      "-c",
      "echo hi",
    ]);
  });

  it("applies a deny nested in a writable path after that path's bind", () => {
    const args = bubblewrapArgs(profile(), command, seams);
    const bind = args.indexOf("/work/ws");
    const deny = args.indexOf("/work/ws/.secrets");
    expect(bind).toBeGreaterThan(0);
    expect(deny).toBeGreaterThan(bind);
    expect(args).not.toContain("/home/u/.ssh/id_rsa");
    expect(args).not.toContain("/missing");
  });

  it("shares the network only in allow mode", () => {
    expect(bubblewrapArgs(profile(), command, seams)).not.toContain(
      "--share-net",
    );
    expect(
      bubblewrapArgs(profile({ network: "allow" }), command, seams),
    ).toContain("--share-net");
  });

  it("keeps host /tmp when it is configured writable", () => {
    const args = bubblewrapArgs(
      profile({ writeAllow: ["/work/ws", tmpRoot] }),
      command,
      seams,
    );
    expect(args.join(" ")).not.toContain(`--tmpfs ${tmpRoot} `);
    expect(args).toContain("--bind");
  });

  it("skips denies hidden by the private /tmp", () => {
    const args = bubblewrapArgs(
      profile({ readDeny: [`${tmpRoot}/other/.ssh`, `${sessionTmp}/k`] }),
      command,
      seams,
    );
    expect(args).not.toContain(`${tmpRoot}/other/.ssh`);
    expect(args).toContain(`${sessionTmp}/k`);
  });

  it("falls back to legacy flags on older bubblewrap", () => {
    const args = bubblewrapArgs(profile(), command, {
      ...seams,
      features: { disableUserns: false, tmpfsPerms: false },
    });
    expect(args).not.toContain("--disable-userns");
    expect(args).not.toContain("--perms");
    expect(args).toContain("--remount-ro");
  });

  it("hides host escape sockets unless they are explicitly writable", () => {
    const args = bubblewrapArgs(profile(), command, {
      ...seams,
      escapePaths: ["/run/user/1000", "/work/ws/docker.sock"],
    });
    expect(args).toContain("/run/user/1000");
    expect(args).not.toContain("/work/ws/docker.sock");
  });
});

describe("seatbelt profile", () => {
  const text = seatbeltProfile(profile(), seams);
  it("denies writes except allowed subpaths and device nodes", () => {
    const denyAll = text.indexOf("(deny file-write*)");
    const allow = text.indexOf("(allow file-write*");
    expect(denyAll).toBeGreaterThan(text.indexOf("(allow default)"));
    expect(allow).toBeGreaterThan(denyAll);
    expect(text).toContain('(subpath "/work/ws")');
    expect(text).toContain('(literal "/dev/null")');
    expect(text).toContain('(regex #"^/dev/fd/[0-9]+$")');
  });
  it("denies reads last, as subpaths for directories and literals for files", () => {
    const deny = text.indexOf("(deny file-read* file-write*");
    expect(deny).toBeGreaterThan(text.indexOf("(allow file-write*"));
    expect(text).toContain('(subpath "/home/u/.ssh")');
    expect(text).toContain('(literal "/home/u/.netrc")');
    expect(text).toContain('(subpath "/work/ws/.secrets")');
    expect(text).toContain('(subpath "/missing")');
    expect(text.trimEnd().endsWith("(deny network*)")).toBe(true);
  });
  it("denies launching processes outside the sandbox through launchd", () => {
    const deny = text.indexOf("(deny lsopen)");
    expect(deny).toBeGreaterThan(text.indexOf("(allow default)"));
    expect(text).toContain("(deny appleevent-send)");
    expect(text).toContain(
      '(global-name "com.apple.coreservices.launchservicesd")',
    );
    expect(text).toContain('(global-name-regex #"^com\\.apple\\.lsd\\.")');
    expect(text).toContain(
      '(global-name "com.apple.coreservices.appleevents")',
    );
    expect(text).toContain('(deny process-exec (literal "/bin/launchctl"))');
    // Only named services are denied; tools still look up everything else.
    expect(text).not.toMatch(/\(deny mach-lookup\)/);
    expect(text).not.toContain("(deny process-exec)");
  });
  it("omits the network deny in allow mode", () => {
    expect(seatbeltProfile(profile({ network: "allow" }), seams)).not.toContain(
      "network",
    );
  });
  it("escapes strings and refuses control characters", () => {
    expect(sbplString('/a "b"\\c')).toBe('"/a \\"b\\"\\\\c"');
    expect(() => sbplString("/a\nb")).toThrow(
      expect.objectContaining({ code: "CONFIG_INVALID" }),
    );
  });
});

describe("adapter selection", () => {
  afterEach(() => vi.unstubAllEnvs());
  it("maps platforms to adapters", () => {
    expect(selectAdapter("linux", {}).id).toBe("linux-bubblewrap");
    expect(selectAdapter("darwin", {}).id).toBe("macos-seatbelt");
    expect(selectAdapter("win32", {}).id).toBe("unsupported");
    expect(selectAdapter("freebsd", {}).id).toBe("unsupported");
    expect(
      selectAdapter("linux", { [ADAPTER_OVERRIDE_VARIABLE]: "unsupported" }).id,
    ).toBe("unsupported");
  });
});

const required: SandboxPolicy = {
  required: true,
  filesystem: { read: { deny: ["~/.ssh"] }, write: { allow: ["workspace"] } },
  network: { mode: "deny" },
  environment: { allow: ["PATH"] },
};

describe("unsupported platforms fail closed", () => {
  afterEach(() => vi.unstubAllEnvs());

  it("throws SANDBOX_UNAVAILABLE on Windows when required", async () => {
    await expect(
      activateSandbox(required, {
        workspace: process.cwd(),
        platform: "win32",
      }),
    ).rejects.toMatchObject({
      code: "SANDBOX_UNAVAILABLE",
      message: expect.stringContaining("not supported on this platform"),
    });
  });

  it("throws when the unsupported adapter is forced through the environment", async () => {
    vi.stubEnv(ADAPTER_OVERRIDE_VARIABLE, "unsupported");
    await expect(
      activateSandbox(required, { workspace: process.cwd() }),
    ).rejects.toMatchObject({ code: "SANDBOX_UNAVAILABLE" });
  });

  it("reports unavailable, not enforced, when optional but requested", async () => {
    const sandbox = await activateSandbox(
      { ...required, required: false },
      { workspace: process.cwd(), platform: "win32", enable: true },
    );
    expect(sandbox.report).toMatchObject({
      level: "unavailable",
      adapter: "unsupported",
      planes: [],
    });
    expect(describeContainment(sandbox.report)).toContain("unavailable");
    sandbox.dispose();
  });

  it("reports not-required without probing", async () => {
    const sandbox = await activateSandbox(
      { ...required, required: false },
      { workspace: process.cwd(), platform: "win32" },
    );
    expect(sandbox.report.level).toBe("not-required");
    expect(describeContainment(sandbox.report)).toMatch(/^not required/);
    sandbox.dispose();
  });
});

// The probe only runs behind a native adapter (Linux, macOS).
describe.skipIf(!posix)("the live probe is not vacuous", () => {
  it("rejects an adapter that does not contain anything", async () => {
    const passthrough: SandboxAdapter = {
      id: "linux-bubblewrap",
      available: async () => ({ available: true }),
      wrap: (_profile, cmd) => ({ ...cmd, args: [...cmd.args] }),
    };
    await expect(
      activateSandbox(required, {
        workspace: process.cwd(),
        adapter: passthrough,
      }),
    ).rejects.toMatchObject({
      code: "SANDBOX_UNAVAILABLE",
      message: expect.stringContaining("a write outside the allowed paths"),
    });
  });
});
