// Network probe declarations a remote sandbox backend must not get away
// with. The host is placed in a shell command inside the sandbox, so
// anything but a bare hostname or IP address is refused, and the port must be
// a real TCP port. The sandbox conformance kit and PiShip's activation each
// validate the probe on their own; network-probe.test.ts runs this one list
// through both so they cannot drift apart.

export const MALFORMED_NETWORK_PROBES: readonly (readonly [
  name: string,
  probe: unknown,
])[] = [
  ["null", null],
  ["a string", "probe.sandbox.test:8443"],
  ["a list", ["probe.sandbox.test", 8443]],
  ["no host", { port: 8443 }],
  ["no port", { host: "probe.sandbox.test" }],
  ["a numeric host", { host: 127001, port: 8443 }],
  ["an empty host", { host: "", port: 8443 }],
  ["a host with a command", { host: "probe.sandbox.test; true", port: 8443 }],
  ["a host with a substitution", { host: "$(touch /tmp/pwned)", port: 8443 }],
  ["a host with a backtick", { host: "probe`id`", port: 8443 }],
  ["a host with a space", { host: "probe sandbox.test", port: 8443 }],
  ["a host with a newline", { host: "probe.sandbox.test\ntrue", port: 8443 }],
  [
    "a host with a trailing newline",
    { host: "probe.sandbox.test\n", port: 8443 },
  ],
  ["a host that is an option", { host: "-oProxyCommand=x", port: 8443 }],
  ["a host starting with a dot", { host: ".probe.sandbox.test", port: 8443 }],
  ["a bracketed IPv6 host", { host: "[::1]", port: 8443 }],
  ["an IPv6 host with a zone", { host: "fe80::1%en0", port: 8443 }],
  ["a host with a path", { host: "probe.sandbox.test/x", port: 8443 }],
  ["a URL as the host", { host: "http://probe.sandbox.test", port: 8443 }],
  ["a host with a user", { host: "user@probe.sandbox.test", port: 8443 }],
  ["a host with an underscore", { host: "probe_sandbox.test", port: 8443 }],
  ["a non-ASCII host", { host: "prøbe.sandbox.test", port: 8443 }],
  ["a host of 254 characters", { host: "a".repeat(254), port: 8443 }],
  ["port 0", { host: "probe.sandbox.test", port: 0 }],
  ["a negative port", { host: "probe.sandbox.test", port: -1 }],
  ["port 65536", { host: "probe.sandbox.test", port: 65536 }],
  ["a fractional port", { host: "probe.sandbox.test", port: 1.5 }],
  ["a port as a string", { host: "probe.sandbox.test", port: "8443" }],
  ["a NaN port", { host: "probe.sandbox.test", port: Number.NaN }],
  [
    "an infinite port",
    { host: "probe.sandbox.test", port: Number.POSITIVE_INFINITY },
  ],
];

/** Well-formed probes both must accept, so a refusal above is the probe's. */
export const WELL_FORMED_NETWORK_PROBES: readonly (readonly [
  name: string,
  probe: { host: string; port: number },
])[] = [
  ["a hostname", { host: "probe.sandbox.test", port: 8443 }],
  ["an IPv4 address", { host: "127.0.0.1", port: 1 }],
  ["an IPv6 address", { host: "fd00::1", port: 65535 }],
  ["a host of 253 characters", { host: "a".repeat(253), port: 443 }],
];
