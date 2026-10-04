// Registers /platform-uptime, which formats the process uptime with the
// package's one runtime dependency, so the vendored node_modules is exercised.
import ms from "ms";

export default function (pi: {
  registerCommand(
    name: string,
    command: { description: string; handler: () => Promise<void> },
  ): void;
}) {
  pi.registerCommand("platform-uptime", {
    description: "Show how long this session's process has been running",
    handler: async () => {
      console.log(ms(Math.round(process.uptime() * 1000), { long: true }));
    },
  });
}
