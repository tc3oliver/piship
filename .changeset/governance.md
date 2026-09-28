---
"@piship/schema": minor
"@piship/contracts": minor
"@piship/policy": minor
"@piship/audit": minor
"@piship/sandbox": minor
"@piship/mcp": minor
"@piship/core": minor
"@piship/pi": minor
"@piship/cli": minor
---

Add a governance preview for `piship/v1alpha3`. Resources are declared by trust class with certified tree integrity, and a layered policy engine decides model use, resource loading, tool calls, file access, shell commands, and MCP server starts and tool calls, with `policy explain` showing the deciding rule and enforcement plane. Project trust classifies the workspace by git origin, and capability contracts provide builtin permissions and a Plan/Build workflow. New packages add governed MCP over stdio and Streamable HTTP, an OS sandbox for tool subprocesses and MCP stdio servers (bubblewrap on Linux, Seatbelt on macOS, fail closed where unavailable), and metadata-first audit with a documented failure matrix. `doctor`, `capabilities`, `config explain`, and `--smoke` report governance state, the lock gains `piship-lock/v1alpha3`, and `piship migrate` upgrades v1alpha1 and v1alpha2 manifests.
