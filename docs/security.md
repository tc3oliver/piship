# Security architecture

Upstream Pi runs the agent. PiShip validates distribution inputs, locks declared resources and package identities, and verifies packaged file hashes before entering Pi. A distribution's extensions are executable code with the user's process privileges. This is resource and state isolation, not an OS sandbox.

The installer owns only its receipt, installed payload, and command shim. Existing install, command, and state collisions fail by default. `uninstall` preserves `~/.piship/<id>`; `purge <id> --yes` removes that one distribution's state after uninstall. The payload is separate from mutable config, sessions, cache, logs, credential metadata, and other runtime data. There is no shared runtime cache in v0.1.

Pi receives a dedicated agent directory, user and acceptance session directories, in-memory settings, and a loader with ambient extension, skill, prompt, theme, and context discovery disabled. Only declared resources are packaged. Packaging rejects symlinks in resource roots and nested files. Project files remain accessible to Pi tools and trusted extensions; PiShip does not yet enforce project trust or tool policy.

The alpha manifest has no credential fields and rejects environment substitutions. It cannot detect every secret embedded in an otherwise allowed string. Never commit secrets in `piship.yaml` or `piship.lock`. Runtime credential files remain in per-distribution state, never in the payload. Purge removes PiShip-owned state files but cannot revoke unknown external credentials; inspect external provider settings separately.

The SHA-256 inventory detects accidental or unauthorized file changes only while the inventory itself is trusted. v0.1 does not sign artifacts, attest their origin, or provide a security boundary against a malicious local user who can rewrite both files and inventory. Signing, provenance, policy, and OS containment are later milestones. Report vulnerabilities through [SECURITY.md](../SECURITY.md).
