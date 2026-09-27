# Claude Code Instructions

Read `AGENTS.md` before making changes.

`AGENTS.md` is the canonical repository instruction file and overrides duplicated guidance elsewhere.

Additional Claude-specific rules:

- Preserve the package and Pi integration boundaries defined in `AGENTS.md`.
- Do not bypass compatibility or architecture checks.
- Do not introduce Pi private or internal imports.
- Run the repository-required validation before reporting completion.
