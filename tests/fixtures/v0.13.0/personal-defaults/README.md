# personal-defaults

No released example relies on the 0.13 personal projectTrust defaults (every
personal example declares all three classes), so this pair was generated with
the v0.13.0 CLI:

1. `git archive v0.13.0 | tar -x -C <dir>`, then `npm ci && npm run build`.
2. Copy `examples/personal` (manifest and `resources/`), delete its
   `policy.projectTrust` block and the comment above `policy`.
3. In a temporary HOME with `PISHIP_INSTALL_HOME`, `PISHIP_STATE_HOME`,
   `PISHIP_BIN_HOME`, and the XDG directories pointed into it, run
   `node <dir>/packages/cli/dist/bin.js lock piship.yaml`.

Its lock records PiShip 0.13.0 and Pi 1.1.0. Do not edit or relock either file.
