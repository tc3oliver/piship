# Personal distribution example

This runnable `piship/v1alpha1` example pins Pi 0.87.1 and declares instructions, a skill, a TypeScript extension, a prompt, and a branded theme. It is a keyless runtime demonstration; live model access requires credentials managed separately in the distribution's state.

From the repository root with Node.js 22.19.0 or newer:

```bash
npm ci
npm run build
npm exec -- piship validate examples/personal/piship.yaml
npm exec -- piship lock examples/personal/piship.yaml
npm exec -- piship test examples/personal/piship.yaml
npm exec -- piship build examples/personal/piship.yaml
node dist/mypi/piship.mjs install dist/mypi
~/.local/bin/mypi --version
~/.local/bin/mypi --smoke
~/.local/bin/mypi
node dist/mypi/piship.mjs inspect mypi
node dist/mypi/piship.mjs doctor mypi
node dist/mypi/piship.mjs uninstall mypi
```

On Windows, use the installed `mypi.cmd` in the bin directory. The installed payload is independent of this checkout; installation and launch do not fetch packages. `--smoke` uses Pi's real SDK, declared TypeScript extension, read tool, and a separate persisted acceptance session without a model request. Repeating it should report the same session ID with `resumed: true`. The interactive command uses its own session directory. State defaults to `~/.piship/mypi`, separate from personal `~/.pi`. Uninstall retains that state; `node dist/mypi/piship.mjs purge mypi --yes` explicitly removes it after uninstall.
