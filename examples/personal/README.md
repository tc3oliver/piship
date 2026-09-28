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

## piship/v1alpha2 personal options

`piship migrate examples/personal/piship.yaml` prints a plan that moves this manifest to `piship/v1alpha2` with the same behavior (`identity.mode: none`, `pi-native` credentials and inference); `--write` applies it. Regenerate the lock and rebuild afterwards. v1alpha1 remains accepted.

A v1alpha2 personal manifest can instead point at an OpenAI-compatible endpoint, such as a local model server, without enterprise identity:

```yaml
schema: piship/v1alpha2
# app, runtime, deployment (mode: personal), and resources as above
variables:
  - MYPI_GATEWAY_URL
identity:
  mode: none
credential:
  provider: local-secret   # or: none, for an endpoint without a key (omit storage)
  storage:
    provider: system       # or: file (owner-only plaintext, explicit opt-in)
inference:
  provider: openai-compatible
  baseUrl: ${MYPI_GATEWAY_URL}
models:
  default: local/coder
  allowed: [local/coder]
  catalog:
    local/coder:
      name: Local Coder
      contextWindow: 32000
      maxOutputTokens: 2048
```

Set `MYPI_GATEWAY_URL` (HTTPS, or `http://127.0.0.1:<port>/...` for loopback) when running the branded command. With `local-secret`, `mypi login` asks for the key and stores it in the secret store; `mypi logout` deletes it. With `none`, no key is stored. `mypi --smoke-model` sends one acceptance prompt. These modes are verified with local fixtures only; a real authenticated personal model request has not been recorded. See the [manifest reference](../../docs/manifest.md).
