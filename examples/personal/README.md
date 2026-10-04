# Personal distribution example

MyPi is the neutral personal reference distribution on `piship/v1alpha5`. It needs no enterprise infrastructure: no identity provider, credential broker, gateway, audit backend, or private network. It shows:

- **Isolated Pi state.** State defaults to `~/.piship/mypi` (or `$PISHIP_STATE_HOME/mypi`), separate from your personal `~/.pi`, which MyPi does not read. Pi's crash log and the `fd` and `rg` binaries it downloads go to MyPi's state too ([interactive launch](#interactive-launch)). No project instructions, skills, extensions, themes, or MCP definitions are loaded from the workspace (`policy.projectTrust` denies every dimension).
- **An exact pinned Pi**, 1.0.0.
- **Personal resources**: instructions, a skill, a TypeScript extension, a prompt, and a branded theme, all in the `user` trust class.
- **No identity and Pi-native access**: `identity.mode: none`, with `credential.provider: pi-native` and `inference.provider: pi-native`. Pi's own providers and sign-in are used, with their credentials kept in MyPi's state. The [local model variant](#local-model-variant) uses a local secret and a direct OpenAI-compatible endpoint instead.
- **A user-managed MCP server.** `mcp.mode: explicit` declares `notes`, a tiny stdio server in `resources/mcp/notes-server.mjs`. It serves two in-memory notes as `mcp__notes__list_notes` and `mcp__notes__read_note`, uses no network and no credential, and must report `serverInfo.name` `mypi-notes`.
- **Optional sandbox and no audit.** `sandbox.required: false` and `audit.enabled: false`. Set `sandbox.required: true` in a copy on Linux or macOS to contain `bash`, `!` commands, and the MCP server.
- **Signed releases, update, and rollback.** `updates` offers the `stable` and `candidate` channels and reads the channel from `${MYPI_UPDATE_SOURCE}`, which is resolved only when `update` runs. The example pins no update trust (no `updates.trust.bootstrap`), so `update` fails closed and `piship release` refuses it until you add your own key.

## Build, install, and run

From the repository root with Node.js 22.19.0 or newer:

```bash
npm ci
npm run build
node packages/cli/dist/bin.js validate examples/personal/piship.yaml
node packages/cli/dist/bin.js lock examples/personal/piship.yaml
node packages/cli/dist/bin.js test examples/personal/piship.yaml
node packages/cli/dist/bin.js build examples/personal/piship.yaml
node dist/mypi/piship.mjs install dist/mypi
~/.local/bin/mypi --version
~/.local/bin/mypi --smoke
~/.local/bin/mypi doctor
~/.local/bin/mypi capabilities
~/.local/bin/mypi
node dist/mypi/piship.mjs inspect mypi
node dist/mypi/piship.mjs uninstall mypi
```

`piship test` runs its acceptance launch against MyPi's real state directory (`~/.piship/mypi`, or `$PISHIP_STATE_HOME/mypi`), so it creates that state and marks it as created by `piship test`; the first install adopts it. Install refuses any other existing state (for example after an uninstall) unless `--use-existing-state` adopts it; without the flag it fails with `State already exists for mypi`. On Windows, use the installed `mypi.cmd` in the bin directory. The installed payload is independent of this checkout; installation and the headless commands (`--version`, `--smoke`, `doctor`, `capabilities`) do not fetch packages.

`--smoke` uses Pi's real SDK, the declared TypeScript extension, the read tool, and a separate persisted acceptance session without a model request. It reports the declared resources, `access` (`identity: null`, `pi-native` credential and inference), and a `governance` summary in which the `notes` MCP server is `healthy` with its two tools. It reports the same session ID with `resumed: true` on every run after the first, and the first `mypi --smoke` here already resumes the session that `piship test` created. `doctor` shows `mcp notes healthy (stdio; 2 tool(s))`, identity mode `none`, and the Pi-native credential as `delegated (no PiShip secret)`. The interactive command uses its own session directory; sign in to a model provider there as with plain Pi, and the credential stays in MyPi's state. Uninstall retains state; `node dist/mypi/piship.mjs purge mypi --yes` explicitly removes it after uninstall, and `node dist/mypi/piship.mjs uninstall mypi --purge --yes` does both in one command.

### Interactive launch

The interactive `mypi` is Pi's own interactive mode. PiShip sets Pi's defaults on every launch: Pi does not ask pi.dev for a newer Pi version (so there is no "Update Available ... Run `pi update`" notice, and a newer Pi comes only with a new MyPi release; MyPi pins Pi 1.0.2), sends no install report or telemetry, keeps its crash log (`crashes.json`) in MyPi's state, starts without the Pi logo, key hints, or resource listing, and leaves the terminal's own scrollback in place instead of taking over the screen. A few things stay Pi's, and PiShip does not change them:

- If `fd` or `rg` is neither on `PATH` nor in `~/.piship/mypi/agent/bin/` (or `$PISHIP_STATE_HOME/mypi/agent/bin/`), Pi downloads it from github.com into that directory. That is MyPi's state, not your `~/.pi`, so `purge` removes it and `uninstall` keeps it; each distribution downloads its own copies.
- Pi may refresh model catalogs over the network.
- On exit Pi prints "To resume this session: pi --session-dir ... --session ...", and the terminal title is "π". `mypi` continues the project's most recent session by itself, and `mypi --new-session` starts a new one.
- Pi's `/share` command uploads the session file as a GitHub gist through your own `gh` CLI.

Start it with `PI_OFFLINE=1` set to stop the download and Pi's other network requests. Pi then warns that `fd` and `rg` were not found, unless they are on `PATH`; the resume hint is still printed. Installing `fd` and `rg` on `PATH` avoids the download without going offline.

## Release, update, and rollback

The lifecycle works as for the demo company ([release](../../docs/release.md)), with nothing to sign in to. Work in a copy so the example stays unchanged:

1. Create a release key outside the repository, then add it under `updates` in the copy as `trust.bootstrap` with `version: 1`, an `expires` timestamp, the printed entry in `keys`, and its ID in both `roles.root` and `roles.channel` (threshold 1). A personal distribution may use one key for both roles ([manifest](../../docs/manifest.md#update-trust-bootstrap-v1alpha5)):

   ```bash
   cp -r examples/personal /tmp/mypi
   mkdir -p ~/mypi-keys
   node packages/cli/dist/bin.js keygen ~/mypi-keys/release.pem --id mypi-release
   ```

2. Lock, release for this machine, and install with the release's own script (`install.ps1` on Windows). The dependency scan needs registry access. `piship release` also runs the offline `--smoke` on the release. Uninstall any earlier `mypi` install first; uninstall keeps state, so pass `--use-existing-state` to adopt it:

   ```bash
   node packages/cli/dist/bin.js lock /tmp/mypi/piship.yaml
   node packages/cli/dist/bin.js release /tmp/mypi/piship.yaml
   tar -xzf dist/releases/mypi-1.0.0-<target>.tar.gz -C /tmp
   sh /tmp/mypi-1.0.0-<target>/install.sh --use-existing-state
   ```

3. Set `app.version` to `1.1.0` in the copy, lock and release again, and sign it into a channel directory:

   ```bash
   node packages/cli/dist/bin.js sign-channel /tmp/mypi-channel dist/releases/mypi-1.1.0-<target>.tar.gz \
     --channel stable --key ~/mypi-keys/release.pem --key-id mypi-release
   export MYPI_UPDATE_SOURCE=/tmp/mypi-channel
   ~/.local/bin/mypi update --check
   ~/.local/bin/mypi update      # 1.0.0 is retained; sessions are kept
   ~/.local/bin/mypi rollback    # back to 1.0.0
   ```

`<target>` is `linux-x64`, `darwin-arm64`, or `win32-x64`. `MYPI_UPDATE_SOURCE` may also be an HTTPS URL, or `http` on loopback, serving the channel directory.

## Local model variant

[`local-model/piship.yaml`](local-model/piship.yaml) is MyPi Local (`mypi-local`), a smaller personal distribution for a local OpenAI-compatible model server, such as llama.cpp, Ollama, or vLLM, with no enterprise identity:

- `credential.provider: local-secret` with `storage.provider: system`: `mypi-local login` asks for the key and keeps it in the system secret store; `logout` deletes it. Use `storage: {provider: file}` for owner-only plaintext files (a personal distribution needs no `acknowledgePlaintext`), or `credential.provider: none` without `storage` for a server without a key.
- `inference.provider: openai-compatible` with `baseUrl: ${MYPI_MODEL_URL}` and a one-model catalog, `local/coder`. The URL must use HTTPS, or `http` on `127.0.0.1`, `localhost`, or `[::1]`.

`local-model/model-server.mjs` is a stand-in server with canned replies, for trying the variant without a model. It is test infrastructure, not a model. In a first terminal, from the repository root after `npm ci` and `npm run build`:

```bash
node examples/personal/local-model/model-server.mjs    # keeps running; prints MYPI_MODEL_URL and the key it accepts
```

In a second terminal, paste the printed `export MYPI_MODEL_URL=...` line (`set` on Windows), then:

```bash
node packages/cli/dist/bin.js validate examples/personal/local-model/piship.yaml
node packages/cli/dist/bin.js build examples/personal/local-model/piship.yaml
dist/mypi-local/bin/mypi-local login           # paste the key
dist/mypi-local/bin/mypi-local --smoke-model   # one request to the local endpoint
dist/mypi-local/bin/mypi-local logout
```

The committed `local-model/piship.lock` is current; run `piship lock` only after editing the manifest. `login` uses the system secret store, as for the demo company: on Linux it needs an unlocked Secret Service and `secret-tool`, otherwise it fails with `SECRET_STORE_UNAVAILABLE`; set `storage: {provider: file}` in a copy to use owner-only files instead. On Windows run `dist\mypi-local\bin\mypi-local.cmd`.

These modes are verified against the stand-in server only; a request to a real local model server has not been recorded.

## What the tests cover

- `tests/e2e/personal-lifecycle.test.ts` releases MyPi 1.0.0 and 1.1.0 with a generated key, installs 1.0.0 with the shipped install script into an empty home, and checks `--smoke`, `doctor`, and `inspect`, including the healthy `notes` server. It updates to 1.1.0 from a signed loopback channel, rolls back, and uninstalls. Throughout, it checks that the session is resumed, that `~/.pi` is byte for byte unchanged, that no identity, credential, or audit state is written, that the channel host sees only channel requests, and that nothing goes out through a trap proxy set in the environment.
- `tests/e2e/personal-local-model.test.ts` checks that the committed `local-model/piship.lock` is current, then builds MyPi Local with the file secret store and runs `login`, `--smoke-model` against the stand-in server, and `logout`.
- `tests/e2e/personal-clean-machine.ts`, run as `personal-clean-machine-mypi.test.ts` and `personal-clean-machine-local.test.ts`, takes MyPi and MyPi Local each through one continuous flow from an empty home and state: install from a verified release, launch, credential, model request, session resume, `doctor`, update from a signed loopback channel, rollback, and uninstall. Both send a real request to the stand-in model server. MyPi delegates the key to Pi (an `auth.json` and a `models.json` in its agent directory, as Pi's own sign-in writes them), and the test checks that neither an environment key nor the user's `~/.pi` reaches the server and that the key is in state only in Pi's `auth.json`, so PiShip copies it nowhere, including into update and rollback records. MyPi Local stores the key with `login`, and `doctor` reports the endpoint's model list. Its test works on a copy of the local-model manifest, not the manifest as committed: the copy uses the file secret store in place of the declared system store, and gains a channel source and a pinned key, which the example ships neither of, for the update. The test checks that the key is in state only in the secret store's file (the file store writes it base64url-encoded, and the test looks for both forms), so no copy of it is in update or rollback records. After both the update and the rollback the session and the key are still there, and the update host is asked only for the signed channel.
- `tests/e2e/cli.test.ts` builds and installs this example as a relocated payload and checks that ambient `~/.pi` and project resources are not loaded.
