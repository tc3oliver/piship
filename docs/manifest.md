# Experimental manifest and lock

`piship/v1alpha1` is the personal distribution contract. It remains experimental. The [personal example](../examples/personal/piship.yaml) is runnable. Managed mode and unknown fields are rejected.

Required fields are `schema`, `app.id`, `app.name`, `app.command`, `app.version`, `runtime.pi`, and `deployment.mode: personal`. `app.banner` is optional. `resources` can declare instruction files and skill, extension, or prompt roots. IDs and commands use safe lowercase names; `app.version` is a distribution semver independent of PiShip and Pi versions. Resource paths start with `./`, stay inside the manifest directory, and may not contain symlinks. Credential fields and `${...}` substitutions are excluded.

```bash
npm exec -- piship init ./my-agent
npm exec -- piship validate ./my-agent/piship.yaml
npm exec -- piship lock ./my-agent/piship.yaml
npm exec -- piship test ./my-agent/piship.yaml
npm exec -- piship build ./my-agent/piship.yaml
node ./dist/my-agent/piship.mjs install ./dist/my-agent
my-agent --version
my-agent --smoke
node ./dist/my-agent/piship.mjs inspect my-agent
node ./dist/my-agent/piship.mjs doctor my-agent
node ./dist/my-agent/piship.mjs uninstall my-agent
node ./dist/my-agent/piship.mjs purge my-agent --yes
```

`dev` builds and starts the interactive branded command with the same resource and state isolation. `test` assembles the artifact and runs a local Pi SDK, extension, read-tool, and session smoke without a model request. `inspect` accepts a manifest, artifact directory, or installed ID. `doctor` accepts an artifact directory or installed ID and verifies payload integrity before launching the smoke. `--smoke` writes a clearly labeled synthetic entry to a separate acceptance session to verify Pi's session persistence; it does not call a provider.

`piship.lock` records the normalized manifest digest, app identity, Pi package and version, PiShip version, committed npm lock digest, resolved package versions and npm integrity strings, declared roots, and SHA-256 hashes for every declared resource. It is deterministic and contains no timestamp. Build rejects a stale lock. The packaged file inventory detects changed manifest, lock, resource, or runtime files before Pi loads. There is no signature or trusted publisher verification in v0.1.

Alpha migration: manifests from the checkout-local preview need `app.version` added; `app.banner` is optional. Regenerate `piship.lock` with the new PiShip CLI, then rebuild. The previous checkout-local output cannot be installed as a portable payload.
