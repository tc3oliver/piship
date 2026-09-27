# Experimental manifest and lock

`piship/v1alpha1` is an experimental contract for the first runnable personal distribution. It is not a stable v1 schema. The [personal example](../examples/personal/piship.yaml) is executable; the [demo company example](../examples/demo-company/README.md) remains illustrative.

The supported fields are `schema`, `app` (`id`, `name`, `command`), `runtime.pi`, `deployment.mode: personal`, and optional `resources` (`instructions`, `skills`, `extensions`, `prompts`). Unknown fields fail validation; `managed` is explicitly rejected by validate, lock, and build. IDs and commands use lowercase letters, digits, and hyphens; resource paths start with `./` and stay within the manifest directory. The current build accepts exactly Pi `0.87.1`. Credential fields and `${...}` environment substitutions are excluded. Validation cannot recognize arbitrary secret text in an otherwise allowed value; review manifests and locks before committing them.

```bash
npm exec -- piship validate examples/personal/piship.yaml
npm exec -- piship lock examples/personal/piship.yaml
npm exec -- piship build examples/personal/piship.yaml
./dist/mypi/bin/mypi
```

On Windows, run `dist\mypi\bin\mypi.cmd`. The command starts the real upstream Pi interactive runtime. `--smoke` initializes the same Pi SDK session and reports the loaded resources and state paths without calling a model; CI uses that mode.

`piship.lock` is generated next to the manifest. It records the manifest digest, app identity, exact Pi package/version, declared resource roots, and SHA-256 hashes for each resource file. The lock is deterministic and intended for Git review. A changed manifest or resource makes `piship build` fail until `piship lock` is rerun. Builds copy declared resources into `dist/<id>/resources` and verify their hashes at launch. This is a checkout-local build, not an installer or standalone binary: keep the repository and its `npm ci` dependencies available.

Declare each extension entry file or extension directory containing `index.ts`/`index.js` as a resource root. Pi discovers that entry through its public loader; other files in that directory are copied and hashed, but are not separate extension entries. Manifest intent and resolved lock state must stay free of credentials. Extensions are executable code and should only be declared from trusted distribution repositories. Managed identity, policy, credential handling, and release packaging are later work.
