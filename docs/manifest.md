# Experimental manifest and lock

`piship/v1alpha1` is an experimental contract for the first runnable personal distribution. It is not a stable v1 schema. The [personal example](../examples/personal/piship.yaml) is executable; the [demo company example](../examples/demo-company/README.md) remains illustrative.

The supported fields are `schema`, `app` (`id`, `name`, `command`), `runtime.pi`, `deployment.mode`, and optional `resources` (`instructions`, `skills`, `extensions`, `prompts`). Unknown fields fail validation. IDs and commands use lowercase letters, digits, and hyphens; resource paths start with `./` and stay within the manifest directory. The current build accepts exactly Pi `0.87.1`. The manifest cannot contain secret values or environment substitutions.

```bash
npm exec -- piship validate examples/personal/piship.yaml
npm exec -- piship lock examples/personal/piship.yaml
npm exec -- piship build examples/personal/piship.yaml
./dist/mypi/bin/mypi
```

On Windows, run `dist\mypi\bin\mypi.cmd`. The command starts the real upstream Pi interactive runtime. `--smoke` initializes the same Pi SDK session and reports the loaded resources and state paths without calling a model; CI uses that mode.

`piship.lock` is generated next to the manifest. It records the manifest digest, app identity, exact Pi package/version, declared resource roots, and SHA-256 hashes for each resource file. The lock is deterministic and intended for Git review. A changed manifest or resource makes `piship build` fail until `piship lock` is rerun. Builds copy declared resources into `dist/<id>/resources` and verify their hashes at launch. This is a checkout-local build, not an installer or standalone binary: keep the repository and its `npm ci` dependencies available.

Manifest intent and resolved lock state must stay free of credentials. Extensions are executable code and should only be declared from trusted distribution repositories. Managed identity, policy, credential handling, and release packaging are later work.
