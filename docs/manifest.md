# Manifest status

The current schema marker is `piship/v1alpha1`. **The manifest API is experimental.** `@piship/schema` checks only the marker on an already parsed object. It does not parse YAML, validate a full manifest, or produce a lockfile.

The [personal](../examples/personal/README.md) and [demo company](../examples/demo-company/README.md) YAML files are fixtures for the intended shape. No current CLI command can consume them. Fields beyond the schema marker may change before the first runnable distribution.
