# Personal distribution example

Today, [piship.yaml](piship.yaml) is an alpha fixture showing a personal agent's name, command, deployment mode, and intended Pi pin. The CLI cannot parse or build it yet.

The planned distribution core will resolve the manifest, isolate Pi state and resources, and launch the branded command. Fields beyond the schema marker may change while `piship/v1alpha1` is experimental.
