# Personal distribution example

This is the runnable `piship/v1alpha1` example. It declares a Pi 0.87.1 pin, brand, and four resource categories. The example extension is a no-op used to verify loading. It does not call a model or demonstrate managed access.

From the repository root after `npm ci` and `npm run build`:

```bash
npm exec -- piship validate examples/personal/piship.yaml
npm exec -- piship lock examples/personal/piship.yaml
npm exec -- piship build examples/personal/piship.yaml
./dist/mypi/bin/mypi --smoke
./dist/mypi/bin/mypi
```

On Windows use `dist\mypi\bin\mypi.cmd`. `--smoke` proves Pi session startup without an API key. The plain command opens upstream Pi's interactive mode; model calls still require provider credentials configured for this isolated distribution. Runtime state defaults to `~/.piship/mypi`, separate from personal `~/.pi`.

The generated output requires this checkout and its installed npm dependencies. It is not a portable installer or release artifact.
