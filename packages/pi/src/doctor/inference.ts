// Inference group: the provider, whether access activates, and the models it
// allows.
import type { DoctorData } from "./data.js";
import type { DoctorSection } from "./report.js";

export function inferenceGroup(data: DoctorData, out: DoctorSection): void {
  const access = data.access;
  if (!access || access.configError) return;
  out.ok("provider", access.manifest.inference.provider);
  if (access.tlsError) out.bad("activation", access.tlsError);
  else if (access.activationError)
    out.bad("activation", access.activationError);
  else if (access.activation)
    out.ok(
      "models",
      `${access.activation.allowedModels} allowed; default ${access.activation.selectedModel ?? "Pi default"}`,
    );
}
