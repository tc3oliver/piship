// Helpers shared by the release modules.
import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { PiShipError } from "@piship/contracts";

export function hash(content: string | Buffer): string {
  return createHash("sha256").update(content).digest("hex");
}

export function gate(
  code: ConstructorParameters<typeof PiShipError>[0],
  gateName: string,
  message: string,
  userAction?: string,
  stage: "Release" | "Build" = "Release",
): PiShipError {
  return new PiShipError(code, `${stage} gate ${gateName}: ${message}`, {
    component: stage === "Release" ? "release" : "build",
    sanitizedDetail: { gate: gateName },
    ...(userAction ? { userAction } : {}),
  });
}

export function writeJson(path: string, value: unknown): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}
