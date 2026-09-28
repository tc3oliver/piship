// Test-only helper: build a self-signed loopback certificate with Node's crypto
// so TLS tests need neither openssl nor committed key material.
import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";

function length(size: number): Buffer {
  if (size < 0x80) return Buffer.from([size]);
  const bytes: number[] = [];
  for (let value = size; value > 0; value >>= 8) bytes.unshift(value & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
function tlv(tag: number, value: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), length(value.length), value]);
}
const sequence = (...items: Buffer[]) => tlv(0x30, Buffer.concat(items));
const set = (...items: Buffer[]) => tlv(0x31, Buffer.concat(items));
const integer = (value: Buffer) =>
  tlv(
    0x02,
    (value[0] ?? 0) & 0x80 ? Buffer.concat([Buffer.from([0]), value]) : value,
  );
const nullValue = () => Buffer.from([0x05, 0x00]);
function oid(text: string): Buffer {
  const parts = text.split(".").map(Number);
  const bytes = [40 * (parts[0] ?? 0) + (parts[1] ?? 0)];
  for (const part of parts.slice(2)) {
    const chunk: number[] = [];
    let value = part;
    do {
      chunk.unshift(value & 0x7f);
      value >>= 7;
    } while (value > 0);
    for (let index = 0; index < chunk.length - 1; index++)
      chunk[index] = (chunk[index] ?? 0) | 0x80;
    bytes.push(...chunk);
  }
  return tlv(0x06, Buffer.from(bytes));
}
const utf8 = (text: string) => tlv(0x0c, Buffer.from(text, "utf8"));
function time(date: Date): Buffer {
  const text = date.toISOString().replace(/[-:T]/g, "").slice(2, 14);
  return tlv(0x17, Buffer.from(`${text}Z`, "ascii"));
}
const explicit = (tag: number, value: Buffer) => tlv(0xa0 | tag, value);

export interface TestCertificate {
  readonly certificate: string;
  readonly key: string;
}

export function selfSignedLoopbackCertificate(
  commonName = "piship-test",
): TestCertificate {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  const algorithm = sequence(oid("1.2.840.113549.1.1.11"), nullValue());
  const name = sequence(set(sequence(oid("2.5.4.3"), utf8(commonName))));
  const now = Date.now();
  const san = sequence(
    tlv(0x82, Buffer.from("localhost")),
    tlv(0x87, Buffer.from([127, 0, 0, 1])),
  );
  const extensions = explicit(
    3,
    sequence(
      sequence(
        oid("2.5.29.19"),
        tlv(0x01, Buffer.from([0xff])),
        tlv(0x04, sequence(tlv(0x01, Buffer.from([0xff])))),
      ),
      sequence(oid("2.5.29.17"), tlv(0x04, san)),
    ),
  );
  const tbs = sequence(
    explicit(0, integer(Buffer.from([2]))),
    integer(Buffer.from([1, 2, 3, 4, 5, 6, 7, 8])),
    algorithm,
    name,
    sequence(time(new Date(now - 3_600_000)), time(new Date(now + 86_400_000))),
    name,
    (publicKey as KeyObject).export({ type: "spki", format: "der" }),
    extensions,
  );
  const signature = sign("sha256", tbs, privateKey);
  const der = sequence(
    tbs,
    algorithm,
    tlv(0x03, Buffer.concat([Buffer.from([0]), signature])),
  );
  const body = der.toString("base64").replace(/(.{64})/g, "$1\n");
  return {
    certificate: `-----BEGIN CERTIFICATE-----\n${body.trim()}\n-----END CERTIFICATE-----\n`,
    key: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
}
