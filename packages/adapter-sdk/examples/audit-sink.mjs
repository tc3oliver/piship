// Example audit sink: the receiving side of PiShip's `http` audit sink. A
// distribution sends `piship-audit-batch/v1` batches to a collector URL; the
// collector hands each parsed request body to `write` and answers 2xx only
// once it resolved. This sink appends new events to a JSON Lines file. It
// imports nothing but @piship/adapter-sdk and Node built-ins.
import { appendFile } from "node:fs/promises";
import { AUDIT_BATCH_SCHEMA, defineAuditSink } from "@piship/adapter-sdk";

// Replace with durable storage. The file is illustrative.
const FILE = new URL("./audit-events.jsonl", import.meta.url);

// A failed batch is resent with the same event IDs, so an event whose ID is
// already stored counts as delivered. Keep the IDs as durable as the events;
// this in-memory set forgets them on restart.
const stored = new Set();

export default defineAuditSink({
  async write(batch, signal) {
    if (batch?.schema !== AUDIT_BATCH_SCHEMA || !Array.isArray(batch.events))
      throw new Error(`expected a ${AUDIT_BATCH_SCHEMA} batch`);
    signal.throwIfAborted();
    // The empty batch is a required sink's readiness probe.
    const fresh = batch.events.filter(
      (event) => !(event.id && stored.has(event.id)),
    );
    if (fresh.length === 0) return;
    await appendFile(
      FILE,
      fresh.map((event) => `${JSON.stringify(event)}\n`).join(""),
    );
    for (const event of fresh) if (event.id) stored.add(event.id);
  },
});
