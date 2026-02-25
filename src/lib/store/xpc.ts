import { xpcLogs } from "../schema.ts";
import { db } from "./db.ts";
import { BaseLogStore } from "./base.ts";

export type XPCRecord = typeof xpcLogs.$inferSelect;

export interface XPCEvent {
  event: "received" | "sent";
  dir: "<" | ">";
  name?: string;
  peer?: number;
  message?: { type?: string } & Record<string, unknown>;
  backtrace?: string[];
}

export class XPCStore extends BaseLogStore<typeof xpcLogs> {
  constructor(deviceId: string, identifier: string) {
    super(xpcLogs, deviceId, identifier, [
      { column: xpcLogs.protocol, queryParam: "protocol" },
    ]);
  }

  append(payload: XPCEvent): void {
    const isNsxpc = payload.message?.type === "nsxpc";

    db.insert(xpcLogs)
      .values({
        deviceId: this.deviceId,
        identifier: this.identifier,
        timestamp: new Date().toISOString(),
        protocol: isNsxpc ? "nsxpc" : "xpc",
        event: payload.event || "unknown",
        direction: payload.dir || "unknown",
        service: payload.name || null,
        peer: payload.peer || null,
        message: payload.message ? JSON.stringify(payload.message) : "{}",
        backtrace: payload.backtrace?.length ? JSON.stringify(payload.backtrace) : null,
      })
      .run();
  }
}
