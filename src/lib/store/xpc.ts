import { xpcLogs } from "../schema.ts";
import { db } from "./db.ts";
import { BaseLogStore } from "./base.ts";

export type XPCRecord = typeof xpcLogs.$inferSelect;

export class XPCStore extends BaseLogStore<typeof xpcLogs> {
  constructor(deviceId: string, identifier: string) {
    super(xpcLogs, deviceId, identifier, [
      { column: xpcLogs.protocol, queryParam: "protocol" },
    ]);
  }

  append(payload: Record<string, unknown>): void {
    const message = payload.message as Record<string, unknown> | undefined;
    const isNsxpc = message?.type === "nsxpc";
    const backtrace = payload.backtrace as string[] | undefined;

    db.insert(xpcLogs)
      .values({
        deviceId: this.deviceId,
        identifier: this.identifier,
        timestamp: new Date().toISOString(),
        protocol: isNsxpc ? "nsxpc" : "xpc",
        event: (payload.event as string) || "unknown",
        direction: (payload.dir as string) || "unknown",
        service: (payload.name as string) || null,
        peer: (payload.peer as number) || null,
        message: message ? JSON.stringify(message) : "{}",
        backtrace: backtrace?.length ? JSON.stringify(backtrace) : null,
      })
      .run();
  }
}
