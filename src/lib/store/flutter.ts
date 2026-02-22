import { flutter } from "../schema.ts";
import { db } from "./db.ts";
import { BaseLogStore } from "./base.ts";

export type FlutterRecord = typeof flutter.$inferSelect;

export class FlutterStore extends BaseLogStore<typeof flutter> {
  constructor(deviceId: string, identifier: string) {
    super(flutter, deviceId, identifier);
  }

  append(event: Record<string, unknown>): void {
    const { type, dir, channel, ...rest } = event;
    db.insert(flutter)
      .values({
        deviceId: this.deviceId,
        identifier: this.identifier,
        timestamp: new Date().toISOString(),
        type: (type as string) || "unknown",
        direction: (dir as string) || "unknown",
        channel: (channel as string) || "unknown",
        data: Object.keys(rest).length > 0 ? JSON.stringify(rest) : null,
      })
      .run();
  }
}
