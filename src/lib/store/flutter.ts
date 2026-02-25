import { flutter } from "../schema.ts";
import { db } from "./db.ts";
import { BaseLogStore } from "./base.ts";
import type { FlutterEvent } from "../../types.ts";

export type FlutterRecord = typeof flutter.$inferSelect;

export class FlutterStore extends BaseLogStore<typeof flutter> {
  constructor(deviceId: string, identifier: string) {
    super(flutter, deviceId, identifier);
  }

  append(event: FlutterEvent): void {
    const { type, dir, channel, ...rest } = event;
    db.insert(flutter)
      .values({
        deviceId: this.deviceId,
        identifier: this.identifier,
        timestamp: new Date().toISOString(),
        type: type || "unknown",
        direction: dir || "unknown",
        channel: channel || "unknown",
        data: Object.keys(rest).length > 0 ? JSON.stringify(rest) : null,
      })
      .run();
  }
}
