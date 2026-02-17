import { eq, and, gt, desc, count as countFn } from "drizzle-orm";
import { flutter } from "../schema.ts";
import { db } from "./db.ts";

export interface FlutterRecord {
  id: number;
  timestamp: string;
  type: string;
  direction: string;
  channel: string;
  data: string | null;
  createdAt: string;
}

export class FlutterStore {
  constructor(
    private deviceId: string,
    private identifier: string,
  ) {}

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

  query(
    options: {
      limit?: number;
      offset?: number;
      since?: string;
    } = {},
  ): FlutterRecord[] {
    const { limit = 1000, offset = 0, since } = options;

    const conditions = [
      eq(flutter.deviceId, this.deviceId),
      eq(flutter.identifier, this.identifier),
    ];

    if (since) {
      conditions.push(gt(flutter.timestamp, since));
    }

    return db
      .select()
      .from(flutter)
      .where(and(...conditions))
      .orderBy(desc(flutter.id))
      .limit(limit)
      .offset(offset)
      .all() as FlutterRecord[];
  }

  count(): number {
    const result = db
      .select({ count: countFn() })
      .from(flutter)
      .where(
        and(
          eq(flutter.deviceId, this.deviceId),
          eq(flutter.identifier, this.identifier),
        ),
      )
      .get();

    return result?.count ?? 0;
  }

  rm(): void {
    db.delete(flutter)
      .where(
        and(
          eq(flutter.deviceId, this.deviceId),
          eq(flutter.identifier, this.identifier),
        ),
      )
      .run();
  }
}
