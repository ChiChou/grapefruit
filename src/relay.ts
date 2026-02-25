import { createHash } from "node:crypto";
import fs from "node:fs";
import { styleText } from "node:util";

import { asset } from "./lib/assets.ts";
import type { LogWriter } from "./lib/log-writer.ts";
import type { NSURLEvent } from "./lib/store/nsurl.ts";
import type { XPCEvent } from "./lib/store/xpc.ts";
import type { BaseMessage } from "@agent/common/hooks/context";
import type { PrivacyMessage } from "@agent/common/hooks/privacy";
import type { JNIEvent } from "@agent/droid/hooks/jni";
import type {
  SessionSocket,
  SessionStores,
  FlutterEvent,
  MemoryScanEvent,
} from "./types.ts";

async function loadBridge(name: string) {
  const valid = ["objc", "java", "swift"];
  const lower = name.toLowerCase();

  if (!valid.includes(lower)) throw new Error(`Invalid bridge name: ${name}`);

  const p = await asset("agent", "dist", "bridges", `${lower}.js`);
  const source = await fs.promises.readFile(p, "utf8");
  return { filename: `${name}.js`, source };
}

export function setup(
  socket: SessionSocket,
  script: Awaited<
    ReturnType<typeof import("frida").Session.prototype.createScript>
  >,
  logger: LogWriter,
  stores: SessionStores,
) {
  const requestsWithBody = new Set<string>();

  script.destroyed.connect(() => {
    console.error("script is destroyed");
    socket.disconnect(true);
  });

  script.message.connect((message, data) => {
    if (message.type === "error") {
      console.error("script error:", message);
      return;
    }

    if (message.type !== "send") return;

    const { payload } = message;
    const { subject } = payload as { subject: string };

    switch (subject) {
      case "frida:load-bridge":
        loadBridge(payload.name)
          .then((result) =>
            script.post({ type: "frida:bridge-loaded", ...result }),
          )
          .catch((err) =>
            console.error(`Failed to load bridge ${payload.name}:`, err),
          );
        break;

      case "syslog":
        if (data) {
          const text = data.toString();
          console.log(`[syslog]`, text);
          socket.emit("syslog", text);
          logger.appendSyslog(text);
        }
        break;

      case "nsurl": {
        let event = payload as NSURLEvent;

        if (event.event === "dataReceived" && data) {
          requestsWithBody.add(event.requestId);
        }

        if (
          event.event === "loadingFinished" &&
          requestsWithBody.has(event.requestId)
        ) {
          event = { ...event, hasBody: true };
          requestsWithBody.delete(event.requestId);
        }

        if (event.event === "loadingFailed") {
          requestsWithBody.delete(event.requestId);
        }

        socket.emit("nsurl", event);
        try {
          const attachment = stores.nsurl.upsert(event);
          if (attachment && data) {
            fs.promises
              .mkdir(stores.nsurl.attachmentsDir, { recursive: true })
              .then(() => fs.promises.appendFile(attachment, Buffer.from(data)))
              .catch((e) => console.error("Failed to write attachment:", e));
          }
        } catch (e) {
          console.error("Failed to persist NSURL event:", e);
        }
        break;
      }

      case "flutter": {
        const { subject: _, ...event } = payload as { subject: string } & FlutterEvent;
        socket.emit("flutter", event);
        stores.flutter.append(event);
        break;
      }

      case "xpc": {
        const { subject: _, ...event } = payload as { subject: string } & XPCEvent;
        socket.emit("xpc", event);
        stores.xpc.append(event);
        break;
      }

      case "jni": {
        const event = payload as JNIEvent;
        socket.emit("jni", event);
        stores.jni.append(event);
        break;
      }

      case "hermes": {
        const buf = data ? Buffer.from(data) : Buffer.alloc(0);
        const hash = createHash("sha256").update(buf).digest("hex");
        const hermesEvent = { url: payload.url as string, hash, size: buf.length };
        socket.emit("hermes", hermesEvent);
        stores.hermes.append(hermesEvent, buf);
        break;
      }

      case "privacy": {
        const msg = payload as PrivacyMessage;
        socket.emit("privacy", msg);
        stores.privacy.append(msg);
        break;
      }

      case "hook": {
        const msg = payload as BaseMessage;
        socket.emit("hook", msg);
        stores.hooks.append(msg);
        break;
      }

      case "memoryScan":
        socket.emit(
          "memoryScan",
          payload as MemoryScanEvent,
          data ? new Uint8Array(data).buffer : undefined,
        );
        break;

      case "crypto": {
        const msg = payload as BaseMessage;
        socket.emit(
          "crypto",
          msg,
          data ? new Uint8Array(data).buffer : undefined,
        );
        stores.crypto.append(msg, data ?? null);
        break;
      }

      case "fatal":
        console.error(
          styleText("redBright", "fatal error from agent:"),
          payload.detail,
        );
        socket.emit("fatal", payload.detail);
        break;

      case "lifecycle":
        socket.emit(subject, payload.event);
        break;

      default:
        console.debug("send", payload);
    }
  });

  script.logHandler = (level, text) => {
    console.log(`[agent][${level}] ${text}`);
    socket.emit("log", level, text);
    logger.appendAgentLog(level, text);
  };
}
