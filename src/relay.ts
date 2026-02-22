import fs from "node:fs";
import { styleText } from "node:util";

import { asset } from "./lib/assets.ts";
import type { LogWriter } from "./lib/log-writer.ts";
import type { NSURLEvent } from "./lib/store/nsurl.ts";
import type { SessionSocket, SessionStores } from "./types.ts";

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
        const event = payload as NSURLEvent;

        if (event.event === "dataReceived" && data) {
          requestsWithBody.add(event.requestId);
        }

        if (
          event.event === "loadingFinished" &&
          requestsWithBody.has(event.requestId)
        ) {
          event.hasBody = true;
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
        const { subject: _, ...event } = payload;
        socket.emit("flutter", event);
        stores.flutter.append(event);
        break;
      }

      case "xpc": {
        const { subject: _, ...event } = payload;
        socket.emit("xpc", event);
        stores.xpc.append(payload);
        break;
      }

      case "jni": {
        const { subject: _, ...event } = payload;
        socket.emit("jni", event);
        stores.jni.append(payload);
        break;
      }

      case "hook":
        socket.emit("hook", payload);
        stores.hooks.append(payload);
        break;

      case "memoryScan":
        socket.emit(
          "memoryScan",
          payload,
          data ? new Uint8Array(data).buffer : undefined,
        );
        break;

      case "crypto":
        socket.emit(
          "crypto",
          payload,
          data ? new Uint8Array(data).buffer : undefined,
        );
        stores.crypto.append(payload, data ?? null);
        break;

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
