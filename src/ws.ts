import { type ServerType } from "@hono/node-server";
import fs from "node:fs";
import { Server, type Socket } from "socket.io";
import { SessionDetachReason, type SpawnOptions, type Device } from "frida";

import frida from "./lib/xvii.ts";
import env from "./lib/env.ts";
import { agent, asset } from "./lib/assets.ts";
import { LogWriter } from "./lib/log-writer.ts";
import { NSURLStore, type NSURLEvent } from "./lib/store/nsurl.ts";
import { HookStore } from "./lib/store/hooks.ts";
import { CryptoStore } from "./lib/store/crypto.ts";
import { FlutterStore } from "./lib/store/flutter.ts";
import { JNIStore } from "./lib/store/jni.ts";
import { createTapStore } from "./lib/store/taps.ts";

import type { BaseMessage as BaseHookMessage } from "@agent/common/hooks/context";
import type { JNIEvent } from "@agent/droid/observers/jni";

type Platform = "fruity" | "droid";
type Mode = "app" | "daemon";

interface SessionParams {
  platform: Platform;
  mode: Mode;
  deviceId: string;
  bundle?: string;
  pid?: number;
  name?: string;
}

interface ServerToClientEvents {
  ready: (pid: number) => void;
  change: () => void;
  detached: (reason: string) => void;
  log: (level: string, text: string) => void;
  syslog: (text: string) => void;
  invalid: () => void;
  lifecycle: (
    event: "inactive" | "active" | "forerground" | "background",
  ) => void;
  hook: (msg: BaseHookMessage) => void;
  flutter: (event: Record<string, unknown>) => void;
  crypto: (msg: BaseHookMessage, data?: ArrayBuffer) => void;
  nsurl: (event: NSURLEvent) => void;
  jni: (event: JNIEvent) => void;
  fatal: (detail: unknown) => void;
}

type ClientCallback = (err: Error | null, result: any) => void;

interface ClientToServerEvents {
  rpc: (mod: string, method: string, args: any[], ack: ClientCallback) => void;
  eval: (source: string, name: string, ack: ClientCallback) => void;
  clearLog: (type: "syslog" | "agent", ack: ClientCallback) => void;
}

function fnv1a(input: string): string {
  let hash = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    hash ^= input.charCodeAt(i);
    hash = (hash * 0x01000193) >>> 0;
  }
  return hash.toString(16).padStart(8, "0");
}

const manager = frida.getDeviceManager();

async function resolveAppPid(
  device: Device,
  bundleId: string,
  platform: Platform,
): Promise<number> {
  const match = await device.enumerateApplications({
    identifiers: [bundleId],
    scope: frida.Scope.Full,
  });

  const app = match.at(0);
  if (!app) throw new Error(`Application ${bundleId} not found on device`);

  const frontmost = await device.getFrontmostApplication();
  if (frontmost?.pid === app.pid) return app.pid;

  const devParams = await device.querySystemParameters();
  const opt: SpawnOptions = {};

  if (platform === "fruity") {
    if (devParams.access === "full" && devParams.os.id === "ios") {
      opt.env = {
        DISABLE_TWEAKS: "1", // workaround for ellekit crash
      };
    }
  }

  return device.spawn(bundleId, opt);
}

interface SessionStores {
  nsurl: NSURLStore;
  hooks: HookStore;
  crypto: CryptoStore;
  flutter: FlutterStore;
  jni: JNIStore;
}

async function loadBridge(name: string) {
  const valid = ["objc", "java", "swift"];
  const lower = name.toLowerCase();

  if (!valid.includes(lower)) throw new Error(`Invalid bridge name: ${name}`);

  const p = await asset("agent", "dist", "bridges", `${lower}.js`);
  const source = await fs.promises.readFile(p, "utf8");
  return { filename: `${name}.js`, source };
}

function setupScriptHandlers(
  socket: Socket<ClientToServerEvents, ServerToClientEvents>,
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

      case "crypto":
        socket.emit(
          "crypto",
          payload,
          data ? new Uint8Array(data).buffer : undefined,
        );
        stores.crypto.append(payload, data ?? null);
        break;

      case "fatal":
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

function setupSocketHandlers(
  socket: Socket<ClientToServerEvents, ServerToClientEvents>,
  script: Awaited<
    ReturnType<typeof import("frida").Session.prototype.createScript>
  >,
  session: Awaited<ReturnType<typeof import("frida").Device.prototype.attach>>,
  logger: LogWriter,
  tapStore: ReturnType<typeof createTapStore>,
) {
  session.detached.connect((reason, crash) => {
    console.error("session detached:", reason, crash);
    switch (reason) {
      case SessionDetachReason.ApplicationRequested:
        break;
      case SessionDetachReason.DeviceLost:
        console.error("device lost");
        break;
      case SessionDetachReason.ProcessTerminated:
      case SessionDetachReason.ProcessReplaced:
        console.error("process was terminated or replaced");
    }
    socket.emit("detached", reason as string);
    socket.disconnect(true);
  });

  socket
    .on("rpc", (ns, method, args, ack) => {
      if (
        typeof ns !== "string" ||
        typeof method !== "string" ||
        !Array.isArray(args)
      ) {
        console.warn(`invalid RPC call ${ns}.${method}, dropping`, args);
        return;
      }

      console.info(`RPC method: ${ns}.${method}`, ...args);
      script.exports
        .invoke(ns, method, args)
        .then(
          (result) => ack(null, result),
          (err: Error) => {
            console.error(`RPC method ${method} failed:`, err);
            ack(err, null);
          },
        )
        .then(() => {
          // Auto-persist after tap toggles (runs on success OR failure,
          // because start() may partially succeed before throwing)
          if (ns === "taps" && (method === "start" || method === "stop")) {
            script.exports
              .snapshot()
              .then((snap: any) => tapStore.save(snap))
              .catch((e: unknown) =>
                console.warn("Failed to persist tap snapshot:", e),
              );
          }
        })
        .catch((err: Error) => {
          console.error(`RPC method ${method} failed:`, err);
          ack(err, null);
        });
    })
    .on("eval", (source, name, ack) => {
      console.info(`evaluating script: ${name}`);
      script.exports
        .invoke("script", "evaluate", [source, name])
        .then((result: unknown) => ack(null, result))
        .catch((err: Error) => ack(err, null));
    })
    .on("clearLog", (type, ack) => {
      logger
        .empty(type)
        .then(() => ack(null, true))
        .catch((err) => ack(err, null));
    })
    .on("disconnect", () => {
      console.info("socket disconnected");
      script
        .unload()
        .finally(() => session.detach())
        .finally(() => logger.close());
    });
}

async function onConnection(
  socket: Socket<ClientToServerEvents, ServerToClientEvents>,
  params: SessionParams,
) {
  const {
    platform,
    mode,
    deviceId,
    bundle,
    pid: targetPid,
    name: processName,
  } = params;
  const device = await manager.getDeviceById(deviceId, env.timeout);

  let pid: number;
  if (mode === "app") {
    if (!bundle) throw new Error("bundle is required for app mode");
    pid = await resolveAppPid(device, bundle, platform);
  } else {
    if (!targetPid) throw new Error("pid is required for daemon mode");
    pid = targetPid;
  }

  const session = await device.attach(pid);

  if (mode === "app") {
    await device.resume(pid).catch(() => {});
  }

  // Compute project identifier
  let identifier: string;
  if (mode === "app") {
    identifier = bundle!;
  } else {
    const pname = processName || `pid`;
    identifier = `${pname}-${fnv1a(pname + pid)}`;
  }

  // Create store instances
  const stores: SessionStores = {
    nsurl: new NSURLStore(deviceId, identifier),
    hooks: new HookStore(deviceId, identifier),
    crypto: new CryptoStore(deviceId, identifier),
    flutter: new FlutterStore(deviceId, identifier),
    jni: new JNIStore(deviceId, identifier),
  };

  const logHandles = await LogWriter.open(deviceId, identifier);
  const tapStore = createTapStore(deviceId, identifier);
  const script = await session.createScript(await agent(platform));

  setupScriptHandlers(socket, script, logHandles, stores);
  setupSocketHandlers(socket, script, session, logHandles, tapStore);

  await script.load();

  // Restore saved taps before emitting ready
  const saved = tapStore.load();
  if (saved) {
    try {
      await script.exports.restore(saved);
    } catch (e) {
      console.warn("Failed to restore taps:", e);
    }
  }

  socket.emit("ready", session.pid);
}

function parseSessionParams(
  query: Record<string, unknown>,
): SessionParams | null {
  const { device, platform, mode, bundle, pid, name } = query;

  if (typeof device !== "string") return null;
  if (platform !== "fruity" && platform !== "droid") return null;
  if (mode !== "app" && mode !== "daemon") return null;

  if (mode === "app" && typeof bundle !== "string") return null;
  if (mode === "daemon" && typeof pid !== "string") return null;

  return {
    deviceId: device,
    platform: platform as Platform,
    mode: mode as Mode,
    bundle: mode === "app" ? (bundle as string) : undefined,
    pid: mode === "daemon" ? parseInt(pid as string, 10) : undefined,
    name: typeof name === "string" ? name : undefined,
  };
}

export default function attach(server: ServerType) {
  const io = new Server<ClientToServerEvents, ServerToClientEvents>(server);

  function onDeviceChange() {
    console.debug("Device manager changed, notifying clients");
    io.of("/devices").emit("change");
  }

  manager.changed.connect(onDeviceChange);
  server.on("close", () => {
    manager.changed.disconnect(onDeviceChange);
  });

  io.of("/devices");
  io.of("/session").on("connection", (socket) => {
    const params = parseSessionParams(socket.handshake.query);
    if (params) {
      onConnection(socket, params).catch((ex) => {
        console.error("failed to establish session, ", ex);
        socket.disconnect(true);
      });
    } else {
      console.error("invalid params:", socket.handshake.query);
      // there is a weird bug that first time calling socket.io
      // the query params are empty
      socket.emit("invalid");
      // Give client time to receive the event before disconnecting
      setTimeout(() => socket.disconnect(true), 100);
    }
  });

  return io;
}
