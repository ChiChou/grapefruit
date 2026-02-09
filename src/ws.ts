import { type ServerType } from "@hono/node-server";
import { Server, type Socket } from "socket.io";
import { SessionDetachReason, type SpawnOptions, type Device } from "frida";
import fs from "node:fs/promises";
import path from "node:path";

import frida from "./lib/xvii.ts";
import env from "./lib/env.ts";
import { agent } from "./lib/assets.ts";
import paths from "./lib/paths.ts";
import { insertHook } from "./lib/localstore.ts";

import type { BaseMessage as BaseHookMessage } from "../agent/types/fruity/hooks/context.d.ts";

type Platform = "fruity" | "droid";
type Mode = "app" | "daemon";

interface SessionParams {
  platform: Platform;
  mode: Mode;
  deviceId: string;
  bundle?: string;
  pid?: number;
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
  httplog: (event: any) => void;
}

type ClientCallback = (err: Error | null, result: any) => void;

interface ClientToServerEvents {
  rpc: (mod: string, method: string, args: any[], ack: ClientCallback) => void;
  eval: (source: string, name: string, ack: ClientCallback) => void;
}

const manager = frida.getDeviceManager();

/**
 * Get log directory and file paths for a session
 */
async function getLogPaths(deviceId: string, identifier: string) {
  const logsDir = path.join(paths.data, "logs", deviceId, identifier);
  await fs.mkdir(logsDir, { recursive: true });
  return {
    syslog: path.join(logsDir, "syslog.log"),
    agentLog: path.join(logsDir, "agent.log"),
  };
}

/**
 * Append a line to a log file
 */
function appendLog(filePath: string, line: string) {
  fs.appendFile(filePath, line + "\n").catch((err) => {
    console.error("Failed to write log:", err);
  });
}

/**
 * Resolve target PID for app mode - spawn if not frontmost
 */
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

  // Platform-specific spawn options
  if (platform === "fruity") {
    if (devParams.access === "full" && devParams.os.id === "ios") {
      opt.env = {
        DISABLE_TWEAKS: "1", // workaround for ellekit crash
      };
    }
  }

  return device.spawn(bundleId, opt);
}

/**
 * Setup socket event handlers for script messages
 */
function setupScriptHandlers(
  socket: Socket<ClientToServerEvents, ServerToClientEvents>,
  script: Awaited<
    ReturnType<typeof import("frida").Session.prototype.createScript>
  >,
  logPaths: { syslog: string; agentLog: string },
  sessionInfo: { deviceId: string; identifier: string },
) {
  script.destroyed.connect(() => {
    console.error("script is destroyed");
    socket.disconnect(true);
  });

  script.message.connect((message, data) => {
    if (message.type === "send") {
      const { payload } = message;
      const { subject } = payload;
      if (subject === "syslog" && data) {
        const text = data.toString();
        console.log(`[syslog]`, text);
        socket.emit("syslog", text);
        appendLog(logPaths.syslog, text);
      } else if (subject === "httplog") {
        console.log(`[httplog]`, payload);
        socket.emit("httplog", payload);
      } else {
        if (subject === "hook") {
          socket.emit(subject, payload);
          // Store hook message in SQLite
          insertHook(sessionInfo.deviceId, sessionInfo.identifier, payload);
        } else if (subject === "lifecycle") {
          socket.emit(subject, payload.event);
        } else {
          console.debug("send", payload);
        }
      }
    } else if (message.type === "error") {
      console.error("script error:", message);
    }
  });

  script.logHandler = (level, text) => {
    console.log(`[agent][${level}] ${text}`);
    socket.emit("log", level, text);
    appendLog(logPaths.agentLog, `[${level}] ${text}`);
  };
}

/**
 * Setup socket RPC and lifecycle handlers
 */
function setupSocketHandlers(
  socket: Socket<ClientToServerEvents, ServerToClientEvents>,
  script: Awaited<
    ReturnType<typeof import("frida").Session.prototype.createScript>
  >,
  session: Awaited<ReturnType<typeof import("frida").Device.prototype.attach>>,
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
        .catch((err: Error) => {
          console.error(`RPC method ${method} failed:`, err);
          ack(err, null);
        })
        .then((result) => ack(null, result));
    })
    .on("eval", (source, name, ack) => {
      console.info(`evaluating script: ${name}`);
      ack(new Error("not implemented"), null);
      return;
    })
    .on("disconnect", async () => {
      console.info("socket disconnected");
      try {
        await script.unload();
        await session.detach();
      } finally {
      }
    });
}

async function onConnection(
  socket: Socket<ClientToServerEvents, ServerToClientEvents>,
  params: SessionParams,
) {
  const { platform, mode, deviceId, bundle, pid: targetPid } = params;
  const device = await manager.getDeviceById(deviceId, env.timeout);

  // Resolve the target PID based on mode
  let pid: number;
  if (mode === "app") {
    if (!bundle) throw new Error("bundle is required for app mode");
    pid = await resolveAppPid(device, bundle, platform);
  } else {
    if (!targetPid) throw new Error("pid is required for daemon mode");
    pid = targetPid;
  }

  const session = await device.attach(pid);

  // Resume only for app mode (spawned processes need resume)
  if (mode === "app") {
    await device.resume(pid).catch(() => {});
  }

  // Get log file paths based on device and identifier
  const identifier = mode === "app" ? bundle! : `pid-${pid}`;
  const logPaths = await getLogPaths(deviceId, identifier);
  const script = await session.createScript(await agent(platform));

  setupScriptHandlers(socket, script, logPaths, { deviceId, identifier });
  setupSocketHandlers(socket, script, session);

  await script.load();
  socket.emit("ready", session.pid);
}

function parseSessionParams(
  query: Record<string, unknown>,
): SessionParams | null {
  const { device, platform, mode, bundle, pid } = query;

  // Validate required params
  if (typeof device !== "string") return null;
  if (platform !== "fruity" && platform !== "droid") return null;
  if (mode !== "app" && mode !== "daemon") return null;

  // Validate mode-specific params
  if (mode === "app" && typeof bundle !== "string") return null;
  if (mode === "daemon" && typeof pid !== "string") return null;

  return {
    deviceId: device,
    platform: platform as Platform,
    mode: mode as Mode,
    bundle: mode === "app" ? (bundle as string) : undefined,
    pid: mode === "daemon" ? parseInt(pid as string, 10) : undefined,
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
