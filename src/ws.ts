import { type ServerType } from "@hono/node-server";
import { Server, type Socket } from "socket.io";
import { SessionDetachReason, type SpawnOptions } from "frida";

import frida from "./lib/xvii.ts";
import env from "./lib/env.ts";
import { readAgent } from "./lib/utils.ts";

interface ServerToClientEvents {
  ready: () => void;
  change: () => void;
  detached: (reason: string) => void;
  log: (level: string, text: string) => void;
}

interface ClientToServerEvents {
  rpc: (
    mod: string,
    method: string,
    args: any[],
    ack: (err: Error | null, result: any) => void,
  ) => void;
}

const manager = frida.getDeviceManager();

async function onConnection(
  socket: Socket<ClientToServerEvents, ServerToClientEvents>,
  deviceId: string,
  bundleId: string,
) {
  const device = await manager.getDeviceById(deviceId, env.timeout);
  const match = await device.enumerateApplications({
    identifiers: [bundleId],
    scope: frida.Scope.Full,
  });

  if (!match.length)
    throw new Error(`Application ${bundleId} not found on device`);

  const app = match.at(0)!;
  const start = async () => {
    const frontmost = await device.getFrontmostApplication();
    if (frontmost?.pid === app.pid) return Promise.resolve(app.pid);

    const devParams = await device.querySystemParameters();
    const opt: SpawnOptions = {};
    if (devParams.access === "full" && devParams.os.id === "ios") {
      opt.env = {
        DISABLE_TWEAKS: "1", // workaround for ellekit crash. todo: move to preferences
      };
    }

    return device.spawn(bundleId, opt);
  };

  const pid = await start();
  const session = await device.attach(pid);
  await device.resume(pid);
  const script = await session.createScript(await readAgent(`fruity`));

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
        console.error("app was terminated or replaced");
    }
    socket.emit("detached", reason as string);
    socket.disconnect(true);
  });

  script.destroyed.connect(() => {
    console.error("script is destroyed");
    socket.disconnect(true);
  });

  script.logHandler = (level, text) => {
    console.log(`[agent][${level}] ${text}`);
    socket.emit("log", level, text);
  };

  await script.load();

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
    .on("disconnect", async () => {
      console.info("socket disconnected");
      try {
        await script.unload();
        await session.detach();
      } finally {
      }
    })
    .emit("ready");
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
    const { device, bundle } = socket.handshake.query;
    if (typeof device === "string" && typeof bundle === "string") {
      onConnection(socket, device, bundle).catch((ex) => {
        console.error(ex);
        socket.disconnect(true);
      });
    } else {
      console.error("invalid param:", device, bundle);
      socket.disconnect(true);
    }
  });

  return io;
}
