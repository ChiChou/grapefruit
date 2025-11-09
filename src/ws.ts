import { type ServerType } from "@hono/node-server";
import { Server, type Socket } from "socket.io";
import frida from "frida";

import type { RemoteRPC as FruityRPC } from "../agent/types/fruity/registry.d.ts";

import env from "./lib/env.ts";
import getVersion from "./lib/version.ts";
import { readAgent } from "./lib/utils.ts";

interface ServerToClientEvents {
  ready: () => void;
  change: () => void;
}

interface ClientToServerEvents {
  rpc: <M extends keyof FruityRPC, F extends keyof FruityRPC[M]>(
    mod: M,
    method: F,
    args: FruityRPC[M][F] extends (...args: infer A) => any ? A : never,
    ack: (
      result: FruityRPC[M][F] extends (...args: any) => infer R ? R : never,
    ) => void,
  ) => void;
}

const manager = frida.getDeviceManager();

async function onConnection(
  socket: Socket<ClientToServerEvents, ServerToClientEvents>,
  deviceId: string,
  bundleId: string,
) {
  const fridaVersion = await getVersion("frida");
  const fridaMajor = fridaVersion.split(".").at(0);
  if (fridaMajor !== "16" && fridaMajor !== "17")
    throw new Error(`Only frida 16 and 17 are supported, got ${fridaVersion}`);

  const device = await manager.getDeviceById(deviceId, env.timeout);
  const match = await device.enumerateApplications({
    identifiers: [bundleId],
    scope: frida.Scope.Full,
  });

  if (!match.length)
    throw new Error(`Application ${bundleId} not found on device`);

  const app = match.at(0)!;
  const pid = app.pid ? app.pid : await device.spawn(bundleId);
  const session = await device.attach(pid);
  const script = await session.createScript(
    await readAgent(`fruity@${fridaMajor}`),
  );

  await script.load();

  socket
    .on("rpc", (ns, method, args, ack) => {
      if (typeof method !== "string" || !Array.isArray(args)) {
        console.warn("invalid RPC call, dropping");
        return;
      }

      console.info(`RPC method called: ${method}`, ...args);
      script.exports
        .invoke(ns, method, args)
        .catch((ex: Error) => {
          console.error(`RPC method ${method} failed:`, ex);
        })
        .then(ack);
    })
    .on("disconnect", async () => {
      await script.unload();
      await session.detach();
      console.info("session detached");
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
