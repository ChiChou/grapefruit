import { type ServerType } from "@hono/node-server";
import { Server } from "socket.io";
import frida from "frida";

interface ServerToClientEvents {
  ready: () => void;
  change: () => void;
}

interface ClientToServerEvents {
  rpc: (method: string) => void;
}

export default function attach(server: ServerType) {
  const manager = frida.getDeviceManager();
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
    socket.emit("ready");

    socket.on("rpc", (method) => {
      console.log(`RPC method called: ${method}`);
    });
  });

  return io;
}
