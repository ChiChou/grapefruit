import { type ServerType } from "@hono/node-server";
import { Server } from "socket.io";

import { manager, parse, connect } from "./session.ts";
import type { ClientToServerEvents, ServerToClientEvents } from "./types.ts";
import { attachR2 } from "./r2ws.ts";

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
    const params = parse(socket.handshake.query);
    if (params) {
      connect(socket, params).catch((ex) => {
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

  attachR2(io);

  return io;
}
