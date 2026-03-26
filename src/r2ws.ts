import type { Server } from "socket.io";

import {
  createLiveSession,
  createDeviceFileSession,
  closeSession,
  type R2Session,
} from "./lib/r2.ts";
import { ansiToHtml } from "./lib/ansi.ts";

type Ack = (err: string | null, result?: any) => void;

export function attachR2(io: Server) {
  io.of("/r2").on("connection", (socket) => {
    let session: R2Session | null = null;

    socket.on("open", async (params: Record<string, any>, ack: Ack) => {
      if (session) return ack("session already open");

      try {
        if (params.path || (params.apk && params.entry)) {
          session = await createDeviceFileSession({
            deviceId: params.deviceId,
            pid: params.pid,
            path: params.path,
            apk: params.apk,
            entry: params.entry,
          });
        } else if (params.arch) {
          session = await createLiveSession({
            deviceId: params.deviceId,
            pid: params.pid,
            arch: params.arch,
            platform: params.platform,
            pointerSize: params.pointerSize,
            pageSize: params.pageSize,
          });
        } else {
          return ack("invalid params: need path/apk+entry or arch");
        }

        ack(null, { id: session.id });
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        console.error("[r2ws] open failed:", msg);
        ack(msg);
      }
    });

    socket.on("cmd", async (command: string, output: string | null, ack: Ack) => {
      if (!session) return ack("no session");
      try {
        const wantHtml = output === "html";
        session.r2.rawCmd(`e scr.color=${wantHtml ? 3 : 0}`);
        const raw = await session.r2.cmd(command);
        session.r2.rawCmd("e scr.color=0");
        ack(null, wantHtml ? ansiToHtml(raw) : raw);
      } catch (e) {
        ack(e instanceof Error ? e.message : String(e));
      }
    });

    socket.on("disassemble", async (address: string, output: string | null, ack: Ack) => {
      if (!session) return ack("no session");
      try {
        const addr = BigInt(address);
        const wantHtml = output === "html";
        session.r2.rawCmd(`e scr.color=${wantHtml ? 3 : 0}`);
        const raw = await session.r2.disassembleFunction(addr);
        session.r2.rawCmd("e scr.color=0");
        ack(null, raw && wantHtml ? ansiToHtml(raw) : raw);
      } catch (e) {
        ack(e instanceof Error ? e.message : String(e));
      }
    });

    socket.on("graph", async (address: string, ack: Ack) => {
      if (!session) return ack("no session");
      try {
        const cfg = await session.r2.functionGraph(BigInt(address));
        ack(null, cfg);
      } catch (e) {
        ack(e instanceof Error ? e.message : String(e));
      }
    });

    socket.on("ic", (ack: Ack) => {
      if (!session) return ack("no session");
      try {
        ack(null, session.r2.rawCmd("ic"));
      } catch (e) {
        ack(e instanceof Error ? e.message : String(e));
      }
    });

    socket.on("strings", (ack: Ack) => {
      if (!session) return ack("no session");
      try {
        ack(null, session.r2.rawCmd("izj"));
      } catch (e) {
        ack(e instanceof Error ? e.message : String(e));
      }
    });

    socket.on("disconnect", () => {
      if (session) {
        console.info(`[r2ws] closing session ${session.id}`);
        closeSession(session.id);
        session = null;
      }
    });
  });
}
