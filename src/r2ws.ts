import type { Server } from "socket.io";

import {
  openLive,
  close,
  type R2Session,
} from "./lib/r2.ts";
import * as ansi from "./lib/ansi.ts";

type Ack = (err: string | null, result?: any) => void;

const R2_THEME = [
  "ecd",
  "ec addr bblack",     // 90  addresses / offsets
  "ec fname yellow",    // 33  function names
  "ec label yellow",    // 33  labels
  "ec flag byellow",    // 93  flags
  "ec fline bblack",    // 90  function boundary lines
  "ec flow green",      // 32  flow lines
  "ec flow2 bblack",    // 90  secondary flow
  "ec comment blue",    // 34  comments
  "ec usrcmt blue",     // 34  user comments
  "ec mov white",       // 37  mov instructions
  "ec jmp green",       // 32  jump
  "ec cjmp bgreen",     // 92  conditional jump
  "ec ujmp green",      // 32  unconditional jump
  "ec call magenta",    // 35  call
  "ec ucall bmagenta",  // 95  indirect call
  "ec ret red",         // 31  return
  "ec nop bblack",      // 90  nop
  "ec num cyan",        // 36  numeric literals
  "ec reg bcyan",       // 96  registers
  "ec creg bred",       // 91  modified registers
  "ec args bcyan",      // 96  arguments
  "ec cmp bblue",       // 94  compare
  "ec math blue",       // 34  math ops
  "ec push cyan",       // 36  push
  "ec pop cyan",        // 36  pop
  "ec trap red",        // 31  trap
  "ec swi red",         // 31  software interrupt
  "ec other bblack",    // 90  other
  "ec bin bblack",      // 90  binary
  "ec btext white",     // 37  text section
  "ec help yellow",     // 33  help
  "ec input white",     // 37  input
  "ec var bcyan",       // 96  variables
  "ec var.type yellow", // 33  variable types
  "ec var.addr bblack", // 90  variable addresses
  "ec var.name bcyan",  // 96  variable names
  "ec linehl bblack",
].join("; ");

export function attachR2(io: Server) {
  io.of("/r2").on("connection", (socket) => {
    let session: R2Session | null = null;

    socket.on("open", async (params: Record<string, any>, ack: Ack) => {
      if (session) return ack("session already open");

      try {
        if (params.arch) {
          session = await openLive({
            deviceId: params.deviceId,
            pid: params.pid,
            arch: params.arch,
            platform: params.platform,
            pointerSize: params.pointerSize,
            pageSize: params.pageSize,
          });
        } else {
          return ack("invalid params: need arch for live session");
        }

        session.r2.rawCmd(R2_THEME);
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
        session.r2.rawCmd(`e scr.color=${wantHtml ? 1 : 0}`);
        const raw = await session.r2.cmd(command);
        session.r2.rawCmd("e scr.color=0");
        ack(null, wantHtml ? ansi.toHtml(raw) : raw);
      } catch (e) {
        ack(e instanceof Error ? e.message : String(e));
      }
    });

    socket.on("disassemble", async (address: string, output: string | null, ack: Ack) => {
      if (!session) return ack("no session");
      try {
        const addr = BigInt(address);
        const wantHtml = output === "html";
        session.r2.rawCmd(`e scr.color=${wantHtml ? 1 : 0}`);
        const raw = await session.r2.disassembleFunction(addr);
        session.r2.rawCmd("e scr.color=0");
        ack(null, raw && wantHtml ? ansi.toHtml(raw) : raw);
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

    socket.on("disconnect", () => {
      if (session) {
        console.info(`[r2ws] closing session ${session.id}`);
        close(session.id);
        session = null;
      }
    });
  });
}
