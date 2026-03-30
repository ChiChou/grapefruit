import { useCallback, useEffect, useRef, useState } from "react";
import { io, type Socket } from "socket.io-client";
import type { CFGNode, CFGEdge } from "@/components/shared/CFGView";

export interface DexClass {
  addr: string;
  name: string;
  superclass: string;
  size: number;
  methods: DexMethod[];
  fields: DexField[];
}

export interface DexMethod {
  addr: string;
  index: number;
  flags: string;
  signature: string;
  name: string;
}

export interface DexField {
  addr: string;
  flags: string;
  signature: string;
  name: string;
}

export interface DexString {
  index: number;
  value: string;
  vaddr: number;
}

export interface StringXref {
  addr: string;
  fcnAddr: number;
  fcnName: string;
}

function parseIc(text: string): DexClass[] {
  const classes: DexClass[] = [];
  let current: DexClass | null = null;

  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    if (trimmed.includes(" class ") && trimmed.includes(" :: ")) {
      const classMatch = trimmed.match(
        /^(0x[0-9a-f]+)\s+\[.*?\]\s+(\d+)\s+java\s+class\s+\d+\s+(\S+)\s+::\s+(\S+)/,
      );
      if (classMatch) {
        current = {
          addr: classMatch[1],
          size: parseInt(classMatch[2], 10),
          name: classMatch[3],
          superclass: classMatch[4],
          methods: [],
          fields: [],
        };
        classes.push(current);
      }
      continue;
    }

    if (!current) continue;

    const methodMatch = trimmed.match(
      /^(0x[0-9a-f]+)\s+java\s+method\s+(\d+)\s+(\S+)\s+(\S+)/,
    );
    if (methodMatch) {
      const signature = methodMatch[4];
      const nameMatch = signature.match(/\.method\.([^(]+)/);
      current.methods.push({
        addr: methodMatch[1],
        index: parseInt(methodMatch[2], 10),
        flags: methodMatch[3],
        signature,
        name: nameMatch ? nameMatch[1] : signature,
      });
      continue;
    }

    const fieldMatch = trimmed.match(
      /^(0x[0-9a-f]+)\s+java\s+var\s+\d+\s+(\S+)\s+(\S+)/,
    );
    if (fieldMatch) {
      const sig = fieldMatch[3];
      const nameMatch = sig.match(/\.sfield_(.+?):|\.ifield_(.+?):/);
      current.fields.push({
        addr: fieldMatch[1],
        flags: fieldMatch[2],
        signature: sig,
        name: nameMatch ? (nameMatch[1] ?? nameMatch[2]) : sig,
      });
    }
  }

  return classes;
}

function socketCmd(
  socket: Socket,
  event: string,
  ...args: any[]
): Promise<any> {
  return new Promise((resolve, reject) => {
    socket.emit(event, ...args, (err: string | null, result?: any) => {
      if (err) reject(new Error(err));
      else resolve(result);
    });
  });
}

export function useDexR2Session(opts: {
  deviceId: string | undefined;
  pid: number | undefined;
  path?: string;
  apk?: string;
  entry?: string;
}) {
  const [classes, setClasses] = useState<DexClass[]>([]);
  const [strings, setStrings] = useState<DexString[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isReady, setIsReady] = useState(false);
  const socketRef = useRef<Socket | null>(null);

  useEffect(() => {
    if (!opts.deviceId || opts.pid === undefined) return;
    if (!opts.path && !(opts.apk && opts.entry)) return;

    setIsLoading(true);
    setError(null);

    const socket = io("/r2", { autoConnect: true });
    socketRef.current = socket;

    socket.on("connect", async () => {
      try {
        await socketCmd(socket, "open", {
          deviceId: opts.deviceId,
          pid: opts.pid,
          path: opts.path,
          apk: opts.apk,
          entry: opts.entry,
        });

        const [icText, strJson] = await Promise.all([
          socketCmd(socket, "ic") as Promise<string>,
          socketCmd(socket, "strings") as Promise<string>,
        ]);

        setClasses(parseIc(icText));

        try {
          const parsed: Array<{ vaddr: number; string: string }> = JSON.parse(strJson);
          setStrings(parsed.map((s, i) => ({ index: i, value: s.string, vaddr: s.vaddr })));
        } catch {
          setStrings([]);
        }

        setIsReady(true);
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        setIsLoading(false);
      }
    });

    socket.on("connect_error", (e) => {
      setError(e.message);
      setIsLoading(false);
    });

    return () => {
      socket.disconnect();
      socketRef.current = null;
    };
  }, [opts.deviceId, opts.pid, opts.path, opts.apk, opts.entry]);

  const cmd = useCallback(
    async (command: string, output?: "plain" | "html"): Promise<string> => {
      if (!socketRef.current) throw new Error("not connected");
      return socketCmd(socketRef.current, "cmd", command, output ?? null);
    },
    [],
  );

  const disassemble = useCallback(
    (address: string, output?: "plain" | "html") =>
      cmd(`s ${address}; af; pdf`, output),
    [cmd],
  );

  const cfg = useCallback(
    async (address: string): Promise<{ nodes: CFGNode[]; edges: CFGEdge[] } | null> => {
      const raw = await cmd(`s ${address}; af; agfj`);
      try {
        const arr = JSON.parse(raw);
        const fn = arr?.[0];
        if (!fn?.blocks) return null;

        const nodes: CFGNode[] = [];
        const edges: CFGEdge[] = [];
        for (const block of fn.blocks) {
          const id = `bb_${block.addr.toString(16)}`;
          const lines = (block.ops ?? []).map(
            (op: any) => op.disasm ?? `0x${op.offset.toString(16)}`,
          );
          nodes.push({ id, label: `0x${block.addr.toString(16)}`, lines });
          if (block.jump !== undefined) {
            edges.push({
              from: id,
              to: `bb_${block.jump.toString(16)}`,
              type: block.fail !== undefined ? "true" : "unconditional",
            });
          }
          if (block.fail !== undefined) {
            edges.push({
              from: id,
              to: `bb_${block.fail.toString(16)}`,
              type: "false",
            });
          }
        }
        return { nodes, edges };
      } catch {
        return null;
      }
    },
    [cmd],
  );

  const xrefs = useCallback(
    async (vaddr: number): Promise<StringXref[]> => {
      if (!vaddr) return [];
      const raw = await cmd(`axtj @ 0x${vaddr.toString(16)}`);
      try {
        const refs: Array<{ from: number; fcn_addr?: number; fcn_name?: string }> =
          JSON.parse(raw);
        return refs.map((r) => ({
          addr: `0x${(r.from ?? 0).toString(16)}`,
          fcnAddr: r.fcn_addr ?? 0,
          fcnName: r.fcn_name ?? "",
        }));
      } catch {
        return [];
      }
    },
    [cmd],
  );

  const funcXrefs = useCallback(
    async (address: string): Promise<StringXref[]> => {
      if (!address) return [];
      const raw = await cmd(`axtj @ ${address}`);
      try {
        const refs: Array<{ from: number; fcn_addr?: number; fcn_name?: string }> =
          JSON.parse(raw);
        return refs.map((r) => ({
          addr: `0x${(r.from ?? 0).toString(16)}`,
          fcnAddr: r.fcn_addr ?? 0,
          fcnName: r.fcn_name ?? "",
        }));
      } catch {
        return [];
      }
    },
    [cmd],
  );

  return {
    classes,
    strings,
    isLoading,
    error,
    isReady,
    cmd,
    disassemble,
    cfg,
    xrefs,
    funcXrefs,
  };
}
