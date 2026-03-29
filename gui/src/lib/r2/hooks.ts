/**
 * React hooks for browser-side radare2 analysis.
 * Replaces use-r2-session.ts (live) and use-dex-r2.ts (DEX file).
 */
import { useCallback, useEffect, useRef, useState } from "react";
import * as r2 from "./client";
import * as ansi from "@/lib/ansi";
import type { CFGNode, CFGEdge } from "@/components/shared/CFGView";

// Re-export types from old use-dex-r2.ts for compatibility
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

export interface R2Function {
  addr: string;
  name: string;
  size: number;
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

/**
 * Hook for static DEX/APK file analysis in the browser.
 * Replaces useDexR2Session (Socket.IO).
 */
export function useR2File(opts: {
  data: ArrayBuffer | null;
  name: string;
}) {
  const [binType, setBinType] = useState("");
  const [arch, setArch] = useState("");
  const [classes, setClasses] = useState<DexClass[]>([]);
  const [functions, setFunctions] = useState<R2Function[]>([]);
  const [strings, setStrings] = useState<DexString[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isReady, setIsReady] = useState(false);
  const ready = useRef(false);

  useEffect(() => {
    if (!opts.data) return;

    let cancelled = false;
    setIsLoading(true);
    setError(null);

    (async () => {
      try {
        await r2.init();
        if (cancelled) return;

        const copy = opts.data!.slice(0);
        await r2.loadFile(opts.name, copy);
        if (cancelled) return;

        const [icText, aflJson, strJson, infoJson] = await Promise.all([
          r2.cmd("ic"),
          r2.cmd("aflj"),
          r2.cmd("izj"),
          r2.cmd("ij"),
        ]);
        if (cancelled) return;

        try {
          const info = JSON.parse(infoJson);
          setBinType(info?.bin?.type ?? info?.core?.type ?? "");
          setArch(info?.bin?.arch ?? "");
        } catch { /* ignore */ }

        setClasses(parseIc(icText));

        try {
          const parsed = JSON.parse(aflJson);
          const fns: R2Function[] = Array.isArray(parsed)
            ? parsed.map((f: any) => ({
                addr: `0x${(f.offset ?? f.addr ?? 0).toString(16)}`,
                name: f.name ?? `fcn.${(f.offset ?? 0).toString(16)}`,
                size: f.size ?? 0,
              }))
            : [];
          setFunctions(fns);
        } catch {
          setFunctions([]);
        }

        try {
          const parsed: Array<{ vaddr: number; string: string }> = JSON.parse(strJson);
          setStrings(parsed.map((s, i) => ({ index: i, value: s.string, vaddr: s.vaddr })));
        } catch {
          setStrings([]);
        }

        ready.current = true;
        setIsReady(true);
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      } finally {
        if (!cancelled) setIsLoading(false);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [opts.data, opts.name]);

  const cmd = useCallback(
    async (command: string, output?: "plain" | "html"): Promise<string> => {
      if (!ready.current) throw new Error("not ready");
      if (output === "html") {
        await r2.cmd("e scr.color=1");
        const raw = await r2.cmd(command);
        await r2.cmd("e scr.color=0");
        return ansi.toHtml(raw);
      }
      return r2.cmd(command);
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
        return refs.map((ref) => ({
          addr: `0x${(ref.from ?? 0).toString(16)}`,
          fcnAddr: ref.fcn_addr ?? 0,
          fcnName: ref.fcn_name ?? "",
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
        return refs.map((ref) => ({
          addr: `0x${(ref.from ?? 0).toString(16)}`,
          fcnAddr: ref.fcn_addr ?? 0,
          fcnName: ref.fcn_name ?? "",
        }));
      } catch {
        return [];
      }
    },
    [cmd],
  );

  return { binType, arch, classes, functions, strings, isLoading, error, isReady, cmd, disassemble, cfg, xrefs, funcXrefs };
}

/**
 * Hook for live memory analysis in the browser.
 * Replaces useR2Session (Socket.IO).
 */
export function useR2Live(opts: {
  arch: string;
  bits: number;
  os: string;
  /** Provided by caller from agent RPC: api.memory.dump(addr, size) */
  readMemory: (address: string, size: number) => Promise<ArrayBuffer | null>;
  enabled?: boolean;
}) {
  const [isReady, setIsReady] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const readMemoryRef = useRef(opts.readMemory);
  readMemoryRef.current = opts.readMemory;
  const pageCache = useRef(new Map<string, boolean>());

  useEffect(() => {
    if (opts.enabled === false) return;

    let cancelled = false;
    setError(null);

    (async () => {
      try {
        await r2.init({ arch: opts.arch, bits: opts.bits, os: opts.os });
        if (!cancelled) setIsReady(true);
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [opts.arch, opts.bits, opts.os, opts.enabled]);

  // Prefetch and map memory pages before analysis
  const mapMemory = useCallback(
    async (address: bigint, size: number) => {
      const pageSize = 4096n;
      const start = address - (address % pageSize);
      const end = address + BigInt(size);
      const endAligned = end % pageSize === 0n ? end : end + pageSize - (end % pageSize);

      for (let page = start; page < endAligned; page += pageSize) {
        const key = page.toString(16);
        if (pageCache.current.has(key)) continue;

        const data = await readMemoryRef.current(`0x${page.toString(16)}`, Number(pageSize));
        if (!data) {
          pageCache.current.set(key, false);
          continue;
        }

        await r2.writeMemory(`0x${page.toString(16)}`, data);
        pageCache.current.set(key, true);
      }
    },
    [],
  );

  const cmd = useCallback(
    async (command: string, output?: "plain" | "html"): Promise<string> => {
      // Prefetch memory for address patterns
      const addrMatch = command.match(/(?:@|^s)\s*(0x[0-9a-fA-F]+)/);
      if (addrMatch) {
        await mapMemory(BigInt(addrMatch[1]), 4096 * 4);
      }

      if (output === "html") {
        await r2.cmd("e scr.color=1");
        const result = await r2.cmd(command);
        await r2.cmd("e scr.color=0");
        return result;
      }
      return r2.cmd(command);
    },
    [mapMemory],
  );

  const analyze = useCallback(
    async (address: string) => {
      const addr = BigInt(address);
      await mapMemory(addr, 4096 * 4);

      // Iterative analysis: map jump targets
      for (let round = 0; round < 10; round++) {
        await r2.cmd(`af- @ ${address}`);
        await r2.cmd(`af @ ${address}`);
        const raw = await r2.cmd(`afbj @ ${address}`);

        let blocks: Array<{ addr: number; size: number; jump?: number; fail?: number }>;
        try {
          blocks = JSON.parse(raw);
        } catch {
          return null;
        }
        if (!blocks?.length) return null;

        let mapped = 0;
        for (const b of blocks) {
          for (const target of [b.addr + b.size, b.jump, b.fail]) {
            if (target == null || target === -1) continue;
            const tPage = BigInt(target) - (BigInt(target) % 4096n);
            if (!pageCache.current.has(tPage.toString(16))) {
              await mapMemory(BigInt(target), 4096 * 4);
              mapped++;
            }
          }
        }
        if (mapped === 0) return blocks;
      }

      const final = await r2.cmd(`afbj @ ${address}`);
      try { return JSON.parse(final); } catch { return null; }
    },
    [mapMemory],
  );

  const disassemble = useCallback(
    async (address: string, output?: "plain" | "html"): Promise<string | null> => {
      await analyze(address);
      return cmd(`pdf @ ${address}`, output);
    },
    [analyze, cmd],
  );

  const graph = useCallback(
    async (address: string): Promise<any> => {
      await analyze(address);
      const raw = await r2.cmd(`agfj @ ${address}`);
      try {
        const arr = JSON.parse(raw);
        return arr?.[0] ?? null;
      } catch {
        return null;
      }
    },
    [analyze],
  );

  return { cmd, analyze, disassemble, graph, isReady, error };
}
