/**
 * Light wrapper around the r2 Emscripten WASM module.
 *
 * r2.mjs + r2.wasm in public/ are downloaded from @frida/react-use-r2 npm
 * by scripts/fetch-r2.ts. They provide on-demand memory reads via an async
 * JS callback (Module.onRead), enabling r2 to lazily fetch pages from a
 * live Frida session as needed during analysis and disassembly.
 *
 * Based on @frida/react-use-r2 by Ole André Vadla Ravnås (MIT).
 */
import { useCallback, useEffect, useRef } from "react";

export type Platform = "windows" | "darwin" | "linux" | "freebsd" | "qnx";
export type Architecture = "ia32" | "x64" | "arm" | "arm64" | "mips";
export type ReadRequestHandler = (
  address: bigint,
  size: number,
) => Promise<Uint8Array | null>;

export interface R2Source {
  platform: Platform;
  arch: Architecture;
  pointerSize: number;
  pageSize: number;
  onReadRequest: ReadRequestHandler;
}

export interface CommandOptions {
  output?: "plain" | "html";
}

interface R2Module {
  ccall(
    ident: string,
    returnType: string,
    argTypes: string[],
    args: unknown[],
    opts?: { async: boolean },
  ): unknown;
  cwrap(
    ident: string,
    returnType: string,
    argTypes: string[],
    opts?: { async: boolean },
  ): (...args: unknown[]) => unknown;
  UTF8ToString(ptr: number): string;
  _free(ptr: number): void;
}

interface CommandRequest {
  command: string;
  options: CommandOptions;
  onComplete(result: string): void;
}

let state: "unloaded" | "loading" | "loaded" | "executing-command" = "unloaded";
let r2Module: R2Module | null = null;
const pendingCommands: CommandRequest[] = [];
const cachedPages = new Map<bigint, Uint8Array | null>([[0n, null]]);

export function useR2({ source }: { source?: R2Source } = {}) {
  const sourceRef = useRef<R2Source | undefined>(undefined);

  useEffect(() => {
    if (source === undefined) return;
    sourceRef.current = source;
    if (state === "unloaded") {
      state = "loading";
      loadR2(sourceRef as React.RefObject<R2Source>);
    }
  });

  const executeR2Command = useCallback(
    (command: string, options: CommandOptions = {}) => {
      return new Promise<string>((resolve) => {
        pendingCommands.push({ command, options, onComplete: resolve });
        maybeProcessPendingCommands();
      });
    },
    [],
  );

  return { executeR2Command };
}

async function loadR2(sourceRef: React.RefObject<R2Source>) {
  // r2.mjs + r2.wasm are built by scripts/build-r2-wasm.sh
  const mod = await import(/* @vite-ignore */ new URL("/r2.mjs", window.location.origin).href);
  const loadR2Module = mod.default as (opts: unknown) => Promise<R2Module>;

  const r2 = (await loadR2Module({
    offset: "0",
    async onRead(offset: string, size: number): Promise<Uint8Array> {
      const address = BigInt(offset);
      const pageSize = BigInt(sourceRef.current!.pageSize);

      const firstPage = pageStart(address, pageSize);
      const lastPage = pageStart(address + BigInt(size) - 1n, pageSize);
      const pageAfterLastPage = lastPage + pageSize;
      const numPages = (pageAfterLastPage - firstPage) / pageSize;

      let allInCache = true;
      for (
        let page = firstPage;
        page !== pageAfterLastPage;
        page += pageSize
      ) {
        const entry = cachedPages.get(page);
        if (entry === null) throw new Error("read failed");
        if (entry === undefined) {
          allInCache = false;
          break;
        }
      }

      if (!allInCache) {
        try {
          const block = await sourceRef.current!.onReadRequest(
            firstPage,
            Number(numPages * pageSize),
          );
          if (!block) throw new Error("read failed");
          for (
            let page = firstPage;
            page !== pageAfterLastPage;
            page += pageSize
          ) {
            const off = page - firstPage;
            cachedPages.set(
              page,
              block.slice(Number(off), Number(off + pageSize)),
            );
          }
        } catch (e) {
          for (
            let page = firstPage;
            page !== pageAfterLastPage;
            page += pageSize
          ) {
            cachedPages.set(page, null);
          }
          throw e;
        }
      }

      const result = new Uint8Array(size);
      let resultOffset = 0;
      for (
        let page = firstPage;
        page !== pageAfterLastPage;
        page += pageSize
      ) {
        const remaining = size - resultOffset;
        const chunkSize = remaining > pageSize ? Number(pageSize) : remaining;
        const fromOffset = Number(
          page === firstPage ? address % pageSize : 0n,
        );
        const pageData = cachedPages.get(page)!;
        result.set(pageData.slice(fromOffset, fromOffset + chunkSize), resultOffset);
        resultOffset += chunkSize;
      }
      return result;
    },
  })) as R2Module;

  const { platform, arch, pointerSize } = sourceRef.current!;
  await r2.ccall(
    "r2_open",
    "void",
    ["string", "string", "int"],
    [platform, archFromFrida(arch), pointerSize * 8],
    { async: true },
  );

  state = "loaded";
  r2Module = r2;
  maybeProcessPendingCommands();
}

function pageStart(address: bigint, pageSize: bigint): bigint {
  return address - (address % pageSize);
}

async function maybeProcessPendingCommands() {
  if (state !== "loaded") return;

  state = "executing-command";
  const r = r2Module!;
  const evaluate = r.cwrap("r2_execute", "number", ["string", "number"], {
    async: true,
  }) as (cmd: string, html: number) => Promise<number>;

  let req: CommandRequest | undefined;
  while ((req = pendingCommands.shift()) !== undefined) {
    const { output = "html" } = req.options;
    const rawResult = await evaluate(req.command, output === "html" ? 1 : 0);
    try {
      req.onComplete(r.UTF8ToString(rawResult));
    } finally {
      r._free(rawResult);
    }
  }

  state = "loaded";
}

function archFromFrida(arch: Architecture): string {
  switch (arch) {
    case "ia32":
    case "x64":
      return "x86";
    case "arm64":
      return "arm";
    default:
      return arch;
  }
}
