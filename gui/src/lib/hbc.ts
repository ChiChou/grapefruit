type Response = { id: number; ok: true; result?: any } | { id: number; ok: false; error: string };

export type WasmStatus = "idle" | "downloading" | "compiling" | "ready" | "failed";
export interface WasmState {
  status: WasmStatus;
  progress?: number;
}

let nextId = 0;
const pending = new Map<number, { resolve: (v: any) => void; reject: (e: Error) => void }>();

let worker: Worker | null = null;

const statusListeners = new Set<(state: WasmState) => void>();
let currentState: WasmState = { status: "idle" };

export function onStatus(fn: (state: WasmState) => void): () => void {
  statusListeners.add(fn);
  fn(currentState);
  return () => statusListeners.delete(fn);
}

function setStatus(state: WasmState) {
  currentState = state;
  for (const fn of statusListeners) fn(state);
}

function w(): Worker {
  if (!worker) {
    worker = new Worker(new URL("./hbc.worker.ts", import.meta.url), { type: "module" });
    worker.onmessage = (e: MessageEvent<Response>) => {
      const { id, ...rest } = e.data;

      // Status events from worker (id=-1)
      if (id === -1 && rest.ok && rest.result?.status) {
        setStatus(rest.result as WasmState);
        return;
      }

      const p = pending.get(id);
      if (!p) return;
      pending.delete(id);
      if (rest.ok) p.resolve(rest.result);
      else p.reject(new Error(rest.error));
    };
    worker.onerror = () => setStatus({ status: "failed" });
  }
  return worker;
}

function rpc<T = void>(msg: Record<string, any>, transfer?: Transferable[]): Promise<T> {
  const id = nextId++;
  return new Promise<T>((resolve, reject) => {
    pending.set(id, { resolve, reject });
    w().postMessage({ id, ...msg }, { transfer: transfer ?? [] });
  });
}

export function open(buffer: ArrayBuffer): Promise<void> {
  return rpc({ type: "open", buffer }, [buffer]);
}

export function close(): Promise<void> {
  return rpc({ type: "close" });
}

export interface AnalyzeResult {
  info: any;
  functions: any[];
  strings: any[];
  xrefs: { strings: Record<string, number[]>; functions: Record<string, number[]> };
}

export function analyze(): Promise<AnalyzeResult> {
  return rpc<AnalyzeResult>({ type: "analyze" });
}

export function disassemble(funcId?: number | null): Promise<string | null> {
  return rpc<string | null>({ type: "disassemble", funcId: funcId ?? undefined });
}

export function decompile(funcId?: number | null, opts?: { offsets?: boolean }): Promise<string | null> {
  return rpc<string | null>({ type: "decompile", funcId: funcId ?? undefined, offsets: opts?.offsets });
}

export function terminate(): void {
  if (worker) {
    worker.terminate();
    worker = null;
    for (const p of pending.values()) p.reject(new Error("Worker terminated"));
    pending.clear();
  }
}
