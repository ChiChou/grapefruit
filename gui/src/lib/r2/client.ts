/**
 * RPC client for the radare2 Web Worker.
 * Same pattern as hbc.ts — singleton worker, promise-based RPC.
 */

type Response = { id: number; ok: true; result?: any } | { id: number; ok: false; error: string };

export type R2Status = "idle" | "downloading" | "cached" | "compiling" | "ready" | "failed";
export interface R2State {
  status: R2Status;
  progress?: number;
}

let nextId = 0;
const pending = new Map<number, { resolve: (v: any) => void; reject: (e: Error) => void }>();

let worker: Worker | null = null;

const statusListeners = new Set<(state: R2State) => void>();
let currentState: R2State = { status: "idle" };

export function onStatus(fn: (state: R2State) => void): () => void {
  statusListeners.add(fn);
  fn(currentState);
  return () => statusListeners.delete(fn);
}

function setStatus(state: R2State) {
  currentState = state;
  for (const fn of statusListeners) fn(state);
}

function w(): Worker {
  if (!worker) {
    worker = new Worker(new URL("./r2.worker.ts", import.meta.url), { type: "module" });
    worker.onmessage = (e: MessageEvent<Response>) => {
      const { id, ...rest } = e.data;

      // Status events from worker (id=-1)
      if (id === -1 && rest.ok && rest.result?.status) {
        setStatus(rest.result as R2State);
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

export function init(opts?: { arch?: string; bits?: number; os?: string }): Promise<void> {
  return rpc({ type: "init", ...opts });
}

export function loadFile(name: string, data: ArrayBuffer): Promise<void> {
  return rpc({ type: "loadFile", name, data }, [data]);
}

export function cmd(command: string): Promise<string> {
  return rpc<string>({ type: "cmd", command });
}

export function writeMemory(address: string, data: ArrayBuffer): Promise<void> {
  return rpc({ type: "writeMemory", address, data }, [data]);
}

export function close(): Promise<void> {
  return rpc({ type: "close" });
}

export function terminate(): void {
  if (worker) {
    worker.terminate();
    worker = null;
    for (const p of pending.values()) p.reject(new Error("Worker terminated"));
    pending.clear();
    setStatus({ status: "idle" });
  }
}
