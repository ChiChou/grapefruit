import type { Platform } from "../types.ts";

const DEFAULT_HOST = "localhost";
const DEFAULT_PORT = 31337;

export interface ClientOptions {
  host?: string;
  port?: number;
}

function baseUrl(opts: ClientOptions): string {
  const host = opts.host ?? DEFAULT_HOST;
  const port = opts.port ?? DEFAULT_PORT;
  return `http://${host}:${port}/api`;
}

export async function get<T>(path: string, opts: ClientOptions = {}): Promise<T> {
  const res = await fetch(`${baseUrl(opts)}${path}`);
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
  return res.json();
}

export async function post<T>(path: string, body?: unknown, opts: ClientOptions = {}): Promise<T> {
  const res = await fetch(`${baseUrl(opts)}${path}`, {
    method: "POST",
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
  const text = await res.text();
  return text ? JSON.parse(text) : (undefined as T);
}

export async function del<T>(path: string, opts: ClientOptions = {}): Promise<T> {
  const res = await fetch(`${baseUrl(opts)}${path}`, { method: "DELETE" });
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
  const text = await res.text();
  return text ? JSON.parse(text) : (undefined as T);
}

export async function getText(path: string, opts: ClientOptions = {}): Promise<string> {
  const res = await fetch(`${baseUrl(opts)}${path}`);
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
  return res.text();
}

export const rest = {
  devices: (opts: ClientOptions) => get("/devices", opts),
  apps: (device: string, opts: ClientOptions) => get(`/device/${device}/apps`, opts),
  processes: (device: string, opts: ClientOptions) => get(`/device/${device}/processes`, opts),
  deviceInfo: (device: string, opts: ClientOptions) => get(`/device/${device}/info`, opts),
  kill: (device: string, pid: number, opts: ClientOptions) => post(`/device/${device}/kill/${pid}`, undefined, opts),
  version: (opts: ClientOptions) => get("/version", opts),
  addRemote: (hostname: string, opts: ClientOptions) => post(`/devices/remote/${hostname}`, undefined, opts),
  removeRemote: (hostname: string, opts: ClientOptions) => del(`/devices/remote/${hostname}`, opts),
  icon: (device: string, bundle: string, opts: ClientOptions) =>
    getText(`/device/${device}/icon/${bundle}`, opts),

  hooks: (device: string, id: string, limit: number, opts: ClientOptions) =>
    get(`/hooks/${device}/${id}?limit=${limit}`, opts),
  clearHooks: (device: string, id: string, opts: ClientOptions) => del(`/hooks/${device}/${id}`, opts),
  crypto: (device: string, id: string, limit: number, opts: ClientOptions) =>
    get(`/history/crypto/${device}/${id}?limit=${limit}`, opts),
  clearCrypto: (device: string, id: string, opts: ClientOptions) => del(`/history/crypto/${device}/${id}`, opts),
  syslog: (device: string, id: string, opts: ClientOptions) => getText(`/logs/${device}/${id}/syslog`, opts),
  agentLog: (device: string, id: string, opts: ClientOptions) => getText(`/logs/${device}/${id}/agent`, opts),
  clearLogs: (device: string, id: string, opts: ClientOptions) => del(`/logs/${device}/${id}`, opts),
  http: (device: string, id: string, limit: number, opts: ClientOptions) =>
    get(`/history/http/${device}/${id}?limit=${limit}`, opts),
  httpHar: (device: string, id: string, opts: ClientOptions) => get(`/history/http/${device}/${id}/har`, opts),
  clearHttp: (device: string, id: string, opts: ClientOptions) => del(`/history/http/${device}/${id}`, opts),
  nsurl: (device: string, id: string, limit: number, opts: ClientOptions) =>
    get(`/history/nsurl/${device}/${id}?limit=${limit}`, opts),
  nsurlHar: (device: string, id: string, opts: ClientOptions) => get(`/history/nsurl/${device}/${id}/har`, opts),
  clearNsurl: (device: string, id: string, opts: ClientOptions) => del(`/history/nsurl/${device}/${id}`, opts),
  jni: (device: string, id: string, limit: number, opts: ClientOptions) =>
    get(`/history/jni/${device}/${id}?limit=${limit}`, opts),
  clearJni: (device: string, id: string, opts: ClientOptions) => del(`/history/jni/${device}/${id}`, opts),
  flutter: (device: string, id: string, limit: number, opts: ClientOptions) =>
    get(`/history/flutter/${device}/${id}?limit=${limit}`, opts),
  clearFlutter: (device: string, id: string, opts: ClientOptions) => del(`/history/flutter/${device}/${id}`, opts),
  xpc: (device: string, id: string, limit: number, opts: ClientOptions) =>
    get(`/history/xpc/${device}/${id}?limit=${limit}`, opts),
  clearXpc: (device: string, id: string, opts: ClientOptions) => del(`/history/xpc/${device}/${id}`, opts),
  privacy: (device: string, id: string, limit: number, opts: ClientOptions) =>
    get(`/history/privacy/${device}/${id}?limit=${limit}`, opts),
  clearPrivacy: (device: string, id: string, opts: ClientOptions) => del(`/history/privacy/${device}/${id}`, opts),
  hermes: (device: string, id: string, limit: number, opts: ClientOptions) =>
    get(`/hermes/${device}/${id}?limit=${limit}`, opts),
  hermesAnalyze: (device: string, id: string, hid: number, opts: ClientOptions) =>
    get(`/hermes/${device}/${id}/analyze/${hid}`, opts),
  hermesDecompile: (device: string, id: string, hid: number, fn: number, opts: ClientOptions) =>
    get(`/hermes/${device}/${id}/decompile/${hid}?fn=${fn}&offsets=1`, opts),
  hermesDisassemble: (device: string, id: string, hid: number, fn: number, opts: ClientOptions) =>
    get(`/hermes/${device}/${id}/disassemble/${hid}?fn=${fn}`, opts),
  hermesDelete: (device: string, id: string, hid: number, opts: ClientOptions) =>
    del(`/hermes/${device}/${id}/${hid}`, opts),
  clearHermes: (device: string, id: string, opts: ClientOptions) => del(`/hermes/${device}/${id}`, opts),
  pins: (device: string, id: string, opts: ClientOptions) => get(`/pins/${device}/${id}`, opts),
  clearPins: (device: string, id: string, opts: ClientOptions) => del(`/pins/${device}/${id}`, opts),
  llm: (prompt: string, opts: ClientOptions) => post("/llm", { prompt }, opts),
};
