import { io } from "socket.io-client";
import type { Platform } from "../types.ts";
import type { ClientOptions } from "./client.ts";

const DEFAULT_HOST = "localhost";
const DEFAULT_PORT = 31337;

export interface SessionParams {
  device: string;
  platform: Platform;
  mode: "app" | "daemon";
  bundle?: string;
  pid?: number;
  name?: string;
}

export interface RpcResult<T = unknown> {
  error: string | null;
  result: T;
}

function socketUrl(opts: ClientOptions): string {
  const host = opts.host ?? DEFAULT_HOST;
  const port = opts.port ?? DEFAULT_PORT;
  return `http://${host}:${port}`;
}

export async function rpc<T = unknown>(
  params: SessionParams,
  ns: string,
  method: string,
  args: unknown[] = [],
  opts: ClientOptions = {}
): Promise<T> {
  return new Promise((resolve, reject) => {
    const url = socketUrl(opts);
    const query: Record<string, string> = {
      device: params.device,
      platform: params.platform,
      mode: params.mode,
    };
    if (params.mode === "app" && params.bundle) {
      query.bundle = params.bundle;
    }
    if (params.mode === "daemon" && params.pid) {
      query.pid = String(params.pid);
    }
    if (params.name) {
      query.name = params.name;
    }

    const socket = io(`${url}/session`, { query, timeout: 15000 });

    socket.on("ready", () => {
      socket.emit("rpc", ns, method, args, (err: string | null, result: T) => {
        socket.disconnect();
        if (err) {
          reject(new Error(err));
        } else {
          resolve(result);
        }
      });
    });

    socket.on("connect_error", (e) => {
      reject(new Error(`Connection error: ${e.message}`));
    });

    socket.on("denied", () => {
      socket.disconnect();
      reject(new Error("Access denied"));
    });

    socket.on("invalid", () => {
      socket.disconnect();
      reject(new Error("Invalid session parameters"));
    });

    setTimeout(() => {
      socket.disconnect();
      reject(new Error("Connection timeout"));
    }, 15000);
  });
}

export const agent = {
  fs: {
    ls: (p: SessionParams, path: string, opts?: ClientOptions) => rpc(p, "fs", "ls", [path], opts),
    cat: (p: SessionParams, path: string, opts?: ClientOptions) => rpc(p, "fs", "text", [path], opts),
    rm: (p: SessionParams, path: string, opts?: ClientOptions) => rpc(p, "fs", "rm", [path], opts),
    cp: (p: SessionParams, src: string, dst: string, opts?: ClientOptions) => rpc(p, "fs", "cp", [src, dst], opts),
    mv: (p: SessionParams, src: string, dst: string, opts?: ClientOptions) => rpc(p, "fs", "mv", [src, dst], opts),
    mkdir: (p: SessionParams, path: string, opts?: ClientOptions) => rpc(p, "fs", "mkdirp", [path], opts),
    stat: (p: SessionParams, path: string, opts?: ClientOptions) => rpc(p, "fs", "attrs", [path], opts),
    roots: (p: SessionParams, opts?: ClientOptions) => rpc(p, "fs", "roots", [], opts),
  },
  app: {
    info: (p: SessionParams, opts?: ClientOptions) => rpc(p, "app", "info", [], opts),
    manifest: (p: SessionParams, opts?: ClientOptions) => rpc(p, "manifest", "xml", [], opts),
    entitlements: (p: SessionParams, opts?: ClientOptions) => rpc(p, "entitlements", "plist", [], opts),
    urls: (p: SessionParams, opts?: ClientOptions) => rpc(p, "info", "urls", [], opts),
  },
  checksec: {
    all: (p: SessionParams, opts?: ClientOptions) => rpc(p, "checksec", "all", [], opts),
    single: (p: SessionParams, name: string, opts?: ClientOptions) => rpc(p, "checksec", "single", [name], opts),
    main: (p: SessionParams, opts?: ClientOptions) => rpc(p, "checksec", "main", [], opts),
  },
  class: {
    list: (p: SessionParams, opts?: ClientOptions) => rpc(p, "classes", "list", [], opts),
    inspect: (p: SessionParams, name: string, opts?: ClientOptions) => rpc(p, "classes", "inspect", [name], opts),
  },
  hook: {
    list: (p: SessionParams, opts?: ClientOptions) => rpc(p, "hook", "list", [], opts),
    status: (p: SessionParams, opts?: ClientOptions) => rpc(p, "hook", "status", [], opts),
    start: (p: SessionParams, group: string, opts?: ClientOptions) => rpc(p, "hook", "start", [group], opts),
    stop: (p: SessionParams, group: string, opts?: ClientOptions) => rpc(p, "hook", "stop", [group], opts),
  },
  crypto: {
    status: (p: SessionParams, opts?: ClientOptions) => rpc(p, "crypto", "status", [], opts),
    start: (p: SessionParams, group: string, opts?: ClientOptions) => rpc(p, "crypto", "start", [group], opts),
    stop: (p: SessionParams, group: string, opts?: ClientOptions) => rpc(p, "crypto", "stop", [group], opts),
  },
  pin: {
    list: (p: SessionParams, opts?: ClientOptions) => rpc(p, "pins", "list", [], opts),
    start: (p: SessionParams, id: string, opts?: ClientOptions) => rpc(p, "pins", "start", [id], opts),
    stop: (p: SessionParams, id: string, opts?: ClientOptions) => rpc(p, "pins", "stop", [id], opts),
  },
  symbol: {
    modules: (p: SessionParams, opts?: ClientOptions) => rpc(p, "symbol", "modules", [], opts),
    exports: (p: SessionParams, path: string, opts?: ClientOptions) => rpc(p, "symbol", "exports", [path], opts),
    imports: (p: SessionParams, path: string, opts?: ClientOptions) => rpc(p, "symbol", "imports", [path, ""], opts),
    strings: (p: SessionParams, path: string, opts?: ClientOptions) => rpc(p, "symbol", "strings", [path], opts),
    symbols: (p: SessionParams, path: string, opts?: ClientOptions) => rpc(p, "symbol", "symbols", [path], opts),
    deps: (p: SessionParams, path: string, opts?: ClientOptions) => rpc(p, "symbol", "dependencies", [path], opts),
  },
  thread: {
    list: (p: SessionParams, opts?: ClientOptions) => rpc(p, "threads", "list", [], opts),
  },
  memory: {
    dump: (p: SessionParams, addr: string, size: number, opts?: ClientOptions) =>
      rpc(p, "memory", "dump", [addr, size], opts),
    scan: (p: SessionParams, pattern: string, opts?: ClientOptions) =>
      rpc(p, "memory", "scan", [pattern], opts),
    ranges: (p: SessionParams, opts?: ClientOptions) => rpc(p, "memory", "allocedRanges", [], opts),
  },
  lsof: (p: SessionParams, opts?: ClientOptions) => rpc(p, "lsof", "fds", [], opts),
  sqlite: {
    tables: (p: SessionParams, path: string, opts?: ClientOptions) => rpc(p, "sqlite", "tables", [path], opts),
    dump: (p: SessionParams, path: string, table: string, opts?: ClientOptions) =>
      rpc(p, "sqlite", "dump", [path, table], opts),
    query: (p: SessionParams, path: string, sql: string, opts?: ClientOptions) =>
      rpc(p, "sqlite", "query", [path, sql], opts),
  },
  android: {
    activities: (p: SessionParams, opts?: ClientOptions) => rpc(p, "activities", "list", [], opts),
    services: (p: SessionParams, opts?: ClientOptions) => rpc(p, "services", "list", [], opts),
    receivers: (p: SessionParams, opts?: ClientOptions) => rpc(p, "receivers", "list", [], opts),
    providers: (p: SessionParams, opts?: ClientOptions) => rpc(p, "provider", "list", [], opts),
    providerQuery: (p: SessionParams, uri: string, opts?: ClientOptions) =>
      rpc(p, "provider", "query", [uri], opts),
    keystore: (p: SessionParams, opts?: ClientOptions) => rpc(p, "keystore", "aliases", [], opts),
    keystoreInfo: (p: SessionParams, alias: string, opts?: ClientOptions) =>
      rpc(p, "keystore", "info", [alias], opts),
    deviceProps: (p: SessionParams, opts?: ClientOptions) => rpc(p, "device", "properties", [], opts),
  },
  ios: {
    keychain: (p: SessionParams, opts?: ClientOptions) => rpc(p, "keychain", "list", [], opts),
    cookies: (p: SessionParams, opts?: ClientOptions) => rpc(p, "cookies", "list", [], opts),
    userdefaults: (p: SessionParams, opts?: ClientOptions) => rpc(p, "userdefaults", "enumerate", [], opts),
    webviews: (p: SessionParams, opts?: ClientOptions) => rpc(p, "webview", "listWK", [], opts),
    jsc: (p: SessionParams, opts?: ClientOptions) => rpc(p, "jsc", "list", [], opts),
    geolocation: (p: SessionParams, lat: number, lng: number, opts?: ClientOptions) =>
      rpc(p, "geolocation", "fake", [lat, lng], opts),
    uidevice: (p: SessionParams, opts?: ClientOptions) => rpc(p, "uidevice", "info", [], opts),
    openUrl: (p: SessionParams, url: string, opts?: ClientOptions) => rpc(p, "url", "open", [url], opts),
  },
  script: {
    eval: (p: SessionParams, source: string, opts?: ClientOptions) =>
      rpc(p, "script", "evaluate", [source], opts),
  },
  rn: {
    list: (p: SessionParams, opts?: ClientOptions) => rpc(p, "rn", "list", [], opts),
    inject: (p: SessionParams, handle: number, arch: string, script: string, opts?: ClientOptions) =>
      rpc(p, "rn", "inject", [handle, arch, script], opts),
  },
  native: {
    list: (p: SessionParams, opts?: ClientOptions) => rpc(p, "native", "list", [], opts),
    start: (p: SessionParams, module: string, name: string, opts?: ClientOptions) =>
      rpc(p, "native", "start", [module, name], opts),
    stop: (p: SessionParams, module: string, name: string, opts?: ClientOptions) =>
      rpc(p, "native", "stop", [module, name], opts),
  },
};
