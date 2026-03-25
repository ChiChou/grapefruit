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

function buildQuery(params: SessionParams): Record<string, string> {
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
  return query;
}

/**
 * One-shot RPC: connect, call, disconnect.
 * Fine for CLI commands that make a single call.
 */
export async function rpc<T = unknown>(
  params: SessionParams,
  ns: string,
  method: string,
  args: unknown[] = [],
  opts: ClientOptions = {}
): Promise<T> {
  return new Promise((resolve, reject) => {
    const url = socketUrl(opts);
    const query = buildQuery(params);

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
    data: (p: SessionParams, path: string, opts?: ClientOptions) => rpc(p, "fs", "data", [path], opts),
    plist: (p: SessionParams, path: string, opts?: ClientOptions) => rpc(p, "fs", "plist", [path], opts),
    preview: (p: SessionParams, path: string, opts?: ClientOptions) => rpc(p, "fs", "preview", [path], opts),
    rm: (p: SessionParams, path: string, opts?: ClientOptions) => rpc(p, "fs", "rm", [path], opts),
    cp: (p: SessionParams, src: string, dst: string, opts?: ClientOptions) => rpc(p, "fs", "cp", [src, dst], opts),
    mv: (p: SessionParams, src: string, dst: string, opts?: ClientOptions) => rpc(p, "fs", "mv", [src, dst], opts),
    mkdir: (p: SessionParams, path: string, opts?: ClientOptions) => rpc(p, "fs", "mkdirp", [path], opts),
    stat: (p: SessionParams, path: string, opts?: ClientOptions) => rpc(p, "fs", "attrs", [path], opts),
    access: (p: SessionParams, path: string, opts?: ClientOptions) => rpc(p, "fs", "access", [path], opts),
    roots: (p: SessionParams, opts?: ClientOptions) => rpc(p, "fs", "roots", [], opts),
    saveText: (p: SessionParams, path: string, content: string, opts?: ClientOptions) =>
      rpc(p, "fs", "saveText", [path, content], opts),
  },
  app: {
    info: (p: SessionParams, opts?: ClientOptions) => rpc(p, "app", "info", [], opts),
    manifest: (p: SessionParams, opts?: ClientOptions) => rpc(p, "manifest", "xml", [], opts),
    entitlements: (p: SessionParams, opts?: ClientOptions) => rpc(p, "entitlements", "plist", [], opts),
    urls: (p: SessionParams, opts?: ClientOptions) => rpc(p, "info", "urls", [], opts),
    plist: (p: SessionParams, opts?: ClientOptions) => rpc(p, "info", "plist", [], opts),
    processInfo: (p: SessionParams, opts?: ClientOptions) => rpc(p, "info", "processInfo", [], opts),
  },
  checksec: {
    all: (p: SessionParams, opts?: ClientOptions) => rpc(p, "checksec", "all", [], opts),
    single: (p: SessionParams, name: string, opts?: ClientOptions) => rpc(p, "checksec", "single", [name], opts),
    main: (p: SessionParams, opts?: ClientOptions) => rpc(p, "checksec", "main", [], opts),
  },
  class: {
    list: (p: SessionParams, opts?: ClientOptions) => rpc(p, "classes", "list", [], opts),
    inspect: (p: SessionParams, name: string, opts?: ClientOptions) => rpc(p, "classes", "inspect", [name], opts),
    constants: (p: SessionParams, name: string, opts?: ClientOptions) => rpc(p, "classes", "constants", [name], opts),
  },
  classdump: {
    list: (p: SessionParams, opts?: ClientOptions) => rpc(p, "classdump", "list", [], opts),
    classesForModule: (p: SessionParams, module: string, opts?: ClientOptions) =>
      rpc(p, "classdump", "classesForModule", [module], opts),
    inheritance: (p: SessionParams, name: string, opts?: ClientOptions) =>
      rpc(p, "classdump", "inheritance", [name], opts),
    inspect: (p: SessionParams, name: string, opts?: ClientOptions) =>
      rpc(p, "classdump", "inspect", [name], opts),
  },
  hook: {
    list: (p: SessionParams, opts?: ClientOptions) => rpc(p, "hook", "list", [], opts),
    status: (p: SessionParams, opts?: ClientOptions) => rpc(p, "hook", "status", [], opts),
    start: (p: SessionParams, group: string, opts?: ClientOptions) => rpc(p, "hook", "start", [group], opts),
    stop: (p: SessionParams, group: string, opts?: ClientOptions) => rpc(p, "hook", "stop", [group], opts),
    userHooks: (p: SessionParams, opts?: ClientOptions) => rpc(p, "hook", "userHooks", [], opts),
  },
  crypto: {
    status: (p: SessionParams, opts?: ClientOptions) => rpc(p, "crypto", "status", [], opts),
    available: (p: SessionParams, opts?: ClientOptions) => rpc(p, "crypto", "available", [], opts),
    start: (p: SessionParams, group: string, opts?: ClientOptions) => rpc(p, "crypto", "start", [group], opts),
    stop: (p: SessionParams, group: string, opts?: ClientOptions) => rpc(p, "crypto", "stop", [group], opts),
  },
  pin: {
    list: (p: SessionParams, opts?: ClientOptions) => rpc(p, "pins", "list", [], opts),
    active: (p: SessionParams, opts?: ClientOptions) => rpc(p, "pins", "active", [], opts),
    available: (p: SessionParams, opts?: ClientOptions) => rpc(p, "pins", "available", [], opts),
    start: (p: SessionParams, id: string, opts?: ClientOptions) => rpc(p, "pins", "start", [id], opts),
    stop: (p: SessionParams, id: string, opts?: ClientOptions) => rpc(p, "pins", "stop", [id], opts),
    snapshot: (p: SessionParams, opts?: ClientOptions) => rpc(p, "pins", "snapshot", [], opts),
    restore: (p: SessionParams, data: unknown, opts?: ClientOptions) => rpc(p, "pins", "restore", [data], opts),
  },
  symbol: {
    modules: (p: SessionParams, opts?: ClientOptions) => rpc(p, "symbol", "modules", [], opts),
    exports: (p: SessionParams, path: string, opts?: ClientOptions) => rpc(p, "symbol", "exports", [path], opts),
    imports: (p: SessionParams, path: string, opts?: ClientOptions) => rpc(p, "symbol", "imports", [path, ""], opts),
    importsGrouped: (p: SessionParams, path: string, opts?: ClientOptions) =>
      rpc(p, "symbol", "importsGrouped", [path], opts),
    strings: (p: SessionParams, path: string, opts?: ClientOptions) => rpc(p, "symbol", "strings", [path], opts),
    symbols: (p: SessionParams, path: string, opts?: ClientOptions) => rpc(p, "symbol", "symbols", [path], opts),
    deps: (p: SessionParams, path: string, opts?: ClientOptions) => rpc(p, "symbol", "dependencies", [path], opts),
    sections: (p: SessionParams, path: string, opts?: ClientOptions) => rpc(p, "symbol", "sections", [path], opts),
    resolve: (p: SessionParams, module: string, name: string, opts?: ClientOptions) =>
      rpc(p, "symbol", "resolve", [module, name], opts),
    symbolicate: (p: SessionParams, addr: string, opts?: ClientOptions) =>
      rpc(p, "symbol", "symbolicate", [addr], opts),
  },
  thread: {
    list: (p: SessionParams, opts?: ClientOptions) => rpc(p, "threads", "list", [], opts),
  },
  memory: {
    dump: (p: SessionParams, addr: string, size: number, opts?: ClientOptions) =>
      rpc(p, "memory", "dump", [addr, size], opts),
    scan: (p: SessionParams, pattern: string, opts?: ClientOptions) =>
      rpc(p, "memory", "scan", [pattern], opts),
    stopScan: (p: SessionParams, opts?: ClientOptions) => rpc(p, "memory", "stopScan", [], opts),
    ranges: (p: SessionParams, opts?: ClientOptions) => rpc(p, "memory", "allocedRanges", [], opts),
    addressInfo: (p: SessionParams, addr: string, opts?: ClientOptions) =>
      rpc(p, "memory", "addressInfo", [addr], opts),
  },
  lsof: (p: SessionParams, opts?: ClientOptions) => rpc(p, "lsof", "fds", [], opts),
  sqlite: {
    tables: (p: SessionParams, path: string, opts?: ClientOptions) => rpc(p, "sqlite", "tables", [path], opts),
    dump: (p: SessionParams, path: string, table: string, opts?: ClientOptions) =>
      rpc(p, "sqlite", "dump", [path, table], opts),
    query: (p: SessionParams, path: string, sql: string, opts?: ClientOptions) =>
      rpc(p, "sqlite", "query", [path, sql], opts),
  },
  il2cpp: {
    available: (p: SessionParams, opts?: ClientOptions) => rpc(p, "il2cpp", "available", [], opts),
    info: (p: SessionParams, opts?: ClientOptions) => rpc(p, "il2cpp", "info", [], opts),
    assemblies: (p: SessionParams, opts?: ClientOptions) => rpc(p, "il2cpp", "assemblies", [], opts),
    classes: (p: SessionParams, assembly: string, opts?: ClientOptions) =>
      rpc(p, "il2cpp", "classes", [assembly], opts),
    searchClasses: (p: SessionParams, query: string, opts?: ClientOptions) =>
      rpc(p, "il2cpp", "searchClasses", [query], opts),
    classDetail: (p: SessionParams, name: string, opts?: ClientOptions) =>
      rpc(p, "il2cpp", "classDetail", [name], opts),
    classDump: (p: SessionParams, name: string, opts?: ClientOptions) =>
      rpc(p, "il2cpp", "classDump", [name], opts),
    gcStats: (p: SessionParams, opts?: ClientOptions) => rpc(p, "il2cpp", "gcStats", [], opts),
    gcCollect: (p: SessionParams, opts?: ClientOptions) => rpc(p, "il2cpp", "gcCollect", [], opts),
    gcToggle: (p: SessionParams, enabled: boolean, opts?: ClientOptions) =>
      rpc(p, "il2cpp", "gcToggle", [enabled], opts),
    threads: (p: SessionParams, opts?: ClientOptions) => rpc(p, "il2cpp", "threads", [], opts),
  },
  android: {
    activities: (p: SessionParams, opts?: ClientOptions) => rpc(p, "activities", "list", [], opts),
    startActivity: (p: SessionParams, name: string, opts?: ClientOptions) =>
      rpc(p, "activities", "start", [name], opts),
    services: (p: SessionParams, opts?: ClientOptions) => rpc(p, "services", "list", [], opts),
    startService: (p: SessionParams, name: string, opts?: ClientOptions) =>
      rpc(p, "services", "start", [name], opts),
    stopService: (p: SessionParams, name: string, opts?: ClientOptions) =>
      rpc(p, "services", "stop", [name], opts),
    receivers: (p: SessionParams, opts?: ClientOptions) => rpc(p, "receivers", "list", [], opts),
    sendBroadcast: (p: SessionParams, action: string, opts?: ClientOptions) =>
      rpc(p, "receivers", "send", [action], opts),
    providers: (p: SessionParams, opts?: ClientOptions) => rpc(p, "provider", "list", [], opts),
    providerQuery: (p: SessionParams, uri: string, opts?: ClientOptions) =>
      rpc(p, "provider", "query", [uri], opts),
    providerInsert: (p: SessionParams, uri: string, values: unknown, opts?: ClientOptions) =>
      rpc(p, "provider", "insert", [uri, values], opts),
    providerUpdate: (p: SessionParams, uri: string, values: unknown, where: string, opts?: ClientOptions) =>
      rpc(p, "provider", "update", [uri, values, where], opts),
    providerDelete: (p: SessionParams, uri: string, where: string, opts?: ClientOptions) =>
      rpc(p, "provider", "del", [uri, where], opts),
    keystore: (p: SessionParams, opts?: ClientOptions) => rpc(p, "keystore", "aliases", [], opts),
    keystoreInfo: (p: SessionParams, alias: string, opts?: ClientOptions) =>
      rpc(p, "keystore", "info", [alias], opts),
    keystoreCert: (p: SessionParams, alias: string, opts?: ClientOptions) =>
      rpc(p, "keystore", "cert", [alias], opts),
    deviceInfo: (p: SessionParams, opts?: ClientOptions) => rpc(p, "device", "info", [], opts),
    deviceProps: (p: SessionParams, opts?: ClientOptions) => rpc(p, "device", "properties", [], opts),
    resources: (p: SessionParams, opts?: ClientOptions) => rpc(p, "resources", "list", [], opts),
    resource: (p: SessionParams, type: string, name: string, opts?: ClientOptions) =>
      rpc(p, "resources", "get", [type, name], opts),
    apkEntries: (p: SessionParams, apk: string, opts?: ClientOptions) =>
      rpc(p, "apk", "entries", [apk], opts),
    apkRead: (p: SessionParams, apk: string, entry: string, opts?: ClientOptions) =>
      rpc(p, "apk", "read", [apk, entry], opts),
    webview: {
      list: (p: SessionParams, opts?: ClientOptions) => rpc(p, "webview", "list", [], opts),
      setDebugging: (p: SessionParams, enabled: boolean, opts?: ClientOptions) =>
        rpc(p, "webview", "setDebugging", [enabled], opts),
      evaluate: (p: SessionParams, handle: string, code: string, opts?: ClientOptions) =>
        rpc(p, "webview", "evaluate", [handle, code], opts),
      navigate: (p: SessionParams, handle: string, url: string, opts?: ClientOptions) =>
        rpc(p, "webview", "navigate", [handle, url], opts),
    },
  },
  ios: {
    keychain: (p: SessionParams, opts?: ClientOptions) => rpc(p, "keychain", "list", [], opts),
    keychainRemove: (p: SessionParams, account: string, opts?: ClientOptions) =>
      rpc(p, "keychain", "remove", [account], opts),
    cookies: (p: SessionParams, opts?: ClientOptions) => rpc(p, "cookies", "list", [], opts),
    cookiesClear: (p: SessionParams, opts?: ClientOptions) => rpc(p, "cookies", "clear", [], opts),
    userdefaults: (p: SessionParams, opts?: ClientOptions) => rpc(p, "userdefaults", "enumerate", [], opts),
    userdefaultsUpdate: (p: SessionParams, key: string, value: unknown, opts?: ClientOptions) =>
      rpc(p, "userdefaults", "update", [key, value], opts),
    userdefaultsRemove: (p: SessionParams, key: string, opts?: ClientOptions) =>
      rpc(p, "userdefaults", "remove", [key], opts),
    webviews: (p: SessionParams, opts?: ClientOptions) => rpc(p, "webview", "listWK", [], opts),
    webviewsUI: (p: SessionParams, opts?: ClientOptions) => rpc(p, "webview", "listUI", [], opts),
    webviewEval: (p: SessionParams, handle: string, code: string, opts?: ClientOptions) =>
      rpc(p, "webview", "evaluate", [handle, code], opts),
    webviewNavigate: (p: SessionParams, handle: string, url: string, opts?: ClientOptions) =>
      rpc(p, "webview", "navigate", [handle, url], opts),
    webviewSetInspectable: (p: SessionParams, handle: string, enabled: boolean, opts?: ClientOptions) =>
      rpc(p, "webview", "setInspectable", [handle, enabled], opts),
    jsc: (p: SessionParams, opts?: ClientOptions) => rpc(p, "jsc", "list", [], opts),
    jscSetInspectable: (p: SessionParams, handle: string, enabled: boolean, opts?: ClientOptions) =>
      rpc(p, "jsc", "setInspectable", [handle, enabled], opts),
    jscDump: (p: SessionParams, handle: string, opts?: ClientOptions) =>
      rpc(p, "jsc", "dump", [handle], opts),
    jscRun: (p: SessionParams, handle: string, code: string, opts?: ClientOptions) =>
      rpc(p, "jsc", "run", [handle, code], opts),
    geolocation: (p: SessionParams, lat: number, lng: number, opts?: ClientOptions) =>
      rpc(p, "geolocation", "fake", [lat, lng], opts),
    geolocationDismiss: (p: SessionParams, opts?: ClientOptions) =>
      rpc(p, "geolocation", "dismiss", [], opts),
    uidevice: (p: SessionParams, opts?: ClientOptions) => rpc(p, "uidevice", "info", [], opts),
    openUrl: (p: SessionParams, url: string, opts?: ClientOptions) => rpc(p, "url", "open", [url], opts),
    ui: {
      dump: (p: SessionParams, opts?: ClientOptions) => rpc(p, "ui", "dump", [], opts),
      highlight: (p: SessionParams, addr: string, opts?: ClientOptions) =>
        rpc(p, "ui", "highlight", [addr], opts),
      dismissHighlight: (p: SessionParams, opts?: ClientOptions) =>
        rpc(p, "ui", "dismissHighlight", [], opts),
    },
    plugins: (p: SessionParams, opts?: ClientOptions) => rpc(p, "plugins", "list", [], opts),
    assetcatalog: {
      open: (p: SessionParams, path: string, opts?: ClientOptions) =>
        rpc(p, "assetcatalog", "open", [path], opts),
      variants: (p: SessionParams, path: string, name: string, opts?: ClientOptions) =>
        rpc(p, "assetcatalog", "variants", [path, name], opts),
      image: (p: SessionParams, path: string, name: string, opts?: ClientOptions) =>
        rpc(p, "assetcatalog", "image", [path, name], opts),
    },
  },
  script: {
    eval: (p: SessionParams, source: string, opts?: ClientOptions) =>
      rpc(p, "script", "evaluate", [source], opts),
  },
  rn: {
    arch: (p: SessionParams, opts?: ClientOptions) => rpc(p, "rn", "arch", [], opts),
    list: (p: SessionParams, opts?: ClientOptions) => rpc(p, "rn", "list", [], opts),
    inject: (p: SessionParams, handle: number, arch: string, script: string, opts?: ClientOptions) =>
      rpc(p, "rn", "inject", [handle, arch, script], opts),
  },
  native: {
    list: (p: SessionParams, opts?: ClientOptions) => rpc(p, "native", "list", [], opts),
    hook: (p: SessionParams, module: string, name: string, opts?: ClientOptions) =>
      rpc(p, "native", "hook", [module, name], opts),
    unhook: (p: SessionParams, module: string, name: string, opts?: ClientOptions) =>
      rpc(p, "native", "unhook", [module, name], opts),
  },
};
