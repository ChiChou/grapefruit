import { randomUUID } from "node:crypto";

import type { Device, SpawnOptions } from "frida";

import frida from "../lib/xvii.ts";
import env from "../lib/env.ts";
import { agent } from "../lib/assets.ts";
import { check as restricted } from "../lib/regulation.ts";
import { Writer } from "../lib/log.ts";
import { fnv1a } from "../lib/hash.ts";
import { createPinStore } from "../lib/store/pins.ts";
import { NSURLStore } from "../lib/store/nsurl.ts";
import { HttpStore } from "../lib/store/http.ts";
import { HookStore } from "../lib/store/hooks.ts";
import { CryptoStore } from "../lib/store/crypto.ts";
import { FlutterStore } from "../lib/store/flutter.ts";
import { JNIStore } from "../lib/store/jni.ts";
import { XPCStore } from "../lib/store/xpc.ts";
import { HermesStore } from "../lib/store/hermes.ts";
import { PrivacyStore } from "../lib/store/privacy.ts";
import { setup as relay } from "../relay.ts";
import type { SessionInfo, Target } from "./protocol.ts";
import { check } from "./rpc.ts";
import type { SessionSocket, SessionStores } from "../types.ts";

const manager = frida.getDeviceManager();

const APP_TTL = parseInt(process.env.IGF_APP_SESSION_TTL_MS || "", 10) || 10 * 60 * 1000;
const INACTIVE_TTL =
  parseInt(process.env.IGF_INACTIVE_SESSION_TTL_MS || "", 10) || 2 * 60 * 1000;
const DAEMON_TTL =
  parseInt(process.env.IGF_DAEMON_SESSION_TTL_MS || "", 10) || 30 * 60 * 1000;

interface Live extends SessionInfo {
  script: Awaited<ReturnType<Awaited<ReturnType<Device["attach"]>>["createScript"]>>;
  session: Awaited<ReturnType<Device["attach"]>>;
  logger: Writer;
}

async function appPid(device: Device, bundleId: string, platform: Target["platform"]): Promise<number> {
  const match = await device.enumerateApplications({
    identifiers: [bundleId],
    scope: frida.Scope.Full,
  });

  const app = match.at(0);
  if (!app) throw new Error(`Application ${bundleId} not found on device`);

  const frontmost = await device.getFrontmostApplication();
  if (frontmost?.pid === app.pid) return app.pid;

  const devParams = await device.querySystemParameters();
  const opt: SpawnOptions = {};

  if (
    platform === "fruity" &&
    devParams.access === "full" &&
    devParams.os.id === "ios"
  ) {
    opt.env = { DISABLE_TWEAKS: "1" };
  }

  return device.spawn(bundleId, opt);
}

function key(target: Target): string {
  if (target.mode === "app") {
    return `app:${target.deviceId}:${target.platform}:${target.bundle}`;
  }
  return `daemon:${target.deviceId}:${target.platform}:${target.pid}`;
}

function stores(deviceId: string, identifier: string): SessionStores {
  return {
    nsurl: new NSURLStore(deviceId, identifier),
    http: new HttpStore(deviceId, identifier),
    hooks: new HookStore(deviceId, identifier),
    crypto: new CryptoStore(deviceId, identifier),
    flutter: new FlutterStore(deviceId, identifier),
    jni: new JNIStore(deviceId, identifier),
    xpc: new XPCStore(deviceId, identifier),
    hermes: new HermesStore(deviceId, identifier),
    privacy: new PrivacyStore(deviceId, identifier),
  };
}

function activeApp(s: Live): boolean {
  return s.mode === "app" && s.platform === "fruity" && s.state === "ready";
}

function ttl(s: Live): number {
  if (s.mode === "daemon") return DAEMON_TTL;
  if (s.lifecycle === "inactive" || s.lifecycle === "background") return INACTIVE_TTL;
  return APP_TTL;
}

export class Sessions {
  #sessions = new Map<string, Live>();

  constructor() {
    const timer = setInterval(() => this.gc(), 60 * 1000);
    timer.unref?.();
  }

  list(): SessionInfo[] {
    return [...this.#sessions.values()].map((s) => ({
      id: s.id,
      key: s.key,
      state: s.state,
      refs: s.refs,
      createdAt: s.createdAt,
      lastUsed: s.lastUsed,
      lifecycle: s.lifecycle,
      deviceId: s.deviceId,
      platform: s.platform,
      mode: s.mode,
      bundle: s.bundle,
      pid: s.pid,
      name: s.name,
    }));
  }

  async open(target: Target, replace = false): Promise<SessionInfo> {
    const s = await this.acquire({ target, replace });
    this.release(s);
    return this.info(s);
  }

  async rpc(
    params: { target?: Target; session?: string; replace?: boolean },
    ns: string,
    method: string,
    args: unknown[],
  ): Promise<unknown> {
    check(ns, method);
    const s = await this.acquire(params);
    try {
      const result = await s.script.exports.invoke(ns, method, args);
      s.lastUsed = Date.now();
      return result;
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      throw new Error(`RPC method ${ns}.${method} failed: ${msg}`);
    } finally {
      this.release(s);
    }
  }

  async close(id: string): Promise<boolean> {
    const s = this.#sessions.get(id);
    if (!s || s.state === "closing") return false;
    s.state = "closing";

    await this.savePins(s).catch((e) => {
      console.error("[igfd] failed to save pins:", e);
    });
    await s.script.unload().catch(() => {});
    await s.session.detach().catch(() => {});
    await s.logger.close();
    this.#sessions.delete(id);
    return true;
  }

  async gc(): Promise<number> {
    const now = Date.now();
    let n = 0;

    for (const s of [...this.#sessions.values()]) {
      if (s.refs > 0) continue;
      if (now - s.lastUsed <= ttl(s)) continue;
      console.info(`[igfd] closing idle session ${s.id}`);
      if (await this.close(s.id)) n++;
    }

    return n;
  }

  async shutdown() {
    await Promise.all([...this.#sessions.keys()].map((id) => this.close(id)));
  }

  async acquire(params: {
    target?: Target;
    session?: string;
    replace?: boolean;
  }): Promise<Live> {
    let s: Live | undefined;

    if (params.session) {
      s = this.#sessions.get(params.session);
      if (!s) throw new Error(`session ${params.session} not found`);
    } else {
      if (!params.target) throw new Error("target or session is required");
      const k = key(params.target);
      s = [...this.#sessions.values()].find((item) => item.key === k);
      if (!s) s = await this.create(params.target, params.replace ?? false);
    }

    if (s.state !== "ready") throw new Error(`session ${s.id} is ${s.state}`);
    s.refs++;
    s.lastUsed = Date.now();
    return s;
  }

  release(s: Live) {
    s.refs = Math.max(0, s.refs - 1);
    s.lastUsed = Date.now();
  }

  info(s: Live): SessionInfo {
    return this.list().find((item) => item.id === s.id)!;
  }

  async create(target: Target, replace: boolean): Promise<Live> {
    if (target.mode === "app") {
      if (!target.bundle) throw new Error("bundle is required for app sessions");
      if (restricted(target.bundle)) throw new Error("access denied");
    } else if (!target.pid) {
      throw new Error("pid is required for daemon sessions");
    }

    if (target.mode === "app" && target.platform === "fruity") {
      const other = [...this.#sessions.values()].find(
        (s) => activeApp(s) && s.deviceId === target.deviceId,
      );
      if (other && other.key !== key(target)) {
        if (other.refs > 0 && !replace) {
          throw new Error(
            `iOS app session ${other.id} is active; pass --replace to close it`,
          );
        }
        await this.close(other.id);
      }
    }

    const id = randomUUID();
    const k = key(target);
    const device = await manager.getDeviceById(target.deviceId, env.timeout);
    const pid =
      target.mode === "app"
        ? await appPid(device, target.bundle!, target.platform)
        : target.pid!;
    const fridaSession = await device.attach(pid);

    if (target.mode === "app") await device.resume(pid).catch(() => {});

    const identifier =
      target.mode === "app"
        ? target.bundle!
        : `${target.name || "pid"}-${fnv1a((target.name || "pid") + pid)}`;

    const logger = await Writer.open(target.deviceId, identifier);
    const script = await fridaSession.createScript(await agent(target.platform));

    const live: Live = {
      id,
      key: k,
      state: "opening",
      refs: 0,
      createdAt: Date.now(),
      lastUsed: Date.now(),
      deviceId: target.deviceId,
      platform: target.platform,
      mode: target.mode,
      bundle: target.bundle,
      pid,
      name: target.name,
      script,
      session: fridaSession,
      logger,
    };

    const socket = {
      emit: (event: string, ...args: unknown[]) => {
        if (event === "lifecycle") live.lifecycle = String(args[0]);
        return true;
      },
      disconnect: () => {
        if (live.state !== "closing") {
          live.state = "detached";
          void this.close(live.id);
        }
        return undefined;
      },
    } as unknown as SessionSocket;

    fridaSession.detached.connect(() => {
      if (live.state !== "closing") {
        live.state = "detached";
        void this.close(live.id);
      }
    });

    this.#sessions.set(id, live);
    relay(socket, script, logger, stores(target.deviceId, identifier));
    await script.load();
    await this.restorePins(live, identifier).catch((e) => {
      console.error("[igfd] failed to restore pins:", e);
    });
    live.state = "ready";
    live.lastUsed = Date.now();
    return live;
  }

  async restorePins(s: Live, identifier: string) {
    const rules = createPinStore(s.deviceId, identifier).load();
    if (rules?.length) await s.script.exports.restore(rules);
  }

  async savePins(s: Live) {
    const identifier =
      s.mode === "app" ? s.bundle! : `${s.name || "pid"}-${fnv1a((s.name || "pid") + s.pid)}`;
    const rules = await s.script.exports.snapshot();
    createPinStore(s.deviceId, identifier).save(rules);
  }
}
