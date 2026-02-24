import { SessionDetachReason, type SpawnOptions, type Device } from "frida";

import frida from "./lib/xvii.ts";
import env from "./lib/env.ts";
import { agent } from "./lib/assets.ts";
import { check as isRestrictedBundle } from "./lib/regulation.ts";
import { LogWriter } from "./lib/log-writer.ts";
import { fnv1a } from "./lib/hash.ts";
import { NSURLStore } from "./lib/store/nsurl.ts";
import { HookStore } from "./lib/store/hooks.ts";
import { CryptoStore } from "./lib/store/crypto.ts";
import { FlutterStore } from "./lib/store/flutter.ts";
import { JNIStore } from "./lib/store/jni.ts";
import { XPCStore } from "./lib/store/xpc.ts";
import { HermesStore } from "./lib/store/hermes.ts";
import { createTapStore } from "./lib/store/taps.ts";
import { setup as setupRelay } from "./relay.ts";
import type {
  Platform,
  SessionParams,
  SessionSocket,
  SessionStores,
} from "./types.ts";

const manager = frida.getDeviceManager();

export { manager };

async function resolveAppPid(
  device: Device,
  bundleId: string,
  platform: Platform,
): Promise<number> {
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

  if (platform === "fruity") {
    if (devParams.access === "full" && devParams.os.id === "ios") {
      opt.env = {
        DISABLE_TWEAKS: "1", // workaround for ellekit crash
      };
    }
  }

  return device.spawn(bundleId, opt);
}

function rpcErrorMessage(ns: string, method: string, err: unknown): string {
  const msg = err instanceof Error ? err.message : String(err);
  return `RPC method ${ns}.${method} failed: ${msg}`;
}

function setupSocketHandlers(
  socket: SessionSocket,
  script: Awaited<
    ReturnType<typeof import("frida").Session.prototype.createScript>
  >,
  session: Awaited<ReturnType<typeof import("frida").Device.prototype.attach>>,
  logger: LogWriter,
  tapStore: ReturnType<typeof createTapStore>,
) {
  session.detached.connect((reason, crash) => {
    console.error("session detached:", reason, crash);
    switch (reason) {
      case SessionDetachReason.ApplicationRequested:
        break;
      case SessionDetachReason.DeviceLost:
        console.error("device lost");
        break;
      case SessionDetachReason.ProcessTerminated:
      case SessionDetachReason.ProcessReplaced:
        console.error("process was terminated or replaced");
    }
    socket.emit("detached", reason as string);
    socket.disconnect(true);
  });

  socket
    .on("rpc", (ns, method, args, ack) => {
      if (
        typeof ns !== "string" ||
        typeof method !== "string" ||
        !Array.isArray(args)
      ) {
        console.warn(`invalid RPC call ${ns}.${method}, dropping`, args);
        return;
      }

      console.info(`RPC method: ${ns}.${method}`, ...args);
      script.exports
        .invoke(ns, method, args)
        .then(
          (result) => ack(null, result),
          (err: Error) => {
            console.error(`RPC method ${method} failed:`, err);
            ack(rpcErrorMessage(ns, method, err), null);
          },
        )
        .then(() => {
          // Auto-persist after tap toggles (runs on success OR failure,
          // because start() may partially succeed before throwing)
          if (ns === "taps" && (method === "start" || method === "stop")) {
            script.exports
              .snapshot()
              .then((snap: any) => tapStore.save(snap))
              .catch((e: unknown) =>
                console.warn("Failed to persist tap snapshot:", e),
              );
          }
        })
        .catch((err: Error) => {
          console.error(`RPC method ${method} failed:`, err);
          ack(rpcErrorMessage(ns, method, err), null);
        });
    })
    .on("eval", (source, name, ack) => {
      console.info(`evaluating script: ${name}`);
      script.exports
        .invoke("script", "evaluate", [source, name])
        .then((result: unknown) => ack(null, result))
        .catch((err: Error) =>
          ack(rpcErrorMessage("script", "evaluate", err), null),
        );
    })
    .on("clearLog", (type, ack) => {
      logger
        .empty(type)
        .then(() => ack(null, true))
        .catch((err) =>
          ack(rpcErrorMessage("log", "clearLog", err), null),
        );
    })
    .on("disconnect", () => {
      console.info("socket disconnected");
      script
        .unload()
        .finally(() => session.detach())
        .finally(() => logger.close());
    });
}

export function parse(query: Record<string, unknown>): SessionParams | null {
  const { device, platform, mode, bundle, pid, name } = query;

  if (typeof device !== "string") return null;
  if (platform !== "fruity" && platform !== "droid") return null;
  if (mode !== "app" && mode !== "daemon") return null;

  if (mode === "app" && typeof bundle !== "string") return null;
  if (mode === "daemon" && typeof pid !== "string") return null;

  return {
    deviceId: device,
    platform: platform as Platform,
    mode: mode as "app" | "daemon",
    bundle: mode === "app" ? (bundle as string) : undefined,
    pid: mode === "daemon" ? parseInt(pid as string, 10) : undefined,
    name: typeof name === "string" ? name : undefined,
  };
}

export async function connect(socket: SessionSocket, params: SessionParams) {
  const {
    platform,
    mode,
    deviceId,
    bundle,
    pid: targetPid,
    name: processName,
  } = params;
  const device = await manager.getDeviceById(deviceId, env.timeout);

  let pid: number;
  if (mode === "app") {
    if (!bundle) throw new Error("bundle is required for app mode");

    if (isRestrictedBundle(bundle)) {
      socket.emit("denied");
      setTimeout(() => socket.disconnect(true), 100);
      return;
    }

    pid = await resolveAppPid(device, bundle, platform);
  } else {
    if (!targetPid) throw new Error("pid is required for daemon mode");
    pid = targetPid;
  }

  const session = await device.attach(pid);

  if (mode === "app") {
    await device.resume(pid).catch(() => {});
  }

  // Compute project identifier
  let identifier: string;
  if (mode === "app") {
    identifier = bundle!;
  } else {
    const pname = processName || `pid`;
    identifier = `${pname}-${fnv1a(pname + pid)}`;
  }

  // Create store instances
  const stores: SessionStores = {
    nsurl: new NSURLStore(deviceId, identifier),
    hooks: new HookStore(deviceId, identifier),
    crypto: new CryptoStore(deviceId, identifier),
    flutter: new FlutterStore(deviceId, identifier),
    jni: new JNIStore(deviceId, identifier),
    xpc: new XPCStore(deviceId, identifier),
    hermes: new HermesStore(deviceId, identifier),
  };

  const logHandles = await LogWriter.open(deviceId, identifier);
  const tapStore = createTapStore(deviceId, identifier);
  const script = await session.createScript(await agent(platform));

  setupRelay(socket, script, logHandles, stores);
  setupSocketHandlers(socket, script, session, logHandles, tapStore);

  await script.load();

  // Restore saved taps before emitting ready
  const saved = tapStore.load();
  if (saved) {
    try {
      await script.exports.restore(saved);
    } catch (e) {
      console.warn("Failed to restore taps:", e);
    }
  }

  socket.emit("ready", session.pid);
}
