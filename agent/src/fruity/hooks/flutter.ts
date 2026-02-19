import ObjC from "frida-objc-bridge";

import { toJS } from "../bridge/object.js";

type Direction = "native" | "dart";
type ChannelType = "method" | "event" | "message";

const subject = "flutter";
const hooks: InvocationListener[] = [];
const hookedBlocks = new Set<string>();
let running = false;

function getName(channel: ObjC.Object) {
  return channel.$ivars._name.toString();
}

export function start() {
  if (running || !available()) return;
  running = true;

  const {
    FlutterMethodChannel,
    FlutterBasicMessageChannel,
    FlutterEventChannel,
  } = ObjC.classes;

  const methodChannelHooks: Record<string, InvocationListenerCallbacks> = {
    "- setMethodCallHandler:": {
      onEnter(args) {
        const handler = args[2];
        if (handler.isNull()) return;

        const name = getName(new ObjC.Object(args[0]));

        ObjC.bind(new ObjC.Object(handler), { name });
        hookBlock(handler, {
          onEnter(args) {
            const ctx = ObjC.getBoundData(new ObjC.Object(args[0])) as
              | { name: string }
              | undefined;
            if (!ctx) return;
            const call = new ObjC.Object(args[1]);
            const method = call.method().toString();
            let jsArgs: unknown;

            try {
              jsArgs = toJS(call.arguments());
            } catch (_) {}

            emit("method", "dart", ctx.name, { method, args: jsArgs });

            const result = args[2];
            if (!result.isNull()) {
              ObjC.bind(new ObjC.Object(result), {
                name: ctx.name,
                method,
                dir: "native" as Direction,
              });
              hookBlock(result, resultHook);
            }
          },
        });
      },
    },
    "- invokeMethod:arguments:result:": {
      onEnter(args) {
        const name = getName(new ObjC.Object(args[0]));
        const method = new ObjC.Object(args[2]).toString();
        const a = args[3].isNull() ? null : toJS(new ObjC.Object(args[3]));
        const result = args[4];

        emit("method", "native", name, { method, args: a });

        if (!result.isNull()) {
          ObjC.bind(new ObjC.Object(result), {
            name,
            method,
            dir: "dart" as Direction,
          });
          hookBlock(result, resultHook);
        }
      },
    },
    "- invokeMethod:arguments:": {
      onEnter(args) {
        const name = getName(new ObjC.Object(args[0]));
        const method = new ObjC.Object(args[2]).toString();
        const a = args[3].isNull() ? null : toJS(new ObjC.Object(args[3]));

        emit("method", "native", name, { method, args: a });
      },
    },
  };

  for (const [sel, cb] of Object.entries(methodChannelHooks)) {
    hooks.push(
      Interceptor.attach(FlutterMethodChannel[sel].implementation, cb),
    );
  }

  if (FlutterBasicMessageChannel) {
    const messageChannelHooks: Record<string, InvocationListenerCallbacks> = {
      "- setMessageHandler:": {
        onEnter(args) {
          const handler = args[2];
          if (handler.isNull()) return;

          const name = getName(new ObjC.Object(args[0]));

          ObjC.bind(new ObjC.Object(handler), { name });
          hookBlock(handler, {
            onEnter(args) {
              const ctx = ObjC.getBoundData(new ObjC.Object(args[0])) as
                | { name: string }
                | undefined;
              if (!ctx) return;
              let msg: unknown;
              try {
                msg = args[1].isNull() ? null : toJS(new ObjC.Object(args[1]));
              } catch (_) {}
              emit("message", "dart", ctx.name, { args: msg });
            },
          });
        },
      },
      "- sendMessage:": {
        onEnter(args) {
          const name = getName(new ObjC.Object(args[0]));
          let msg: unknown;
          try {
            msg = args[2].isNull() ? null : toJS(new ObjC.Object(args[2]));
          } catch (_) {}
          emit("message", "native", name, { args: msg });
        },
      },
      "- sendMessage:reply:": {
        onEnter(args) {
          const name = getName(new ObjC.Object(args[0]));
          let msg: unknown;
          try {
            msg = args[2].isNull() ? null : toJS(new ObjC.Object(args[2]));
          } catch (_) {}
          emit("message", "native", name, { args: msg });
        },
      },
    };

    for (const [sel, cb] of Object.entries(messageChannelHooks)) {
      hooks.push(
        Interceptor.attach(FlutterBasicMessageChannel[sel].implementation, cb),
      );
    }
  }

  if (FlutterEventChannel) {
    hooks.push(
      Interceptor.attach(
        FlutterEventChannel["- setStreamHandler:"].implementation,
        {
          onEnter(args) {
            const handler = args[2];
            if (handler.isNull()) return;

            const name = getName(new ObjC.Object(args[0]));
            const handlerObj = new ObjC.Object(handler);
            ObjC.bind(handlerObj, { name });
            hookStreamHandler(handlerObj);
          },
        },
      ),
    );
  }
}

const resultHook: InvocationListenerCallbacks = {
  onEnter(args) {
    const ctx = ObjC.getBoundData(new ObjC.Object(args[0])) as
      | { name: string; method: string; dir: Direction }
      | undefined;
    if (!ctx) return;
    let res: unknown;
    try {
      res = args[1].isNull() ? null : toJS(new ObjC.Object(args[1]));
    } catch (_) {}
    emit("method", ctx.dir, ctx.name, { method: ctx.method, result: res });
  },
};

export function stop() {
  for (const hook of hooks) {
    hook.detach();
  }
  hooks.length = 0;
  hookedBlocks.clear();
  running = false;
}

export function status(): boolean {
  return running;
}

export function available() {
  if (!ObjC.available) return false;
  const engine = Process.findModuleByName("Flutter");
  return Boolean(engine && ObjC.classes.FlutterMethodChannel);
}

function hookStreamHandler(handler: ObjC.Object) {
  const selectors = [
    { sel: "- onListenWithArguments:eventSink:", method: "listen" },
    { sel: "- onCancelWithArguments:", method: "cancel" },
  ] as const;

  for (const { sel, method } of selectors) {
    const m = (handler.$class as Record<string, ObjC.ObjectMethod>)[sel];
    if (!m) continue;
    const key = m.implementation.strip().toString();
    if (hookedBlocks.has(key)) continue;
    hookedBlocks.add(key);
    hooks.push(
      Interceptor.attach(m.implementation, {
        onEnter(args) {
          const ctx = ObjC.getBoundData(new ObjC.Object(args[0])) as
            | { name: string }
            | undefined;
          if (!ctx) return;
          let a: unknown;
          try {
            a = args[2].isNull() ? null : toJS(new ObjC.Object(args[2]));
          } catch (_) {}
          emit("event", "dart", ctx.name, { method, args: a });
        },
      }),
    );
  }
}

function hookBlock(
  block: NativePointer,
  callbacks: InvocationListenerCallbacks,
) {
  const invoke = block.add(16).readPointer();
  const key = invoke.strip().toString();
  if (hookedBlocks.has(key)) return;
  hookedBlocks.add(key);
  hooks.push(Interceptor.attach(invoke, callbacks));
}

function emit(
  type: ChannelType,
  dir: Direction,
  channel: string,
  detail: Record<string, unknown>,
) {
  send({ subject, type, dir, channel, ...detail });
}
