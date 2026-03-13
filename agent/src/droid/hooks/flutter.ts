import Java from "frida-java-bridge";

import { hook } from "@/common/hooks/java.js";
import { toJS } from "@/droid/bridge/object.js";

type Direction = "native" | "dart";
type ChannelType = "method" | "event" | "message";

const subject = "flutter";
const hooks: InvocationListener[] = [];
let running = false;

function safelyConvert(obj: Java.Wrapper | null): unknown {
  try {
    return toJS(obj);
  } catch {
    return null;
  }
}

let classIdCounter = Math.floor(Math.random() * 1024);
// todo: do we need to obfuscate?
const namespace = `org.flutter.agent`;
function nextClassName(base: string): string {
  return `${namespace}.${base}${++classIdCounter}`;
}

function verifyClass(cls: Java.Wrapper, base: string): boolean {
  const prefix = namespace + "." + base;
  return cls.$className?.startsWith(prefix);
}

function wrapHandler(
  method: Java.MethodDispatcher,
  base: string,
  Proxy: Java.Wrapper,
) {
  const String = Java.use("java.lang.String");
  hooks.push(hook(method, (original, self, args) => {
    const [handler] = args as [Java.Wrapper | null];
    if (!handler || verifyClass(handler, base)) {
      return original.call(self, handler);
    }
    return original.call(
      self,
      Proxy.$new(handler, String.$new(self.name.value)),
    );
  }));
}

export function start() {
  if (running || !available()) return;
  running = true;

  Java.perform(() => {
    const targets = [
      ["MethodChannel", hookMethodChannel],
      ["BasicMessageChannel", hookBasicMessageChannel],
      ["EventChannel", hookEventChannel],
    ] as const;

    for (const [name, fn] of targets) {
      try {
        fn();
      } catch (e) {
        console.warn(`flutter: ${name} hooks unavailable:`, e);
      }
    }
  });
}

function hookMethodChannel() {
  const MethodChannel = Java.use("io.flutter.plugin.common.MethodChannel");
  const MethodCallHandler = Java.use(
    "io.flutter.plugin.common.MethodChannel$MethodCallHandler",
  );
  const classNameBase = "MCH";
  const HandlerProxy = Java.registerClass({
    name: nextClassName(classNameBase),
    implements: [MethodCallHandler],
    fields: {
      delegate: "io.flutter.plugin.common.MethodChannel$MethodCallHandler",
      channelName: "java.lang.String",
    },
    methods: {
      $init: [
        {
          returnType: "void",
          argumentTypes: [
            "io.flutter.plugin.common.MethodChannel$MethodCallHandler",
            "java.lang.String",
          ],
          implementation(this: Java.Wrapper, d: Java.Wrapper, n: Java.Wrapper) {
            this.delegate.value = d;
            this.channelName.value = n;
          },
        },
      ],
      onMethodCall: [
        {
          returnType: "void",
          argumentTypes: [
            "io.flutter.plugin.common.MethodCall",
            "io.flutter.plugin.common.MethodChannel$Result",
          ],
          implementation(
            this: Java.Wrapper,
            call: Java.Wrapper,
            result: Java.Wrapper,
          ) {
            const name = this.channelName.value.toString();
            const method = call.method.value?.toString() || "<unknown>";
            const args = safelyConvert(call.arguments.value);

            emit("method", "dart", name, { method, args });
            this.delegate.value.onMethodCall(call, result);
          },
        },
      ],
    },
  });

  wrapHandler(
    MethodChannel.setMethodCallHandler.overload(
      "io.flutter.plugin.common.MethodChannel$MethodCallHandler",
    ),
    classNameBase,
    HandlerProxy,
  );

  // invokeMethod(String, Object)
  hooks.push(hook(
    MethodChannel.invokeMethod.overload("java.lang.String", "java.lang.Object"),
    (original, self, args) => {
      const [method, a] = args as [Java.Wrapper, Java.Wrapper];
      emit("method", "native", self.name.value, {
        method: method?.toString() || "<unknown>",
        args: safelyConvert(a),
      });
      return original.call(self, method, a);
    },
  ));

  // invokeMethod(String, Object, Result)
  hooks.push(hook(
    MethodChannel.invokeMethod.overload(
      "java.lang.String",
      "java.lang.Object",
      "io.flutter.plugin.common.MethodChannel$Result",
    ),
    (original, self, args) => {
      const [method, a, cb] = args as [
        Java.Wrapper,
        Java.Wrapper,
        Java.Wrapper,
      ];
      emit("method", "native", self.name.value, {
        method: method?.toString() || "<unknown>",
        args: safelyConvert(a),
      });
      return original.call(self, method, a, cb);
    },
  ));
}

function hookBasicMessageChannel() {
  const BasicMessageChannel = Java.use(
    "io.flutter.plugin.common.BasicMessageChannel",
  );
  const MessageHandler = Java.use(
    "io.flutter.plugin.common.BasicMessageChannel$MessageHandler",
  );
  const classNameBase = "BMH";
  const HandlerProxy = Java.registerClass({
    name: nextClassName(classNameBase),
    implements: [MessageHandler],
    fields: {
      delegate: "io.flutter.plugin.common.BasicMessageChannel$MessageHandler",
      channelName: "java.lang.String",
    },
    methods: {
      $init: [
        {
          returnType: "void",
          argumentTypes: [
            "io.flutter.plugin.common.BasicMessageChannel$MessageHandler",
            "java.lang.String",
          ],
          implementation(this: Java.Wrapper, d: Java.Wrapper, n: Java.Wrapper) {
            this.delegate.value = d;
            this.channelName.value = n;
          },
        },
      ],
      onMessage: [
        {
          returnType: "void",
          argumentTypes: [
            "java.lang.Object",
            "io.flutter.plugin.common.BasicMessageChannel$Reply",
          ],
          implementation(
            this: Java.Wrapper,
            message: Java.Wrapper,
            reply: Java.Wrapper,
          ) {
            const name = this.channelName.value.toString();
            emit("message", "dart", name, { args: safelyConvert(message) });
            this.delegate.value.onMessage(message, reply);
          },
        },
      ],
    },
  });

  wrapHandler(
    BasicMessageChannel.setMessageHandler.overload(
      "io.flutter.plugin.common.BasicMessageChannel$MessageHandler",
    ),
    classNameBase,
    HandlerProxy,
  );

  // send(Object)
  hooks.push(hook(
    BasicMessageChannel.send.overload("java.lang.Object"),
    (original, self, args) => {
      const [msg] = args as [Java.Wrapper];
      emit("message", "native", self.name.value, { args: safelyConvert(msg) });
      return original.call(self, msg);
    },
  ));

  // send(Object, Reply)
  hooks.push(hook(
    BasicMessageChannel.send.overload(
      "java.lang.Object",
      "io.flutter.plugin.common.BasicMessageChannel$Reply",
    ),
    (original, self, args) => {
      const [msg, reply] = args as [Java.Wrapper, Java.Wrapper];
      emit("message", "native", self.name.value, { args: safelyConvert(msg) });
      return original.call(self, msg, reply);
    },
  ));
}

function hookEventChannel() {
  const EventChannel = Java.use("io.flutter.plugin.common.EventChannel");
  const StreamHandler = Java.use(
    "io.flutter.plugin.common.EventChannel$StreamHandler",
  );
  const EventSink = Java.use("io.flutter.plugin.common.EventChannel$EventSink");
  const sinkBase = "ES";
  const handlerBase = "SH";

  const SinkProxy = Java.registerClass({
    name: nextClassName(sinkBase),
    implements: [EventSink],
    fields: {
      delegate: "io.flutter.plugin.common.EventChannel$EventSink",
      channelName: "java.lang.String",
    },
    methods: {
      $init: [
        {
          returnType: "void",
          argumentTypes: [
            "io.flutter.plugin.common.EventChannel$EventSink",
            "java.lang.String",
          ],
          implementation(this: Java.Wrapper, d: Java.Wrapper, n: Java.Wrapper) {
            this.delegate.value = d;
            this.channelName.value = n;
          },
        },
      ],
      success: [
        {
          returnType: "void",
          argumentTypes: ["java.lang.Object"],
          implementation(this: Java.Wrapper, value: Java.Wrapper) {
            const name = this.channelName.value.toString();
            emit("event", "native", name, {
              method: "success",
              result: safelyConvert(value),
            });
            this.delegate.value.success(value);
          },
        },
      ],
      error: [
        {
          returnType: "void",
          argumentTypes: [
            "java.lang.String",
            "java.lang.String",
            "java.lang.Object",
          ],
          implementation(
            this: Java.Wrapper,
            code: Java.Wrapper,
            message: Java.Wrapper,
            details: Java.Wrapper,
          ) {
            const name = this.channelName.value.toString();
            emit("event", "native", name, {
              method: "error",
              result: {
                code: code?.toString(),
                message: message?.toString(),
                details: safelyConvert(details),
              },
            });
            this.delegate.value.error(code, message, details);
          },
        },
      ],
      endOfStream: [
        {
          returnType: "void",
          argumentTypes: [],
          implementation(this: Java.Wrapper) {
            const name = this.channelName.value.toString();
            emit("event", "native", name, { method: "endOfStream" });
            this.delegate.value.endOfStream();
          },
        },
      ],
    },
  });

  const StreamHandlerProxy = Java.registerClass({
    name: nextClassName(handlerBase),
    implements: [StreamHandler],
    fields: {
      delegate: "io.flutter.plugin.common.EventChannel$StreamHandler",
      channelName: "java.lang.String",
    },
    methods: {
      $init: [
        {
          returnType: "void",
          argumentTypes: [
            "io.flutter.plugin.common.EventChannel$StreamHandler",
            "java.lang.String",
          ],
          implementation(this: Java.Wrapper, d: Java.Wrapper, n: Java.Wrapper) {
            this.delegate.value = d;
            this.channelName.value = n;
          },
        },
      ],
      onListen: [
        {
          returnType: "void",
          argumentTypes: [
            "java.lang.Object",
            "io.flutter.plugin.common.EventChannel$EventSink",
          ],
          implementation(
            this: Java.Wrapper,
            a: Java.Wrapper,
            sink: Java.Wrapper,
          ) {
            const name = this.channelName.value.toString();
            emit("event", "dart", name, {
              method: "listen",
              args: safelyConvert(a),
            });
            const wrapped = SinkProxy.$new(sink, this.channelName.value);
            this.delegate.value.onListen(a, wrapped);
          },
        },
      ],
      onCancel: [
        {
          returnType: "void",
          argumentTypes: ["java.lang.Object"],
          implementation(this: Java.Wrapper, a: Java.Wrapper) {
            const name = this.channelName.value.toString();
            emit("event", "dart", name, {
              method: "cancel",
              args: safelyConvert(a),
            });
            this.delegate.value.onCancel(a);
          },
        },
      ],
    },
  });

  wrapHandler(
    EventChannel.setStreamHandler.overload(
      "io.flutter.plugin.common.EventChannel$StreamHandler",
    ),
    handlerBase,
    StreamHandlerProxy,
  );
}

export function stop() {
  for (const h of hooks) {
    try { h.detach(); } catch { /* ignore */ }
  }
  hooks.length = 0;
  running = false;
}

export function status(): boolean {
  return running;
}

export function available() {
  if (!Java.available) return false;
  const engine = Process.findModuleByName("libflutter.so");
  if (!engine) return false;
  let found = false;
  Java.perform(() => {
    try {
      Java.use("io.flutter.plugin.common.MethodChannel");
      found = true;
    } catch {}
  });
  return found;
}

function emit(
  type: ChannelType,
  dir: Direction,
  channel: string,
  detail: Record<string, unknown>,
) {
  send({ subject, type, dir, channel, ...detail });
}
