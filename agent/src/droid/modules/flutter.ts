import Java from "frida-java-bridge";

export interface FlutterRuntimeInfo {
  isFlutter: boolean;
  platform: "android";
  engineModule: string | null;
  appModule: string | null;
  hints?: string[];
}

export interface ChannelHookOptions {
  allowlistChannels?: string[];
  denylistChannels?: string[];
  maxPayloadBytes?: number;
  maxEventsPerSecond?: number;
  includeStack?: boolean;
}

interface GroupStatus {
  active: boolean;
  startedAt?: number;
  dropped?: number;
}

type FlutterChannelType = "method" | "event" | "message";
type FlutterChannelDirection = "dart->native" | "native->dart";
type FlutterCodec = "standard" | "json" | "binary" | "unknown";

interface NormalizedChannelHookOptions {
  allowlistChannels: string[];
  denylistChannels: string[];
  maxPayloadBytes: number;
  maxEventsPerSecond: number;
  includeStack: boolean;
}

interface InternalState {
  active: boolean;
  startedAt?: number;
  dropped: number;
  emitted: number;
  windowSecond: number;
  windowCount: number;
  options: NormalizedChannelHookOptions;
  teardown: (() => void) | null;
}

interface JavaRefs {
  JavaString: Java.Wrapper;
  ReflectArray: Java.Wrapper;
  MapClass: Java.Wrapper;
  ListClass: Java.Wrapper;
  SetClass: Java.Wrapper;
}

interface EncodedValue {
  value: unknown;
  truncated: boolean;
  codec: FlutterCodec;
  rawHex?: string;
}

const DEFAULT_OPTIONS: NormalizedChannelHookOptions = {
  allowlistChannels: [],
  denylistChannels: [],
  maxPayloadBytes: 16 * 1024,
  maxEventsPerSecond: 50,
  includeStack: false,
};

const MAX_DEPTH = 5;
const MAX_COLLECTION_ITEMS = 64;
const CHANNEL_GROUP = "channels";

const runtime: InternalState = {
  active: false,
  dropped: 0,
  emitted: 0,
  windowSecond: 0,
  windowCount: 0,
  options: { ...DEFAULT_OPTIONS },
  teardown: null,
};

let refs: JavaRefs | null = null;
let classCounter = 0;

function ensureJavaRefs(): JavaRefs {
  if (refs) return refs;
  refs = {
    JavaString: Java.use("java.lang.String"),
    ReflectArray: Java.use("java.lang.reflect.Array"),
    MapClass: Java.use("java.util.Map"),
    ListClass: Java.use("java.util.List"),
    SetClass: Java.use("java.util.Set"),
  };
  return refs;
}

function normalizeOptions(options?: ChannelHookOptions): NormalizedChannelHookOptions {
  const maxPayloadBytes = Number(options?.maxPayloadBytes);
  const maxEventsPerSecond = Number(options?.maxEventsPerSecond);

  return {
    allowlistChannels: Array.isArray(options?.allowlistChannels)
      ? options!.allowlistChannels.filter((entry): entry is string => typeof entry === "string" && entry.length > 0)
      : [],
    denylistChannels: Array.isArray(options?.denylistChannels)
      ? options!.denylistChannels.filter((entry): entry is string => typeof entry === "string" && entry.length > 0)
      : [],
    maxPayloadBytes:
      Number.isFinite(maxPayloadBytes) && maxPayloadBytes > 256
        ? Math.floor(maxPayloadBytes)
        : DEFAULT_OPTIONS.maxPayloadBytes,
    maxEventsPerSecond:
      Number.isFinite(maxEventsPerSecond) && maxEventsPerSecond > 0
        ? Math.floor(maxEventsPerSecond)
        : DEFAULT_OPTIONS.maxEventsPerSecond,
    includeStack: Boolean(options?.includeStack),
  };
}

function encodeUtf8(value: string): number {
  if (typeof TextEncoder !== "undefined") {
    return new TextEncoder().encode(value).byteLength;
  }
  return value.length;
}

function trimByBytes(value: string, maxBytes: number): string {
  if (maxBytes <= 0) return "";
  if (encodeUtf8(value) <= maxBytes) return value;

  let out = "";
  for (const ch of value) {
    const next = out + ch;
    if (encodeUtf8(next) > maxBytes) break;
    out = next;
  }

  return out;
}

function safeString(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") {
    return `${value}`;
  }

  try {
    if (typeof (value as { toString?: unknown }).toString === "function") {
      return (value as { toString: () => string }).toString();
    }
  } catch {
    // fall through
  }

  return "<unknown>";
}

function shouldCaptureChannel(channel: string): boolean {
  if (
    runtime.options.denylistChannels.some(
      (needle) => needle.length > 0 && channel.includes(needle),
    )
  ) {
    return false;
  }

  if (runtime.options.allowlistChannels.length === 0) {
    return true;
  }

  return runtime.options.allowlistChannels.some(
    (needle) => needle.length > 0 && channel.includes(needle),
  );
}

function consumeRateLimit(): boolean {
  const second = Math.floor(Date.now() / 1000);
  if (runtime.windowSecond !== second) {
    runtime.windowSecond = second;
    runtime.windowCount = 0;
  }

  if (runtime.windowCount >= runtime.options.maxEventsPerSecond) {
    runtime.dropped += 1;
    return false;
  }

  runtime.windowCount += 1;
  runtime.emitted += 1;
  return true;
}

function bytesToHex(bytes: number[], maxPayloadBytes: number): {
  hex: string;
  truncated: boolean;
} {
  const maxBytes = Math.max(1, Math.floor(maxPayloadBytes / 2));
  const truncated = bytes.length > maxBytes;
  const capped = truncated ? bytes.slice(0, maxBytes) : bytes;
  const hex = capped
    .map((v) => ((v & 0xff) + 0x100).toString(16).slice(-2))
    .join("");

  return {
    hex: truncated ? `${hex}...` : hex,
    truncated,
  };
}

function getJavaClassName(value: unknown): string | null {
  if (!value || typeof value !== "object") return null;

  const wrapped = value as Record<string, unknown>;
  if (typeof wrapped.$className === "string") {
    return wrapped.$className;
  }

  try {
    const cls = (value as { getClass: () => Java.Wrapper }).getClass();
    return cls.getName().toString();
  } catch {
    return null;
  }
}

function isJavaInstance(value: unknown, clazz: Java.Wrapper): boolean {
  if (!value || typeof value !== "object") return false;

  try {
    return Boolean(clazz.class.isInstance(value));
  } catch {
    return false;
  }
}

function decodeJavaValue(value: unknown, depth = 0): EncodedValue {
  if (value === null || value === undefined) {
    return { value: null, truncated: false, codec: "standard" };
  }

  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return { value, truncated: false, codec: "standard" };
  }

  if (depth > MAX_DEPTH) {
    return {
      value: "<max-depth>",
      truncated: true,
      codec: "unknown",
    };
  }

  try {
    const className = getJavaClassName(value);
    if (!className) {
      return { value: safeString(value), truncated: false, codec: "unknown" };
    }

    if (className === "[B") {
      const javaRefs = ensureJavaRefs();
      const length = Number(javaRefs.ReflectArray.getLength(value));
      const array: number[] = [];
      for (let index = 0; index < length; index += 1) {
        array.push(Number(javaRefs.ReflectArray.get(value, index)));
      }
      const { hex, truncated } = bytesToHex(array, runtime.options.maxPayloadBytes);
      return {
        value: hex,
        rawHex: hex,
        truncated,
        codec: "binary",
      };
    }

    if (
      className === "java.lang.String" ||
      className === "java.lang.Boolean" ||
      className.startsWith("java.lang.Integer") ||
      className.startsWith("java.lang.Long") ||
      className.startsWith("java.lang.Float") ||
      className.startsWith("java.lang.Double") ||
      className.startsWith("java.lang.Short") ||
      className.startsWith("java.lang.Byte")
    ) {
      return { value: safeString(value), truncated: false, codec: "standard" };
    }

    const javaRefs = ensureJavaRefs();

    if (isJavaInstance(value, javaRefs.MapClass)) {
      const out: Record<string, unknown> = {};
      const entries = (value as Java.Wrapper).entrySet().iterator();
      let count = 0;
      while (entries.hasNext() && count < MAX_COLLECTION_ITEMS) {
        const entry = entries.next();
        const key = safeString(entry.getKey());
        const decoded = decodeJavaValue(entry.getValue(), depth + 1);
        out[key] = decoded.value;
        count += 1;
      }
      if (entries.hasNext()) {
        out.__truncated = true;
      }
      return { value: out, truncated: false, codec: "json" };
    }

    if (isJavaInstance(value, javaRefs.ListClass)) {
      const list = value as Java.Wrapper;
      const size = Number(list.size());
      const cap = Math.min(size, MAX_COLLECTION_ITEMS);
      const out: unknown[] = [];
      for (let index = 0; index < cap; index += 1) {
        out.push(decodeJavaValue(list.get(index), depth + 1).value);
      }
      if (size > cap) {
        out.push("<truncated>");
      }
      return { value: out, truncated: false, codec: "json" };
    }

    if (isJavaInstance(value, javaRefs.SetClass)) {
      const iterator = (value as Java.Wrapper).iterator();
      const out: unknown[] = [];
      let count = 0;
      while (iterator.hasNext() && count < MAX_COLLECTION_ITEMS) {
        out.push(decodeJavaValue(iterator.next(), depth + 1).value);
        count += 1;
      }
      if (iterator.hasNext()) {
        out.push("<truncated>");
      }
      return { value: out, truncated: false, codec: "json" };
    }

    if (className.startsWith("[")) {
      const length = Number(javaRefs.ReflectArray.getLength(value));
      const cap = Math.min(length, MAX_COLLECTION_ITEMS);
      const out: unknown[] = [];
      for (let index = 0; index < cap; index += 1) {
        const item = javaRefs.ReflectArray.get(value, index);
        out.push(decodeJavaValue(item, depth + 1).value);
      }
      if (length > cap) {
        out.push("<truncated>");
      }
      return { value: out, truncated: false, codec: "json" };
    }

    return { value: safeString(value), truncated: false, codec: "unknown" };
  } catch {
    return { value: safeString(value), truncated: false, codec: "unknown" };
  }
}

function truncateValue(value: unknown): { value: unknown; truncated: boolean } {
  if (value === null || value === undefined) {
    return { value, truncated: false };
  }

  if (typeof value === "string") {
    const trimmed = trimByBytes(value, runtime.options.maxPayloadBytes);
    return {
      value: trimmed,
      truncated: trimmed.length !== value.length,
    };
  }

  try {
    const text = JSON.stringify(value);
    if (!text) {
      return { value, truncated: false };
    }

    const bytes = encodeUtf8(text);
    if (bytes <= runtime.options.maxPayloadBytes) {
      return { value, truncated: false };
    }

    return {
      value: `${trimByBytes(text, runtime.options.maxPayloadBytes)}...`,
      truncated: true,
    };
  } catch {
    const text = safeString(value);
    const trimmed = trimByBytes(text, runtime.options.maxPayloadBytes);
    return {
      value: trimmed,
      truncated: trimmed.length !== text.length,
    };
  }
}

function encodeValue(value: unknown): EncodedValue {
  const decoded = decodeJavaValue(value);
  const fit = truncateValue(decoded.value);
  return {
    value: fit.value,
    truncated: decoded.truncated || fit.truncated,
    codec: decoded.codec,
    rawHex: decoded.rawHex,
  };
}

function readJavaField(target: unknown, fieldName: string): unknown {
  if (!target || typeof target !== "object") return undefined;

  try {
    const value = (target as Record<string, unknown>)[fieldName];
    if (value && typeof value === "object" && "value" in value) {
      return (value as { value: unknown }).value;
    }
    if (value !== undefined) {
      return value;
    }
  } catch {
    // fall through
  }

  try {
    const cls = (target as { getClass: () => Java.Wrapper }).getClass();
    const field = cls.getDeclaredField(fieldName);
    field.setAccessible(true);
    return field.get(target);
  } catch {
    return undefined;
  }
}

function getChannelName(channelObject: unknown): string {
  if (!channelObject) return "<unknown>";

  const directName = readJavaField(channelObject, "name");
  const result = safeString(directName);
  return result.length > 0 ? result : "<unknown>";
}

function maybeStack(): string[] | undefined {
  if (!runtime.options.includeStack) return undefined;
  const stack = new Error().stack;
  if (!stack) return undefined;
  return stack
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .slice(0, 8);
}

function emitChannelEvent(params: {
  symbol: string;
  type: FlutterChannelType;
  direction: FlutterChannelDirection;
  channel: string;
  method?: string;
  args?: unknown;
  result?: unknown;
  error?: string;
}): void {
  if (!runtime.active) return;
  if (!shouldCaptureChannel(params.channel)) return;
  if (!consumeRateLimit()) return;

  const extra: Record<string, unknown> = {
    platform: "android",
    type: params.type,
    dir: params.direction,
    channel: params.channel,
  };

  if (params.method) {
    extra.method = params.method;
  }

  let truncated = false;
  let codec: FlutterCodec = "standard";

  if (params.args !== undefined) {
    const encoded = encodeValue(params.args);
    extra.args = encoded.value;
    if (encoded.rawHex) {
      extra.argsRawHex = encoded.rawHex;
    }
    truncated ||= encoded.truncated;
    codec = encoded.codec;
  }

  if (params.result !== undefined) {
    const encoded = encodeValue(params.result);
    extra.result = encoded.value;
    truncated ||= encoded.truncated;
    if (codec !== "binary") {
      codec = encoded.codec;
    }
  }

  if (params.error) {
    extra.error = params.error;
  }

  extra.codec = codec;
  if (truncated) {
    extra.truncated = true;
  }

  const methodPart = params.method ? ` method=${params.method}` : "";
  const directionLabel =
    params.direction === "dart->native" ? "[Dart->Native]" : "[Native->Dart]";

  send({
    subject: "hook",
    category: "flutter.channel",
    symbol: params.symbol,
    dir: params.direction === "dart->native" ? "enter" : "leave",
    line: `${directionLabel} channel=${params.channel}${methodPart}`,
    backtrace: maybeStack(),
    extra,
  });
}

function patchOverload(
  overload: Java.MethodDispatcher,
  replacement: (self: Java.Wrapper, args: unknown[]) => unknown,
  restores: Array<() => void>,
): void {
  const originalImplementation = overload.implementation;

  overload.implementation = function (this: Java.Wrapper, ...args: unknown[]) {
    return replacement(this, args);
  };

  restores.push(() => {
    overload.implementation = originalImplementation;
  });
}

function nextClassName(base: string): string {
  classCounter += 1;
  return `org.igf.flutter.${base}${Date.now()}${classCounter}`;
}

async function installChannelHooks(): Promise<() => void> {
  const restores: Array<() => void> = [];

  await new Promise<void>((resolve, reject) => {
    Java.perform(() => {
      try {
        ensureJavaRefs();

        const methodHandlerRefs = new Map<string, Java.Wrapper>();
        const messageHandlerRefs = new Map<string, Java.Wrapper>();
        const streamHandlerRefs = new Map<string, Java.Wrapper>();
        const eventSinkRefs: Java.Wrapper[] = [];

        // MethodChannel
        try {
          const MethodChannel = Java.use("io.flutter.plugin.common.MethodChannel");
          const MethodCallHandler = Java.use(
            "io.flutter.plugin.common.MethodChannel$MethodCallHandler",
          );
          const JavaString = Java.use("java.lang.String");

          const MethodCallHandlerProxy = Java.registerClass({
            name: nextClassName("MethodCallHandlerProxy"),
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
                  implementation(this: Java.Wrapper, delegate: Java.Wrapper, channelName: Java.Wrapper) {
                    this.delegate.value = delegate;
                    this.channelName.value = channelName;
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
                  implementation(this: Java.Wrapper, methodCall: Java.Wrapper, result: Java.Wrapper) {
                    const channel = safeString(this.channelName.value);
                    const method = safeString(readJavaField(methodCall, "method")) || "<unknown>";
                    const argumentsObject = readJavaField(methodCall, "arguments");

                    emitChannelEvent({
                      symbol: "android.MethodChannel.setMethodCallHandler",
                      type: "method",
                      direction: "dart->native",
                      channel,
                      method,
                      args: argumentsObject,
                    });

                    this.delegate.value.onMethodCall(methodCall, result);
                  },
                },
              ],
            },
          });

          const setMethodCallHandler = MethodChannel.setMethodCallHandler.overload(
            "io.flutter.plugin.common.MethodChannel$MethodCallHandler",
          );
          patchOverload(
            setMethodCallHandler,
            (self, args) => {
              const [handler] = args as [Java.Wrapper | null];
              if (!handler) {
                return setMethodCallHandler.call(self, handler);
              }

              const className = safeString((handler as Record<string, unknown>).$className);
              if (className.includes("MethodCallHandlerProxy")) {
                return setMethodCallHandler.call(self, handler);
              }

              const channelName = getChannelName(self);
              const wrapped = MethodCallHandlerProxy.$new(
                handler,
                JavaString.$new(channelName),
              );
              const key = `${safeString((self as Record<string, unknown>).$h)}:${safeString((handler as Record<string, unknown>).$h)}`;
              methodHandlerRefs.set(key, wrapped);

              return setMethodCallHandler.call(self, wrapped);
            },
            restores,
          );

          const invokeMethod2 = MethodChannel.invokeMethod.overload(
            "java.lang.String",
            "java.lang.Object",
          );
          patchOverload(
            invokeMethod2,
            (self, args) => {
              const [method, argumentsObject] = args;
              emitChannelEvent({
                symbol: "android.MethodChannel.invokeMethod",
                type: "method",
                direction: "native->dart",
                channel: getChannelName(self),
                method: safeString(method) || "<unknown>",
                args: argumentsObject,
              });
              return invokeMethod2.call(self, method, argumentsObject);
            },
            restores,
          );

          const invokeMethod3 = MethodChannel.invokeMethod.overload(
            "java.lang.String",
            "java.lang.Object",
            "io.flutter.plugin.common.MethodChannel$Result",
          );
          patchOverload(
            invokeMethod3,
            (self, args) => {
              const [method, argumentsObject, callback] = args;
              emitChannelEvent({
                symbol: "android.MethodChannel.invokeMethod",
                type: "method",
                direction: "native->dart",
                channel: getChannelName(self),
                method: safeString(method) || "<unknown>",
                args: argumentsObject,
              });
              return invokeMethod3.call(self, method, argumentsObject, callback);
            },
            restores,
          );
        } catch (error) {
          console.warn(`flutter channels: MethodChannel hook unavailable: ${error}`);
        }

        // BasicMessageChannel
        try {
          const BasicMessageChannel = Java.use(
            "io.flutter.plugin.common.BasicMessageChannel",
          );
          const MessageHandler = Java.use(
            "io.flutter.plugin.common.BasicMessageChannel$MessageHandler",
          );
          const JavaString = Java.use("java.lang.String");

          const MessageHandlerProxy = Java.registerClass({
            name: nextClassName("BasicMessageHandlerProxy"),
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
                  implementation(this: Java.Wrapper, delegate: Java.Wrapper, channelName: Java.Wrapper) {
                    this.delegate.value = delegate;
                    this.channelName.value = channelName;
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
                  implementation(this: Java.Wrapper, message: unknown, reply: Java.Wrapper) {
                    const channel = safeString(this.channelName.value);
                    emitChannelEvent({
                      symbol: "android.BasicMessageChannel.setMessageHandler",
                      type: "message",
                      direction: "dart->native",
                      channel,
                      method: "message",
                      args: message,
                    });

                    this.delegate.value.onMessage(message, reply);
                  },
                },
              ],
            },
          });

          const setMessageHandler = BasicMessageChannel.setMessageHandler.overload(
            "io.flutter.plugin.common.BasicMessageChannel$MessageHandler",
          );
          patchOverload(
            setMessageHandler,
            (self, args) => {
              const [handler] = args as [Java.Wrapper | null];
              if (!handler) {
                return setMessageHandler.call(self, handler);
              }

              const className = safeString((handler as Record<string, unknown>).$className);
              if (className.includes("BasicMessageHandlerProxy")) {
                return setMessageHandler.call(self, handler);
              }

              const channelName = getChannelName(self);
              const wrapped = MessageHandlerProxy.$new(
                handler,
                JavaString.$new(channelName),
              );
              const key = `${safeString((self as Record<string, unknown>).$h)}:${safeString((handler as Record<string, unknown>).$h)}`;
              messageHandlerRefs.set(key, wrapped);

              return setMessageHandler.call(self, wrapped);
            },
            restores,
          );

          const send1 = BasicMessageChannel.send.overload("java.lang.Object");
          patchOverload(
            send1,
            (self, args) => {
              const [message] = args;
              emitChannelEvent({
                symbol: "android.BasicMessageChannel.send",
                type: "message",
                direction: "native->dart",
                channel: getChannelName(self),
                method: "send",
                args: message,
              });
              return send1.call(self, message);
            },
            restores,
          );

          const send2 = BasicMessageChannel.send.overload(
            "java.lang.Object",
            "io.flutter.plugin.common.BasicMessageChannel$Reply",
          );
          patchOverload(
            send2,
            (self, args) => {
              const [message, reply] = args;
              emitChannelEvent({
                symbol: "android.BasicMessageChannel.send",
                type: "message",
                direction: "native->dart",
                channel: getChannelName(self),
                method: "send",
                args: message,
              });
              return send2.call(self, message, reply);
            },
            restores,
          );
        } catch (error) {
          console.warn(`flutter channels: BasicMessageChannel hook unavailable: ${error}`);
        }

        // EventChannel
        try {
          const EventChannel = Java.use("io.flutter.plugin.common.EventChannel");
          const StreamHandler = Java.use(
            "io.flutter.plugin.common.EventChannel$StreamHandler",
          );
          const EventSink = Java.use("io.flutter.plugin.common.EventChannel$EventSink");
          const JavaString = Java.use("java.lang.String");

          const EventSinkProxy = Java.registerClass({
            name: nextClassName("EventSinkProxy"),
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
                  implementation(this: Java.Wrapper, delegate: Java.Wrapper, channelName: Java.Wrapper) {
                    this.delegate.value = delegate;
                    this.channelName.value = channelName;
                  },
                },
              ],
              success: [
                {
                  returnType: "void",
                  argumentTypes: ["java.lang.Object"],
                  implementation(this: Java.Wrapper, value: unknown) {
                    emitChannelEvent({
                      symbol: "android.EventChannel.EventSink.success",
                      type: "event",
                      direction: "native->dart",
                      channel: safeString(this.channelName.value),
                      method: "success",
                      result: value,
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
                  implementation(this: Java.Wrapper, code: unknown, message: unknown, details: unknown) {
                    emitChannelEvent({
                      symbol: "android.EventChannel.EventSink.error",
                      type: "event",
                      direction: "native->dart",
                      channel: safeString(this.channelName.value),
                      method: "error",
                      result: { code: safeString(code), message: safeString(message), details },
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
                    emitChannelEvent({
                      symbol: "android.EventChannel.EventSink.endOfStream",
                      type: "event",
                      direction: "native->dart",
                      channel: safeString(this.channelName.value),
                      method: "endOfStream",
                    });
                    this.delegate.value.endOfStream();
                  },
                },
              ],
            },
          });

          const StreamHandlerProxy = Java.registerClass({
            name: nextClassName("StreamHandlerProxy"),
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
                  implementation(this: Java.Wrapper, delegate: Java.Wrapper, channelName: Java.Wrapper) {
                    this.delegate.value = delegate;
                    this.channelName.value = channelName;
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
                  implementation(this: Java.Wrapper, argumentsObject: unknown, eventSink: Java.Wrapper) {
                    const channelName = safeString(this.channelName.value);
                    emitChannelEvent({
                      symbol: "android.EventChannel.setStreamHandler",
                      type: "event",
                      direction: "dart->native",
                      channel: channelName,
                      method: "listen",
                      args: argumentsObject,
                    });

                    const wrappedSink = EventSinkProxy.$new(eventSink, this.channelName.value);
                    eventSinkRefs.push(wrappedSink);
                    this.delegate.value.onListen(argumentsObject, wrappedSink);
                  },
                },
              ],
              onCancel: [
                {
                  returnType: "void",
                  argumentTypes: ["java.lang.Object"],
                  implementation(this: Java.Wrapper, argumentsObject: unknown) {
                    emitChannelEvent({
                      symbol: "android.EventChannel.setStreamHandler",
                      type: "event",
                      direction: "dart->native",
                      channel: safeString(this.channelName.value),
                      method: "cancel",
                      args: argumentsObject,
                    });
                    this.delegate.value.onCancel(argumentsObject);
                  },
                },
              ],
            },
          });

          const setStreamHandler = EventChannel.setStreamHandler.overload(
            "io.flutter.plugin.common.EventChannel$StreamHandler",
          );
          patchOverload(
            setStreamHandler,
            (self, args) => {
              const [handler] = args as [Java.Wrapper | null];
              if (!handler) {
                return setStreamHandler.call(self, handler);
              }

              const className = safeString((handler as Record<string, unknown>).$className);
              if (className.includes("StreamHandlerProxy")) {
                return setStreamHandler.call(self, handler);
              }

              const channelName = getChannelName(self);
              const wrapped = StreamHandlerProxy.$new(
                handler,
                JavaString.$new(channelName),
              );
              const key = `${safeString((self as Record<string, unknown>).$h)}:${safeString((handler as Record<string, unknown>).$h)}`;
              streamHandlerRefs.set(key, wrapped);

              return setStreamHandler.call(self, wrapped);
            },
            restores,
          );
        } catch (error) {
          console.warn(`flutter channels: EventChannel hook unavailable: ${error}`);
        }

        restores.push(() => {
          methodHandlerRefs.clear();
          messageHandlerRefs.clear();
          streamHandlerRefs.clear();
          eventSinkRefs.length = 0;
        });

        resolve();
      } catch (error) {
        reject(error);
      }
    });
  });

  return () => {
    Java.perform(() => {
      for (let index = restores.length - 1; index >= 0; index -= 1) {
        try {
          restores[index]();
        } catch (error) {
          console.error(`flutter channels: failed to restore hook: ${error}`);
        }
      }
    });
  };
}

export function detect(): FlutterRuntimeInfo {
  const modules = Process.enumerateModules();
  const engine = modules.find((mod) => mod.name === "libflutter.so");
  const app = modules.find((mod) => mod.name === "libapp.so");

  const hints: string[] = [];
  if (engine) hints.push(`Found ${engine.name}`);
  if (app) hints.push(`Found ${app.name}`);

  return {
    isFlutter: Boolean(engine || app),
    platform: "android",
    engineModule: engine?.name || null,
    appModule: app?.name || null,
    hints: hints.length > 0 ? hints : undefined,
  };
}

export function list(): { groups: string[] } {
  return {
    groups: [CHANNEL_GROUP],
  };
}

export function status(): Record<string, GroupStatus> {
  return {
    [CHANNEL_GROUP]: {
      active: runtime.active,
      startedAt: runtime.startedAt,
      dropped: runtime.dropped,
    },
  };
}

export async function start(args: {
  group: "channels";
  options?: ChannelHookOptions;
}): Promise<{ ok: boolean }> {
  if (!args || args.group !== CHANNEL_GROUP) {
    return { ok: false };
  }

  if (runtime.active) {
    return { ok: true };
  }

  runtime.options = normalizeOptions(args.options);
  runtime.dropped = 0;
  runtime.emitted = 0;
  runtime.windowSecond = 0;
  runtime.windowCount = 0;

  try {
    runtime.teardown = await installChannelHooks();
    runtime.active = true;
    runtime.startedAt = Date.now();
    return { ok: true };
  } catch (error) {
    runtime.teardown = null;
    runtime.active = false;
    runtime.startedAt = undefined;
    console.error(`flutter channels: failed to start hooks: ${error}`);
    return { ok: false };
  }
}

export async function stop(args: { group: "channels" }): Promise<{ ok: boolean }> {
  if (!args || args.group !== CHANNEL_GROUP) {
    return { ok: false };
  }

  if (!runtime.active) {
    return { ok: true };
  }

  runtime.active = false;
  runtime.startedAt = undefined;

  const teardown = runtime.teardown;
  runtime.teardown = null;

  if (teardown) {
    try {
      teardown();
    } catch (error) {
      console.error(`flutter channels: failed to stop hooks: ${error}`);
      return { ok: false };
    }
  }

  return { ok: true };
}
