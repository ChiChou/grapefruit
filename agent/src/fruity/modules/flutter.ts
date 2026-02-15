import ObjC from "frida-objc-bridge";

import { bt } from "@/common/hooks/context.js";
import { toJS } from "@/fruity/bridge/object.js";

export interface FlutterRuntimeInfo {
  isFlutter: boolean;
  platform: "ios";
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
  listeners: InvocationListener[];
  restoreBlocks: Map<string, { block: ObjC.Block; original: (...args: unknown[]) => unknown }>;
  streamHandlerChannels: Map<string, string>;
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

const CHANNEL_GROUP = "channels";
const MAX_DEPTH = 5;
const MAX_COLLECTION_ITEMS = 64;

const runtime: InternalState = {
  active: false,
  dropped: 0,
  emitted: 0,
  windowSecond: 0,
  windowCount: 0,
  options: { ...DEFAULT_OPTIONS },
  listeners: [],
  restoreBlocks: new Map(),
  streamHandlerChannels: new Map(),
};

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
  if (typeof value === "number" || typeof value === "boolean") return `${value}`;

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

function toHex(data: ArrayBuffer, maxPayloadBytes: number): {
  value: string;
  truncated: boolean;
} {
  const bytes = new Uint8Array(data);
  const maxBytes = Math.max(1, Math.floor(maxPayloadBytes / 2));
  const truncated = bytes.byteLength > maxBytes;
  const cap = truncated ? bytes.slice(0, maxBytes) : bytes;

  const hex = Array.from(cap)
    .map((value) => value.toString(16).padStart(2, "0"))
    .join("");

  return {
    value: truncated ? `${hex}...` : hex,
    truncated,
  };
}

function asObjCObject(value: unknown): ObjC.Object | null {
  if (!value) return null;

  try {
    if (value instanceof ObjC.Object) {
      return value;
    }
  } catch {
    // ignored
  }

  try {
    if (typeof value === "object" && "$className" in (value as object)) {
      return value as ObjC.Object;
    }
  } catch {
    // ignored
  }

  try {
    const pointer = value as NativePointer;
    if (pointer.isNull()) {
      return null;
    }
    return new ObjC.Object(pointer);
  } catch {
    return null;
  }
}

function encodeNSData(object: ObjC.Object): EncodedValue | null {
  if (!ObjC.available) return null;

  const dataClass = ObjC.classes.NSData;
  if (!dataClass || !object.isKindOfClass_(dataClass)) return null;

  try {
    const length = Number((object as ObjC.Object & { length: () => number }).length());
    if (length <= 0) {
      return {
        value: "",
        truncated: false,
        codec: "binary",
        rawHex: "",
      };
    }

    const bytesPtr = (object as ObjC.Object & { bytes: () => NativePointer }).bytes();
    const cap = Math.min(length, Math.max(1, Math.floor(runtime.options.maxPayloadBytes / 2)));
    const buffer = bytesPtr.readByteArray(cap);
    if (!buffer) {
      return {
        value: "<binary>",
        truncated: true,
        codec: "binary",
      };
    }

    const hex = toHex(buffer, runtime.options.maxPayloadBytes);
    return {
      value: hex.value,
      rawHex: hex.value,
      truncated: hex.truncated,
      codec: "binary",
    };
  } catch {
    return {
      value: "<binary>",
      truncated: false,
      codec: "binary",
    };
  }
}

function decodeObjCValue(value: unknown, depth = 0): EncodedValue {
  if (value === null || value === undefined) {
    return { value: null, truncated: false, codec: "standard" };
  }

  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return { value, truncated: false, codec: "standard" };
  }

  if (!ObjC.available) {
    return { value: safeString(value), truncated: false, codec: "unknown" };
  }

  if (depth > MAX_DEPTH) {
    return {
      value: "<max-depth>",
      truncated: true,
      codec: "unknown",
    };
  }

  const object = asObjCObject(value);
  if (!object) {
    return {
      value: safeString(value),
      truncated: false,
      codec: "unknown",
    };
  }

  const dataEncoded = encodeNSData(object);
  if (dataEncoded) {
    return dataEncoded;
  }

  try {
    const { NSArray, NSDictionary, NSString, NSNumber, NSNull } = ObjC.classes;

    if (NSString && object.isKindOfClass_(NSString)) {
      return {
        value: object.toString(),
        truncated: false,
        codec: "standard",
      };
    }

    if (NSNumber && object.isKindOfClass_(NSNumber)) {
      return {
        value: Number(object.toString()),
        truncated: false,
        codec: "standard",
      };
    }

    if (NSNull && object.isKindOfClass_(NSNull)) {
      return {
        value: null,
        truncated: false,
        codec: "standard",
      };
    }

    if (NSDictionary && object.isKindOfClass_(NSDictionary)) {
      const converted = toJS(object);
      const capped: Record<string, unknown> = {};
      let count = 0;
      for (const [key, item] of Object.entries(converted as Record<string, unknown>)) {
        if (count >= MAX_COLLECTION_ITEMS) {
          capped.__truncated = true;
          break;
        }
        capped[key] = decodeObjCValue(item, depth + 1).value;
        count += 1;
      }

      return {
        value: capped,
        truncated: false,
        codec: "json",
      };
    }

    if (NSArray && object.isKindOfClass_(NSArray)) {
      const converted = toJS(object);
      const values: unknown[] = [];
      if (Array.isArray(converted)) {
        const cap = Math.min(converted.length, MAX_COLLECTION_ITEMS);
        for (let index = 0; index < cap; index += 1) {
          values.push(decodeObjCValue(converted[index], depth + 1).value);
        }
        if (converted.length > cap) {
          values.push("<truncated>");
        }
      }

      return {
        value: values,
        truncated: false,
        codec: "json",
      };
    }

    return {
      value: object.toString(),
      truncated: false,
      codec: "unknown",
    };
  } catch {
    return {
      value: safeString(object),
      truncated: false,
      codec: "unknown",
    };
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
  const decoded = decodeObjCValue(value);
  const fit = truncateValue(decoded.value);

  return {
    value: fit.value,
    truncated: decoded.truncated || fit.truncated,
    codec: decoded.codec,
    rawHex: decoded.rawHex,
  };
}

function selector(name: string): NativePointer {
  return ObjC.selector(name);
}

function channelNameFromObject(channelObject: ObjC.Object): string {
  try {
    if (channelObject.respondsToSelector_(selector("name"))) {
      const value = (channelObject as ObjC.Object & { name: () => ObjC.Object | null }).name();
      if (value) return value.toString();
    }
  } catch {
    // fall through
  }

  try {
    const ivars = (channelObject as ObjC.Object & { $ivars?: Record<string, unknown> }).$ivars;
    if (ivars) {
      const direct = ivars._name ?? ivars.name;
      if (direct) return safeString(direct);
    }
  } catch {
    // fall through
  }

  return "<unknown>";
}

function getMethodCallData(methodCallPointer: NativePointer): {
  method: string;
  argumentsValue: unknown;
} {
  if (methodCallPointer.isNull()) {
    return {
      method: "<unknown>",
      argumentsValue: null,
    };
  }

  try {
    const callObject = new ObjC.Object(methodCallPointer);
    const methodValue = (callObject as ObjC.Object & { method: () => ObjC.Object | null }).method();
    const argsValue = (callObject as ObjC.Object & { arguments: () => ObjC.Object | null }).arguments();

    return {
      method: methodValue ? methodValue.toString() : "<unknown>",
      argumentsValue: argsValue,
    };
  } catch {
    return {
      method: "<unknown>",
      argumentsValue: null,
    };
  }
}

function emitChannelEvent(
  params: {
    symbol: string;
    type: FlutterChannelType;
    direction: FlutterChannelDirection;
    channel: string;
    method?: string;
    args?: unknown;
    result?: unknown;
    error?: string;
  },
  context?: CpuContext,
): void {
  if (!runtime.active) return;
  if (!shouldCaptureChannel(params.channel)) return;
  if (!consumeRateLimit()) return;

  const extra: Record<string, unknown> = {
    platform: "ios",
    type: params.type,
    dir: params.direction,
    channel: params.channel,
  };

  if (params.method) {
    extra.method = params.method;
  }

  let codec: FlutterCodec = "standard";
  let truncated = false;

  if (params.args !== undefined) {
    const encoded = encodeValue(params.args);
    extra.args = encoded.value;
    if (encoded.rawHex) {
      extra.argsRawHex = encoded.rawHex;
    }
    codec = encoded.codec;
    truncated ||= encoded.truncated;
  }

  if (params.result !== undefined) {
    const encoded = encodeValue(params.result);
    extra.result = encoded.value;
    if (codec !== "binary") {
      codec = encoded.codec;
    }
    truncated ||= encoded.truncated;
  }

  if (params.error) {
    extra.error = params.error;
  }

  extra.codec = codec;
  if (truncated) {
    extra.truncated = true;
  }

  const directionLabel =
    params.direction === "dart->native" ? "[Dart->Native]" : "[Native->Dart]";
  const methodPart = params.method ? ` method=${params.method}` : "";

  send({
    subject: "hook",
    category: "flutter.channel",
    symbol: params.symbol,
    dir: params.direction === "dart->native" ? "enter" : "leave",
    line: `${directionLabel} channel=${params.channel}${methodPart}`,
    backtrace: runtime.options.includeStack && context ? bt(context) : undefined,
    extra,
  });
}

function wrapBlockWithLogging(
  blockPointer: NativePointer,
  wrapper: (original: (...args: unknown[]) => unknown) => (...args: unknown[]) => unknown,
): void {
  if (blockPointer.isNull()) return;

  const key = blockPointer.toString();
  if (runtime.restoreBlocks.has(key)) return;

  try {
    const block = new ObjC.Block(blockPointer);
    const original = block.implementation;
    block.implementation = wrapper(original);
    runtime.restoreBlocks.set(key, { block, original });
  } catch (error) {
    console.warn(`flutter channels: failed to wrap block ${key}: ${error}`);
  }
}

function attachMethod(
  klass: ObjC.Object,
  selectorName: string,
  callbacks: Parameters<typeof Interceptor.attach>[1],
): void {
  const method = (klass as Record<string, ObjC.ObjectMethod | undefined>)[selectorName];
  if (!method) return;

  runtime.listeners.push(Interceptor.attach(method.implementation, callbacks));
}

function hookMethodChannel(klass: ObjC.Object): void {
  attachMethod(klass, "- setMethodCallHandler:", {
    onEnter(args) {
      if (args[2].isNull()) return;

      const channel = channelNameFromObject(new ObjC.Object(args[0]));
      wrapBlockWithLogging(args[2], (original) => {
        return function (...blockArgs: unknown[]) {
          const methodCallPointer = blockArgs[0] as NativePointer | undefined;
          const resultCallback = blockArgs[1];
          const safePointer =
            methodCallPointer && typeof methodCallPointer.isNull === "function"
              ? methodCallPointer
              : NULL;
          const { method, argumentsValue } = getMethodCallData(safePointer);
          emitChannelEvent({
            symbol: "ios.FlutterMethodChannel.setMethodCallHandler",
            type: "method",
            direction: "dart->native",
            channel,
            method,
            args: argumentsValue,
          });

          return original(safePointer, resultCallback);
        };
      });
    },
  });

  attachMethod(klass, "- invokeMethod:arguments:", {
    onEnter(args) {
      const channel = channelNameFromObject(new ObjC.Object(args[0]));
      const method = args[2].isNull() ? "<unknown>" : new ObjC.Object(args[2]).toString();
      const argumentsValue = args[3].isNull() ? null : new ObjC.Object(args[3]);

      emitChannelEvent(
        {
          symbol: "ios.FlutterMethodChannel.invokeMethod",
          type: "method",
          direction: "native->dart",
          channel,
          method,
          args: argumentsValue,
        },
        this.context,
      );
    },
  });

  attachMethod(klass, "- invokeMethod:arguments:result:", {
    onEnter(args) {
      const channel = channelNameFromObject(new ObjC.Object(args[0]));
      const method = args[2].isNull() ? "<unknown>" : new ObjC.Object(args[2]).toString();
      const argumentsValue = args[3].isNull() ? null : new ObjC.Object(args[3]);

      emitChannelEvent(
        {
          symbol: "ios.FlutterMethodChannel.invokeMethod",
          type: "method",
          direction: "native->dart",
          channel,
          method,
          args: argumentsValue,
        },
        this.context,
      );
    },
  });
}

function hookBasicMessageChannel(klass: ObjC.Object): void {
  attachMethod(klass, "- sendMessage:", {
    onEnter(args) {
      const channel = channelNameFromObject(new ObjC.Object(args[0]));
      const message = args[2].isNull() ? null : new ObjC.Object(args[2]);

      emitChannelEvent(
        {
          symbol: "ios.FlutterBasicMessageChannel.sendMessage",
          type: "message",
          direction: "native->dart",
          channel,
          method: "send",
          args: message,
        },
        this.context,
      );
    },
  });

  attachMethod(klass, "- sendMessage:reply:", {
    onEnter(args) {
      const channel = channelNameFromObject(new ObjC.Object(args[0]));
      const message = args[2].isNull() ? null : new ObjC.Object(args[2]);

      emitChannelEvent(
        {
          symbol: "ios.FlutterBasicMessageChannel.sendMessage",
          type: "message",
          direction: "native->dart",
          channel,
          method: "send",
          args: message,
        },
        this.context,
      );
    },
  });

  attachMethod(klass, "- setMessageHandler:", {
    onEnter(args) {
      if (args[2].isNull()) return;

      const channel = channelNameFromObject(new ObjC.Object(args[0]));
      wrapBlockWithLogging(args[2], (original) => {
        return function (...blockArgs: unknown[]) {
          const messagePointer = blockArgs[0] as NativePointer | undefined;
          const reply = blockArgs[1];
          const safePointer =
            messagePointer && typeof messagePointer.isNull === "function"
              ? messagePointer
              : NULL;
          const message =
            !safePointer.isNull()
              ? new ObjC.Object(safePointer)
              : null;
          emitChannelEvent({
            symbol: "ios.FlutterBasicMessageChannel.setMessageHandler",
            type: "message",
            direction: "dart->native",
            channel,
            method: "message",
            args: message,
          });

          return original(safePointer, reply);
        };
      });
    },
  });
}

function hookEventStreamHandler(handlerPointer: NativePointer, channel: string): void {
  if (handlerPointer.isNull()) return;

  const key = handlerPointer.toString();
  runtime.streamHandlerChannels.set(key, channel);

  let handlerObject: ObjC.Object;
  try {
    handlerObject = new ObjC.Object(handlerPointer);
  } catch {
    return;
  }

  const selectors = [
    "- onListenWithArguments:eventSink:",
    "- onCancelWithArguments:",
  ] as const;

  for (const selectorName of selectors) {
    const method =
      (handlerObject.$class as Record<string, ObjC.ObjectMethod | undefined>)[selectorName];
    if (!method) continue;

    const symbolKey = `${handlerObject.$className}:${selectorName}`;
    if (runtime.restoreBlocks.has(symbolKey)) continue;

    const listener = Interceptor.attach(method.implementation, {
      onEnter(args) {
        const instanceKey = args[0].toString();
        const ch = runtime.streamHandlerChannels.get(instanceKey) || channel;

        if (selectorName === "- onListenWithArguments:eventSink:") {
          const argumentsValue = args[2].isNull() ? null : new ObjC.Object(args[2]);
          emitChannelEvent(
            {
              symbol: "ios.FlutterEventChannel.setStreamHandler",
              type: "event",
              direction: "dart->native",
              channel: ch,
              method: "listen",
              args: argumentsValue,
            },
            this.context,
          );
        } else {
          const argumentsValue = args[2].isNull() ? null : new ObjC.Object(args[2]);
          emitChannelEvent(
            {
              symbol: "ios.FlutterEventChannel.setStreamHandler",
              type: "event",
              direction: "dart->native",
              channel: ch,
              method: "cancel",
              args: argumentsValue,
            },
            this.context,
          );
        }
      },
    });

    runtime.listeners.push(listener);
    runtime.restoreBlocks.set(symbolKey, {
      block: null as unknown as ObjC.Block,
      original: () => {
        listener.detach();
      },
    });
  }
}

function hookEventChannel(klass: ObjC.Object): void {
  attachMethod(klass, "- setStreamHandler:", {
    onEnter(args) {
      if (args[2].isNull()) return;

      const channel = channelNameFromObject(new ObjC.Object(args[0]));
      hookEventStreamHandler(args[2], channel);
    },
  });
}

function installChannelHooks(): boolean {
  if (!ObjC.available) return false;

  runtime.listeners = [];
  runtime.restoreBlocks.clear();
  runtime.streamHandlerChannels.clear();

  let installed = false;

  const methodChannel = ObjC.classes.FlutterMethodChannel;
  if (methodChannel) {
    hookMethodChannel(methodChannel);
    installed = true;
  }

  const basicMessageChannel = ObjC.classes.FlutterBasicMessageChannel;
  if (basicMessageChannel) {
    hookBasicMessageChannel(basicMessageChannel);
    installed = true;
  }

  const eventChannel = ObjC.classes.FlutterEventChannel;
  if (eventChannel) {
    hookEventChannel(eventChannel);
    installed = true;
  }

  return installed;
}

function uninstallChannelHooks(): void {
  for (const listener of runtime.listeners) {
    try {
      listener.detach();
    } catch {
      // ignore detach errors
    }
  }
  runtime.listeners.length = 0;

  for (const [key, entry] of runtime.restoreBlocks) {
    try {
      if (key.includes(":")) {
        entry.original();
      } else {
        entry.block.implementation = entry.original;
      }
    } catch {
      // ignore restore errors
    }
  }
  runtime.restoreBlocks.clear();
  runtime.streamHandlerChannels.clear();
}

export function detect(): FlutterRuntimeInfo {
  const hints: string[] = [];

  const engine = Process.enumerateModules().find((module) => {
    if (module.name === "Flutter") return true;
    if (module.name === "Flutter.framework") return true;
    return module.path.includes("Flutter.framework");
  });

  const hasMethodChannelClass = Boolean(ObjC.available && ObjC.classes.FlutterMethodChannel);

  if (engine) {
    hints.push(`Found ${engine.name}`);
  }
  if (hasMethodChannelClass) {
    hints.push("Found ObjC class FlutterMethodChannel");
  }

  return {
    isFlutter: Boolean(engine || hasMethodChannelClass),
    platform: "ios",
    engineModule: engine?.name || null,
    appModule: Process.mainModule?.name || null,
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

export function start(args: {
  group: "channels";
  options?: ChannelHookOptions;
}): { ok: boolean } {
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
    const installed = installChannelHooks();
    if (!installed) {
      return { ok: false };
    }

    runtime.active = true;
    runtime.startedAt = Date.now();
    return { ok: true };
  } catch (error) {
    runtime.active = false;
    runtime.startedAt = undefined;
    console.error(`flutter channels: failed to start hooks: ${error}`);
    return { ok: false };
  }
}

export function stop(args: { group: "channels" }): { ok: boolean } {
  if (!args || args.group !== CHANNEL_GROUP) {
    return { ok: false };
  }

  if (!runtime.active) {
    return { ok: true };
  }

  runtime.active = false;
  runtime.startedAt = undefined;

  try {
    uninstallChannelHooks();
    return { ok: true };
  } catch (error) {
    console.error(`flutter channels: failed to stop hooks: ${error}`);
    return { ok: false };
  }
}
