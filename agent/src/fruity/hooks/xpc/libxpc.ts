import ObjC from "frida-objc-bridge";

import getLibXpcApi from "@/fruity/native/libxpc.js";
import getLibSystemApi from "@/fruity/native/libsystem.js";
import { symbolFromName } from "@/fruity/native/libdyld.js";
import { bt } from "@/common/hooks/context.js";

import type { XPCNode } from "./index.js";

const subject = "xpc";

function copyDescription(obj: NativePointer): string {
  const api = getLibXpcApi();
  const desc = api.xpc_copy_description(obj);
  const str = desc.readUtf8String();
  getLibSystemApi().free(desc);
  return str ?? "";
}

class LogSerializer {
  #dataBuffers: ArrayBuffer[] = [];
  #offset = 0;

  constructor(private readonly root: NativePointer) {}

  serialize(): [XPCNode, ArrayBuffer] {
    const json = this.dump(this.root);
    const joint = new Uint8Array(this.#offset);

    for (let i = 0, offset = 0; i < this.#dataBuffers.length; i++) {
      const buf = this.#dataBuffers[i];
      joint.set(new Uint8Array(buf), offset);
      offset += buf.byteLength;
    }

    return [json, joint.buffer as ArrayBuffer];
  }

  private appendData(data: ArrayBuffer): number {
    const offset = this.#offset;
    this.#dataBuffers.push(data);
    this.#offset += data.byteLength;
    return offset;
  }

  private dump(xpcObj: NativePointer): XPCNode {
    const api = getLibXpcApi();
    const t = api.xpc_get_type(xpcObj);
    const description = copyDescription(xpcObj);

    if (t.equals(api.xpcDictionaryType)) {
      const keys: string[] = [];
      const values: XPCNode[] = [];

      api.xpc_dictionary_apply(
        xpcObj,
        new ObjC.Block({
          retType: "bool",
          argTypes: ["pointer", "pointer"],
          implementation: (key: NativePointer, value: NativePointer) => {
            keys.push(key.readUtf8String()!);
            values.push(this.dump(value));
            return true;
          },
        }),
      );

      return { description, keys, values, type: "dictionary" };
    }

    if (t.equals(api.xpcArrayType)) {
      const values: XPCNode[] = [];
      api.xpc_array_apply(
        xpcObj,
        new ObjC.Block({
          retType: "bool",
          argTypes: ["uint64", "pointer"],
          implementation: (_index: number, value: NativePointer) => {
            values.push(this.dump(value));
            return true;
          },
        }),
      );

      return { description, values, type: "array" };
    }

    for (const xpcType of api.xpcTypes) {
      if (api.xpc_get_type(xpcObj).equals(xpcType.address)) {
        const type = xpcType.name.replace(/^_xpc_type_/, "");

        if (type === "string") {
          const value = api
            .xpc_string_get_string_ptr(xpcObj)
            .readUtf8String(api.xpc_string_get_length(xpcObj).toNumber());
          return { description, value, type };
        } else if (type === "data") {
          const base = api.xpc_data_get_bytes_ptr(xpcObj);
          const length = api.xpc_data_get_length(xpcObj).toNumber();

          let offset = 0;
          if (!base.isNull()) {
            const data = base.readByteArray(length);
            if (data) {
              offset = this.appendData(data);
            }
          }

          return { description, type, offset, length };
        } else if (type === "uuid") {
          const p = api.xpc_uuid_get_bytes(xpcObj);
          const data = p.readByteArray(16)!;
          const offset = this.appendData(data);
          const value = [...new Uint8Array(data)]
            .map((x) => x.toString(16).padStart(2, "0"))
            .join("");

          return { description, type, offset, value };
        } else if (type === "double") {
          const value = api.xpc_double_get_value(xpcObj);
          return { description, type, value };
        } else if (type === "uint64") {
          const value = api.xpc_uint64_get_value(xpcObj).toString();
          return { description, type, value };
        } else if (type === "int64") {
          const value = api.xpc_int64_get_value(xpcObj).toString();
          return { description, type, value };
        } else if (type === "bool") {
          const value = api.xpc_bool_get_value(xpcObj) !== 0;
          return { description, type, value };
        } else if (type === "fd") {
          const F_GETPATH = 50;
          const MAXPATHLEN = 1024;
          const buf = Memory.alloc(MAXPATHLEN);
          const value = api.xpc_fd_dup(xpcObj) as number;
          const rc = getLibSystemApi().fcntl(value, F_GETPATH, buf);
          const path = rc === 0 ? buf.readUtf8String() : undefined;

          return { description, type, value, path };
        } else if (type === "date") {
          const value = api.xpc_date_get_value(xpcObj).toString();
          return { description, type, value };
        } else if (
          type === "shmem" ||
          type === "error" ||
          type === "endpoint" ||
          type === "connection" ||
          type === "null"
        ) {
          return { description, type };
        }

        return { description, type: "unknown" };
      }
    }

    return { description, type: "unknown" };
  }
}

export function hookXPC(): InvocationListener[] {
  const api = getLibXpcApi();
  const listeners: InvocationListener[] = [];

  const dispatcher = symbolFromName(
    "libxpc.dylib",
    "_xpc_connection_call_event_handler",
  );
  if (dispatcher.isNull()) {
    console.warn(
      "xpc: _xpc_connection_call_event_handler not found, skipping incoming XPC hooks",
    );
    return listeners;
  }

  listeners.push(
    Interceptor.attach(dispatcher, {
      onEnter(args) {
        const conn = args[0];
        const msg = args[1];

        if (!api.xpc_get_type(msg).equals(api.xpcDictionaryType)) return;

        const name = api.xpc_connection_get_name(conn).readUtf8String();
        const pid = api.xpc_connection_get_pid(conn) as number;

        try {
          const serializer = new LogSerializer(msg);
          const [json, data] = serializer.serialize();

          send(
            {
              subject,
              event: "received",
              name,
              peer: pid,
              dir: "<",
              message: json,
            },
            data,
          );
        } catch (e) {
          console.warn("xpc: failed to serialize incoming message:", e);
        }
      },
    }),
  );

  for (const suffix of ["", "_with_reply", "_with_reply_sync"]) {
    const fnName = `xpc_connection_send_message${suffix}`;
    const fnAddr = api.libxpc.findExportByName(fnName);
    if (!fnAddr) continue;

    listeners.push(
      Interceptor.attach(fnAddr, {
        onEnter(args) {
          const conn = args[0];
          const msg = args[1];

          const name = api.xpc_connection_get_name(conn).readUtf8String();
          const pid = api.xpc_connection_get_pid(conn) as number;

          try {
            const serializer = new LogSerializer(msg);
            const [json, data] = serializer.serialize();
            const backtrace = bt(this.context);

            send(
              {
                subject,
                event: "sent",
                name,
                peer: pid,
                dir: ">",
                message: json,
                backtrace,
              },
              data,
            );
          } catch (e) {
            console.warn("xpc: failed to serialize outgoing message:", e);
          }
        },
      }),
    );
  }

  return listeners;
}
