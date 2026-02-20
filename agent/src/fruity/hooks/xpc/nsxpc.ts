import ObjC from "frida-objc-bridge";

import { symbolFromName, symbolsFromGlob } from "@/fruity/native/libdyld.js";
import { bt } from "@/common/hooks/context.js";

const subject = "xpc";

function formatArgs(
  args: InvocationArguments,
  signature: ObjC.Object,
): string[] {
  const nargs = signature.numberOfArguments();
  const result: string[] = [];
  for (let i = 2; i < nargs; i++) {
    const arg = args[i];
    const t = signature.getArgumentTypeAtIndex_(i);
    const wrapped = t.toString().startsWith("@") ? new ObjC.Object(arg) : arg;
    result.push(wrapped.toString());
  }
  return result;
}

function formatDescription(
  self: NativePointer,
  clazz: string,
  sel: string,
  args: InvocationArguments,
): string {
  const parts = sel.split(":");
  const nparams = sel.includes(":") ? parts.length - 1 : 0;

  function* gen() {
    yield `<${clazz} ${self}>`;
    if (nparams === 0) {
      yield ` ${sel}`;
      return;
    }
    for (let i = 0; i < nparams; i++) {
      if (i === 0) yield " ";
      yield `${parts[i] || ""}:${args[i + 2]}`;
    }
  }

  return [...gen()].join("");
}

export function hookNSXPC(): InvocationListener[] {
  const listeners: InvocationListener[] = [];
  if (!ObjC.available) return listeners;

  ObjC.classes.NSBundle.bundleWithPath_(
    "/System/Library/Frameworks/Foundation.framework",
  ).load();

  // Hook incoming invocations
  const invoker = symbolFromName(
    "Foundation",
    "__NSXPCCONNECTION_IS_CALLING_OUT_TO_EXPORTED_OBJECT__",
  );

  if (!invoker.isNull()) {
    listeners.push(
      Interceptor.attach(invoker.strip(), {
        onEnter(args) {
          const invocation = new ObjC.Object(args[0]);
          const target = invocation.target();
          const selector = invocation.selector();
          const sel = ObjC.selectorAsString(selector);

          const imp = target
            .methodForSelector_(selector)
            .strip() as NativePointer;
          const signature = target.methodSignatureForSelector_(
            selector,
          ) as ObjC.Object;

          this.hook = Interceptor.attach(imp, {
            onEnter(innerArgs) {
              const json = {
                type: "nsxpc",
                sel,
                args: formatArgs(innerArgs, signature),
                description: formatDescription(
                  innerArgs[0],
                  target.$className,
                  sel,
                  innerArgs,
                ),
              };

              send({
                subject,
                event: "received",
                dir: "<",
                message: json,
              });
            },
          });
        },
        onLeave() {
          this.hook.detach();
        },
      }),
    );
  }

  // Hook fast-path incoming invocations
  for (const func of symbolsFromGlob(
    "Foundation",
    "__NSXPCCONNECTION_IS_CALLING_OUT_TO_EXPORTED_OBJECT_S*",
  )) {
    const plain = func.strip();
    if (plain.isNull()) continue;

    listeners.push(
      Interceptor.attach(plain, {
        onEnter(args) {
          const targetClass = new ObjC.Object(args[0]);
          const sel = ObjC.selectorAsString(args[1]);
          const signature = targetClass.methodSignatureForSelector_(args[1]);

          const json = {
            type: "nsxpc",
            sel,
            args: formatArgs(args, signature),
            description: formatDescription(
              args[0],
              targetClass.$className,
              sel,
              args,
            ),
          };

          send({
            subject,
            event: "received",
            dir: "<",
            message: json,
          });
        },
      }),
    );
  }

  // Track proxy creation to bind connection info
  const protocol = ObjC.protocols.NSXPCProxyCreating;
  const cls = ObjC.classes.NSXPCConnection;
  if (protocol && cls) {
    for (const sel in protocol.methods) {
      if (!cls[sel]) continue;

      listeners.push(
        Interceptor.attach(cls[sel].implementation, {
          onEnter(args) {
            this.conn = args[0];
          },
          onLeave(retValue) {
            try {
              ObjC.bind(retValue, { conn: this.conn });
            } catch {
              /* may fail if retValue is not an ObjC object */
            }
          },
        }),
      );
    }
  }

  // Hook outgoing messages via distant object sends
  for (const func of symbolsFromGlob(
    "Foundation",
    "_NSXPCDistantObjectSimpleMessageSend*",
  )) {
    if (func.isNull()) continue;

    listeners.push(
      Interceptor.attach(func, {
        onEnter(args) {
          const proxy = new ObjC.Object(args[0]);
          const sel = ObjC.selectorAsString(args[1]);
          const clazz = proxy.$className;

          const signature = proxy.methodSignatureForSelector_(
            args[1],
          ) as ObjC.Object;

          let name = "";
          let peer = 0;

          try {
            const { conn } = ObjC.getBoundData(args[0]);
            if (conn) {
              const connObj = new ObjC.Object(conn as NativePointer);
              if (typeof connObj.serviceName === "function") {
                name = connObj.serviceName() + "";
                peer = connObj.processIdentifier();
              }
            }
          } catch {
            /* no bound data */
          }

          const json = {
            type: "nsxpc",
            sel,
            args: formatArgs(args, signature),
            description: formatDescription(args[0], clazz, sel, args),
          };

          const backtrace = bt(this.context);

          send({
            subject,
            event: "sent",
            name,
            peer,
            dir: ">",
            message: json,
            backtrace,
          });
        },
      }),
    );
  }

  return listeners;
}
