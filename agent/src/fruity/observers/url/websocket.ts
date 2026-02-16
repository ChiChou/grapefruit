import type {
  NSURLSessionWebSocketTask,
  NSURLSessionWebSocketMessage,
  NSError,
} from "@/fruity/typings.js";
import { wrapObjC } from "@/fruity/typings.js";

import { ObjC, hooks, recordWebSocketMessage } from "./common.js";

export function hookWebSocketMethods() {
  const classes = [
    ObjC.classes.__NSURLSessionWebSocketTask,
    ObjC.classes.NSURLSessionWebSocketTask,
  ].filter(Boolean);

  const hookedSendInvokers = new Set<string>();
  const hookedRecvInvokers = new Set<string>();

  for (const clazz of classes) {
    // -sendMessage:completionHandler:
    const sendMethod = clazz["- sendMessage:completionHandler:"] as
      | ObjC.ObjectMethod
      | undefined;
    if (sendMethod) {
      hooks.push(
        Interceptor.attach(sendMethod.implementation, {
          onEnter(args) {
            const task = wrapObjC<NSURLSessionWebSocketTask>(args[0]);
            const message = wrapObjC<NSURLSessionWebSocketMessage>(args[2]);
            recordWebSocketMessage("send", task, message);

            // Hook completion to capture send errors
            const blockPtr = args[3];
            if (blockPtr.isNull()) return;

            const invokePtr = blockPtr.add(0x10).readPointer();
            const key = invokePtr.toString();
            if (!hookedSendInvokers.has(key)) {
              hookedSendInvokers.add(key);
              hooks.push(
                Interceptor.attach(invokePtr, {
                  onEnter(innerArgs) {
                    if (innerArgs[1].isNull()) return;

                    const block = new ObjC.Object(innerArgs[0]);
                    const meta = ObjC.getBoundData(block) as {
                      task?: NSURLSessionWebSocketTask;
                      message?: NSURLSessionWebSocketMessage;
                    };
                    if (!meta?.task || !meta?.message) return;

                    recordWebSocketMessage(
                      "send",
                      meta.task,
                      meta.message,
                      wrapObjC<NSError>(innerArgs[1]),
                    );
                  },
                }),
              );
            }

            const block = new ObjC.Object(blockPtr);
            ObjC.bind(block, { task, message });
          },
        }),
      );
    }

    // -receiveMessageWithCompletionHandler:
    const recvMethod = clazz["- receiveMessageWithCompletionHandler:"] as
      | ObjC.ObjectMethod
      | undefined;
    if (recvMethod) {
      hooks.push(
        Interceptor.attach(recvMethod.implementation, {
          onEnter(args) {
            const task = wrapObjC<NSURLSessionWebSocketTask>(args[0]);
            const blockPtr = args[2];
            if (blockPtr.isNull()) return;

            const invokePtr = blockPtr.add(0x10).readPointer();
            const key = invokePtr.toString();
            if (!hookedRecvInvokers.has(key)) {
              hookedRecvInvokers.add(key);
              hooks.push(
                Interceptor.attach(invokePtr, {
                  onEnter(innerArgs) {
                    if (innerArgs[1].isNull()) return;

                    const block = new ObjC.Object(innerArgs[0]);
                    const meta = ObjC.getBoundData(block) as {
                      task?: NSURLSessionWebSocketTask;
                    };
                    if (!meta?.task) return;

                    recordWebSocketMessage(
                      "receive",
                      meta.task,
                      wrapObjC<NSURLSessionWebSocketMessage>(innerArgs[1]),
                      innerArgs[2].isNull()
                        ? null
                        : wrapObjC<NSError>(innerArgs[2]),
                    );
                  },
                }),
              );
            }

            const block = new ObjC.Object(blockPtr);
            ObjC.bind(block, { task });
          },
        }),
      );
    }
  }
}
