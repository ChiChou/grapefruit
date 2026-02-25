import ObjC from "frida-objc-bridge";

import type {
  NSURLSessionWebSocketTask,
  NSURLSessionWebSocketMessage,
  NSError,
} from "@/fruity/typings.js";
import { wrapObjC } from "@/fruity/typings.js";

import {
  hooks,
  getMethodImp,
  recordWebSocketMessage,
  emitNetworkEvent,
  type WebSocketSendEvent,
} from "./common.js";

interface WebSocketSendBoundData {
  requestId?: string;
  messageType?: string;
  dataLength?: number;
  messageText?: string;
}

export function hookWebSocketMethods() {
  const classes = [
    ObjC.classes.__NSURLSessionWebSocketTask,
    ObjC.classes.NSURLSessionWebSocketTask,
  ].filter(Boolean);

  const hookedSendInvokers = new Set<string>();
  const hookedRecvInvokers = new Set<string>();

  for (const clazz of classes) {
    // -sendMessage:completionHandler:
    const sendImp = getMethodImp(
      clazz,
      "sendMessage:completionHandler:",
      false,
    );
    if (sendImp) {
      hooks.push(
        Interceptor.attach(sendImp, {
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
                    const meta = ObjC.getBoundData(
                      block,
                    ) as WebSocketSendBoundData;
                    if (!meta?.requestId) return;

                    const event: WebSocketSendEvent = {
                      event: "webSocketSend",
                      requestId: meta.requestId,
                      timestamp: Date.now(),
                      messageType: meta.messageType ?? "data",
                      ...(meta.dataLength !== undefined && {
                        dataLength: meta.dataLength,
                      }),
                      ...(meta.messageText !== undefined && {
                        message: meta.messageText,
                      }),
                      error: wrapObjC<NSError>(innerArgs[1]).toString(),
                    };
                    emitNetworkEvent(event);
                  },
                }),
              );
            }

            // Snapshot message data now while objects are alive,
            // the completion handler fires later when they may be freed
            const requestId = task.taskIdentifier().toString();
            const msgType = message.type();
            const msgData = message.data();
            const msgString = message.string();
            const snapshot: WebSocketSendBoundData = {
              requestId,
              messageType: msgType === 0 ? "data" : "string",
            };
            if (msgType === 0 && msgData)
              snapshot.dataLength = msgData.length();
            if (msgType === 1 && msgString)
              snapshot.messageText = msgString.toString();

            const block = new ObjC.Object(blockPtr);
            ObjC.bind(block, snapshot);
          },
        }),
      );
    }

    // -receiveMessageWithCompletionHandler:
    const recvImp = getMethodImp(
      clazz,
      "receiveMessageWithCompletionHandler:",
      false,
    );
    if (recvImp) {
      hooks.push(
        Interceptor.attach(recvImp, {
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
