import ObjC from "frida-objc-bridge";

import { hookXPC } from "./libxpc.js";
import { hookNSXPC } from "./nsxpc.js";

interface XPCNodeBase {
  description: string;
}

export interface XPCDictionaryNode extends XPCNodeBase {
  type: "dictionary";
  keys: string[];
  values: XPCNode[];
}

export interface XPCArrayNode extends XPCNodeBase {
  type: "array";
  values: XPCNode[];
}

export interface XPCStringNode extends XPCNodeBase {
  type: "string";
  value: string | null;
}

export interface XPCDataNode extends XPCNodeBase {
  type: "data";
  offset: number;
  length: number;
}

export interface XPCUUIDNode extends XPCNodeBase {
  type: "uuid";
  offset: number;
  value: string;
}

export interface XPCDoubleNode extends XPCNodeBase {
  type: "double";
  value: number;
}

export interface XPCUInt64Node extends XPCNodeBase {
  type: "uint64";
  value: string;
}

export interface XPCInt64Node extends XPCNodeBase {
  type: "int64";
  value: string;
}

export interface XPCBoolNode extends XPCNodeBase {
  type: "bool";
  value: boolean;
}

export interface XPCFdNode extends XPCNodeBase {
  type: "fd";
  value: number;
  path?: string | null;
}

export interface XPCNullNode extends XPCNodeBase {
  type: "null";
}

export interface XPCDateNode extends XPCNodeBase {
  type: "date";
  value: string;
}

export interface XPCShmemNode extends XPCNodeBase {
  type: "shmem";
}

export interface XPCErrorNode extends XPCNodeBase {
  type: "error";
}

export interface XPCEndpointNode extends XPCNodeBase {
  type: "endpoint";
}

export interface XPCConnectionNode extends XPCNodeBase {
  type: "connection";
}

export interface XPCUnknownNode extends XPCNodeBase {
  type: "unknown";
}

export type XPCNode =
  | XPCDictionaryNode
  | XPCArrayNode
  | XPCStringNode
  | XPCDataNode
  | XPCUUIDNode
  | XPCDoubleNode
  | XPCUInt64Node
  | XPCInt64Node
  | XPCBoolNode
  | XPCFdNode
  | XPCNullNode
  | XPCDateNode
  | XPCShmemNode
  | XPCErrorNode
  | XPCEndpointNode
  | XPCConnectionNode
  | XPCUnknownNode;

export type XPCNodeType = XPCNode["type"];

let running = false;
const listeners: InvocationListener[] = [];

export function start(): void {
  if (running) return;
  if (!ObjC.available) return;

  console.log("start logging XPC/NSXPC traffic");
  running = true;

  listeners.push(...hookXPC(), ...hookNSXPC());
}

export function stop(): void {
  if (!running) return;
  running = false;
  for (const listener of listeners) {
    listener.detach();
  }
  listeners.length = 0;
}

export function status(): boolean {
  return running;
}

export function available(): boolean {
  return ObjC.available && Process.findModuleByName("libxpc.dylib") !== null;
}
