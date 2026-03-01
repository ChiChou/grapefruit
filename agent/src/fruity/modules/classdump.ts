import ObjC from "frida-objc-bridge";
import {
  copyIvars,
  copyProperties,
  type Ivar,
  type Property,
} from "@/fruity/bridge/runtime.js";

export type { Ivar, Property };

export interface Method {
  name: string;
  impl: string;
  types: string;
}

export interface ClassDetail {
  name: string;
  protocols: string[];
  methods: Method[];
  ownMethods: string[]; // lookup in methods
  proto: string[]; // superclass chain
  ivars: Ivar[];
  module: string;
  properties: Record<string, Property>;
}

export function classesForModule(path: string) {
  const ownedBy = new ModuleMap((m) => m.path === path);
  if (!ObjC.available) throw new Error("Objective-C not available");
  return ObjC.enumerateLoadedClassesSync({ ownedBy })[path];
}

export function list(scope: string): string[] {
  const mainBundle = ObjC.classes.NSBundle.mainBundle();

  const moduleMaps: { [key: string]: ModuleMap } = {
    __global__: new ModuleMap(),
    __app__: new ModuleMap((module) =>
      module.path.startsWith(mainBundle.bundlePath().toString()),
    ),
    __main__: new ModuleMap(
      (module) => module.path === Process.mainModule.path,
    ),
  };

  const ownedBy = moduleMaps.hasOwnProperty(scope)
    ? moduleMaps[scope]
    : new ModuleMap((module) => module.path === scope);

  const groupBy = ObjC.enumerateLoadedClassesSync({ ownedBy });
  const all = [];
  for (const mod in groupBy) {
    all.push(...groupBy[mod]);
  }
  return all;
}

export function inheritance(): Record<string, string | null> {
  const result: Record<string, string | null> = {};
  for (const [name, clazz] of Object.entries(ObjC.classes)) {
    result[name] = clazz.$superClass?.$className ?? null;
  }
  return result;
}

export function inspect(name: string): ClassDetail {
  const clazz = ObjC.classes[name];
  if (!clazz) throw new Error(`class ${name} not found`);

  const methods: Method[] = clazz.$methods.map((sel) => {
    const meth = clazz[sel] as ObjC.ObjectMethod;
    // const addr = meth.implementation;

    // too much overhead
    // const mod = Process.findModuleByAddress(addr);
    // const offset = mod ? `${mod.name}+${addr.sub(mod.base)}` : "";
    // const impl = `${addr} ${offset}`;

    return {
      name: sel,
      impl: meth.implementation.toString(),
      types: meth.types,
    };
  });

  const protocols = Object.keys(clazz.$protocols);
  const module = clazz.$moduleName;
  const ivars = copyIvars(clazz);

  const proto = [];
  {
    let cur = clazz;
    while ((cur = cur.$superClass)) proto.unshift(cur.$className);
  }

  const properties = copyProperties(clazz);

  return {
    name: name,
    protocols,
    properties,
    methods,
    proto,
    ownMethods: clazz.$ownMethods,
    ivars,
    module,
  };
}
