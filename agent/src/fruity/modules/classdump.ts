import ObjC from "frida-objc-bridge";

type Tree<T> = {
  [name: string]: Tree<T> | T;
};

const PROPERTY_ATTRS = "TRC&WNOD" as const;
type Property = Record<(typeof PROPERTY_ATTRS)[number], string>;

// interface Property {
//   T: string; // type
//   R?: ""; // readonly
//   C?: ""; // copy
//   "&"?: ""; // strong
//   W?: ""; // weak
//   N?: ""; // nonatomic
//   D?: ""; // dynamic
// }

export interface Ivar {
  name: string;
  offset: number;
  type: string;
}

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

function copyIvars(clazz: ObjC.Object) {
  const { pointerSize } = Process;
  const numIvarsBuf = Memory.alloc(pointerSize);
  const ivarHandles = ObjC.api.class_copyIvarList(clazz.handle, numIvarsBuf);
  const result: Ivar[] = [];

  if (ivarHandles.isNull()) return result;

  try {
    const numIvars = numIvarsBuf.readUInt();
    for (let i = 0; i < numIvars; i++) {
      const handle = ivarHandles.add(i * pointerSize).readPointer();
      const name = ObjC.api.ivar_getName(handle).readUtf8String() as string;
      const offset = ObjC.api.ivar_getOffset(handle).toInt32();
      const type = ObjC.api
        .ivar_getTypeEncoding(handle)
        .readUtf8String() as string;

      result.push({
        name,
        offset,
        type,
      });
    }
  } finally {
    ObjC.api.free(ivarHandles);
  }

  return result;
}

export function hierarchy(): Tree<string> {
  const tree: Tree<string> = {};
  for (const [name, clazz] of Object.entries(ObjC.classes)) {
    const chain = [name];

    let parent = clazz;
    /* eslint no-cond-assign:0 */
    while ((parent = parent.$superClass)) chain.unshift(parent.$className);

    let node = tree;
    for (const className of chain) {
      if (!node[className]) node[className] = {};
      node = node[className] as Tree<string>;
    }
  }

  return tree;
}

let api: {
  class_copyPropertyList: NativeFunction<
    NativePointer,
    [NativePointerValue, NativePointerValue]
  >;
  property_copyAttributeValue: NativeFunction<
    NativePointer,
    [NativePointerValue, NativePointerValue]
  >;
  property_getName: NativeFunction<NativePointer, [NativePointerValue]>;
};

function ObjCRuntime() {
  if (api) return api;

  const libobjc = Process.getModuleByName("libobjc.A.dylib");
  const class_copyPropertyList = new NativeFunction(
    libobjc.getExportByName("class_copyPropertyList"),
    "pointer",
    ["pointer", "pointer"],
  );

  const property_copyAttributeValue = new NativeFunction(
    libobjc.getExportByName("property_copyAttributeValue"),
    "pointer",
    ["pointer", "pointer"],
  );

  const property_getName = new NativeFunction(
    libobjc.getExportByName("property_getName"),
    "pointer",
    ["pointer"],
  );

  return (api = {
    class_copyPropertyList,
    property_copyAttributeValue,
    property_getName,
  });
}

function copyProperties(clazz: ObjC.Object): Record<string, Property> {
  const {
    property_getName,
    property_copyAttributeValue,
    class_copyPropertyList,
  } = ObjCRuntime();

  const result: Record<string, Property> = {};

  const nPropsBuf = Memory.alloc(Process.pointerSize);
  const props = class_copyPropertyList(clazz.handle, nPropsBuf);
  const nProps = nPropsBuf.readUInt();

  if (props.isNull()) return result;

  const keys: Record<string, NativePointerValue> = {};
  for (const c of PROPERTY_ATTRS) {
    keys[c] = Memory.allocUtf8String(c);
  }

  try {
    for (let i = 0; i < nProps; i++) {
      const handle = props.add(i * Process.pointerSize).readPointer();
      const namePtr = property_getName(handle);
      if (namePtr.isNull()) continue;
      const name = namePtr.readUtf8String() as string;
      const attrs: Record<string, string> = {};

      for (const [key, keyStr] of Object.entries(keys)) {
        const v = property_copyAttributeValue(handle, keyStr);
        if (v.isNull()) continue;
        attrs[key] = v.readUtf8String() as string;
      }

      result[name] = attrs;
    }
  } finally {
    ObjC.api.free(props);
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
