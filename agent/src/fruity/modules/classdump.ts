import ObjC from "frida-objc-bridge";
type Tree<T> = {
  [name: string]: Tree<T> | T;
};

export function classesForModule(path: string) {
  const ownedBy = new ModuleMap((m) => m.path === path);
  if (!ObjC.available) throw new Error("Objective-C not available");
  return ObjC.enumerateLoadedClassesSync({ ownedBy })[path];
}

export function list(scope: string) {
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

export function find(keyword: string): string[] {
  const regex = new RegExp(keyword, "i");
  function* gen() {
    for (const name in ObjC.classes) if (regex.test(name)) yield name;
  }

  return [...gen()];
}

function copyIvars(clazz: ObjC.Object): { [offset: string]: string } {
  const { pointerSize } = Process;
  const numIvarsBuf = Memory.alloc(pointerSize);
  const ivarHandles = ObjC.api.class_copyIvarList(clazz.handle, numIvarsBuf);
  const result = new Map<string, string>();

  try {
    const numIvars = numIvarsBuf.readUInt();
    for (let i = 0; i < numIvars; i++) {
      const handle = ivarHandles.add(i * pointerSize).readPointer();
      const name = ObjC.api.ivar_getName(handle).readUtf8String() as string;
      const offset = "0x" + ObjC.api.ivar_getOffset(handle).toString(16);
      result.set(offset, name);
    }
  } finally {
    ObjC.api.free(ivarHandles);
  }

  return Object.fromEntries(result);
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

export interface ClassInfo {
  name: string;
  protocols: string[];
  methods: { [key: string]: string };
  proto: string[];
  own: string[];
  ivars: { [offset: string]: string };
  module: string;
}

export function inspect(name: string): ClassInfo {
  const clazz = ObjC.classes[name];
  if (!clazz) throw new Error(`class ${name} not found`);

  const methods: { [key: string]: string } = {};
  clazz.$methods.forEach((sel) => {
    const impl = clazz[sel].implementation as NativePointer;
    methods[sel] = `${impl}`;
    const mod = Process.findModuleByAddress(impl);
    if (mod) {
      methods[sel] += ` (${mod.name}+${impl.sub(mod.base)})`;
    }
  });

  const protocols = Object.keys(clazz.$protocols);
  const module = clazz.$moduleName;
  const own = clazz.$ownMethods;
  const ivars = copyIvars(clazz);

  const proto = [];
  {
    let cur = clazz;
    while ((cur = cur.$superClass)) proto.unshift(cur.$className);
  }

  return {
    name: name,
    protocols,
    methods,
    proto: proto,
    own,
    ivars,
    module,
  };
}
