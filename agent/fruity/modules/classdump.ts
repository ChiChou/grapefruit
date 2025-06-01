import ObjC from "frida-objc-bridge";

type Tree<T> = {
  [name: string]: Tree<T> | T;
}

const mainBundle = ObjC.classes.NSBundle.mainBundle()

const moduleMaps: { [key: string]: ModuleMap } = {
  __global__: new ModuleMap,
  __app__: new ModuleMap(module => module.path.startsWith(mainBundle.bundlePath().toString())),
  __main__: new ModuleMap(module => module.path === Process.mainModule.path),
}

export function list(scope: string) {
  const ownedBy = moduleMaps.hasOwnProperty(scope) ?
    moduleMaps[scope] :
    new ModuleMap(module => module.path === scope)

  return ObjC.enumerateLoadedClassesSync({ ownedBy })
}

export function find(keyword: string): string[] {
  const regex = new RegExp(keyword, 'i')
  function *gen() {
    for (const name in ObjC.classes)
      if (regex.test(name))
        yield name
  }

  return [...gen()]
}

function copyIvars(clazz: ObjC.Object) {
  const { pointerSize } = Process
  const numIvarsBuf = Memory.alloc(pointerSize)
  const ivarHandles = ObjC.api.class_copyIvarList(clazz.handle, numIvarsBuf)
  const result = new Map<string, string>();

  try {
    const numIvars = numIvarsBuf.readUInt()
    for (let i = 0; i < numIvars; i++) {
      const handle = ivarHandles.add(i * pointerSize).readPointer()
      const name = ObjC.api.ivar_getName(handle).readUtf8String() as string
      const offset = '0x' + ObjC.api.ivar_getOffset(handle).toString(16)
      result.set(offset, name)
    }
  } finally {
    ObjC.api.free(ivarHandles)
  }

  return { ...result }
}

export function hierarchy(): Tree<string> {
  const tree: Tree<string> = {}
  for (const [name, clazz] of Object.entries(ObjC.classes)) {
    const chain = [name]

    let parent = clazz
    /* eslint no-cond-assign:0 */
    while (parent = parent.$superClass)
      chain.unshift(parent.$className)

    let node = tree
    for (const className of chain) {
      if (!node[className])
        node[className] = {}
      node = node[className] as Tree<string>
    }
  }

  return tree
}

type Method = {
  name: string;
  impl: string;
}

// type MethodDecl = {
//   required: boolean;
//   types: string;
// }

// type Protocol = {
//   name: string;
//   methods: {[key: string]: MethodDecl};
//   properties: string[];
// }

export function inspect(clazz: string) {
  let cls = ObjC.classes[clazz]
  if (!cls) throw new Error(`class ${clazz} not found`)

  const methods: { [key: string]: Method } = {}
  cls.$methods.forEach(name => {
    const impl = cls[name].implementation.toString()
    methods[name] = { name, impl }
  })

  const protocols = JSON.parse(JSON.stringify(cls.$protocols)) as { [key: string]: ObjC.Protocol }
  for (const protocol of Object.values(protocols)) {
    if (protocol.protocols) protocol.protocols = {}
  }

  const module = cls.$moduleName
  const own = cls.$ownMethods
  const ivars = copyIvars(cls)

  const proto = []
  while (cls = cls.$superClass)
    proto.unshift(cls.$className)

  return {
    protocols,
    methods,
    prototypeChain: proto,
    own,
    ivars,
    module
  }
}
