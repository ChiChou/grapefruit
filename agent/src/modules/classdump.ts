const { NSBundle, NSString } = ObjC.classes
const copyClassNamesForImage = new NativeFunction(
  Module.findExportByName(null, 'objc_copyClassNamesForImage')!, 'pointer', ['pointer', 'pointer']
)
const free = new NativeFunction(Module.findExportByName(null, 'free')!, 'void', ['pointer'])

export function dump(path?: string): string[] {
  const filename = path || NSBundle.mainBundle().executablePath().toString()
  const image = Memory.allocUtf8String(filename)

  const p = Memory.alloc(Process.pointerSize).writePointer(NULL)
  const pClasses = copyClassNamesForImage(image, p) as NativePointer
  const count = p.readUInt()
  const classes = new Array(count)
  for (let i = 0; i < count; i++) {
    const pClassName = pClasses.add(i * Process.pointerSize).readPointer()
    classes[i] = pClassName.readUtf8String()
  }
  free(pClasses)
  return classes
}

const normalize = (path: string) => NSString.stringWithString_(path).stringByResolvingAndStandardizingPath().toString()
const flattern = (array: any[]) => array.reduce((sum, item) => sum.concat(item), [])

export function ownClasses(): string[] {
  const bundle = normalize(NSBundle.mainBundle().bundlePath())
  const result = Process.enumerateModules()
    .filter(mod => normalize(mod.path).startsWith(bundle))
    .map(mod => dump(mod.path))
  return flattern(result)
}

type Tree<T> = {
  [name: string]: Tree<T> | T;
}

export type Scope = '__global__' | '__app__' | '__main__'

export function list(scope: Scope | string[] | string): string[] {
  if (scope === '__global__') return Object.keys(ObjC.classes)
  else if (scope === '__app__') return ownClasses()
  else if (scope === '__main__') return dump()
  else if (Array.isArray(scope)) return flattern(scope.map(dump)) // list of paths
  return dump(scope) // a module path
}

export function search(scope: Scope | string[] | string, keyword?: string): string[] {
  const all = list(scope)
  if (!keyword || !keyword.length) return all
  const query = new RegExp(keyword/*.split('').join('.*?')*/, 'i')
  return all.filter(name => query.test(name))
}

export function hierarchy(scope: string): Tree<string> {
  const classes = list(scope)
  const tree: Tree<string> = {}
  for (const name of classes) {
    const clazz = ObjC.classes[name]
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

  const methods: {[key: string]: Method } = {}
  cls.$methods.forEach(name => {
    const impl = cls[name].implementation.toString()
    methods[name] = { name, impl }
  })

  const protocols = JSON.parse(JSON.stringify(cls.$protocols)) as {[key: string]: ObjC.Protocol}
  for (const protocol of Object.values(protocols)) {
    if (protocol.protocols) protocol.protocols = {}
  }

  const module = cls.$moduleName
  const ivars = Object.keys(cls.$ivars)
  const own = cls.$ownMethods

  const prototypeChain = []
  while (cls = cls.$superClass)
    prototypeChain.unshift(cls.$className)

  return {
    protocols,
    methods,
    prototypeChain,
    own,
    ivars,
    module
  }
}
