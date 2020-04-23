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

export function inspect(clazz: string) {
  const proto = []
  let clz = ObjC.classes[clazz]
  if (!clz)
    throw new Error(`class ${clazz} not found`)

  while (clz = clz.$superClass)
    proto.unshift(clz.$className)

  return {
    methods: ObjC.classes[clazz].$ownMethods,
    proto
  }
}
