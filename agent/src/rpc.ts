const exported = new Map()

export function register(func: Function, name?: string) {
  const key = name || func.name
  if (exported.has(key))
    throw new Error(`Name collinsion: ${key}`)

  exported.set(key, func)
}

export function invoke(name: string, args: any[]) {
  const { NSAutoreleasePool } = ObjC.classes
  const pool = NSAutoreleasePool.alloc().init()
  const method = exported.get(name)
  if (!method)
    throw new Error(`method "${name}" not found`)

  try {
    return method(...args)
  } finally {
    pool.release()
  }
}

export function interfaces() {
  return [...exported.keys()]
}
