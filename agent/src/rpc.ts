import ObjC from 'frida-objc-bridge'

const exported = new Map()

export function register(func: Function, name?: string) {
  const key = name || func.name
  if (exported.has(key))
    throw new Error(`Name collinsion: ${key}`)

  exported.set(key, func)
}

export function invoke(name: string, args=[]) {
  const method = exported.get(name)
  if (!method)
    throw new Error(`method "${name}" not found`)

  const { NSAutoreleasePool } = ObjC.classes
  const pool = NSAutoreleasePool.alloc().init()
  try {
    return method(...args)
  } finally {
    pool.release()
  }
}

export function interfaces() {
  return [...exported.keys()] as string[]
}
