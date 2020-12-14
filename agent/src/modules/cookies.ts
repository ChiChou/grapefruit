const PROPERTIES = ['version', 'name', 'value', 'domain', 'path', 'expiresDate', 'portList', 'sameSitePolicy']

type Cookie = { [key:string]: string | boolean }

function shared() {
  return ObjC.classes.NSHTTPCookieStorage.sharedHTTPCookieStorage()
}

function *cookies(storage: ObjC.Object) {
  const jar = storage.cookies()
  for (let i = 0; i < jar.count(); i++) {
    yield jar.objectAtIndex_(i)
  }
}

export function list(): Cookie[] {
  const result = []
  for (const cookie of cookies(shared())) {
    const entry: Cookie = {}
    for (const prop of PROPERTIES) {
      const val = cookie[prop]()
      if (val) entry[prop] = val.toString()
    }
    entry.HTTPOnly = cookie.isHTTPOnly()
    entry.secure = cookie.isSecure()
    entry.sessionOnly = cookie.isSessionOnly()
    result.push(entry)
  }

  return result
}

export function write(predicate: Cookie, value: string) {
  const storage = shared()  
  const keys = ['name', 'domain', 'path', 'portList']
  for (const cookie of cookies(storage)) {
    if (keys.every(key => cookie[key]() === predicate[key])) {
      cookie.setValue_(value)
      storage.setCookie_(cookie)
      return true
    }
  }
  return false  // not found
}

export function clear() {
  const storage = shared()
  for (const cookie of cookies(storage)) {
    storage.deleteCookie_(cookie)
  }
}
