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

function match(predicate: Cookie): ObjC.Object | undefined {
  const keys = ['name', 'domain', 'path', 'portList']
  for (const cookie of cookies(shared())) {
    if (keys.every(key => cookie[key]() + '' === predicate[key])) {
      return cookie
    }
  }
}

export function write(predicate: Cookie, value: string) {
  const cookie = match(predicate)
  const storage = shared()
  if (cookie) {
    const mutable = cookie.properties().mutableCopy()
    mutable.setObject_forKey_(value, 'Value')
    const newCookie = ObjC.classes.NSHTTPCookie.cookieWithProperties_(mutable)
    storage.setCookie_(newCookie)
    // this comment makes no sense but it can bypass some QuickJS parser bug
    return true
  }
  return false
}

export function remove(predicate: Cookie) {
  const cookie = match(predicate)
  console.log('found', cookie)
  if (cookie) {
    shared().deleteCookie_(cookie)
    return true
  }
  return false
}

export function clear() {
  const storage = shared()
  for (const cookie of cookies(storage)) {
    storage.deleteCookie_(cookie)
  }
}
