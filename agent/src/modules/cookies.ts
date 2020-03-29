const PROPERTIES = ['version', 'name', 'value', 'domain', 'path']

type Cookie = { [key:string]: string | boolean }

export function list(): Cookie[] {
  const jar = ObjC.classes.NSHTTPCookieStorage.sharedHTTPCookieStorage().cookies()
  const result = new Array(jar.count())
  for (let i = 0; i < jar.count(); i++) {
    const cookie = jar.objectAtIndex_(i)
    const entry: Cookie = {}
    for (const prop of PROPERTIES) {
      entry[prop] = cookie[prop]().toString()
      entry.isSecure = cookie.isSecure()
    }
    result[i] = entry
  }

  return result
}

// to mute eslint "Prefer default export"
export function write() {

}
