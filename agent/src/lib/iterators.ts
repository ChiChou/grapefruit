import ObjC from 'frida-objc-bridge'

export class Dict {
  static *keys(dict: ObjC.Object) {
    if (!dict.isKindOfClass_(ObjC.classes.NSDictionary))
      throw new Error(`Unknown class ${dict.$className}`)
    yield *Arr.values(dict.allKeys())
  }

  static *values(dict: ObjC.Object) {
    for (const key of Dict.keys(dict))
      yield dict.objectForKey_(key)
  }

  static *entries(dict: ObjC.Object) {
    for (const key of Dict.keys(dict)) {
      const value = dict.objectForKey_(key)
      yield [key, value]
    }
  }
}

export class Arr {
  static *values(arr: ObjC.Object) {
    if (!arr.isKindOfClass_(ObjC.classes.NSArray))
      throw new Error(`Unknown class ${arr.$className}`)
    
    const count = arr.count()
    for (let i = 0; i < count; i++)
      yield arr.objectAtIndex_(i)
  }
}
