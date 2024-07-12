import { NSObject, NSArray, NSDictionary } from "./foundation.js"

export namespace NS {
  export namespace Dictionary {
    export function* keys(dict: NSDictionary<NSObject, NSObject>) {
      if (!dict.isKindOfClass_(ObjC.classes.NSDictionary))
        throw new Error(`Unexpected class ${dict.$className}`)
      Array.values(dict.allKeys())
    }
  }

  export namespace Array {
    export function* values(arr: NSArray<NSObject>) {
      if (!arr.isKindOfClass_(ObjC.classes.NSArray))
        throw new Error(`Unexpected class ${arr.$className}`)

      const count = arr.count()
      for (let i = 0; i < count; i++)
        yield arr.objectAtIndex_(i)
    }
  }
}
