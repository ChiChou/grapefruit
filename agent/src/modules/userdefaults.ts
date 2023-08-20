import { valueOf } from '../lib/dict.js'
import { NSDictionary, NSObject } from '../objc-types.js'

interface NSUserDefaults extends NSObject {
  dictionaryRepresentation(): NSDictionary<string, NSObject>
}

interface UserDefaultsDict {
  [key: string]: UserDefaultsEntry
}

/**
 * A default object must be a property list—that is, an instance of (or for collections, 
 * a combination of instances of) NSData, NSString, NSNumber, NSDate, NSArray, or NSDictionary.
 * If you want to store any other type of object, you should typically archive it to create an instance of NSData.
 * 
 * https://developer.apple.com/documentation/foundation/nsuserdefaults
 */

type UserDefaultsType = 'data' | 'string' | 'number' | 'date' | 'array' | 'dict'

interface UserDefaultsEntry {
  type: UserDefaultsType
  readable: string
  value: any
}

function typeName(value: NSObject): UserDefaultsType {
  if (value.isKindOfClass_(ObjC.classes.NSData))
    return 'data'

  if (value.isKindOfClass_(ObjC.classes.NSString))
    return 'string'

  if (value.isKindOfClass_(ObjC.classes.NSNumber))
    return 'number'

  if (value.isKindOfClass_(ObjC.classes.NSDate))
    return 'date'

  if (value.isKindOfClass_(ObjC.classes.NSArray))
    return 'array'

  if (value.isKindOfClass_(ObjC.classes.NSDictionary))
    return 'dict'

  throw new Error(`Unknown type: ${value}`)
}

export default function () {
  const defaults = ObjC.classes.NSUserDefaults.standardUserDefaults() as NSUserDefaults
  const asDict = defaults.dictionaryRepresentation()
  const keys = asDict.allKeys()

  function *gen() {
    for (let i = 0; i < keys.count(); i++) {
      const key = keys.objectAtIndex_(i)
      const value = asDict.objectForKey_(key)
      
      yield [key.toString(), {
        type: typeName(value),
        readable: value.toString(),
        value: valueOf(value)
      }]
    }
  }

  return Object.fromEntries(gen()) as UserDefaultsDict
}
