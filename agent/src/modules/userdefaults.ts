import { valueOf } from '../lib/dict.js'
import { NSDictionary, NSArray, NSObject, NSNumber, NSString, NSDate, NSData } from '../objc-types.js'

/**
 * A default object must be a property list—that is, an instance of (or for collections, 
 * a combination of instances of) NSData, NSString, NSNumber, NSDate, NSArray, or NSDictionary.
 * If you want to store any other type of object, you should typically archive it to create an instance of NSData.
 * 
 * https://developer.apple.com/documentation/foundation/nsuserdefaults
 */

type UserDefaultsType = 'data' | 'string' | 'number' | 'date' | 'array' | 'dict'
type UserDefaultsValue = NSString | NSData | NSNumber | NSDate |
  NSArray<UserDefaultsValue> | NSDictionary<NSString, UserDefaultsValue>

interface UserDefaultsEntry {
  type: UserDefaultsType
  readable: string
  value: any
}

interface UserDefaultsDict {
  [key: string]: UserDefaultsEntry
}

interface NSUserDefaults extends NSObject {
  dictionaryRepresentation(): NSDictionary<string, UserDefaultsValue>
  objectForKey_(key: string): UserDefaultsValue
}

function typeName(value: NSObject): UserDefaultsType {
  const mapping: {[className: string]: UserDefaultsType} = {
    'NSData': 'data',
    'NSString': 'string',
    'NSNumber': 'number',
    'NSDate': 'date',
    'NSArray': 'array',
    'NSDictionary': 'dict'
  }

  for (const [className, type] of Object.entries(mapping)) {
    if (value.isKindOfClass_(ObjC.classes[className]))
      return type
  }

  throw new Error(`Unknown type: ${value}`)
}

function singleton() {
  return ObjC.classes.NSUserDefaults.standardUserDefaults() as NSUserDefaults
}

export function enumerate() {
  const asDict = singleton().dictionaryRepresentation()
  const keys = asDict.allKeys()

  function* gen() {
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

/*
 * It's impossible for us to distinguish among different types of NSNumbers and boolean values.
 * Also, we can't handle nested array and dictionary.
 *
 * So only support NSString, NSData and NSDate here.
 */

export function update(key: string, value: string | number) {
  const userDefaults = singleton()
  const current = userDefaults.objectForKey_(key)
  if (!current) throw new Error(`key ${key} not found`)
  if (current.isKindOfClass_(ObjC.classes.NSString) && typeof value === 'string') {
    // string literal
    userDefaults.setObject_forKey_(value, key)
  } else if (current.isKindOfClass_(ObjC.classes.NSDate) && typeof value === 'number') {
    // timestamp
    userDefaults.setObject_forKey_(ObjC.classes.NSDate.dateWithTimeIntervalSince1970_(value), key)
  } else if (current.isKindOfClass_(ObjC.classes.NSData) && typeof value === 'string') {
    // base64 encoded string
    userDefaults.setObject_forKey_(ObjC.classes.NSData.alloc().initWithBase64EncodedString_options_(value, 0), key)
  } else {
    throw new Error(`Unable to update ${key} with ${value}, either type mismatch or unsupported type`)
  }
}

export function remove(key: string) {
  // no need to do existence check
  singleton().removeObjectForKey_(key)
}

// @todo: shall we support value creation?
