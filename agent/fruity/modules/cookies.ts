import ObjC from "frida-objc-bridge";

import type { NSObject, NSArray, NSDate, NSDictionary, NSURL, NSNumber } from "../typings.js";
import { toJsArray } from '../bridge/dictionary.js';


export type CookiePredicate = Partial<{
  name: string;
  domain: string;
  path: string;
  isSecure: boolean;
  isHTTPOnly: boolean;
  isSessionOnly: boolean;
}>

export interface Cookie {
  version: number,
  name: string,
  value: string,
  expiresDate: Date,
  domain: string,
  path: string,
  isSecure: boolean,
  isHTTPOnly: boolean,
  portList: number[],
  comment?: string,
  commentURL?: string,
  isSessionOnly: boolean,
  sameSitePolicy?: string,
}


interface NSHTTPCookie extends NSObject {
  version(): number;
  name(): string;
  value(): string;
  expiresDate(): NSDate;
  sessionOnly(): boolean;
  domain(): string;
  path(): string;
  isSecure(): boolean;
  isHTTPOnly(): boolean;
  portList(): NSArray<NSNumber>;
  comment(): string | null;
  commentURL(): NSURL | null;
  properties(): NSDictionary<string, NSObject>;
  isSessionOnly(): boolean;
  sameSitePolicy(): string | null;
}

interface NSHTTPCookieStorage extends NSObject {
  cookies(): NSArray<NSHTTPCookie>;
  setCookie_(cookie: NSHTTPCookie): void;
  deleteCookie_(cookie: NSHTTPCookie): void;
}


function shared() {
  return ObjC.classes.NSHTTPCookieStorage.sharedHTTPCookieStorage() as NSHTTPCookieStorage
}

function* iter(storage: NSHTTPCookieStorage) {
  const jar = storage.cookies()
  for (let i = 0; i < jar.count(); i++) {
    yield jar.objectAtIndex_(i)
  }
}

export function list(): Cookie[] {
  return Array.from(iter(shared())).map(cookie => {
    const entry: Cookie = {
      version: cookie.version(),
      name: cookie.name().toString(),
      value: cookie.value().toString(),
      expiresDate: cookie.expiresDate() ?
        new Date(cookie.expiresDate().timeIntervalSince1970() * 1000) : new Date(),
      domain: cookie.domain().toString(),
      path: cookie.path().toString(),
      isSecure: cookie.isSecure(),
      isHTTPOnly: cookie.isHTTPOnly(),
      portList: toJsArray(cookie.portList()),
      comment: cookie.comment()?.toString(),
      commentURL: cookie.commentURL()?.toString(),
      isSessionOnly: cookie.isSessionOnly(),
    }

    if (cookie.respondsToSelector_(ObjC.selector('sameSitePolicy'))) {
      entry.sameSitePolicy = cookie.sameSitePolicy()?.toString()
    }

    return entry
  })
}

function find(predicate: CookiePredicate): NSHTTPCookie | undefined {
  type K = keyof CookiePredicate
  const keys: K[] = ['name', 'domain', 'path', 'isSecure', 'isHTTPOnly', 'isSessionOnly']
  const set = new Set(keys)
  for (const cookie of iter(shared())) {
    const valid = (Object.keys(predicate) as K[])
      .filter(key => set.has(key))
      .every(key => cookie[key]() + '' === predicate[key])

    if (valid) {
      return cookie
    }
  }
}

export function write(predicate: CookiePredicate, value: string) {
  const cookie = find(predicate)
  if (!cookie) return false

  const storage = shared()
  const mutable = cookie.properties().mutableCopy()
  mutable.setObject_forKey_(value, 'Value')
  const newCookie = ObjC.classes.NSHTTPCookie.cookieWithProperties_(mutable)
  storage.setCookie_(newCookie)
  return true
}

export function remove(predicate: CookiePredicate) {
  const cookie = find(predicate)
  if (!cookie) return false
  shared().deleteCookie_(cookie)
  return true
}

export function clear() {
  const storage = shared()
  for (const cookie of iter(storage)) {
    storage.deleteCookie_(cookie)
  }
}
