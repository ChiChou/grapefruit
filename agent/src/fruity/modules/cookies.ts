import ObjC from "frida-objc-bridge";
import type {
  NSObject,
  NSArray,
  NSDate,
  NSDictionary,
  NSURL,
  NSNumber,
  StringLike,
  NSMutableDictionary,
  NSString,
} from "../typings.js";
import { toJsArray } from "../bridge/dictionary.js";

export type CookiePredicate = Partial<{
  name: string;
  domain: string;
  path: string;
}>;

export interface Cookie {
  version: number;
  name: string;
  value: string;
  expiresDate: Date | null;
  domain: string;
  path: string;
  isSecure: boolean;
  isHTTPOnly: boolean;
  portList: number[];
  comment?: string;
  commentURL?: string;
  isSessionOnly: boolean;
  sameSitePolicy?: string;
}

const PropertyKey = (suffix: string) => {
  let Foundation: Module | null = null;
  if (!Foundation) Foundation = Process.getModuleByName("Foundation");
  return new ObjC.Object(
    Foundation.getExportByName("NSHTTPCookie" + suffix).readPointer(),
  ) as NSString;
};

function NSCookieFromJS(cookie: Cookie) {
  const { NSString, NSDate } = ObjC.classes;
  const dict =
    ObjC.classes.NSMutableDictionary.alloc().init() as NSMutableDictionary<
      StringLike,
      NSObject
    >;

  dict.setObject_forKey_(
    NSString.stringWithString_(cookie.name),
    PropertyKey("Name"),
  );
  dict.setObject_forKey_(
    NSString.stringWithString_(cookie.value),
    PropertyKey("Value"),
  );
  dict.setObject_forKey_(
    NSString.stringWithString_(cookie.domain),
    PropertyKey("Domain"),
  );
  dict.setObject_forKey_(
    NSString.stringWithString_(cookie.path),
    PropertyKey("Path"),
  );
  dict.setObject_forKey_(
    NSString.stringWithString_(cookie.version.toString()),
    PropertyKey("Version"),
  );

  if (cookie.expiresDate) {
    dict.setObject_forKey_(
      NSDate.dateWithTimeIntervalSince1970_(
        cookie.expiresDate.getTime() / 1000,
      ),
      PropertyKey("Expires"),
    );
  }

  if (cookie.isSecure) {
    dict.setObject_forKey_(
      NSString.stringWithString_("TRUE"),
      PropertyKey("Secure"),
    );
  }

  if (cookie.isSessionOnly) {
    dict.setObject_forKey_(
      NSString.stringWithString_("TRUE"),
      PropertyKey("Discard"),
    );
  }

  if (cookie.portList && cookie.portList.length > 0) {
    dict.setObject_forKey_(
      NSString.stringWithString_(cookie.portList.join(",")),
      PropertyKey("Port"),
    );
  }

  if (cookie.comment) {
    dict.setObject_forKey_(
      NSString.stringWithString_(cookie.comment),
      PropertyKey("Comment"),
    );
  }

  if (cookie.commentURL) {
    dict.setObject_forKey_(
      NSString.stringWithString_(cookie.commentURL),
      PropertyKey("CommentURL"),
    );
  }

  if (cookie.sameSitePolicy) {
    dict.setObject_forKey_(
      NSString.stringWithString_(cookie.sameSitePolicy),
      PropertyKey("SameSitePolicy"),
    );
  }

  return ObjC.classes.NSHTTPCookie.cookieWithProperties_(dict);
}

function JSCookieFromNS(cookie: NSHTTPCookie) {
  const entry: Cookie = {
    version: cookie.version(),
    name: cookie.name().toString(),
    value: cookie.value().toString(),
    expiresDate: new Date(cookie.expiresDate()?.timeIntervalSince1970() * 1000),
    domain: cookie.domain().toString(),
    path: cookie.path().toString(),
    isSecure: cookie.isSecure(),
    isHTTPOnly: cookie.isHTTPOnly(),
    portList: toJsArray(cookie.portList()),
    comment: cookie.comment()?.toString(),
    commentURL: cookie.commentURL()?.toString(),
    isSessionOnly: cookie.isSessionOnly(),
  };

  if (cookie.respondsToSelector_(ObjC.selector("sameSitePolicy"))) {
    entry.sameSitePolicy = cookie.sameSitePolicy()?.toString();
  }

  return entry;
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
  comment(): StringLike | null;
  commentURL(): NSURL | null;
  properties(): NSDictionary<StringLike, NSObject>;
  isSessionOnly(): boolean;
  sameSitePolicy(): string | null;
}

interface NSHTTPCookieStorage extends NSObject {
  cookies(): NSArray<NSHTTPCookie>;
  setCookie_(cookie: NSHTTPCookie): void;
  deleteCookie_(cookie: NSHTTPCookie): void;
}

function shared() {
  return ObjC.classes.NSHTTPCookieStorage.sharedHTTPCookieStorage() as NSHTTPCookieStorage;
}

function* iter(storage: NSHTTPCookieStorage) {
  const jar = storage.cookies();
  for (let i = 0; i < jar.count(); i++) {
    yield jar.objectAtIndex_(i);
  }
}

export function list(): Cookie[] {
  return Array.from(iter(shared())).map(JSCookieFromNS);
}

export function add(cookie: Cookie) {
  shared().setCookie_(NSCookieFromJS(cookie));
}

function find(predicate: CookiePredicate): NSHTTPCookie | undefined {
  type K = keyof CookiePredicate;
  const keys = Object.keys(predicate) as K[];
  const set = new Set(keys);
  for (const cookie of iter(shared())) {
    const valid = (Object.keys(predicate) as K[])
      .filter((key) => set.has(key))
      .every((key) => cookie[key]() + "" === predicate[key]);

    if (valid) {
      return cookie;
    }
  }
}

export function create(
  domain: string,
  name: string,
  value: string,
  expires: Date,
  httpOnly = false,
  secure = false,
) {
  throw new Error("not implemented");
}

export function update(
  predicate: CookiePredicate,
  field: "expiresDate" | "value",
  value: number | string, // timestamp or value
) {
  const cookie = find(predicate);
  if (!cookie) return false;

  const storage = shared();
  const mutable = cookie.properties().mutableCopy();

  if (field === "expiresDate") {
    const ts = value as number;
    const nsDate = ObjC.classes.NSDate.dateWithTimeIntervalSince1970_(
      ts / 1000,
    );
    mutable.setObject_forKey_(nsDate, PropertyKey("Expires"));
  } else {
    mutable.setObject_forKey_(value as string, PropertyKey("Value"));
  }

  const newCookie = ObjC.classes.NSHTTPCookie.cookieWithProperties_(mutable);
  storage.setCookie_(newCookie);
  return true;
}

export function remove(predicate: CookiePredicate) {
  const cookie = find(predicate);
  if (!cookie) return false;
  shared().deleteCookie_(cookie);
  return true;
}

export function clear() {
  const storage = shared();
  for (const cookie of iter(storage)) {
    storage.deleteCookie_(cookie);
  }
}
