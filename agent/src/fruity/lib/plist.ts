import ObjC from "frida-objc-bridge";

import { NSData } from "../typings.js";
import { toJS } from "../bridge/object.js";

export function nsdata2str(data: NSData) {
  const NSUTF8StringEncoding = 4;
  return ObjC.classes.NSString.alloc()
    .initWithData_encoding_(data, NSUTF8StringEncoding)
    .toString() as string;
}

export function toXML(obj: ObjC.Object) {
  const NSPropertyListXMLFormat_v1_0 = 100;
  const xml: NSData =
    ObjC.classes.NSPropertyListSerialization.dataWithPropertyList_format_options_error_(
      obj,
      NSPropertyListXMLFormat_v1_0,
      0,
      NULL,
    );

  return nsdata2str(xml);
}

export function toJSON(obj: ObjC.Object) {
  const data: NSData =
    ObjC.classes.NSJSONSerialization.dataWithJSONObject_options_error_(
      obj,
      0,
      NULL,
    );

  return nsdata2str(data);
}

export interface UnifiedPlistFormat {
  xml: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  value: any;
}

export function dump(obj: ObjC.Object) {
  const xml = toXML(obj);
  const value = toJS(obj);
  return { xml, value };
}
