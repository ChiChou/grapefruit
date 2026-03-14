import Java from "frida-java-bridge";

import { perform } from "@/common/hooks/java.js";
import { getContext } from "../lib/context.js";

export interface ResourceTree {
  [category: string]: string[];
}

const SUPPORTED_TYPES = new Set(["string", "xml", "raw", "array"]);

export function list(): Promise<ResourceTree> {
  return perform(() => {
    const packageName = getContext().getPackageName();

    const RClass = Java.use(packageName + ".R");
    const innerClasses = RClass.class.getDeclaredClasses();
    const Modifier = Java.use("java.lang.reflect.Modifier");

    const result: ResourceTree = {};

    for (let i = 0; i < innerClasses.length; i++) {
      const clazz = innerClasses[i];
      const className: string = clazz.getName();
      const typeName = className.split("$").pop()!;

      if (!SUPPORTED_TYPES.has(typeName.toLowerCase())) continue;

      const fields = clazz.getDeclaredFields();
      const names: string[] = [];

      for (let j = 0; j < fields.length; j++) {
        const field = fields[j];
        if (!Modifier.isStatic(field.getModifiers())) continue;
        names.push(field.getName());
      }

      if (names.length > 0) {
        result[typeName] = names.sort();
      }
    }

    return result;
  });
}

export function get(category: string, name: string): Promise<string> {
  return perform(() => {
    const appContext = getContext();
    const resources = appContext.getResources();
    const packageName = appContext.getPackageName();

    const resId: number = resources.getIdentifier(name, category, packageName);
    if (resId === 0) throw new Error(`Resource not found: ${category}/${name}`);

    switch (category) {
      case "string":
        return String(resources.getString(resId));

      case "array": {
        try {
          const arr = resources.getStringArray(resId);
          const items: string[] = [];
          for (let i = 0; i < arr.length; i++) {
            items.push(String(arr[i]));
          }
          return JSON.stringify(items, null, 2);
        } catch {
          try {
            const arr = resources.getIntArray(resId);
            const items: number[] = [];
            for (let i = 0; i < arr.length; i++) {
              items.push(arr[i]);
            }
            return JSON.stringify(items, null, 2);
          } catch {
            return "[array]";
          }
        }
      }

      case "xml": {
        const XmlBlock$Parser = Java.use("android.content.res.XmlBlock$Parser");
        const rawParser = resources.getXml(resId);
        const parser = Java.cast(rawParser, XmlBlock$Parser);

        const END_DOCUMENT = 1;
        const START_TAG = 2;
        const END_TAG = 3;
        const TEXT = 4;

        let xml = "";
        let indent = 0;
        let eventType: number = parser.getEventType();

        while (eventType !== END_DOCUMENT) {
          if (eventType === START_TAG) {
            xml += "  ".repeat(indent) + "<" + parser.getName();
            const attrCount: number = parser.getAttributeCount();
            for (let i = 0; i < attrCount; i++) {
              xml +=
                " " +
                parser.getAttributeName(i) +
                '="' +
                parser.getAttributeValue(i) +
                '"';
            }
            xml += ">\n";
            indent++;
          } else if (eventType === END_TAG) {
            indent--;
            xml += "  ".repeat(indent) + "</" + parser.getName() + ">\n";
          } else if (eventType === TEXT) {
            const text: string = parser.getText();
            if (text.trim()) {
              xml += "  ".repeat(indent) + text + "\n";
            }
          }
          parser.next();
          eventType = parser.getEventType();
        }

        return xml || "<empty xml>";
      }

      case "bool":
        return String(resources.getBoolean(resId));

      case "integer":
        return String(resources.getInteger(resId));

      case "dimen":
        return String(resources.getDimension(resId));

      case "color":
        return (
          "#" + (resources.getColor(resId) >>> 0).toString(16).padStart(8, "0")
        );

      case "raw":
        return "<raw resource — use download>";

      default:
        return `<${category} resource>`;
    }
  });
}
