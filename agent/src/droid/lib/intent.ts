import Java from "frida-java-bridge";

import { getContext } from "./context.js";

export interface IntentOptions {
  action?: string;
  component?: string;
  data?: string;
  categories?: string[];
  extras?: Record<string, string | number | boolean>;
  flags?: number;
  mimeType?: string;
}

export function buildIntent(options: IntentOptions): Java.Wrapper {
  const Intent = Java.use("android.content.Intent");
  const ComponentName = Java.use("android.content.ComponentName");
  const Uri = Java.use("android.net.Uri");

  const intent = Intent.$new();

  if (options.action) intent.setAction(options.action);

  if (options.component) {
    const parts = options.component.split("/");
    if (parts.length === 2) {
      intent.setComponent(ComponentName.$new(parts[0], parts[1]));
    } else {
      const pkg = getContext().getPackageName();
      intent.setComponent(ComponentName.$new(pkg, options.component));
    }
  }

  if (options.mimeType) {
    if (options.data) {
      intent.setDataAndType(Uri.parse(options.data), options.mimeType);
    } else {
      intent.setType(options.mimeType);
    }
  } else if (options.data) {
    intent.setData(Uri.parse(options.data));
  }

  if (options.categories) {
    for (const cat of options.categories) {
      intent.addCategory(cat);
    }
  }

  if (options.extras) {
    for (const [key, value] of Object.entries(options.extras)) {
      if (typeof value === "string") {
        intent.putExtra(key, Java.use("java.lang.String").$new(value));
      } else if (typeof value === "number") {
        intent.putExtra(key, Java.use("java.lang.Integer").$new(value));
      } else if (typeof value === "boolean") {
        intent.putExtra(key, Java.use("java.lang.Boolean").$new(value));
      }
    }
  }

  if (options.flags !== undefined) {
    intent.setFlags(options.flags);
  }

  return intent;
}
