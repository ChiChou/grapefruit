/**
 * Hook code generation utilities for Frida
 */

/**
 * Format an Objective-C method name in standard notation
 * e.g., cls="NSObject", sel="- release" → "-[NSObject release]"
 */
export function formatObjCMethod(cls: string, sel: string): string {
  const sign = sel.charAt(0);
  const methodName = sel.substring(2);
  return `${sign}[${cls} ${methodName}]`;
}

export interface NativeHookTarget {
  type: "native";
  module: string | null;
  name: string;
}

export interface ObjCHookTarget {
  type: "objc";
  cls: string;
  sel: string;
}

export type HookTarget = NativeHookTarget | ObjCHookTarget;

/**
 * Generate Frida hook code for a native function
 */
export function generateNativeHook(target: NativeHookTarget): string {
  const { module, name } = target;
  const varName = sanitizeName(name);
  const addrVar = `${varName}Addr`;

  if (module) {
    // Module-specific export
    return `// Hook ${module}!${name}
const ${addrVar} = Module.findExportByName(${JSON.stringify(module)}, ${JSON.stringify(name)});
if (${addrVar}) {
  Interceptor.attach(${addrVar}, {
    onEnter(args) {
      console.log("[${name}] called");
      // console.log("  arg0:", args[0]);
    },
    onLeave(retval) {
      console.log("[${name}] returned:", retval);
    }
  });
}
`;
  }

  // Global export (null module)
  return `// Hook ${name}
const ${addrVar} = Module.findExportByName(null, ${JSON.stringify(name)});
if (${addrVar}) {
  Interceptor.attach(${addrVar}, {
    onEnter(args) {
      console.log("[${name}] called");
      // console.log("  arg0:", args[0]);
    },
    onLeave(retval) {
      console.log("[${name}] returned:", retval);
    }
  });
}
`;
}

/**
 * Generate Frida hook code for an Objective-C method
 */
export function generateObjCHook(target: ObjCHookTarget): string {
  const { cls, sel } = target;
  const methodLabel = formatObjCMethod(cls, sel);
  const varName = `${sanitizeName(cls)}_${sanitizeSelector(sel)}`;

  return `// Hook ${methodLabel}
const ${varName} = ObjC.classes[${JSON.stringify(cls)}][${JSON.stringify(sel)}];
if (${varName}) {
  Interceptor.attach(${varName}.implementation, {
    onEnter(args) {
      // args[0] = self, args[1] = _cmd, args[2+] = method arguments
      const self = new ObjC.Object(args[0]);
      console.log("${methodLabel} called");
    },
    onLeave(retval) {
      console.log("${methodLabel} returned:", retval);
    }
  });
}
`;
}

/**
 * Generate hook code for multiple targets
 */
export function generateHooks(targets: HookTarget[]): string {
  const parts: string[] = [];

  for (const target of targets) {
    if (target.type === "native") {
      parts.push(generateNativeHook(target));
    } else if (target.type === "objc") {
      parts.push(generateObjCHook(target));
    }
  }

  return parts.join("\n");
}

/**
 * Sanitize a name for use as a JavaScript variable
 */
function sanitizeName(name: string): string {
  return name.replace(/[^a-zA-Z0-9_]/g, "_").replace(/^(\d)/, "_$1");
}

/**
 * Sanitize an Objective-C selector for use as part of a variable name
 */
function sanitizeSelector(sel: string): string {
  return sel
    .replace(/^[+-]\s*/, "")
    .replace(/:/g, "_")
    .replace(/[^a-zA-Z0-9_]/g, "_");
}
