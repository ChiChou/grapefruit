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

const interceptorBlock = (name: string) => `Interceptor.attach(addr, {
  onEnter(args) {
    console.log("[${name}] called");
    // console.log("  arg0:", args[0]);
  },
  onLeave(retval) {
    console.log("[${name}] returned:", retval);
  }
});`;

/**
 * Generate Frida hook code for a native function
 */
export function native(target: NativeHookTarget, fridaMajor: number = 17): string {
  const { module, name } = target;

  if (fridaMajor >= 17) {
    if (module) {
      return `// Hook ${module}!${name}
{
  const mod = Process.findModuleByName(${JSON.stringify(module)});
  if (mod) {
    const addr = mod.findExportByName(${JSON.stringify(name)});
    if (addr) {
      ${interceptorBlock(name)}
    }
  }
}
`;
    }

    return `// Hook ${name}
{
  const addr = Module.findGlobalExportByName(${JSON.stringify(name)});
  if (addr) {
    ${interceptorBlock(name)}
  }
}
`;
  }

  // Frida 16
  if (module) {
    return `// Hook ${module}!${name}
{
  const addr = Module.findExportByName(${JSON.stringify(module)}, ${JSON.stringify(name)});
  if (addr) {
    ${interceptorBlock(name)}
  }
}
`;
  }

  return `// Hook ${name}
{
  const addr = Module.findExportByName(null, ${JSON.stringify(name)});
  if (addr) {
    ${interceptorBlock(name)}
  }
}
`;
}

/**
 * Generate Frida hook code for an Objective-C method
 */
export function objc(target: ObjCHookTarget): string {
  const { cls, sel } = target;
  const methodLabel = formatObjCMethod(cls, sel);

  return `// Hook ${methodLabel}
{
  const method = ObjC.classes[${JSON.stringify(cls)}][${JSON.stringify(sel)}];
  if (method) {
    Interceptor.attach(method.implementation, {
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
}
`;
}

/**
 * Generate hook code for multiple targets
 */
export function batch(targets: HookTarget[], fridaMajor: number = 17): string {
  const parts: string[] = [];

  for (const target of targets) {
    if (target.type === "native") {
      parts.push(native(target, fridaMajor));
    } else if (target.type === "objc") {
      parts.push(objc(target));
    }
  }

  return parts.join("\n");
}
