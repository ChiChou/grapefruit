import ObjC from "frida-objc-bridge";

import { getMethodImp } from "./common.js";

const hookedMethods = new Set<string>();
const injectedRtsClasses = new Set<string>();

/**
 * Given a delegate object and a selector→handler map,
 * hook every selector the delegate's class implements.
 * Skip already-hooked (className, selector) pairs.
 */
export function hookDelegateClass(
  delegate: ObjC.Object,
  handlers: Record<string, InvocationListenerCallbacks>,
): InvocationListener[] {
  const listeners: InvocationListener[] = [];
  const className = delegate.$className;
  const clazz = ObjC.classes[className];
  if (!clazz) return listeners;

  for (const [sel, handler] of Object.entries(handlers)) {
    const key = `${className}\t${sel}`;
    if (hookedMethods.has(key)) continue;

    const imp = getMethodImp(clazz, sel, false);
    if (!imp) continue;

    try {
      const listener = Interceptor.attach(imp, handler);
      listeners.push(listener);
      hookedMethods.add(key);
    } catch (e) {
      console.warn(`Failed to hook ${sel} on ${className}:`, e);
    }
  }

  return listeners;
}

/**
 * If delegate implements didReceiveData: or didCompleteWithError:
 * but NOT didReceiveResponse:completionHandler:, hook its
 * respondsToSelector: to return YES for the latter.
 */
export function injectRespondsToSelector(
  delegate: ObjC.Object,
): InvocationListener | null {
  const className = delegate.$className;
  if (injectedRtsClasses.has(className)) return null;

  const clazz = ObjC.classes[className];
  if (!clazz) return null;

  const hasData = !!getMethodImp(
    clazz,
    "URLSession:dataTask:didReceiveData:",
    false,
  );
  const hasComplete = !!getMethodImp(
    clazz,
    "URLSession:task:didCompleteWithError:",
    false,
  );

  if (!hasData && !hasComplete) return null;

  // Skip if the class already implements didReceiveResponse:completionHandler:
  if (
    getMethodImp(
      clazz,
      "URLSession:dataTask:didReceiveResponse:completionHandler:",
      false,
    )
  )
    return null;

  const rtsImp = getMethodImp(clazz, "respondsToSelector:", false);
  if (!rtsImp) return null;

  injectedRtsClasses.add(className);

  const targetSel = ObjC.selector(
    "URLSession:dataTask:didReceiveResponse:completionHandler:",
  );

  return Interceptor.attach(rtsImp, {
    onEnter(args) {
      const sel = args[2] as NativePointer;
      this._replace = sel.equals(targetSel);
    },
    onLeave(retval) {
      if (this._replace) retval.replace(ptr(1));
    },
  });
}

export function reset(): void {
  hookedMethods.clear();
  injectedRtsClasses.clear();
}
