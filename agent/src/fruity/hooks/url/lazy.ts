import ObjC from "frida-objc-bridge";

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

    const method = clazz["- " + sel] as ObjC.ObjectMethod | undefined;
    if (!method) continue;

    try {
      const listener = Interceptor.attach(method.implementation, handler);
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

  const hasData = !!(clazz["- URLSession:dataTask:didReceiveData:"] as
    | ObjC.ObjectMethod
    | undefined);
  const hasComplete = !!(clazz["- URLSession:task:didCompleteWithError:"] as
    | ObjC.ObjectMethod
    | undefined);

  if (!hasData && !hasComplete) return null;

  // Skip if the class already implements didReceiveResponse:completionHandler:
  const existing = clazz[
    "- URLSession:dataTask:didReceiveResponse:completionHandler:"
  ] as ObjC.ObjectMethod | undefined;
  if (existing) return null;

  const rtsMethod = clazz["- respondsToSelector:"] as
    | ObjC.ObjectMethod
    | undefined;
  if (!rtsMethod) return null;

  injectedRtsClasses.add(className);

  const targetSel = ObjC.selector(
    "URLSession:dataTask:didReceiveResponse:completionHandler:",
  );

  return Interceptor.attach(rtsMethod.implementation, {
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
