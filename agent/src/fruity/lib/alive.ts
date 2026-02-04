import ObjC from "frida-objc-bridge";

export class AliveTracker {
  private handles = new Set<string>();
  private hooked = false;

  constructor(private clazz: ObjC.Object) {}

  private hook() {
    if (this.hooked) return;
    this.hooked = true;

    const handles = this.handles;
    const listener = Interceptor.attach(this.clazz["- dealloc"].implementation, {
      onEnter(args) {
        handles.delete(args[0].toString());
      },
    });
    Script.bindWeak(globalThis, listener.detach.bind(listener));
  }

  track(handle: string) {
    this.hook();
    this.handles.add(handle);
  }

  has(handle: string): boolean {
    return this.handles.has(handle);
  }

  get(handle: string): ObjC.Object {
    if (!this.handles.has(handle)) {
      throw new Error(`${this.clazz.$className} ${handle} not found`);
    }
    return new ObjC.Object(ptr(handle));
  }
}
