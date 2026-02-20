export interface HookGroup {
  list(): string[];
  status(): Record<string, boolean>;
  start(group: string): void;
  stop(group: string): void;
}

export function createNative(
  groups: readonly string[],
  get: (group: string) => InvocationListener[] | undefined,
): HookGroup {
  const active = new Map<string, InvocationListener[]>();

  return {
    list: () => [...groups],

    status() {
      const result: Record<string, boolean> = {};
      for (const group of groups) {
        result[group] = active.has(group);
      }
      return result;
    },

    start(group: string) {
      if (active.has(group)) return;
      const hooks = get(group);
      if (!hooks) return;
      active.set(group, hooks);
    },

    stop(group: string) {
      const hooks = active.get(group);
      if (!hooks) return;
      for (const hook of hooks) {
        hook.detach();
      }
      active.delete(group);
    },
  };
}

/**
 * Java hook entry with tap-style start/stop lifecycle.
 */
export interface JavaHookEntry {
  start(): void;
  stop(): void;
  status(): boolean;
  available(): boolean;
}

/**
 * Create a hook group for Java-based hooks (Android).
 * Unlike native hooks that return InvocationListener[], Java hooks
 * use method implementation replacement with their own cleanup.
 */
export function createJava(registry: Map<string, JavaHookEntry>): HookGroup {
  return {
    list() {
      return [...registry.keys()];
    },

    status() {
      const result: Record<string, boolean> = {};
      for (const [id, entry] of registry) {
        result[id] = entry.status();
      }
      return result;
    },

    start(group: string) {
      const entry = registry.get(group);
      if (!entry) throw new Error(`Unknown hook group: ${group}`);
      entry.start();
    },

    stop(group: string) {
      const entry = registry.get(group);
      if (!entry) throw new Error(`Unknown hook group: ${group}`);
      entry.stop();
    },
  };
}
