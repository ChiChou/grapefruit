export interface HookGroup {
  list(): string[];
  status(): Record<string, boolean>;
  start(group: string): void;
  stop(group: string): void;
}

export function createHookGroup(
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
