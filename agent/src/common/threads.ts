export interface ThreadInfo {
  id: number;
  name: string | null;
  state: string;
  pc: string;
  symbol: string | null;
  moduleName: string | null;
}

export function list(): ThreadInfo[] {
  return Process.enumerateThreads().map((t) => {
    const sym = DebugSymbol.fromAddress(t.context.pc);
    return {
      id: t.id,
      name: t.name ?? null,
      state: t.state,
      pc: t.context.pc.toString(),
      symbol: sym.name,
      moduleName: sym.moduleName,
    };
  });
}
