export interface Frame {
  mod: string | null;
  name: string | null;
  addr: string;
}

export interface BaseMessage {
  subject: string;
  category: string;
  symbol: string;
  dir: "enter" | "leave";
  bt?: Frame[];

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  details?: any;
}

export function bt(ctx: CpuContext): Frame[] {
  return Thread.backtrace(ctx, Backtracer.ACCURATE).map((addr) => {
    const { moduleName, name } = DebugSymbol.fromAddress(addr);
    return { mod: moduleName, name, addr: addr.toString()! };
  });
}
