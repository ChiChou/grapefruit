export interface BaseMessage {
  subject: string;
  category: string;
  symbol: string;
  dir: "enter" | "leave";
  line?: string;
  backtrace?: string[];
  extra?: Record<string, unknown>;
}

export function bt(ctx: CpuContext): string[] {
  return Thread.backtrace(ctx, Backtracer.ACCURATE).map((addr) => {
    const { moduleName, name } = DebugSymbol.fromAddress(addr);
    return `${moduleName}!${name} (${addr})`;
  });
}
