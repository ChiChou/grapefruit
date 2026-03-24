export class HBC {
  static fromBuffer(buffer: ArrayBuffer | Uint8Array): Promise<HBC>;
  info(): {
    version: number;
    sourceHash: string;
    fileLength: number;
    globalCodeIndex: number;
    functionCount: number;
    stringCount: number;
    identifierCount: number;
    overflowStringCount: number;
    regExpCount: number;
    cjsModuleCount: number;
    hasAsync: boolean;
    staticBuiltins: boolean;
  };
  functions(): Array<{
    id: number;
    name: string;
    offset: number;
    size: number;
    paramCount: number;
  }>;
  strings(): Array<{
    index: number;
    value: string;
    kind: string;
  }>;
  decompile(functionId?: number, options?: { offsets?: boolean }): string | null;
  disassemble(functionId?: number): string;
  close(): void;
}
