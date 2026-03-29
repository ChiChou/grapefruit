import { useCallback, useEffect, useRef, useState } from "react";
import * as hbc from "./hbc";

export interface HBCInfo {
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
}

export interface HBCFunction {
  id: number;
  name: string;
  offset: number;
  size: number;
  paramCount: number;
}

export interface HBCString {
  index: number;
  value: string;
  kind: string;
}

export interface HBCXrefs {
  strings: Record<string, number[]>;
  functions: Record<string, number[]>;
}

export interface AnalysisData {
  info: HBCInfo;
  functions: HBCFunction[];
  strings: HBCString[];
}

export interface HBCHandle {
  data: AnalysisData | null;
  xrefs: HBCXrefs | null;
  isLoading: boolean;
  error: string | null;
  disassemble: (funcId?: number | null) => Promise<string | null>;
  decompile: (funcId?: number | null, opts?: { offsets?: boolean }) => Promise<string | null>;
  buffer: ArrayBuffer | null;
}

export function useHBC(buffer: ArrayBuffer | null): HBCHandle {
  const openRef = useRef(false);
  const [data, setData] = useState<AnalysisData | null>(null);
  const [xrefs, setXrefs] = useState<HBCXrefs | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!buffer) {
      if (openRef.current) {
        hbc.close();
        openRef.current = false;
      }
      setData(null);
      setXrefs(null);
      setError(null);
      return;
    }

    let cancelled = false;
    setIsLoading(true);
    setError(null);

    (async () => {
      try {
        // Transfer a copy — the original buffer may be reused by caller
        const copy = buffer.slice(0);
        await hbc.open(copy);
        if (cancelled) {
          hbc.close();
          return;
        }
        openRef.current = true;

        const result = await hbc.analyze();
        if (cancelled) return;

        setData({
          info: result.info,
          functions: result.functions,
          strings: result.strings,
        });
        setXrefs(result.xrefs);
      } catch (e) {
        if (!cancelled) {
          setError(e instanceof Error ? e.message : "Failed to parse Hermes bytecode");
        }
      } finally {
        if (!cancelled) setIsLoading(false);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [buffer]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (openRef.current) {
        hbc.close();
        openRef.current = false;
      }
    };
  }, []);

  const disassemble = useCallback(
    (funcId?: number | null): Promise<string | null> => {
      if (!openRef.current) return Promise.resolve(null);
      return hbc.disassemble(funcId);
    },
    [],
  );

  const decompile = useCallback(
    (funcId?: number | null, opts?: { offsets?: boolean }): Promise<string | null> => {
      if (!openRef.current) return Promise.resolve(null);
      return hbc.decompile(funcId, opts);
    },
    [],
  );

  return { data, xrefs, isLoading, error, disassemble, decompile, buffer };
}
