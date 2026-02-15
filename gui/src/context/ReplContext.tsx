import React, { useState, useCallback } from "react";
import { ReplContext } from "./useRepl";

const STORAGE_KEY = "igf:repl:content";

export function ReplProvider({ children }: { children: React.ReactNode }) {
  const [content, setContentState] = useState(
    () => localStorage.getItem(STORAGE_KEY) ?? "",
  );
  const [dirty, setDirty] = useState(false);

  const setContent = useCallback((value: string) => {
    setContentState(value);
    setDirty(true);
  }, []);

  const save = useCallback(() => {
    setContentState((cur) => {
      localStorage.setItem(STORAGE_KEY, cur);
      return cur;
    });
    setDirty(false);
  }, []);

  const appendCode = useCallback((code: string) => {
    setContentState((prev) => {
      const separator = prev.length > 0 && !prev.endsWith("\n") ? "\n\n" : "";
      const next = prev + separator + code;
      return next;
    });
    setDirty(true);
    window.dispatchEvent(new CustomEvent("repl:content-added"));
  }, []);

  return (
    <ReplContext.Provider value={{ content, setContent, appendCode, save, dirty }}>
      {children}
    </ReplContext.Provider>
  );
}
