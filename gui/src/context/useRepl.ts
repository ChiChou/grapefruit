import { createContext, useContext } from "react";

export interface ReplContextType {
  content: string;
  setContent: (content: string) => void;
  appendCode: (code: string) => void;
  save: () => void;
  dirty: boolean;
}

const defaultContext: ReplContextType = {
  content: "",
  setContent: () => {},
  appendCode: () => {},
  save: () => {},
  dirty: false,
};

export const ReplContext = createContext<ReplContextType>(defaultContext);

export const useRepl = () => useContext(ReplContext);
