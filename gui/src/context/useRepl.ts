import { createContext, useContext } from "react";

export interface ReplDocument {
  id: string;
  name: string;
  content: string;
}

export interface ReplContextType {
  documents: ReplDocument[];
  activeDocId: string | null;
  addDocument: (name?: string, content?: string) => string;
  removeDocument: (id: string) => void;
  updateDocument: (id: string, content: string) => void;
  renameDocument: (id: string, name: string) => void;
  setActiveDocument: (id: string) => void;
  appendToActiveDocument: (code: string) => void;
  createDocumentWithCode: (code: string, name?: string) => string;
}

const defaultContext: ReplContextType = {
  documents: [],
  activeDocId: null,
  addDocument: () => "",
  removeDocument: () => {},
  updateDocument: () => {},
  renameDocument: () => {},
  setActiveDocument: () => {},
  appendToActiveDocument: () => {},
  createDocumentWithCode: () => "",
};

export const ReplContext = createContext<ReplContextType>(defaultContext);

export const useRepl = () => useContext(ReplContext);
