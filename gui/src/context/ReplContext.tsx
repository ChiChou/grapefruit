import React, { useState, useCallback, useEffect } from "react";
import { ReplContext, type ReplDocument } from "./useRepl";

const REPL_DOCUMENTS_STATE = "REPL_DOCUMENTS_STATE";

function generateId(): string {
  return `doc_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
}

interface StoredState {
  documents: ReplDocument[];
  activeDocId: string | null;
}

function loadState(): StoredState {
  try {
    const stored = localStorage.getItem(REPL_DOCUMENTS_STATE);
    if (stored) {
      const parsed = JSON.parse(stored) as StoredState;
      if (Array.isArray(parsed.documents)) {
        return parsed;
      }
    }
  } catch {
    // Ignore parse errors
  }
  return { documents: [], activeDocId: null };
}

function saveState(state: StoredState): void {
  try {
    localStorage.setItem(REPL_DOCUMENTS_STATE, JSON.stringify(state));
  } catch {
    // Ignore storage errors
  }
}

export function ReplProvider({ children }: { children: React.ReactNode }) {
  const [documents, setDocuments] = useState<ReplDocument[]>(() => loadState().documents);
  const [activeDocId, setActiveDocId] = useState<string | null>(() => loadState().activeDocId);

  // Persist state changes
  useEffect(() => {
    saveState({ documents, activeDocId });
  }, [documents, activeDocId]);

  const addDocument = useCallback((name?: string, content?: string): string => {
    const id = generateId();
    const docNumber = documents.length + 1;
    const newDoc: ReplDocument = {
      id,
      name: name || `Untitled-${docNumber}`,
      content: content || "",
    };
    setDocuments((prev) => [...prev, newDoc]);
    setActiveDocId(id);
    return id;
  }, [documents.length]);

  const removeDocument = useCallback((id: string) => {
    setDocuments((prev) => {
      const newDocs = prev.filter((doc) => doc.id !== id);
      // If we removed the active document, select another one
      if (activeDocId === id && newDocs.length > 0) {
        const removedIndex = prev.findIndex((doc) => doc.id === id);
        const newActiveIndex = Math.min(removedIndex, newDocs.length - 1);
        setActiveDocId(newDocs[newActiveIndex].id);
      } else if (newDocs.length === 0) {
        setActiveDocId(null);
      }
      return newDocs;
    });
  }, [activeDocId]);

  const updateDocument = useCallback((id: string, content: string) => {
    setDocuments((prev) =>
      prev.map((doc) => (doc.id === id ? { ...doc, content } : doc))
    );
  }, []);

  const renameDocument = useCallback((id: string, name: string) => {
    setDocuments((prev) =>
      prev.map((doc) => (doc.id === id ? { ...doc, name } : doc))
    );
  }, []);

  const setActiveDocument = useCallback((id: string) => {
    setActiveDocId(id);
  }, []);

  const appendToActiveDocument = useCallback((code: string) => {
    if (!activeDocId) {
      // Create a new document if none exists
      const id = generateId();
      const newDoc: ReplDocument = {
        id,
        name: "Untitled-1",
        content: code,
      };
      setDocuments((prev) => [...prev, newDoc]);
      setActiveDocId(id);
    } else {
      setDocuments((prev) =>
        prev.map((doc) => {
          if (doc.id === activeDocId) {
            const separator = doc.content.length > 0 && !doc.content.endsWith("\n") ? "\n\n" : "";
            return { ...doc, content: doc.content + separator + code };
          }
          return doc;
        })
      );
    }
    // Dispatch event to activate REPL tab
    window.dispatchEvent(new CustomEvent("repl:content-added"));
  }, [activeDocId]);

  const createDocumentWithCode = useCallback((code: string, name?: string): string => {
    const id = generateId();
    const docNumber = documents.length + 1;
    const newDoc: ReplDocument = {
      id,
      name: name || `Untitled-${docNumber}`,
      content: code,
    };
    setDocuments((prev) => [...prev, newDoc]);
    setActiveDocId(id);
    // Dispatch event to activate REPL tab
    window.dispatchEvent(new CustomEvent("repl:content-added"));
    return id;
  }, [documents.length]);

  return (
    <ReplContext.Provider
      value={{
        documents,
        activeDocId,
        addDocument,
        removeDocument,
        updateDocument,
        renameDocument,
        setActiveDocument,
        appendToActiveDocument,
        createDocumentWithCode,
      }}
    >
      {children}
    </ReplContext.Provider>
  );
}
