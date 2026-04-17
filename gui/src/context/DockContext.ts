import React, { useContext } from "react";
import type { DockviewApi, AddPanelOptions } from "dockview";

export interface DockContextType {
  api: DockviewApi | null;
  /**
   * Open or focus a singleton panel (only one instance allowed).
   * If the panel already exists, it will be focused instead of creating a new one.
   */
  openSingletonPanel: (options: AddPanelOptions) => void;
  /**
   * Open or focus a file viewer panel.
   * Panels are identified by their id (e.g. constructed from file path).
   * If a panel with the same id exists, it will be focused.
   */
  openFilePanel: (options: AddPanelOptions) => void;
  /**
   * Reset the dock layout to the default (Home tab only).
   */
  resetLayout: () => void;
}

const defaultContext: DockContextType = {
  api: null,
  openSingletonPanel: () => {},
  openFilePanel: () => {},
  resetLayout: () => {},
};

export const DockContext = React.createContext<DockContextType>(defaultContext);

export const useDock = () => useContext(DockContext);
