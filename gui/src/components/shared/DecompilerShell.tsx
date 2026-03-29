/**
 * Shared shell for decompiler pages: sidebar, tab bar, drop zone, status bar.
 * Used by both HermesPage and R2Page.
 */
import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { Link } from "react-router";
import { useTranslation } from "react-i18next";
import {
  Upload,
  FileCode,
  Plus,
  Loader2,
  X,
  GripVertical,
  ChevronDown,
} from "lucide-react";

import icon from "../../assets/grapefruit.svg";
import { DarkmodeToggle } from "./DarkmodeToggle";
import { LanguageSelector } from "./LanguageSelector";
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
} from "@/components/ui/dropdown-menu";

export interface Tab {
  id: string;
  name: string;
}

export interface FileStore {
  list(): Promise<{ id: string }[]>;
  put(file: { id: string; name: string; data: ArrayBuffer; addedAt: number; source: string }): Promise<void>;
  remove(id: string): Promise<void>;
  usage(): Promise<number>;
  get(id: string): Promise<{ data: ArrayBuffer } | undefined>;
}

export interface DecompilerShellProps {
  /** Sidebar nav icons */
  sidebarItems: ReactNode;
  /** IndexedDB store for file persistence */
  store: FileStore;
  /** localStorage key for tab state */
  storeKey: string;
  /** File input accept attribute */
  accept?: string;
  /** Drop zone description */
  dropLabel: string;
  /** Drop zone file types */
  dropTypes: string;
  /** Status bar left content */
  statusLeft?: ReactNode;
  /** Render the active tab content */
  children: (fileId: string) => ReactNode;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function loadTabState(key: string): { tabs: Tab[]; active: string | null } {
  try {
    const raw = localStorage.getItem(key);
    if (raw) return JSON.parse(raw);
  } catch { /* ignore */ }
  return { tabs: [], active: null };
}

function saveTabState(key: string, tabs: Tab[], active: string | null) {
  localStorage.setItem(key, JSON.stringify({ tabs, active }));
}

export function DecompilerShell({
  sidebarItems,
  store,
  storeKey,
  accept = "*",
  dropLabel,
  dropTypes,
  statusLeft,
  children,
}: DecompilerShellProps) {
  const { t } = useTranslation();
  const inputRef = useRef<HTMLInputElement>(null);
  const contentRef = useRef<HTMLDivElement>(null);
  const [dragging, setDragging] = useState(false);
  const [loading, setLoading] = useState(true);

  const [tabs, setTabs] = useState<Tab[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [dbUsage, setDbUsage] = useState(0);

  const dragIdx = useRef<number | null>(null);
  const [dragOver, setDragOver] = useState<number | null>(null);

  // Restore tabs from IndexedDB
  useEffect(() => {
    (async () => {
      const saved = loadTabState(storeKey);
      const stored = await store.list();
      const storedIds = new Set(stored.map((s) => s.id));
      const validTabs = saved.tabs.filter((t) => storedIds.has(t.id));
      setTabs(validTabs);
      setActiveId(
        validTabs.some((t) => t.id === saved.active)
          ? saved.active
          : validTabs[0]?.id ?? null,
      );
      setLoading(false);
    })();
  }, [store, storeKey]);

  const addTab = useCallback((tab: Tab) => {
    setTabs((prev) => {
      if (prev.some((t) => t.id === tab.id)) return prev;
      return [...prev, tab];
    });
    setActiveId(tab.id);
  }, []);

  // Persist tab state
  useEffect(() => {
    if (!loading) saveTabState(storeKey, tabs, activeId);
  }, [tabs, activeId, loading, storeKey]);

  // Refresh usage
  useEffect(() => {
    store.usage().then(setDbUsage);
  }, [tabs, store]);

  const closeTab = useCallback(
    (id: string) => {
      store.remove(id);
      setTabs((prev) => {
        const next = prev.filter((t) => t.id !== id);
        if (activeId === id) {
          const idx = prev.findIndex((t) => t.id === id);
          const neighbor = next[Math.min(idx, next.length - 1)];
          setActiveId(neighbor?.id ?? null);
        }
        return next;
      });
    },
    [activeId, store],
  );

  const addLocalFile = useCallback(
    async (file: File) => {
      const data = await file.arrayBuffer();
      const id = `local-${Date.now()}-${file.name}`;
      await store.put({ id, name: file.name, data, addedAt: Date.now(), source: "local" });
      addTab({ id, name: file.name });
    },
    [addTab, store],
  );

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragging(false);
      const file = e.dataTransfer.files[0];
      if (file) addLocalFile(file);
    },
    [addLocalFile],
  );

  const onFileChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (file) addLocalFile(file);
      e.target.value = "";
    },
    [addLocalFile],
  );

  const onTabDragStart = useCallback((idx: number) => { dragIdx.current = idx; }, []);
  const onTabDragOver = useCallback((e: React.DragEvent, idx: number) => { e.preventDefault(); setDragOver(idx); }, []);
  const onTabDrop = useCallback((idx: number) => {
    const from = dragIdx.current;
    dragIdx.current = null;
    setDragOver(null);
    if (from === null || from === idx) return;
    setTabs((prev) => {
      const next = [...prev];
      const [moved] = next.splice(from, 1);
      next.splice(idx, 0, moved);
      return next;
    });
  }, []);
  const onTabDragEnd = useCallback(() => { dragIdx.current = null; setDragOver(null); }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin" />
      </div>
    );
  }

  return (
    <div className="h-screen w-screen flex flex-col">
      <div className="flex-1 flex min-h-0">
        {/* Left sidebar */}
        <div className="w-16 bg-sidebar border-r border-sidebar-border flex flex-col shrink-0">
          <div className="p-2 flex items-center justify-center border-b border-sidebar-border">
            <Link to="/" className="flex items-center">
              <img src={icon} alt="IGF" className="h-6 w-6" />
            </Link>
          </div>
          <div className="flex-1 flex flex-col gap-1 pt-2">
            {sidebarItems}
          </div>
          <div className="flex flex-col gap-1 py-2 items-center">
            <LanguageSelector />
            <DarkmodeToggle />
          </div>
        </div>

        {/* Main area */}
        <div className="flex-1 flex flex-col min-w-0">
          {/* Tab bar */}
          {tabs.length > 0 && (
            <div
              className="flex items-end shrink-0 bg-muted/50 h-[35px] border-b border-border"
              onDoubleClick={(e) => {
                if (e.target === e.currentTarget) inputRef.current?.click();
              }}
            >
              <div
                className="flex items-end flex-1 min-w-0 overflow-x-auto"
                onDoubleClick={(e) => {
                  if (e.target === e.currentTarget) inputRef.current?.click();
                }}
              >
                {tabs.map((tab, idx) => (
                  <div
                    key={tab.id}
                    draggable
                    onDragStart={() => onTabDragStart(idx)}
                    onDragOver={(e) => onTabDragOver(e, idx)}
                    onDrop={() => onTabDrop(idx)}
                    onDragEnd={onTabDragEnd}
                    className={`group flex items-center gap-1.5 px-3 h-[34px] text-xs cursor-pointer shrink-0 select-none transition-colors ${
                      tab.id === activeId
                        ? "bg-background text-foreground rounded-t border-t border-x border-border"
                        : "text-muted-foreground hover:text-foreground hover:bg-muted/80 mb-px"
                    } ${dragOver === idx ? "border-l-2 border-l-primary" : ""}`}
                    onClick={() => setActiveId(tab.id)}
                  >
                    <GripVertical className="h-3 w-3 opacity-0 group-hover:opacity-40 shrink-0 cursor-grab" />
                    <span className="truncate max-w-32">{tab.name}</span>
                    <button
                      className="ml-0.5 p-0.5 rounded hover:bg-accent opacity-0 group-hover:opacity-100 transition-opacity shrink-0"
                      onClick={(e) => { e.stopPropagation(); closeTab(tab.id); }}
                    >
                      <X className="h-2.5 w-2.5" />
                    </button>
                  </div>
                ))}
                <button
                  className="h-[34px] px-2.5 shrink-0 text-muted-foreground hover:text-foreground hover:bg-muted/80 transition-colors self-end mb-px"
                  onClick={() => inputRef.current?.click()}
                  title={t("open")}
                >
                  <Plus className="h-3.5 w-3.5" />
                </button>
              </div>
              {/* Tab overflow menu */}
              <DropdownMenu>
                <DropdownMenuTrigger
                  render={
                    <button className="h-[34px] px-2 hover:bg-muted/80 shrink-0 flex items-center gap-1 text-xs text-muted-foreground max-w-48 self-end mb-px" />
                  }
                >
                  <span className="truncate">
                    {tabs.find((t) => t.id === activeId)?.name ?? ""}
                  </span>
                  <ChevronDown className="h-3 w-3 shrink-0 opacity-50" />
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  {tabs.map((tab) => (
                    <DropdownMenuItem
                      key={tab.id}
                      className="flex items-center justify-between gap-4"
                      onClick={() => setActiveId(tab.id)}
                    >
                      <span className={`text-xs truncate ${tab.id === activeId ? "font-medium" : ""}`}>
                        {tab.name}
                      </span>
                      <button
                        className="p-0.5 rounded hover:bg-accent shrink-0"
                        onClick={(e) => { e.stopPropagation(); closeTab(tab.id); }}
                      >
                        <X className="h-3 w-3 text-muted-foreground" />
                      </button>
                    </DropdownMenuItem>
                  ))}
                  {tabs.length > 1 && (
                    <>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem
                        className="text-xs text-destructive"
                        onClick={() => {
                          for (const tab of tabs) store.remove(tab.id);
                          setTabs([]);
                          setActiveId(null);
                        }}
                      >
                        {t("clear_all")}
                      </DropdownMenuItem>
                    </>
                  )}
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
          )}

          <input ref={inputRef} type="file" accept={accept} className="hidden" onChange={onFileChange} />

          {/* Content — drop zone */}
          <div
            ref={contentRef}
            className="flex-1 overflow-hidden relative"
            onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
            onDragLeave={(e) => {
              if (e.currentTarget === e.target || !contentRef.current?.contains(e.relatedTarget as Node))
                setDragging(false);
            }}
            onDrop={onDrop}
          >
            {dragging && (
              <div className="absolute inset-0 z-50 flex items-center justify-center bg-background/80 pointer-events-none">
                <div className="flex flex-col items-center gap-3">
                  <FileCode className="h-12 w-12 text-primary" />
                  <p className="text-sm font-medium text-primary">{t("hermes_drop_to_analyze")}</p>
                </div>
              </div>
            )}

            {activeId ? (
              children(activeId)
            ) : (
              <div className="flex items-center justify-center h-full">
                <div
                  className="flex flex-col items-center gap-4 max-w-sm text-center border-2 border-dashed border-muted-foreground/25 hover:border-muted-foreground/50 rounded-lg px-12 py-10 cursor-pointer transition-colors"
                  onClick={() => inputRef.current?.click()}
                >
                  <Upload className="h-10 w-10 text-muted-foreground/40" />
                  <div>
                    <p className="text-sm font-medium">{dropLabel}</p>
                    <p className="text-xs text-muted-foreground mt-1">{dropTypes}</p>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Status bar */}
      <footer className="bg-muted px-3 py-0.5 text-[10px] text-muted-foreground flex items-center gap-3 shrink-0 border-t">
        {statusLeft}
        <span className="ml-auto">{formatBytes(dbUsage)} stored</span>
      </footer>
    </div>
  );
}
