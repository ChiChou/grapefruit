import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { Search, Loader2, Download, FolderOpen, FileText } from "lucide-react";
import Editor from "@monaco-editor/react";
import { List, type RowComponentProps } from "react-window";

import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  ResizableHandle,
  ResizablePanel,
  ResizablePanelGroup,
} from "@/components/ui/resizable";
import { useDroidQuery } from "@/lib/queries";
import { useSession } from "@/context/SessionContext";
import { useTheme } from "@/components/providers/ThemeProvider";

import type { ResourceTree } from "@agent/droid/modules/resources";

const ITEM_HEIGHT = 36;

function CategoryRow({
  index,
  style,
  items,
  selected,
  onClick,
}: RowComponentProps<{
  items: { name: string; count: number }[];
  selected: string | null;
  onClick: (name: string) => void;
}>) {
  const item = items[index];
  const isSelected = item.name === selected;

  return (
    <button
      type="button"
      className={`w-full text-left px-4 py-2 border-b border-border hover:bg-accent ${isSelected ? "bg-accent" : ""}`}
      style={style}
      onClick={() => onClick(item.name)}
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 min-w-0">
          <FolderOpen className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
          <span className="text-sm font-mono truncate">{item.name}</span>
        </div>
        <Badge variant="secondary" className="text-[10px] px-1.5 py-0 shrink-0 ml-2">
          {item.count}
        </Badge>
      </div>
    </button>
  );
}

function ResourceNameRow({
  index,
  style,
  items,
  selected,
  onClick,
}: RowComponentProps<{
  items: string[];
  selected: string | null;
  onClick: (name: string) => void;
}>) {
  const item = items[index];
  const isSelected = item === selected;

  return (
    <button
      type="button"
      className={`w-full text-left px-4 py-2 border-b border-border hover:bg-accent ${isSelected ? "bg-accent" : ""}`}
      style={style}
      onClick={() => onClick(item)}
    >
      <div className="flex items-center gap-2 min-w-0">
        <FileText className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
        <span className="text-sm font-mono truncate">{item}</span>
      </div>
    </button>
  );
}

function ResourceContent({
  category,
  name,
}: {
  category: string;
  name: string;
}) {
  const { t } = useTranslation();
  const { device, pid } = useSession();
  const { theme } = useTheme();

  const isRaw = category === "raw";
  const isXml = category === "xml";

  const {
    data: value,
    isLoading,
    error,
  } = useDroidQuery<string>(
    ["resourceGet", category, name],
    (api) => api.resources.get(category, name),
    { enabled: !isRaw },
  );

  if (isRaw) {
    const downloadUrl = `/api/resource/${device}/${pid}?type=${encodeURIComponent(category)}&name=${encodeURIComponent(name)}`;
    return (
      <div className="h-full flex flex-col items-center justify-center gap-4 p-4">
        <Download className="h-10 w-10 text-muted-foreground" />
        <p className="text-sm text-muted-foreground">
          Raw resources cannot be displayed inline.
        </p>
        <a
          href={downloadUrl}
          download={name}
          className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-md bg-primary text-primary-foreground hover:bg-primary/90"
        >
          <Download className="h-4 w-4" />
          {t("download")} {name}
        </a>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="h-full flex items-center justify-center text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin mr-2" />
        {t("loading")}...
      </div>
    );
  }

  if (error) {
    return (
      <div className="h-full p-4">
        <div className="text-sm text-destructive">
          {(error as Error).message}
        </div>
      </div>
    );
  }

  if (isXml && value) {
    return (
      <Editor
        height="100%"
        language="xml"
        value={value}
        theme={theme === "dark" ? "vs-dark" : "light"}
        options={{
          readOnly: true,
          domReadOnly: true,
          minimap: { enabled: false },
          scrollBeyondLastLine: false,
          wordWrap: "on",
          fontSize: 13,
          lineNumbers: "off",
          folding: true,
          automaticLayout: true,
          renderLineHighlight: "none",
          overviewRulerLanes: 0,
          hideCursorInOverviewRuler: true,
          overviewRulerBorder: false,
          scrollbar: { verticalScrollbarSize: 8, horizontalScrollbarSize: 8 },
          glyphMargin: false,
          lineDecorationsWidth: 0,
          lineNumbersMinChars: 0,
        }}
      />
    );
  }

  return (
    <div className="h-full overflow-auto">
      <pre className="p-4 text-sm font-mono whitespace-pre-wrap break-all">
        {value}
      </pre>
    </div>
  );
}

export function DroidResourcesTab() {
  const { t } = useTranslation();
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);
  const [selectedName, setSelectedName] = useState<string | null>(null);
  const [categorySearch, setCategorySearch] = useState("");
  const [nameSearch, setNameSearch] = useState("");

  const { data: tree, isLoading } = useDroidQuery<ResourceTree>(
    ["resourceList"],
    (api) => api.resources.list(),
  );

  const categories = useMemo(() => {
    if (!tree) return [];
    return Object.entries(tree)
      .map(([name, ids]) => ({ name, count: ids.length }))
      .sort((a, b) => a.name.localeCompare(b.name));
  }, [tree]);

  const filteredCategories = useMemo(() => {
    if (!categorySearch.trim()) return categories;
    const q = categorySearch.toLowerCase();
    return categories.filter((c) => c.name.toLowerCase().includes(q));
  }, [categories, categorySearch]);

  const names = useMemo(() => {
    if (!tree || !selectedCategory) return [];
    return tree[selectedCategory] ?? [];
  }, [tree, selectedCategory]);

  const filteredNames = useMemo(() => {
    if (!nameSearch.trim()) return names;
    const q = nameSearch.toLowerCase();
    return names.filter((n) => n.toLowerCase().includes(q));
  }, [names, nameSearch]);

  const handleSelectCategory = (name: string) => {
    setSelectedCategory(name);
    setSelectedName(null);
    setNameSearch("");
  };

  return (
    <ResizablePanelGroup
      orientation="horizontal"
      className="h-full"
      autoSaveId="droid-resources-tab"
    >
      {/* Categories panel */}
      <ResizablePanel defaultSize="20%" minSize="12%">
        <div className="h-full flex flex-col">
          <div className="p-2 border-b border-border space-y-1">
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
              <Input
                placeholder={t("search")}
                value={categorySearch}
                onChange={(e) => setCategorySearch(e.target.value)}
                className="pl-8 h-8 text-xs"
              />
            </div>
            <div className="text-[10px] text-muted-foreground px-1">
              {filteredCategories.length} / {categories.length}
            </div>
          </div>
          <div className="flex-1 min-h-0">
            {isLoading ? (
              <div className="flex items-center justify-center h-full text-muted-foreground">
                <Loader2 className="h-4 w-4 animate-spin mr-2" />
                {t("loading")}...
              </div>
            ) : filteredCategories.length === 0 ? (
              <div className="flex items-center justify-center h-full text-sm text-muted-foreground">
                No categories
              </div>
            ) : (
              <div className="flex h-full">
                <List
                  rowComponent={CategoryRow}
                  rowCount={filteredCategories.length}
                  rowHeight={ITEM_HEIGHT}
                  rowProps={{
                    items: filteredCategories,
                    selected: selectedCategory,
                    onClick: handleSelectCategory,
                  }}
                />
              </div>
            )}
          </div>
        </div>
      </ResizablePanel>

      <ResizableHandle withHandle />

      {/* Names panel */}
      <ResizablePanel defaultSize="30%" minSize="15%">
        <div className="h-full flex flex-col">
          {selectedCategory ? (
            <>
              <div className="p-2 border-b border-border space-y-1">
                <div className="relative">
                  <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                  <Input
                    placeholder={t("search")}
                    value={nameSearch}
                    onChange={(e) => setNameSearch(e.target.value)}
                    className="pl-8 h-8 text-xs"
                  />
                </div>
                <div className="text-[10px] text-muted-foreground px-1">
                  {filteredNames.length} / {names.length}
                </div>
              </div>
              <div className="flex-1 min-h-0">
                {filteredNames.length === 0 ? (
                  <div className="flex items-center justify-center h-full text-sm text-muted-foreground">
                    No resources
                  </div>
                ) : (
                  <div className="flex h-full">
                    <List
                      rowComponent={ResourceNameRow}
                      rowCount={filteredNames.length}
                      rowHeight={ITEM_HEIGHT}
                      rowProps={{
                        items: filteredNames,
                        selected: selectedName,
                        onClick: setSelectedName,
                      }}
                    />
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="flex items-center justify-center h-full text-sm text-muted-foreground">
              Select a category
            </div>
          )}
        </div>
      </ResizablePanel>

      <ResizableHandle withHandle />

      {/* Content panel */}
      <ResizablePanel minSize="20%">
        {selectedCategory && selectedName ? (
          <ResourceContent category={selectedCategory} name={selectedName} />
        ) : (
          <div className="flex items-center justify-center h-full text-sm text-muted-foreground">
            Select a resource to view
          </div>
        )}
      </ResizablePanel>
    </ResizablePanelGroup>
  );
}
