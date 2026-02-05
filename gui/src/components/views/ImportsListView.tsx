import { useMemo, useState, useRef, useCallback } from "react";
import { useTranslation } from "react-i18next";
import {
  ChevronRight,
  ChevronDown,
  ExternalLink,
  Search,
  FileCode,
  Database,
} from "lucide-react";
import { useDock } from "@/context/DockContext";
import { useRpcQuery } from "@/lib/queries";
import { Input } from "@/components/ui/input";

import type {
  ImportGroup,
  Imported,
} from "../../../../agent/types/fruity/modules/symbol";

interface ImportsListViewProps {
  path: string;
}

const DEFAULT_WIDTHS = {
  icon: 32,
  name: 300,
  address: 140,
  demangled: 400,
};

export function ImportsListView({ path }: ImportsListViewProps) {
  const { openFilePanel } = useDock();
  const { t } = useTranslation();
  const [expandedModules, setExpandedModules] = useState<Set<string>>(
    new Set()
  );
  const [search, setSearch] = useState("");
  const [columnWidths, setColumnWidths] = useState(DEFAULT_WIDTHS);

  const resizing = useRef<{
    column: keyof typeof DEFAULT_WIDTHS;
    startX: number;
    startWidth: number;
  } | null>(null);

  const { data: importGroups, isLoading: loading } = useRpcQuery(
    ["importsGrouped", path],
    (api) => api.symbol.importsGrouped(path)
  );

  const filteredGroups = useMemo(() => {
    if (!importGroups) return [];
    if (!search.trim()) return importGroups;

    const query = search.toLowerCase();
    return importGroups
      .map((group) => {
        const moduleMatches = group.module.toLowerCase().includes(query);
        const matchingImports = group.imports.filter(
          (imp) =>
            imp.name.toLowerCase().includes(query) ||
            imp.addr.toLowerCase().includes(query) ||
            (imp.demangled && imp.demangled.toLowerCase().includes(query))
        );

        if (moduleMatches || matchingImports.length > 0) {
          return {
            ...group,
            imports: moduleMatches ? group.imports : matchingImports,
          };
        }
        return null;
      })
      .filter((group): group is ImportGroup => group !== null);
  }, [importGroups, search]);

  const toggleModule = (module: string) => {
    setExpandedModules((prev) => {
      const next = new Set(prev);
      if (next.has(module)) {
        next.delete(module);
      } else {
        next.add(module);
      }
      return next;
    });
  };

  const expandAll = () => {
    if (!filteredGroups) return;
    setExpandedModules(new Set(filteredGroups.map((g) => g.module)));
  };

  const collapseAll = () => {
    setExpandedModules(new Set());
  };

  const openModuleTab = (modulePath: string, e: React.MouseEvent) => {
    e.stopPropagation();
    const name = modulePath.split("/").pop() || modulePath;
    openFilePanel({
      id: `module_${modulePath}`,
      component: "moduleDetail",
      title: name,
      params: { path: modulePath },
    });
  };

  const openDisassemblyTab = (address: string, name?: string) => {
    openFilePanel({
      id: `disasm_${address}`,
      component: "disassembly",
      title: name ? `${name}` : address,
      params: { address, name },
    });
  };

  const openClassTab = (className: string) => {
    openFilePanel({
      id: `class_${className}`,
      component: "classDetail",
      title: className,
      params: { className },
    });
  };

  const handleAddressClick = (imp: Imported) => {
    // Check if it's an ObjC class reference
    if (imp.name.startsWith("OBJC_CLASS_$_")) {
      const className = imp.name.replace("OBJC_CLASS_$_", "");
      openClassTab(className);
      return;
    }
    // Only open disassembly for functions
    if (imp.type === "f" && imp.addr) {
      openDisassemblyTab(imp.addr, imp.name);
    }
  };

  const isClickable = (imp: Imported): boolean => {
    // ObjC class references are always clickable
    if (imp.name.startsWith("OBJC_CLASS_$_")) return true;
    // Only functions with addresses are clickable for disassembly
    return imp.type === "f" && !!imp.addr;
  };

  const handleMouseDown = useCallback(
    (column: keyof typeof DEFAULT_WIDTHS, e: React.MouseEvent) => {
      e.preventDefault();
      resizing.current = {
        column,
        startX: e.clientX,
        startWidth: columnWidths[column],
      };

      const handleMouseMove = (e: MouseEvent) => {
        if (!resizing.current) return;
        const delta = e.clientX - resizing.current.startX;
        const newWidth = Math.max(40, resizing.current.startWidth + delta);
        setColumnWidths((prev) => ({
          ...prev,
          [resizing.current!.column]: newWidth,
        }));
      };

      const handleMouseUp = () => {
        resizing.current = null;
        document.removeEventListener("mousemove", handleMouseMove);
        document.removeEventListener("mouseup", handleMouseUp);
      };

      document.addEventListener("mousemove", handleMouseMove);
      document.addEventListener("mouseup", handleMouseUp);
    },
    [columnWidths]
  );

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full text-gray-500">
        {t("loading")}...
      </div>
    );
  }

  if (!importGroups || importGroups.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-gray-500">
        {t("no_results")}
      </div>
    );
  }

  // Build flat row list for rendering
  const rows: Array<
    | { type: "group"; group: ImportGroup; isExpanded: boolean }
    | { type: "import"; import: Imported; module: string }
  > = [];

  for (const group of filteredGroups) {
    const isExpanded = expandedModules.has(group.module);
    rows.push({ type: "group", group, isExpanded });
    if (isExpanded) {
      for (const imp of group.imports) {
        rows.push({ type: "import", import: imp, module: group.module });
      }
    }
  }

  const ResizeHandle = ({
    column,
  }: {
    column: keyof typeof DEFAULT_WIDTHS;
  }) => (
    <div
      className="absolute right-0 top-0 h-full w-1 cursor-col-resize hover:bg-blue-500/50 active:bg-blue-500"
      onMouseDown={(e) => handleMouseDown(column, e)}
    />
  );

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center gap-2 mb-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
          <Input
            placeholder={t("search")}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
          />
        </div>
        <button
          type="button"
          className="flex items-center gap-2 px-3 py-1.5 text-xs font-medium bg-gray-100 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-md hover:bg-gray-200 dark:hover:bg-gray-700 cursor-pointer transition"
          onClick={expandAll}
        >
          <span>⤢</span>
          {t("expand_all")}
        </button>
        <button
          type="button"
          className="flex items-center gap-2 px-3 py-1.5 text-xs font-medium bg-gray-100 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-md hover:bg-gray-200 dark:hover:bg-gray-700 cursor-pointer transition"
          onClick={collapseAll}
        >
          <span>⤡</span>
          {t("collapse_all")}
        </button>
      </div>
      <div className="overflow-auto flex-1">
        <table className="w-full text-sm border-collapse">
          <thead className="sticky top-0 bg-background z-10">
            <tr className="border-b">
              <th
                className="relative text-left font-medium p-2"
                style={{ width: columnWidths.icon }}
              />
              <th
                className="relative text-left font-medium p-2"
                style={{ width: columnWidths.name }}
              >
                {t("name")}
                <ResizeHandle column="name" />
              </th>
              <th
                className="relative text-left font-medium p-2"
                style={{ width: columnWidths.address }}
              >
                {t("address")}
                <ResizeHandle column="address" />
              </th>
              <th
                className="relative text-left font-medium p-2"
                style={{ width: columnWidths.demangled }}
              >
                {t("demangled")}
                <ResizeHandle column="demangled" />
              </th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row, idx) => {
              if (row.type === "group") {
                const { group, isExpanded } = row;
                return (
                  <tr
                    key={`group-${group.module}`}
                    className="cursor-pointer bg-muted/30 hover:bg-muted/50 border-b"
                    onClick={() => toggleModule(group.module)}
                  >
                    <td
                      className="p-2"
                      style={{ width: columnWidths.icon }}
                    >
                      {isExpanded ? (
                        <ChevronDown className="w-4 h-4" />
                      ) : (
                        <ChevronRight className="w-4 h-4" />
                      )}
                    </td>
                    <td colSpan={3} className="p-2 font-medium">
                      <div className="flex items-center gap-2">
                        <span className="truncate">{group.module}</span>
                        <span className="px-1.5 py-0.5 text-[10px] rounded bg-blue-100 text-blue-700 dark:bg-blue-900/50 dark:text-blue-300">
                          {group.imports.length}
                        </span>
                        <button
                          type="button"
                          className="p-1 rounded hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-500 hover:text-blue-600 dark:hover:text-blue-400"
                          onClick={(e) => openModuleTab(group.module, e)}
                          aria-label="Open module"
                        >
                          <ExternalLink className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              } else {
                const { import: imp } = row;
                return (
                  <tr
                    key={`import-${idx}`}
                    className="border-b hover:bg-muted/50"
                  >
                    <td
                      className="p-2"
                      style={{ width: columnWidths.icon }}
                    >
                      {imp.type === "f" ? (
                        <FileCode className="w-3.5 h-3.5 text-blue-500" />
                      ) : imp.type === "v" ? (
                        <Database className="w-3.5 h-3.5 text-green-500" />
                      ) : null}
                    </td>
                    <td
                      className="p-2 font-mono text-xs truncate"
                      style={{ width: columnWidths.name, maxWidth: columnWidths.name }}
                    >
                      {imp.name}
                    </td>
                    <td
                      className="p-2 font-mono text-xs"
                      style={{ width: columnWidths.address }}
                    >
                      {imp.addr ? (
                        isClickable(imp) ? (
                          <button
                            type="button"
                            className="text-blue-600 dark:text-blue-400 hover:underline cursor-pointer"
                            onClick={() => handleAddressClick(imp)}
                          >
                            {imp.addr}
                          </button>
                        ) : (
                          <span className="text-muted-foreground">{imp.addr}</span>
                        )
                      ) : (
                        "-"
                      )}
                    </td>
                    <td
                      className="p-2 font-mono text-xs truncate"
                      style={{ width: columnWidths.demangled, maxWidth: columnWidths.demangled }}
                    >
                      {imp.demangled || "-"}
                    </td>
                  </tr>
                );
              }
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
