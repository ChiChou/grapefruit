import { useMemo, useState, useRef, useCallback } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router";
import { toast } from "sonner";
import {
  ChevronRight,
  ChevronDown,
  ExternalLink,
  Search,
  Anchor,
  Code,
  Layers,
} from "lucide-react";
import { useDock } from "@/context/DockContext";
import { useRpcQuery } from "@/lib/queries";
import { useSession, Status, Mode } from "@/context/SessionContext";
import { useRepl } from "@/context/useRepl";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { generateNativeHook, type NativeHookTarget } from "@/lib/hook-codegen";

import type {
  ImportGroup,
  Imported,
} from "@agent/common/symbol";

interface ImportsListViewProps {
  path: string;
}

const DEFAULT_WIDTHS = {
  icon: 90,
  name: 300,
  address: 140,
  demangled: 400,
};

export function ImportsListView({ path }: ImportsListViewProps) {
  const { openFilePanel } = useDock();
  const { t } = useTranslation();
  const { fruity, status, platform, mode, device, bundle, pid } = useSession();
  const { appendCode } = useRepl();
  const navigate = useNavigate();

  const hooksPath = `/workspace/${platform}/${device}/${mode}/${mode === Mode.App ? bundle : pid}/hooks`;
  const [expandedModules, setExpandedModules] = useState<Set<string>>(
    new Set(),
  );
  const [search, setSearch] = useState("");
  const [batchMode, setBatchMode] = useState(false);
  const [selectedImports, setSelectedImports] = useState<Set<string>>(
    new Set(),
  );
  const [columnWidths, setColumnWidths] = useState(DEFAULT_WIDTHS);

  const resizing = useRef<{
    column: keyof typeof DEFAULT_WIDTHS;
    startX: number;
    startWidth: number;
  } | null>(null);

  const { data: importGroups, isLoading: loading } = useRpcQuery(
    ["importsGrouped", path],
    (api) => api.symbol.importsGrouped(path),
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
            (imp.demangled && imp.demangled.toLowerCase().includes(query)),
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

  const isFunction = (imp: Imported): boolean => {
    return imp.type === "f";
  };

  const getImportKey = (module: string, name: string): string => {
    return `${module}:${name}`;
  };

  const handleSelectImport = (
    module: string,
    imp: Imported,
    checked: boolean,
  ) => {
    const key = getImportKey(module, imp.name);
    setSelectedImports((prev) => {
      const next = new Set(prev);
      if (checked) {
        next.add(key);
      } else {
        next.delete(key);
      }
      return next;
    });
  };

  const getModuleFunctions = (group: ImportGroup): Imported[] => {
    return group.imports.filter((imp) => imp.type === "f");
  };

  const getModuleSelectionState = (
    group: ImportGroup,
  ): "all" | "some" | "none" => {
    const functions = getModuleFunctions(group);
    if (functions.length === 0) return "none";

    const selectedCount = functions.filter((imp) =>
      selectedImports.has(getImportKey(group.module, imp.name)),
    ).length;

    if (selectedCount === 0) return "none";
    if (selectedCount === functions.length) return "all";
    return "some";
  };

  const handleSelectModule = (group: ImportGroup, checked: boolean) => {
    const functions = getModuleFunctions(group);
    setSelectedImports((prev) => {
      const next = new Set(prev);
      for (const imp of functions) {
        const key = getImportKey(group.module, imp.name);
        if (checked) {
          next.add(key);
        } else {
          next.delete(key);
        }
      }
      return next;
    });
  };

  const handleHookFunction = async (module: string, imp: Imported) => {
    if (!fruity || status !== Status.Ready) return;
    try {
      await fruity.native.hook(module, imp.name);
      // Navigate to hooks panel, show toast, and trigger refresh
      navigate(hooksPath);
      toast.success(t("hook_added"), {
        description: `${module}!${imp.name}`,
      });
      window.dispatchEvent(new CustomEvent("hooks:refresh"));
    } catch (error) {
      console.error("Failed to hook function:", error);
      toast.error(t("hook_failed"));
    }
  };

  const handleGenerateCode = (module: string, imp: Imported) => {
    const target: NativeHookTarget = {
      type: "native",
      module,
      name: imp.name,
    };
    const code = generateNativeHook(target);
    appendCode(code);
  };

  const handleBatchHook = async () => {
    if (!fruity || status !== Status.Ready) return;

    let successCount = 0;
    for (const key of selectedImports) {
      const [module, name] = key.split(":");
      try {
        await fruity.native.hook(module, name);
        successCount++;
      } catch (error) {
        console.error(`Failed to hook ${name}:`, error);
      }
    }

    if (successCount > 0) {
      // Navigate to hooks panel, show toast, and trigger refresh
      navigate(hooksPath);
      toast.success(t("hook_added_count", { count: successCount }));
      window.dispatchEvent(new CustomEvent("hooks:refresh"));
      setSelectedImports(new Set());
    }
  };

  const handleBatchGenerateCode = () => {
    const codes: string[] = [];

    for (const key of selectedImports) {
      const [module, name] = key.split(":");
      const target: NativeHookTarget = {
        type: "native",
        module,
        name,
      };
      codes.push(generateNativeHook(target));
    }

    if (codes.length > 0) {
      appendCode(codes.join("\n"));
    }
  };

  const toggleBatchMode = useCallback(() => {
    setBatchMode((prev) => !prev);
    setSelectedImports(new Set());
  }, []);

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
    [columnWidths],
  );

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        {t("loading")}...
      </div>
    );
  }

  if (!importGroups || importGroups.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
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
      className="absolute right-0 top-0 h-full w-1 cursor-col-resize hover:bg-amber-500/50 active:bg-amber-500"
      onMouseDown={(e) => handleMouseDown(column, e)}
    />
  );

  const selectedCount = selectedImports.size;

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center gap-2 mb-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder={t("search")}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
          />
        </div>
        <Button
          variant={batchMode ? "secondary" : "outline"}
          size="sm"
          onClick={toggleBatchMode}
          className="gap-1.5"
        >
          <Layers className="h-4 w-4" />
          {t("hook_batch_mode")}
        </Button>
        <button
          type="button"
          className="flex items-center gap-2 px-3 py-1.5 text-xs font-medium bg-muted border border-border rounded-md hover:bg-accent cursor-pointer transition"
          onClick={expandAll}
        >
          <span>⤢</span>
          {t("expand_all")}
        </button>
        <button
          type="button"
          className="flex items-center gap-2 px-3 py-1.5 text-xs font-medium bg-muted border border-border rounded-md hover:bg-accent cursor-pointer transition"
          onClick={collapseAll}
        >
          <span>⤡</span>
          {t("collapse_all")}
        </button>
      </div>

      {batchMode && (
        <div className="flex items-center gap-2 mb-2 p-2 bg-muted/50 rounded-md">
          <span className="text-sm text-muted-foreground">
            {t("hook_selected_count", { count: selectedCount })}
          </span>
          <div className="flex-1" />
          <Button
            variant="outline"
            size="sm"
            onClick={handleBatchHook}
            disabled={status !== Status.Ready || selectedCount === 0}
            className="gap-1.5"
          >
            <Anchor className="h-4 w-4" />
            {t("hook_batch_hook")}
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={handleBatchGenerateCode}
            disabled={selectedCount === 0}
            className="gap-1.5"
          >
            <Code className="h-4 w-4" />
            {t("hook_batch_generate")}
          </Button>
        </div>
      )}

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
                const moduleSelectionState = batchMode
                  ? getModuleSelectionState(group)
                  : "none";
                return (
                  <tr
                    key={`group-${group.module}`}
                    className="cursor-pointer bg-muted/30 hover:bg-muted/50 border-b"
                    onClick={() => toggleModule(group.module)}
                  >
                    <td className="p-2" style={{ width: columnWidths.icon }}>
                      <div className="flex items-center gap-1">
                        {batchMode && (
                          <Checkbox
                            checked={moduleSelectionState === "all"}
                            indeterminate={moduleSelectionState === "some"}
                            onCheckedChange={(checked) => {
                              handleSelectModule(group, !!checked);
                            }}
                            onClick={(e) => e.stopPropagation()}
                            aria-label="Select all in module"
                            className="shrink-0"
                          />
                        )}
                        {isExpanded ? (
                          <ChevronDown className="w-4 h-4 shrink-0" />
                        ) : (
                          <ChevronRight className="w-4 h-4 shrink-0" />
                        )}
                      </div>
                    </td>
                    <td colSpan={3} className="p-2 font-medium">
                      <div className="flex items-center gap-2">
                        <span className="truncate">{group.module}</span>
                        <span className="px-1.5 py-0.5 text-[10px] rounded bg-amber-100 text-amber-700 dark:bg-amber-900/50 dark:text-amber-300">
                          {group.imports.length}
                        </span>
                        <button
                          type="button"
                          className="p-1 rounded hover:bg-accent text-muted-foreground hover:text-amber-600 dark:hover:text-amber-400"
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
                const { import: imp, module } = row;
                const key = getImportKey(module, imp.name);
                const isSelected = selectedImports.has(key);
                return (
                  <tr
                    key={`import-${idx}`}
                    className="border-b hover:bg-muted/50 group"
                  >
                    <td className="p-2" style={{ width: columnWidths.icon }}>
                      <div className="flex items-center gap-1">
                        {isFunction(imp) && (batchMode ? (
                          <Checkbox
                            checked={isSelected}
                            onCheckedChange={(checked) =>
                              handleSelectImport(module, imp, !!checked)
                            }
                            aria-label="Select row"
                            className="shrink-0"
                          />
                        ) : (
                          <div className="flex items-center gap-0.5 shrink-0">
                            <Button
                              variant="ghost"
                              size="icon"
                              className="h-6 w-6 opacity-0 group-hover:opacity-100 transition-opacity"
                              onClick={() => handleHookFunction(module, imp)}
                              disabled={status !== Status.Ready}
                              title={t("hook_add")}
                            >
                              <Anchor className="h-3.5 w-3.5" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="icon"
                              className="h-6 w-6 opacity-0 group-hover:opacity-100 transition-opacity"
                              onClick={() => handleGenerateCode(module, imp)}
                              title={t("hook_generate_code")}
                            >
                              <Code className="h-3.5 w-3.5" />
                            </Button>
                          </div>
                        ))}
                      </div>
                    </td>
                    <td
                      className="p-2 font-mono text-xs truncate"
                      style={{
                        width: columnWidths.name,
                        maxWidth: columnWidths.name,
                      }}
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
                            className="text-amber-600 dark:text-amber-400 hover:underline cursor-pointer"
                            onClick={() => handleAddressClick(imp)}
                          >
                            {imp.addr}
                          </button>
                        ) : (
                          <span className="text-muted-foreground">
                            {imp.addr}
                          </span>
                        )
                      ) : (
                        "-"
                      )}
                    </td>
                    <td
                      className="p-2 font-mono text-xs truncate"
                      style={{
                        width: columnWidths.demangled,
                        maxWidth: columnWidths.demangled,
                      }}
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
