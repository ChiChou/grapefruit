import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { ExternalLink } from "lucide-react";
import { useSession } from "@/context/SessionContext";
import { useDock } from "@/context/DockContext";
import { SymbolsTableView } from "../SymbolsTableView";

import type { Symbol } from "../../../../agent/types/fruity/modules/symbol";

interface DependenciesListViewProps {
  path: string;
}

export function DependenciesListView({ path }: DependenciesListViewProps) {
  const { api } = useSession();
  const { openFilePanel } = useDock();
  const { t } = useTranslation();
  const [dependencies, setDependencies] = useState<string[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [expandedDeps, setExpandedDeps] = useState<Set<string>>(new Set());
  const [importsLoading, setImportsLoading] = useState<Set<string>>(new Set());
  const [importedData, setImportedData] = useState<
    Record<string, Symbol[] | null>
  >({});

  const loadDependencies = useCallback(async () => {
    if (!api) return;
    if (dependencies !== null) return;

    setLoading(true);
    try {
      const result = await api.symbol.dependencies(path);
      setDependencies(result);
    } catch (err) {
      console.error("Failed to load dependencies:", err);
      setDependencies([]);
    } finally {
      setLoading(false);
    }
  }, [api, path, dependencies]);

  useEffect(() => {
    loadDependencies();
  }, [loadDependencies]);

  const loadImportsForDep = useCallback(
    async (dep: string) => {
      if (!api) return;
      if (importedData[dep] !== undefined) return;

      setImportsLoading((prev) => new Set(prev).add(dep));
      try {
        const result = await api.symbol.imports(path, dep);
        setImportedData((prev) => ({ ...prev, [dep]: result }));
      } catch (err) {
        console.error(`Failed to load imports for ${dep}:`, err);
        setImportedData((prev) => ({ ...prev, [dep]: [] }));
      } finally {
        setImportsLoading((prev) => {
          const next = new Set(prev);
          next.delete(dep);
          return next;
        });
      }
    },
    [api, path, importedData],
  );

  const toggleDep = (dep: string) => {
    const newExpanded = new Set(expandedDeps);
    if (newExpanded.has(dep)) {
      newExpanded.delete(dep);
    } else {
      newExpanded.add(dep);
      loadImportsForDep(dep);
    }
    setExpandedDeps(newExpanded);
  };

  const expandAll = () => {
    if (!dependencies) return;
    const newExpanded = new Set<string>(dependencies);
    dependencies.forEach((dep) => {
      if (importedData[dep] === undefined) {
        loadImportsForDep(dep);
      }
    });
    setExpandedDeps(newExpanded);
  };

  const collapseAll = () => {
    setExpandedDeps(new Set());
  };

  const openModuleTab = (depPath: string) => {
    const name = depPath.split("/").pop() || depPath;
    openFilePanel({
      id: `module_${depPath}`,
      component: "moduleDetail",
      title: name,
      params: { path: depPath },
    });
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full text-gray-500">
        {t("loading")}...
      </div>
    );
  }

  if (!dependencies || dependencies.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-gray-500">
        {t("no_results")}
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center gap-2 mb-3">
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
      <div className="overflow-auto flex-1 rounded-lg border border-gray-200 dark:border-gray-800 bg-white/60 dark:bg-gray-900/60 p-3 shadow-inner">
        <ul className="space-y-2">
          {dependencies.map((dep) => {
            const isExpanded = expandedDeps.has(dep);
            const imports = importedData[dep];
            const isLoading = importsLoading.has(dep);
            const importCount = imports?.length ?? 0;
            const hasLoaded = imports !== undefined;

            return (
              <li
                key={dep}
                className="rounded-md border border-gray-100 dark:border-gray-800 bg-gray-50/70 dark:bg-gray-900/40 px-3 py-2 transition hover:border-blue-200 dark:hover:border-blue-500/50"
              >
                <div className="space-y-2">
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      aria-expanded={isExpanded}
                      className="flex flex-1 items-center gap-2 px-3 py-2 text-sm font-medium text-gray-900 dark:text-gray-100 rounded-md bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 hover:border-blue-300 dark:hover:border-blue-500/60 hover:text-blue-600 dark:hover:text-blue-300 transition"
                      onClick={() => toggleDep(dep)}
                    >
                      <span className="text-base font-semibold text-gray-600 dark:text-gray-300">
                        {isExpanded ? "–" : "+"}
                      </span>
                      <span className="truncate">{dep}</span>
                    </button>
                    {hasLoaded && (
                      <span className="px-2 py-0.5 text-[10px] uppercase tracking-wide rounded-md bg-blue-50 text-blue-600 dark:bg-blue-500/20 dark:text-blue-200 font-semibold">
                        {importCount} {t("items")}
                      </span>
                    )}
                    <button
                      type="button"
                      className="p-2 rounded-md border border-transparent text-gray-500 hover:text-blue-600 dark:text-gray-300 dark:hover:text-blue-300 hover:border-blue-200 dark:hover:border-blue-500/50 transition"
                      onClick={() => openModuleTab(dep)}
                      aria-label={t("open_details", {
                        defaultValue: "Open details",
                      })}
                    >
                      <ExternalLink className="w-4 h-4" />
                    </button>
                  </div>
                  {isExpanded && (
                    <div className="relative pl-4 border-l border-dashed border-gray-200 dark:border-gray-700">
                      {isLoading ? (
                        <span className="text-xs text-gray-500 flex items-center gap-2 mt-1">
                          <span className="w-2 h-2 rounded-full bg-gray-400 animate-pulse" />
                          {t("loading")}...
                        </span>
                      ) : imports && imports.length > 0 ? (
                        <div className="mt-2 rounded-md bg-white dark:bg-gray-950/40 border border-gray-100 dark:border-gray-800 px-2 py-1.5 shadow-sm">
                          <SymbolsTableView symbols={imports} loading={false} />
                        </div>
                      ) : (
                        <span className="text-xs text-gray-500 mt-1 block">
                          {t("no_results")}
                        </span>
                      )}
                    </div>
                  )}
                </div>
              </li>
            );
          })}
        </ul>
      </div>
    </div>
  );
}
