import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
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
      <div className="flex items-center gap-2 mb-2">
        <button
          type="button"
          className="px-3 py-1 text-xs bg-gray-100 dark:bg-gray-800 rounded hover:bg-gray-200 dark:hover:bg-gray-700 cursor-pointer"
          onClick={expandAll}
        >
          {t("expand_all")}
        </button>
        <button
          type="button"
          className="px-3 py-1 text-xs bg-gray-100 dark:bg-gray-800 rounded hover:bg-gray-200 dark:hover:bg-gray-700 cursor-pointer"
          onClick={collapseAll}
        >
          {t("collapse_all")}
        </button>
      </div>
      <div className="overflow-auto flex-1">
        <ul className="p-2 space-y-1">
          {dependencies.map((dep) => {
            const isExpanded = expandedDeps.has(dep);
            const imports = importedData[dep];
            const isLoading = importsLoading.has(dep);

            return (
              <li key={dep}>
                <div className="flex items-start gap-1">
                  <button
                    type="button"
                    className="mt-0.5 w-4 h-4 flex items-center justify-center text-gray-500 hover:text-gray-700 dark:hover:text-gray-300 cursor-pointer"
                    onClick={() => toggleDep(dep)}
                  >
                    {isExpanded ? "▼" : "▶"}
                  </button>
                  <div className="flex-1">
                    <button
                      type="button"
                      className="text-sm text-blue-600 dark:text-blue-400 hover:underline cursor-pointer text-left"
                      onClick={() => openModuleTab(dep)}
                    >
                      {dep}
                    </button>
                    {isExpanded && (
                      <div className="ml-4 mt-1">
                        {isLoading ? (
                          <span className="text-xs text-gray-500">
                            {t("loading")}...
                          </span>
                        ) : imports && imports.length > 0 ? (
                          <div className="mt-1">
                            <SymbolsTableView
                              symbols={imports}
                              loading={false}
                            />
                          </div>
                        ) : (
                          <span className="text-xs text-gray-500">
                            {t("no_results")}
                          </span>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              </li>
            );
          })}
        </ul>
      </div>
    </div>
  );
}
