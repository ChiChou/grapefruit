import { useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Search } from "lucide-react";

import { ConnectionStatus, useSession } from "@/context/SessionContext";
import { useDock } from "@/context/DockContext";
import { Input } from "@/components/ui/input";
import type { ModuleInfo } from "../../../../agent/types/fruity/modules/symbol";

const ITEM_HEIGHT = 72;
const OVERSCAN = 5;

export function ModulesPanel() {
  const { t } = useTranslation();
  const { api, status } = useSession();
  const { openFilePanel } = useDock();
  const [isLoading, setIsLoading] = useState(false);
  const [modules, setModules] = useState<ModuleInfo[]>([]);
  const [search, setSearch] = useState("");
  const [scrollTop, setScrollTop] = useState(0);
  const containerRef = useRef<HTMLDivElement>(null);
  const [containerHeight, setContainerHeight] = useState(0);

  useEffect(() => {
    if (!api || status !== ConnectionStatus.Ready) return;

    setIsLoading(true);
    api.symbol
      .modules()
      .then((mods) => setModules(mods))
      .finally(() => setIsLoading(false));
  }, [status, api]);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const observer = new ResizeObserver((entries) => {
      setContainerHeight(entries[0].contentRect.height);
    });
    observer.observe(container);
    return () => observer.disconnect();
  }, []);

  const filteredModules = useMemo(() => {
    if (!search.trim()) return modules;
    const query = search.toLowerCase();
    return modules.filter(
      (m) =>
        m.name.toLowerCase().includes(query) ||
        m.path.toLowerCase().includes(query),
    );
  }, [modules, search]);

  const { startIndex, visibleItems } = useMemo(() => {
    const start = Math.max(0, Math.floor(scrollTop / ITEM_HEIGHT) - OVERSCAN);
    const visibleCount =
      Math.ceil(containerHeight / ITEM_HEIGHT) + OVERSCAN * 2;
    const end = Math.min(filteredModules.length, start + visibleCount);
    return {
      startIndex: start,
      visibleItems: filteredModules.slice(start, end),
    };
  }, [scrollTop, containerHeight, filteredModules]);

  const handleScroll = (e: React.UIEvent<HTMLDivElement>) => {
    setScrollTop(e.currentTarget.scrollTop);
  };

  return (
    <div className="h-full flex flex-col">
      <div className="p-4 space-y-4">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
          <Input
            placeholder={t("search")}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
          />
        </div>
        <div className="text-xs text-gray-500">
          {filteredModules.length} / {modules.length}
        </div>
      </div>
      <div
        ref={containerRef}
        className="flex-1 overflow-auto"
        onScroll={handleScroll}
      >
        {isLoading ? (
          <div className="flex items-center justify-center h-full text-gray-500">
            {t("loading")}...
          </div>
        ) : (
          <div
            style={{ height: filteredModules.length * ITEM_HEIGHT }}
            className="relative"
          >
            {visibleItems.map((mod, idx) => (
              <div
                key={mod.base}
                className="absolute left-0 right-0 px-4 py-2 border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-800"
                style={{
                  height: ITEM_HEIGHT,
                  top: (startIndex + idx) * ITEM_HEIGHT,
                }}
              >
                <button
                  type="button"
                  className="text-sm font-medium truncate text-left w-full text-blue-600 dark:text-blue-400 hover:underline cursor-pointer"
                  onClick={() =>
                    openFilePanel({
                      id: `module_${mod.base}`,
                      component: "moduleDetail",
                      title: mod.name,
                      params: {
                        path: mod.path,
                      },
                    })
                  }
                >
                  {mod.name}
                </button>
                <div className="text-xs text-gray-500 font-mono truncate">
                  {mod.base.toLowerCase()}-
                  {"0x" +
                    (parseInt(mod.base, 16) + mod.size)
                      .toString(16)
                      .toLowerCase()}
                </div>
                <div className="text-xs text-gray-400 truncate">{mod.path}</div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
