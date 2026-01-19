import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Search } from "lucide-react";

import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { ConnectionStatus, useSession } from "@/context/SessionContext";
import { useDock } from "@/context/DockContext";

const ITEM_HEIGHT = 32;
const OVERSCAN = 5;

type ScopeType = "__main__" | "__app__" | "__global__";

export function ClassesPanel() {
  const { t } = useTranslation();
  const { api, status } = useSession();
  const { openFilePanel } = useDock();
  const [isLoading, setIsLoading] = useState(false);
  const [classes, setClasses] = useState<string[]>([]);
  const [scope, setScope] = useState<ScopeType>("__app__");
  const [search, setSearch] = useState("");
  const [scrollTop, setScrollTop] = useState(0);
  const containerRef = useRef<HTMLDivElement>(null);
  const [containerHeight, setContainerHeight] = useState(0);

  const loadClasses = useCallback(
    async (scopeValue: ScopeType) => {
      if (status !== ConnectionStatus.Ready || !api) return;

      setIsLoading(true);
      try {
        const result = await api.classdump.list(scopeValue);
        setClasses(result as unknown as string[]);
      } catch (err) {
        console.error("Failed to load classes:", err);
        setClasses([]);
      } finally {
        setIsLoading(false);
      }
    },
    [api, status],
  );

  useEffect(() => {
    loadClasses(scope);
  }, [scope, loadClasses]);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const observer = new ResizeObserver((entries) => {
      setContainerHeight(entries[0].contentRect.height);
    });
    observer.observe(container);
    return () => observer.disconnect();
  }, []);

  const filteredClasses = useMemo(() => {
    if (!search.trim()) return classes;
    const query = search.toLowerCase();
    return classes.filter((c) => c.toLowerCase().includes(query));
  }, [classes, search]);

  const { startIndex, visibleItems } = useMemo(() => {
    const start = Math.max(0, Math.floor(scrollTop / ITEM_HEIGHT) - OVERSCAN);
    const visibleCount =
      Math.ceil(containerHeight / ITEM_HEIGHT) + OVERSCAN * 2;
    const end = Math.min(filteredClasses.length, start + visibleCount);
    return {
      startIndex: start,
      visibleItems: filteredClasses.slice(start, end),
    };
  }, [scrollTop, containerHeight, filteredClasses]);

  const handleScroll = (e: React.UIEvent<HTMLDivElement>) => {
    setScrollTop(e.currentTarget.scrollTop);
  };

  const handleScopeChange = (value: string) => {
    setScope(value as ScopeType);
    setScrollTop(0);
  };

  return (
    <div className="h-full flex flex-col">
      <div className="p-4 space-y-4">
        <RadioGroup
          value={scope}
          onValueChange={handleScopeChange}
          className="flex flex-row gap-4"
        >
          <div className="flex items-center space-x-2">
            <RadioGroupItem value="__main__" id="scope-main" />
            <Label htmlFor="scope-main" className="cursor-pointer">
              {t("main")}
            </Label>
          </div>
          <div className="flex items-center space-x-2">
            <RadioGroupItem value="__app__" id="scope-app" />
            <Label htmlFor="scope-app" className="cursor-pointer">
              {t("app")}
            </Label>
          </div>
          <div className="flex items-center space-x-2">
            <RadioGroupItem value="__global__" id="scope-global" />
            <Label htmlFor="scope-global" className="cursor-pointer">
              {t("global")}
            </Label>
          </div>
        </RadioGroup>
        {!isLoading && (
          <>
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
              {filteredClasses.length} / {classes.length}
            </div>
          </>
        )}
      </div>
      <div
        ref={containerRef}
        className="flex-1 overflow-auto"
        onScroll={handleScroll}
      >
        {isLoading ? (
          <div className="flex items-center justify-center h-full">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600" />
          </div>
        ) : (
          <div
            style={{ height: filteredClasses.length * ITEM_HEIGHT }}
            className="relative"
          >
            {visibleItems.map((className, idx) => (
              <div
                key={className}
                className="absolute left-0 right-0 px-4 py-1 border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-800"
                style={{
                  height: ITEM_HEIGHT,
                  top: (startIndex + idx) * ITEM_HEIGHT,
                }}
              >
                <button
                  type="button"
                  className="text-sm font-mono truncate block text-left w-full text-blue-600 dark:text-blue-400 hover:underline cursor-pointer"
                  onClick={() =>
                    openFilePanel({
                      id: `class_${className}`,
                      component: "classDetail",
                      title: className,
                      params: { className },
                    })
                  }
                >
                  {className}
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
