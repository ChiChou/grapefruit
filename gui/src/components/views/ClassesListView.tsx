import { useCallback, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { Search } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Spinner } from "@/components/ui/spinner";
import { useDock } from "@/context/DockContext";
import { useFruityQuery } from "@/lib/queries";

interface ClassesListViewProps {
  path: string;
}

export function ClassesListView({ path }: ClassesListViewProps) {
  const { openFilePanel } = useDock();
  const { t } = useTranslation();
  const [searchValue, setSearchValue] = useState("");

  const { data: classes, isLoading: loading } = useFruityQuery(
    ["moduleClasses", path],
    (api) => api.classdump.classesForModule(path)
  );

  const searchTerm = searchValue.trim();
  const searchLower = searchTerm.toLowerCase();

  const filtered = useMemo(
    () => classes?.filter((c) => c.toLowerCase().includes(searchLower)),
    [classes, searchLower],
  );

  const highlightMatch = useCallback(
    (className: string) => {
      if (!searchTerm) return className;

      const lower = className.toLowerCase();
      const idx = lower.indexOf(searchLower);
      if (idx === -1) return className;

      const before = className.slice(0, idx);
      const match = className.slice(idx, idx + searchTerm.length);
      const after = className.slice(idx + searchTerm.length);

      return (
        <>
          {before}
          <span className="rounded bg-yellow-200 px-0.5 text-yellow-900 dark:bg-yellow-400/70 dark:text-yellow-900">
            {match}
          </span>
          {after}
        </>
      );
    },
    [searchLower, searchTerm],
  );

  const openClassTab = useCallback(
    (className: string) => {
      openFilePanel({
        id: `class_${className}`,
        component: "classDetail",
        title: className,
        params: { className },
      });
    },
    [openFilePanel],
  );

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full gap-2 text-muted-foreground">
        <Spinner />
        {t("loading")}...
      </div>
    );
  }

  if (!classes || classes.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        {t("no_results")}
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      <div className="relative mb-3">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <Input
          placeholder={t("search")}
          value={searchValue}
          onChange={(e) => setSearchValue(e.target.value)}
          className="pl-9 h-8 text-sm"
        />
      </div>
      <div className="text-xs text-muted-foreground mb-2">
        {filtered?.length.toLocaleString() ?? 0} / {classes?.length.toLocaleString() ?? 0} {t("items")}
      </div>
      <div className="flex-1 overflow-auto">
        {filtered && filtered.length > 0 ? (
          <div className="flex flex-wrap gap-3">
            {filtered.map((className) => (
              <button
                key={className}
                type="button"
                className="cursor-pointer rounded-md border border-border/50 bg-muted/30 px-3 py-1.5 text-xs font-mono text-foreground/90 transition-colors hover:bg-accent hover:text-accent-foreground hover:border-accent"
                onClick={() => openClassTab(className)}
              >
                {highlightMatch(className)}
              </button>
            ))}
          </div>
        ) : (
          <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
            {t("no_results")}
          </div>
        )}
      </div>
    </div>
  );
}
