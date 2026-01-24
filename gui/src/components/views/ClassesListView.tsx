import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Search } from "lucide-react";
import { Input } from "@/components/ui/input";
import { useDock } from "@/context/DockContext";
import { useSession } from "@/context/SessionContext";

interface ClassesListViewProps {
  path: string;
}

export function ClassesListView({ path }: ClassesListViewProps) {
  const { api } = useSession();
  const { openFilePanel } = useDock();
  const { t } = useTranslation();
  const [classes, setClasses] = useState<string[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [searchValue, setSearchValue] = useState("");

  const loadClasses = useCallback(async () => {
    if (!api) return;
    if (classes !== null) return;

    setLoading(true);
    try {
      const result = await api.classdump.classesForModule(path);
      setClasses(result);
    } catch (err) {
      console.error("Failed to load classes:", err);
      setClasses([]);
    } finally {
      setLoading(false);
    }
  }, [api, path, classes]);

  useEffect(() => {
    loadClasses();
  }, [loadClasses]);

  const filtered = classes?.filter((c) =>
    c.toLowerCase().includes(searchValue.toLowerCase()),
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
      <div className="flex items-center justify-center h-full text-gray-500">
        {t("loading")}...
      </div>
    );
  }

  if (!classes || classes.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-gray-500">
        {t("no_results")}
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      <div className="relative mb-4">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
        <Input
          placeholder={t("search")}
          value={searchValue}
          onChange={(e) => setSearchValue(e.target.value)}
          className="border-gray-200 bg-white pl-10 pr-4 py-2 text-sm shadow-inner transition focus:border-blue-400 focus:ring-blue-200 dark:border-gray-700 dark:bg-gray-900"
        />
      </div>
      <div className="flex-1 overflow-auto">
        {filtered && filtered.length > 0 ? (
          <div className="flex flex-wrap gap-3">
            {filtered.map((className) => (
              <button
                key={className}
                type="button"
                className="cursor-pointer rounded-md hover:border-blue-200 border-transparent bg-transparent px-4 py-2 text-sm font-medium text-blue-800 shadow-sm transition  hover:bg-blue-50 dark:border-blue-900 dark:bg-transparent dark:text-blue-200 dark:hover:border-blue-700 dark:hover:bg-blue-900/70"
                onClick={() => openClassTab(className)}
              >
                {className}
              </button>
            ))}
          </div>
        ) : (
          <div className="flex h-full items-center justify-center text-sm text-gray-500 dark:text-gray-400">
            {t("no_results")}
          </div>
        )}
      </div>
    </div>
  );
}
