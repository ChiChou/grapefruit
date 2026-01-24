import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Search } from "lucide-react";
import { Input } from "@/components/ui/input";
import { useDock } from "@/context/DockContext";
import { useSession } from "@/context/SessionContext";

interface ClassesListViewProps {
  path: string;
}

export function ClassesListView({
  path,
}: ClassesListViewProps) {
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
    c.toLowerCase().includes(searchValue.toLowerCase())
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
      <div className="relative mb-2">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
        <Input
          placeholder={t("search")}
          value={searchValue}
          onChange={(e) => setSearchValue(e.target.value)}
          className="pl-9"
        />
      </div>
      <div className="overflow-auto flex-1">
        <div className="flex flex-wrap gap-2 p-2">
          {filtered?.map((className) => (
            <button
              key={className}
              type="button"
              className="px-3 py-1 text-sm bg-blue-100 dark:bg-blue-900 text-blue-700 dark:text-blue-300 rounded-md hover:bg-blue-200 dark:hover:bg-blue-800 cursor-pointer truncate max-w-xs"
              onClick={() => openClassTab(className)}
            >
              {className}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
