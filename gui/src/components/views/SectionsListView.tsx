import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import type { Section } from "../../../../agent/types/fruity/modules/symbol";
import { useDock } from "@/context/DockContext";
import { useSession } from "@/context/SessionContext";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

interface SectionsListViewProps {
  path: string;
}

export function SectionsListView({
  path,
}: SectionsListViewProps) {
  const { api } = useSession();
  const { openFilePanel } = useDock();
  const { t } = useTranslation();
  const [sections, setSections] = useState<Section[] | null>(null);
  const [loading, setLoading] = useState(false);

  const loadSections = useCallback(async () => {
    if (!api) return;
    if (sections !== null) return;

    setLoading(true);
    try {
      const result = await api.symbol.sections(path);
      setSections(result);
    } catch (err) {
      console.error("Failed to load sections:", err);
      setSections([]);
    } finally {
      setLoading(false);
    }
  }, [api, path, sections]);

  useEffect(() => {
    loadSections();
  }, [loadSections]);

  const openMemoryPreviewTab = (address: string, size: number) => {
    openFilePanel({
      id: `memory_${address}_${size}`,
      component: "memory",
      title: `Memory ${address}`,
      params: { address, size },
    });
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full text-gray-500">
        {t("loading")}...
      </div>
    );
  }

  if (!sections || sections.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-gray-500">
        {t("no_results")}
      </div>
    );
  }

  return (
    <div className="overflow-auto h-full">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>{t("name")}</TableHead>
            <TableHead>{t("address")}</TableHead>
            <TableHead className="text-right">{t("size")}</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {sections.map((section) => (
            <TableRow key={section.addr}>
              <TableCell className="font-mono">{section.name}</TableCell>
              <TableCell className="font-mono">
                <button
                  type="button"
                  className="text-blue-600 dark:text-blue-400 hover:underline cursor-pointer text-left"
                  onClick={() =>
                    openMemoryPreviewTab(section.addr, section.size)
                  }
                >
                  {section.addr}
                </button>
              </TableCell>
              <TableCell className="font-mono text-right">
                {"0x" + section.size.toString(16)}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
