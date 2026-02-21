import { useTranslation } from "react-i18next";
import { useDock } from "@/context/DockContext";
import { Spinner } from "@/components/ui/spinner";
import { usePlatformRpcQuery } from "@/lib/queries";
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
  const { openFilePanel } = useDock();
  const { t } = useTranslation();

  const { data: sections, isLoading: loading } = usePlatformRpcQuery(
    ["sections", path],
    (api) => api.symbol.sections(path)
  );

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
      <div className="flex items-center justify-center h-full gap-2 text-muted-foreground">
        <Spinner />
        {t("loading")}...
      </div>
    );
  }

  if (!sections || sections.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
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
                  className="text-amber-600 dark:text-amber-400 hover:underline cursor-pointer text-left"
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
