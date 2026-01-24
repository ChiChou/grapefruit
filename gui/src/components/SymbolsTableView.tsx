import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { Search } from "lucide-react";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

import type { Symbol } from "../../../agent/types/fruity/modules/symbol";

interface SymbolsTableViewProps {
  symbols: Symbol[] | null;
  loading: boolean;
}

export function SymbolsTableView({ symbols, loading }: SymbolsTableViewProps) {
  const { t } = useTranslation();
  const [search, setSearch] = useState("");

  const filtered = useMemo(() => {
    if (!symbols) return [];
    if (!search.trim()) return symbols;
    const query = search.toLowerCase();
    return symbols.filter(
      (item) =>
        item.name.toLowerCase().includes(query) ||
        (item.demangled && item.demangled.toLowerCase().includes(query)),
    );
  }, [symbols, search]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full text-gray-500">
        {t("loading")}...
      </div>
    );
  }

  if (!symbols || symbols.length === 0) {
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
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="pl-9"
        />
      </div>
      <div className="overflow-auto flex-1">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t("name")}</TableHead>
              <TableHead>{t("address")}</TableHead>
              <TableHead>{t("demangled")}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filtered.map((item, idx) => (
              <TableRow key={item.addr || idx}>
                <TableCell className="font-mono text-xs">{item.name}</TableCell>
                <TableCell className="font-mono text-xs">
                  {item.addr || "-"}
                </TableCell>
                <TableCell className="font-mono text-xs">
                  {item.demangled || "-"}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
