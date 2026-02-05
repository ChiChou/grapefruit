import { useMemo, useState, useRef, useCallback } from "react";
import { useTranslation } from "react-i18next";
import { Search, FileCode, Database } from "lucide-react";
import {
  useReactTable,
  getCoreRowModel,
  getFilteredRowModel,
  flexRender,
  type ColumnDef,
  type ColumnResizeMode,
} from "@tanstack/react-table";
import { useVirtualizer } from "@tanstack/react-virtual";
import { Input } from "@/components/ui/input";
import { useDock } from "@/context/DockContext";

import type {
  Symbol,
  Exported,
} from "../../../agent/types/fruity/modules/symbol";

type SymbolItem = Symbol | Exported;

interface SymbolsTableViewProps {
  symbols: SymbolItem[] | null;
  loading: boolean;
}

const DEFAULT_WIDTHS = {
  type: 32,
  name: 300,
  address: 140,
  demangled: 400,
};

export function SymbolsTableView({ symbols, loading }: SymbolsTableViewProps) {
  const { t } = useTranslation();
  const { openFilePanel } = useDock();
  const [globalFilter, setGlobalFilter] = useState("");
  const [columnSizing, setColumnSizing] = useState<Record<string, number>>({
    type: DEFAULT_WIDTHS.type,
    name: DEFAULT_WIDTHS.name,
    address: DEFAULT_WIDTHS.address,
    demangled: DEFAULT_WIDTHS.demangled,
  });
  const tableContainerRef = useRef<HTMLDivElement>(null);

  const openDisassemblyTab = useCallback(
    (address: string, name?: string) => {
      openFilePanel({
        id: `disasm_${address}`,
        component: "disassembly",
        title: name ? `${name}` : address,
        params: { address, name },
      });
    },
    [openFilePanel]
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
    [openFilePanel]
  );

  const handleAddressClick = useCallback(
    (item: SymbolItem) => {
      // Check if it's an ObjC class reference
      if (item.name.startsWith("OBJC_CLASS_$_")) {
        const className = item.name.replace("OBJC_CLASS_$_", "");
        openClassTab(className);
        return;
      }
      // Open disassembly if clickable (already validated by isClickable)
      if (item.addr) {
        openDisassemblyTab(item.addr, item.name);
      }
    },
    [openClassTab, openDisassemblyTab]
  );

  const isClickable = useCallback((item: SymbolItem): boolean => {
    // ObjC class references are always clickable
    if (item.name.startsWith("OBJC_CLASS_$_")) return true;
    // No address means not clickable
    if (!item.addr) return false;
    // Check if item has type info (Exported/Imported types have this)
    const typed = item as Exported;
    if (typed.type !== undefined) {
      // Only functions are clickable for disassembly
      return typed.type === "f";
    }
    // For Symbol type (no type field), assume it's clickable
    return true;
  }, []);

  const columns = useMemo<ColumnDef<SymbolItem>[]>(
    () => [
      {
        id: "type",
        header: "",
        size: DEFAULT_WIDTHS.type,
        minSize: 32,
        maxSize: 50,
        cell: ({ row }) => {
          const item = row.original as Exported;
          if (item.type === "f") {
            return <FileCode className="w-3.5 h-3.5 text-blue-500" />;
          } else if (item.type === "v") {
            return <Database className="w-3.5 h-3.5 text-green-500" />;
          }
          return null;
        },
      },
      {
        accessorKey: "name",
        header: () => t("name"),
        size: DEFAULT_WIDTHS.name,
        minSize: 100,
      },
      {
        accessorKey: "addr",
        header: () => t("address"),
        size: DEFAULT_WIDTHS.address,
        minSize: 80,
        cell: ({ row }) => {
          const item = row.original;
          const addr = item.addr;
          if (!addr) return "-";
          if (isClickable(item)) {
            return (
              <button
                type="button"
                className="text-blue-600 dark:text-blue-400 hover:underline cursor-pointer"
                onClick={() => handleAddressClick(item)}
              >
                {addr}
              </button>
            );
          }
          return <span className="text-muted-foreground">{addr}</span>;
        },
      },
      {
        accessorKey: "demangled",
        header: () => t("demangled"),
        size: DEFAULT_WIDTHS.demangled,
        minSize: 100,
        cell: ({ getValue }) => getValue() || "-",
      },
    ],
    [t, handleAddressClick, isClickable]
  );

  const data = useMemo(() => symbols ?? [], [symbols]);

  const table = useReactTable({
    data,
    columns,
    state: {
      globalFilter,
      columnSizing,
    },
    onGlobalFilterChange: setGlobalFilter,
    onColumnSizingChange: setColumnSizing,
    getCoreRowModel: getCoreRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    columnResizeMode: "onChange" as ColumnResizeMode,
    enableColumnResizing: true,
  });

  const { rows } = table.getRowModel();

  const rowVirtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => tableContainerRef.current,
    estimateSize: () => 32,
    overscan: 20,
  });

  const virtualRows = rowVirtualizer.getVirtualItems();
  const totalSize = rowVirtualizer.getTotalSize();

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
          value={globalFilter}
          onChange={(e) => setGlobalFilter(e.target.value)}
          className="pl-9"
        />
      </div>
      <div className="text-xs text-muted-foreground mb-1">
        {rows.length.toLocaleString()} / {data.length.toLocaleString()}{" "}
        {t("items")}
      </div>
      <div ref={tableContainerRef} className="overflow-auto flex-1">
        <table
          className="w-full text-sm border-collapse"
          style={{ width: table.getCenterTotalSize() }}
        >
          <thead className="sticky top-0 bg-background z-10">
            {table.getHeaderGroups().map((headerGroup) => (
              <tr key={headerGroup.id} className="border-b">
                {headerGroup.headers.map((header) => (
                  <th
                    key={header.id}
                    className="relative text-left font-medium p-2 select-none"
                    style={{ width: header.getSize() }}
                  >
                    {header.isPlaceholder
                      ? null
                      : flexRender(
                          header.column.columnDef.header,
                          header.getContext()
                        )}
                    {header.column.getCanResize() && (
                      <div
                        onMouseDown={header.getResizeHandler()}
                        onTouchStart={header.getResizeHandler()}
                        className={`absolute right-0 top-0 h-full w-1 cursor-col-resize select-none touch-none hover:bg-blue-500/50 ${
                          header.column.getIsResizing() ? "bg-blue-500" : ""
                        }`}
                      />
                    )}
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody>
            {/* Spacer for virtual scroll */}
            {virtualRows.length > 0 && virtualRows[0].start > 0 && (
              <tr>
                <td
                  colSpan={columns.length}
                  style={{ height: virtualRows[0].start }}
                />
              </tr>
            )}
            {virtualRows.map((virtualRow) => {
              const row = rows[virtualRow.index];
              return (
                <tr
                  key={virtualRow.index}
                  className="border-b hover:bg-muted/50"
                  style={{ height: virtualRow.size }}
                >
                  {row.getVisibleCells().map((cell) => (
                    <td
                      key={cell.id}
                      className="p-2 font-mono text-xs truncate"
                      style={{
                        width: cell.column.getSize(),
                        maxWidth: cell.column.getSize(),
                      }}
                    >
                      {flexRender(
                        cell.column.columnDef.cell,
                        cell.getContext()
                      )}
                    </td>
                  ))}
                </tr>
              );
            })}
            {/* Spacer for virtual scroll end */}
            {virtualRows.length > 0 && (
              <tr>
                <td
                  colSpan={columns.length}
                  style={{
                    height:
                      totalSize -
                      (virtualRows[virtualRows.length - 1]?.end ?? 0),
                  }}
                />
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
